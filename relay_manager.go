package nebula

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

const (
	relayRequested = iota
	relayPeerRequested
	relayEstablished
	relayDisestablished
)

const (
	relayTypeUnknown = iota
	relayTypeForwarding
	relayTypeTerminal
)

type relay struct {
	created     time.Time
	lastRequest time.Time
	Type        int
	State       int
	LocalIndex  uint32
	RemoteIndex uint32
	PeerAddr    netip.Addr
}

// relayState publishes immutable mappings in both indexes under one lock.
type relayState struct {
	sync.RWMutex
	relays         []netip.Addr
	relayForByAddr map[netip.Addr]*relay
	relayForByIdx  map[uint32]*relay
}

// storeLocked publishes a new mapping or a copy of an updated mapping.
func (rs *relayState) storeLocked(r *relay) {
	if rs.relayForByAddr == nil {
		rs.relayForByAddr = make(map[netip.Addr]*relay)
		rs.relayForByIdx = make(map[uint32]*relay)
	}
	rs.relayForByAddr[r.PeerAddr] = r
	rs.relayForByIdx[r.LocalIndex] = r
}

func (rs *relayState) setStateByAddr(vpnIp netip.Addr, state int) {
	rs.Lock()
	defer rs.Unlock()
	if r, ok := rs.relayForByAddr[vpnIp]; ok && r.State != state {
		newRelay := *r
		newRelay.State = state
		rs.storeLocked(&newRelay)
	}
}

func (rs *relayState) setStateByIndex(idx uint32, state int) {
	rs.Lock()
	defer rs.Unlock()
	if r, ok := rs.relayForByIdx[idx]; ok && r.State != state {
		newRelay := *r
		newRelay.State = state
		rs.storeLocked(&newRelay)
	}
}

func (rs *relayState) mappings() []*relay {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]*relay, 0, len(rs.relayForByIdx))
	for _, r := range rs.relayForByIdx {
		ret = append(ret, r)
	}
	return ret
}

func (rs *relayState) addRelayAddress(ip netip.Addr) {
	rs.Lock()
	defer rs.Unlock()
	if !slices.Contains(rs.relays, ip) {
		rs.relays = append(rs.relays, ip)
	}
}

func (rs *relayState) relayAddresses() []netip.Addr {
	rs.RLock()
	defer rs.RUnlock()
	return slices.Clone(rs.relays)
}

func (rs *relayState) localIndexes() []uint32 {
	rs.RLock()
	defer rs.RUnlock()
	ret := make([]uint32, 0, len(rs.relayForByIdx))
	for i := range rs.relayForByIdx {
		ret = append(ret, i)
	}
	return ret
}

func (rs *relayState) establishRelay(localIdx, remoteIdx uint32) {
	rs.Lock()
	defer rs.Unlock()
	r := rs.relayForByIdx[localIdx]
	if r == nil || (r.State == relayEstablished && r.RemoteIndex == remoteIdx) {
		return
	}
	newRelay := *r
	newRelay.State = relayEstablished
	newRelay.RemoteIndex = remoteIdx
	rs.storeLocked(&newRelay)
}

func (rs *relayState) mappingByAddr(vpnIp netip.Addr) (*relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByAddr[vpnIp]
	return r, ok
}

func (rs *relayState) mappingByIndex(idx uint32) (*relay, bool) {
	rs.RLock()
	defer rs.RUnlock()
	r, ok := rs.relayForByIdx[idx]
	return r, ok
}

// getOrAddRelay associates a neighbor's mapping with both the local index and the remote peer.
func (hm *hostMap) getOrAddRelay(leg *hostInfo, peer netip.Addr, remoteIndex uint32, role, state int) (*relay, error) {
	hm.Lock()
	defer hm.Unlock()
	rs := &leg.relayState
	if existing, ok := rs.mappingByAddr(peer); ok {
		if existing.Type != role || (remoteIndex != 0 && existing.RemoteIndex != 0 && existing.RemoteIndex != remoteIndex) {
			return nil, errors.New("conflicting relay mapping")
		}
		return existing, nil
	}
	if len(hm.Relays) >= hm.maxRelayMappings {
		return nil, errors.New("relay capacity reached")
	}
	for range 32 {
		index, err := generateIndex(hm.l)
		if err != nil {
			return nil, err
		}
		if _, exists := hm.Relays[index]; exists {
			continue
		}
		if !hm.unlockedMakePrimary(leg) {
			return nil, errors.New("relay neighbor is no longer in the hostmap")
		}
		r := &relay{created: time.Now(), Type: role, State: state, LocalIndex: index, RemoteIndex: remoteIndex, PeerAddr: peer}
		hm.Relays[index] = leg
		rs.Lock()
		rs.storeLocked(r)
		rs.Unlock()
		return r, nil
	}
	return nil, errors.New("failed to generate a unique relay index")
}

// directNeighbor never starts a relay-dependent handshake on behalf of a transit leg.
func (f *packetEngine) directNeighbor(addr netip.Addr) *hostInfo {
	if !f.myVpnNetworksTable.Contains(addr) || f.myVpnAddrsTable.Contains(addr) {
		return nil
	}
	h := f.hostMap.QueryVpnAddr(addr)
	ids := []netip.Addr{addr}
	if h != nil {
		ids = h.vpnAddrs
	}
	if !f.paths.config.Load().allows(ids, netip.Addr{}, nil) {
		return nil
	}
	if h != nil && h.GetRemote().IsValid() {
		if h.paths.failedDirect(h.GetRemote(), f.paths.selection.FailureThreshold) {
			now := time.Now()
			h.verifyNeighbor(now.Add(-time.Second), now)
			return nil
		}
		return h
	}
	f.handshakeManager.startHandshake(addr, nil, true)
	return nil
}

// ensureRelay can establish a terminal mapping for a pending or an existing end-to-end session.
func (f *packetEngine) ensureRelay(h *hostInfo, addr netip.Addr) (tunnelRoute, bool) {
	if !f.paths.config.Load().allows(h.vpnAddrs, addr, h.remotes, f.hostMap.relayIdentities(addr)...) {
		return tunnelRoute{}, false
	}
	s := &h.paths
	now := time.Now()
	s.mu.Lock()
	if s.building != addr && now.Before(s.buildUntil) {
		s.mu.Unlock()
		return tunnelRoute{}, false
	}
	if s.building != addr || !now.Before(s.buildUntil) {
		s.building = addr
		s.buildUntil = now.Add(max(250*time.Millisecond, 3*f.handshakeManager.config.TryInterval))
	}
	s.mu.Unlock()
	leg := f.directNeighbor(addr)
	if leg == nil {
		return tunnelRoute{}, false
	}
	peer := h.vpnAddrs[0]
	if r, ok := leg.relayState.mappingByAddr(peer); ok && r.Type == relayTypeTerminal && r.State == relayEstablished {
		return receivedRoute(packetSender{UdpAddr: leg.GetRemote(), relayHI: leg, relay: r, IsRelayed: true}), true
	}
	r, err := f.hostMap.getOrAddRelay(leg, peer, 0, relayTypeTerminal, relayRequested)
	if err == nil {
		f.sendRelayControl(leg, f.myVpnAddrs[0], peer, r.LocalIndex, 0)
	}
	return tunnelRoute{}, false
}

// The wire encoding follows the receiving neighbor's certificate version.
func (f *packetEngine) sendRelayControl(leg *hostInfo, from, to netip.Addr, initiator, responder uint32) {
	if responder == 0 {
		rs := &leg.relayState
		rs.Lock()
		entry := rs.relayForByIdx[initiator]
		if entry == nil || time.Since(entry.lastRequest) < f.hostMap.relayRequestInterval {
			rs.Unlock()
			return
		}
		updated := *entry
		updated.lastRequest = time.Now()
		rs.storeLocked(&updated)
		rs.Unlock()
	}
	msg := NebulaControl{Type: NebulaControl_CreateRelayRequest, InitiatorRelayIndex: initiator, ResponderRelayIndex: responder}
	if responder != 0 {
		msg.Type = NebulaControl_CreateRelayResponse
	}
	if leg.GetCert().Certificate.Version() == cert.Version1 {
		if !from.Is4() || !to.Is4() {
			return
		}
		a, b := from.As4(), to.As4()
		msg.OldRelayFromAddr = binary.BigEndian.Uint32(a[:])
		msg.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
	} else {
		msg.RelayFromAddr = netAddrToProtoAddr(from)
		msg.RelayToAddr = netAddrToProtoAddr(to)
	}
	data, err := msg.Marshal()
	if err == nil && leg.GetRemote().IsValid() {
		path := tunnelRoute{TunnelPath: TunnelPath{Endpoint: leg.GetRemote()}}
		if f.myVpnAddrsTable.Contains(from) {
			path.relayFor = to
		} else if f.myVpnAddrsTable.Contains(to) {
			path.relayFor = from
		}
		f.sendOnRoute(header.Control, 0, leg, path, data, make([]byte, 12), make([]byte, mtu))
	}
}

func (f *packetEngine) handleRelayControl(h *hostInfo, d []byte) {
	var msg NebulaControl
	if err := msg.Unmarshal(d); err != nil || msg.InitiatorRelayIndex == 0 {
		return
	}
	var from, to netip.Addr
	if msg.OldRelayFromAddr != 0 || msg.OldRelayToAddr != 0 {
		var a, b [4]byte
		binary.BigEndian.PutUint32(a[:], msg.OldRelayFromAddr)
		binary.BigEndian.PutUint32(b[:], msg.OldRelayToAddr)
		from, to = netip.AddrFrom4(a), netip.AddrFrom4(b)
	} else if msg.RelayFromAddr != nil && msg.RelayToAddr != nil {
		from, to = protoAddrToNetAddr(msg.RelayFromAddr), protoAddrToNetAddr(msg.RelayToAddr)
	} else {
		return
	}
	if !isTunnelUnicast(from) || !isTunnelUnicast(to) || from == to {
		return
	}
	idx := msg.InitiatorRelayIndex
	switch msg.Type {
	case NebulaControl_CreateRelayResponse:
		r, ok := h.relayState.mappingByIndex(idx)
		if !ok || msg.ResponderRelayIndex == 0 || (r.RemoteIndex != 0 && r.RemoteIndex != msg.ResponderRelayIndex) {
			return
		}
		if r.Type == relayTypeTerminal {
			if !f.myVpnAddrsTable.Contains(from) || r.PeerAddr != to {
				return
			}
		} else if r.PeerAddr != from || !slices.Contains(h.vpnAddrs, to) {
			return
		}
		h.relayState.establishRelay(idx, msg.ResponderRelayIndex)
		if r.Type == relayTypeForwarding {
			src := f.hostMap.QueryVpnAddr(from)
			if src == nil {
				return
			}
			other, ok := src.relayState.mappingByAddr(to)
			if !ok || other.Type != relayTypeForwarding || other.RemoteIndex == 0 {
				return
			}
			src.relayState.setStateByAddr(to, relayEstablished)
			f.sendRelayControl(src, from, to, other.RemoteIndex, other.LocalIndex)
		}
	case NebulaControl_CreateRelayRequest:
		if f.myVpnAddrsTable.Contains(from) {
			return
		}
		if f.myVpnAddrsTable.Contains(to) {
			if slices.Contains(h.vpnAddrs, from) {
				return
			}
			ids := []netip.Addr{from}
			var remotes *remoteList
			if end := f.hostMap.QueryVpnAddr(from); end != nil {
				ids, remotes = end.vpnAddrs, end.remotes
			} else if f.paths.config.Load().policy(ids, f.hostMap).Mode == RelayOnly {
				remotes = f.lightHouse.getOrCreateRemotes(ids)
			}
			if !f.paths.config.Load().allows(ids, h.vpnAddrs[0], remotes, h.vpnAddrs...) {
				return
			}
			r, err := f.hostMap.getOrAddRelay(h, from, idx, relayTypeTerminal, relayEstablished)
			if err == nil {
				h.relayState.establishRelay(r.LocalIndex, idx)
				f.sendRelayControl(h, from, to, idx, r.LocalIndex)
			}
			return
		}
		if !f.servesRelays || !slices.Contains(h.vpnAddrs, from) || slices.Contains(h.vpnAddrs, to) {
			return
		}
		target := f.directNeighbor(to)
		if target == nil || target == h {
			return
		}
		r, err := f.hostMap.getOrAddRelay(h, to, idx, relayTypeForwarding, relayPeerRequested)
		if err != nil {
			return
		}
		targetRoute, err := f.hostMap.getOrAddRelay(target, from, 0, relayTypeForwarding, relayRequested)
		if err != nil {
			return
		}
		if targetRoute.State == relayEstablished {
			h.relayState.establishRelay(r.LocalIndex, idx)
			f.sendRelayControl(h, from, to, idx, r.LocalIndex)
		} else {
			// Simultaneous requests can supply both neighbors' indices.
			if r.RemoteIndex == 0 {
				h.relayState.establishRelay(r.LocalIndex, idx)
			}
			f.sendRelayControl(target, from, to, targetRoute.LocalIndex, 0)
		}
	}
}

func (hm *hostMap) expirePendingRelays(now time.Time) {
	hm.Lock()
	defer hm.Unlock()
	for idx, h := range hm.Relays {
		rs := &h.relayState
		rs.Lock()
		if r := rs.relayForByIdx[idx]; r != nil && r.State != relayEstablished && now.Sub(r.created) > hm.pendingRelayTimeout {
			delete(hm.Relays, idx)
			delete(rs.relayForByIdx, idx)
			delete(rs.relayForByAddr, r.PeerAddr)
		}
		rs.Unlock()
	}
}
