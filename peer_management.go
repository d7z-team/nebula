package nebula

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// ErrPeerUnavailable reports an invalid remote overlay address or an outbound
// handshake that exhausted its retries without establishing a tunnel.
var ErrPeerUnavailable = errors.New("nebula peer is unavailable")

// NodeState is the externally observable lifecycle state of a Node.
type NodeState uint8

const (
	NodeStateReady NodeState = iota
	NodeStateRunning
	NodeStateClosed
)

// NodeSnapshot is a detached copy of the node's local state. Certificates are
// copied and none of the returned slices share storage with the Node.
type NodeSnapshot struct {
	State             NodeState
	OverlayAddresses  []netip.Addr
	Certificates      []cert.Certificate
	InitiatingVersion cert.Version
	TransportAddress  netip.AddrPort
}

// Snapshot returns local state without invoking the transport, initiating
// discovery, or performing other network activity. TransportAddress is the
// most recently cached address and may be invalid before a successful read.
func (n *Node) Snapshot() NodeSnapshot {
	n.mu.Lock()
	state := n.state
	transportAddr := n.transportAddr
	n.mu.Unlock()

	out := NodeSnapshot{
		State:            state,
		OverlayAddresses: cloneAddresses(n.engine.myVpnAddrs),
		TransportAddress: transportAddr,
	}
	slices.SortFunc(out.OverlayAddresses, netip.Addr.Compare)
	cs := n.engine.pki.getCertState()
	out.InitiatingVersion = cs.DefaultVersion()
	if cs.v1Cert != nil {
		out.Certificates = append(out.Certificates, cs.v1Cert.Copy())
	}
	if cs.v2Cert != nil {
		out.Certificates = append(out.Certificates, cs.v2Cert.Copy())
	}
	return out
}

// Err reports a fatal read error from the datagram transport or the managed
// control socket. It returns nil while the node is running and on normal shutdown.
func (n *Node) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fatalErr
}

type PeerState uint8

const (
	PeerStateConnecting PeerState = iota + 1
	PeerStateEstablished
)

// TunnelPath identifies the underlay destination and optional overlay relay.
type TunnelPath struct {
	Circuit  string // Managed multi-hop generation, empty on standard routes.
	Endpoint netip.AddrPort
	Relay    netip.Addr
}

// PeerSnapshot is a detached view of one logical Nebula peer. A connecting
// peer has a nil Certificate and an invalid CurrentEndpoint.
type PeerSnapshot struct {
	Addresses        []netip.Addr
	State            PeerState
	HandshakePending bool
	CurrentEndpoint  netip.AddrPort
	PathHealth       PeerPathSnapshot
	LastDataPath     TunnelPath // Last successful IP datagram write to the transport.
	KnownEndpoints   []netip.AddrPort
	RelayCandidates  []netip.Addr
	Initiator        bool
	Certificate      cert.Certificate
}

// Peers returns detached established peers and outbound handshakes in stable
// address order. Rehandshake-era old tunnels are intentionally hidden. Like
// other concurrent snapshots, a transition racing this call may be reflected
// immediately or by the next call.
func (n *Node) Peers() []PeerSnapshot {
	return n.snapshotPeers(netip.Addr{})
}

func (n *Node) snapshotPeers(filter netip.Addr) []PeerSnapshot {
	hostMap := n.engine.hostMap
	hostMap.RLock()
	capacity := len(hostMap.Hosts)
	if filter.IsValid() {
		capacity = 1
	}
	established := make([]*hostInfo, 0, capacity)
	if filter.IsValid() {
		if h := hostMap.Hosts[filter]; h != nil {
			established = append(established, h)
		}
	} else {
		for addr, h := range hostMap.Hosts {
			if len(h.vpnAddrs) > 0 && addr == h.vpnAddrs[0] {
				established = append(established, h)
			}
		}
	}
	n.handshake.RLock()
	capacity = len(n.handshake.vpnIps)
	if filter.IsValid() {
		capacity = 1
	}
	pending := make(map[*handshakeHostInfo]struct{}, capacity)
	if filter.IsValid() {
		addrs := []netip.Addr{filter}
		if len(established) > 0 {
			addrs = established[0].vpnAddrs
		}
		for _, addr := range addrs {
			if hh := n.handshake.vpnIps[addr]; hh != nil {
				pending[hh] = struct{}{}
			}
		}
	} else {
		for _, hh := range n.handshake.vpnIps {
			pending[hh] = struct{}{}
		}
	}
	n.handshake.RUnlock()
	hostMap.RUnlock()

	peers := make([]PeerSnapshot, 0, len(established)+len(pending))
	peerByAddress := make(map[netip.Addr]int)
	for _, h := range established {
		addresses := cloneAddresses(h.vpnAddrs)
		slices.SortFunc(addresses, netip.Addr.Compare)
		known, relays := h.remotes.candidates().copyPaths()
		peer := PeerSnapshot{
			PathHealth:      n.engine.pathSnapshot(h),
			Addresses:       addresses,
			State:           PeerStateEstablished,
			CurrentEndpoint: unmapAddrPort(h.GetRemote()),
			KnownEndpoints:  known,
			RelayCandidates: relays,
		}
		if path := h.lastDataPath.Load(); path != nil {
			peer.LastDataPath = *path
		}
		if h.connectionState != nil {
			peer.Initiator = h.connectionState.initiator
			if h.connectionState.peerCert != nil && h.connectionState.peerCert.Certificate != nil {
				peer.Certificate = h.connectionState.peerCert.Certificate.Copy()
			}
		}
		index := len(peers)
		peers = append(peers, peer)
		for _, addr := range addresses {
			peerByAddress[addr] = index
		}
	}

	for hh := range pending {
		hh.Lock()
		n.handshake.RLock()
		tracked := false
		for _, addr := range hh.hostinfo.vpnAddrs {
			if n.handshake.vpnIps[addr] == hh {
				tracked = true
				break
			}
		}
		n.handshake.RUnlock()
		if !tracked {
			hh.Unlock()
			continue
		}
		addresses := cloneAddresses(hh.hostinfo.vpnAddrs)
		known, relays := hh.hostinfo.remotes.candidates().copyPaths()
		hh.Unlock()
		slices.SortFunc(addresses, netip.Addr.Compare)

		matched := -1
		for _, addr := range addresses {
			if index, ok := peerByAddress[addr]; ok {
				matched = index
				break
			}
		}
		if matched >= 0 {
			peers[matched].HandshakePending = true
			continue
		}

		index := len(peers)
		policy := n.engine.paths.config.Load().effectivePolicy(addresses, hostMap).clone()
		peers = append(peers, PeerSnapshot{
			Addresses:        addresses,
			State:            PeerStateConnecting,
			PathHealth:       PeerPathSnapshot{Policy: policy},
			HandshakePending: true,
			KnownEndpoints:   known,
			RelayCandidates:  relays,
		})
		for _, addr := range addresses {
			peerByAddress[addr] = index
		}
	}

	slices.SortFunc(peers, func(a, b PeerSnapshot) int {
		if len(a.Addresses) == 0 {
			if len(b.Addresses) == 0 {
				return 0
			}
			return -1
		}
		if len(b.Addresses) == 0 {
			return 1
		}
		return a.Addresses[0].Compare(b.Addresses[0])
	})
	return peers
}

// Peer returns the logical peer that owns addr, whether addr is its primary
// certificate address or an additional address.
func (n *Node) Peer(addr netip.Addr) (PeerSnapshot, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return PeerSnapshot{}, false
	}
	for _, peer := range n.snapshotPeers(addr) {
		if slices.Contains(peer.Addresses, addr) {
			return peer, true
		}
	}
	return PeerSnapshot{}, false
}

// ConnectPeer starts or joins an outbound handshake and waits until the peer
// has an established session with a usable exit. Canceling ctx ends this wait.
func (n *Node) ConnectPeer(ctx context.Context, addr netip.Addr) error {
	if err := n.requireStarted(); err != nil {
		return err
	}
	addr = addr.Unmap()
	if err := n.validatePeerAddress(addr); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// Hold the host map read lock through StartHandshake. Handshake completion
	// takes hostMap -> handshake, so this closes the window where another
	// handshake could become established between our check and insertion and
	// leave an unnecessary rehandshake behind.
	hosts := n.engine.hostMap
	hosts.RLock()
	existing := hosts.Hosts[addr]
	if existing == nil && ctx.Err() == nil {
		n.handshake.StartHandshake(addr, nil)
	}
	hosts.RUnlock()
	if existing != nil && n.engine.currentRoute(existing).Endpoint.IsValid() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tries := time.Duration(n.handshake.config.Retries)
	deadline := time.NewTimer(n.handshake.config.TryInterval*(tries+1)*(tries+2)/2 + time.Second)
	defer deadline.Stop()
	interval := n.handshake.config.TryInterval / 4
	if interval <= 0 || interval > 25*time.Millisecond {
		interval = 25 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		hosts.RLock()
		n.handshake.RLock()
		h := hosts.Hosts[addr]
		pending := n.handshake.vpnIps[addr] != nil
		n.handshake.RUnlock()
		hosts.RUnlock()
		if h != nil {
			if n.engine.currentRoute(h).Endpoint.IsValid() {
				return nil
			}
			h.paths.mu.Lock()
			h.paths.demand = time.Now()
			h.paths.mu.Unlock()
		} else if !pending {
			return fmt.Errorf("%w: handshake with %s failed", ErrPeerUnavailable, addr)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.ctx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrNodeClosed
		case <-deadline.C:
			return fmt.Errorf("%w: no usable path to %s", ErrPeerUnavailable, addr)
		case <-ticker.C:
		}
	}
}

type DisconnectOptions struct {
	// LocalOnly suppresses the standard Nebula CloseTunnel notification.
	LocalOnly bool
}

// DisconnectAllOptions controls bulk tunnel teardown.
type DisconnectAllOptions struct {
	// LocalOnly suppresses standard Nebula CloseTunnel notifications.
	LocalOnly bool
	// KeepLighthouses preserves pending and established lighthouse peers.
	KeepLighthouses bool
}

// DisconnectResult reports work completed by a disconnect operation.
type DisconnectResult struct {
	// TunnelsClosed is the number of established tunnels removed locally.
	TunnelsClosed int
	// HandshakesCanceled is the number of distinct outbound handshakes removed.
	HandshakesCanceled int
}

// DisconnectPeer cancels pending handshakes and closes every current tunnel
// belonging to the certificate identity that owns addr. It is idempotent.
func (n *Node) DisconnectPeer(addr netip.Addr, options DisconnectOptions) (DisconnectResult, error) {
	if err := n.requireStarted(); err != nil {
		return DisconnectResult{}, err
	}
	addr = addr.Unmap()
	if err := n.validatePeerAddress(addr); err != nil {
		return DisconnectResult{}, err
	}

	targets := map[netip.Addr]struct{}{addr: {}}
	n.engine.hostMap.RLock()
	for _, h := range n.engine.hostMap.Indexes {
		if !slices.Contains(h.vpnAddrs, addr) {
			continue
		}
		for _, peerAddr := range h.vpnAddrs {
			targets[peerAddr.Unmap()] = struct{}{}
		}
	}
	n.engine.hostMap.RUnlock()
	matchesTarget := func(addrs []netip.Addr) bool {
		for _, peerAddr := range addrs {
			if _, ok := targets[peerAddr.Unmap()]; ok {
				return true
			}
		}
		return false
	}
	return n.disconnectMatching(options.LocalOnly, matchesTarget), nil
}

// DisconnectAll cancels pending handshakes and closes all established
// tunnels. Tunnels carrying relay traffic are closed last so notifications for
// direct peers can continue to use them.
func (n *Node) DisconnectAll(options DisconnectAllOptions) (DisconnectResult, error) {
	if err := n.requireStarted(); err != nil {
		return DisconnectResult{}, err
	}

	return n.disconnectMatching(options.LocalOnly, func(addrs []netip.Addr) bool {
		return !options.KeepLighthouses || !n.lighthouse.IsAnyLighthouseAddr(addrs)
	}), nil
}

func (n *Node) disconnectMatching(localOnly bool, include func([]netip.Addr) bool) DisconnectResult {
	result := DisconnectResult{HandshakesCanceled: n.cancelPendingHandshakes(include)}
	hosts := n.engine.hostMap
	hosts.RLock()
	tunnels := make([]*hostInfo, 0, len(hosts.Indexes))
	for _, h := range hosts.Indexes {
		if include(h.vpnAddrs) {
			tunnels = append(tunnels, h)
		}
	}
	hosts.RUnlock()
	sortTunnelsRelayLast(tunnels)
	for _, h := range tunnels {
		if n.disconnectTunnel(h, localOnly) {
			result.TunnelsClosed++
		}
	}
	return result
}

func sortTunnelsRelayLast(tunnels []*hostInfo) {
	relayAddresses := make(map[netip.Addr]struct{})
	relayTunnels := make(map[*hostInfo]bool, len(tunnels))
	for _, h := range tunnels {
		rs := &h.relayState
		rs.RLock()
		relayTunnels[h] = len(rs.relayForByAddr) > 0
		for _, addr := range rs.relays {
			relayAddresses[addr.Unmap()] = struct{}{}
		}
		rs.RUnlock()
	}
	for _, h := range tunnels {
		for _, addr := range h.vpnAddrs {
			if _, ok := relayAddresses[addr.Unmap()]; ok {
				relayTunnels[h] = true
				break
			}
		}
	}
	slices.SortStableFunc(tunnels, func(a, b *hostInfo) int {
		aRelay, bRelay := relayTunnels[a], relayTunnels[b]
		if aRelay != bRelay {
			if aRelay {
				return 1
			}
			return -1
		}
		if len(a.vpnAddrs) > 0 && len(b.vpnAddrs) > 0 {
			if cmp := a.vpnAddrs[0].Compare(b.vpnAddrs[0]); cmp != 0 {
				return cmp
			}
		}
		return cmp.Compare(a.localIndexId, b.localIndexId)
	})
}

func (n *Node) validatePeerAddress(addr netip.Addr) error {
	if addr.Zone() != "" || !isTunnelUnicast(addr) || !n.engine.myVpnNetworksTable.Contains(addr) || n.engine.myVpnAddrsTable.Contains(addr) {
		return fmt.Errorf("%w: %s is not a remote overlay address", ErrPeerUnavailable, addr)
	}
	if _, broadcast := n.engine.overlayBroadcasts[addr]; broadcast {
		return fmt.Errorf("%w: %s is an overlay broadcast address", ErrPeerUnavailable, addr)
	}
	return nil
}

func (n *Node) cancelPendingHandshakes(include func([]netip.Addr) bool) int {
	n.handshake.RLock()
	pending := make(map[*handshakeHostInfo]struct{}, len(n.handshake.vpnIps))
	for _, hh := range n.handshake.vpnIps {
		pending[hh] = struct{}{}
	}
	n.handshake.RUnlock()

	canceled := 0
	for hh := range pending {
		hh.Lock()
		n.handshake.Lock()
		tracked := false
		for _, addr := range hh.hostinfo.vpnAddrs {
			if n.handshake.vpnIps[addr] == hh {
				tracked = true
				break
			}
		}
		if tracked && include(hh.hostinfo.vpnAddrs) {
			n.handshake.unlockedDeleteHostInfo(hh.hostinfo)
			canceled++
		}
		n.handshake.Unlock()
		hh.Unlock()
	}
	return canceled
}

func (n *Node) disconnectTunnel(h *hostInfo, localOnly bool) bool {
	route := n.engine.currentRoute(h)
	if !n.engine.closeTunnel(h) {
		return false
	}
	if !localOnly && h.connectionState != nil {
		n.engine.sendOnRoute(header.CloseTunnel, 0, h, route, nil, make([]byte, 12), make([]byte, mtu))
	}
	return true
}

func unmapAddrPort(addr netip.AddrPort) netip.AddrPort {
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}
