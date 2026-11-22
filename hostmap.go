package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// maxHostInfosPerVPNAddr is the max number of hostinfos we will track for a given vpn ip
// 5 allows for an initial handshake and each host pair re-handshaking twice
const maxHostInfosPerVPNAddr = 5

// roamingSuppressDuration prevents flapping back to a previous endpoint while
// packets from the old path are still in flight.
const roamingSuppressDuration = 2 * time.Second

type hostMap struct {
	sync.RWMutex
	Indexes       map[uint32]*hostInfo
	Relays        map[uint32]*hostInfo // Maps a relay IDX to a relay hostInfo object
	RemoteIndexes map[uint32]*hostInfo
	// Hosts maps a vpn address to its primary hostinfo, one entry per address we hold a tunnel
	// for. moreHosts only has an entry while an address is held by 2 or more hostinfos and stores
	// the full most-recent-first list; moreHosts[a][0] is always the same hostinfo as Hosts[a].
	// Each address gets its own independent list, so a hostinfo owning multiple addresses can
	// never corrupt another address's ordering the way the old shared next/prev chain could.
	// Entries in moreHosts are only ever written by unlockedSetHostsForAddr; Hosts is written
	// directly only in the single-hostinfo fast paths where moreHosts is known to have no entry,
	// and unlockedDeleteHostInfo swaps either map for a fresh one when it fully drains.
	Hosts     map[netip.Addr]*hostInfo
	moreHosts map[netip.Addr][]*hostInfo
	l         *slog.Logger
}

type networkType uint8

const (
	networkTypeUnknown networkType = iota
	// networkTypeVPN is a network that overlaps one or more of the vpnNetworks in our certificate
	networkTypeVPN
	// networkTypeVPNPeer is a network that does not overlap one of our networks
	networkTypeVPNPeer
	// networkTypeUnsafe is a network from Certificate.UnsafeNetworks()
	networkTypeUnsafe
	// networkTypeUnsafeVPNOverlap is the overlap between a network from Certificate.UnsafeNetworks()
	// and one of the vpnNetworks in our certificate
	networkTypeUnsafeVPNOverlap
)

type hostInfo struct {
	remote          atomic.Pointer[netip.AddrPort]
	paths           sessionPaths
	lastDataPath    atomic.Pointer[TunnelPath]
	connectionState *connectionState

	// Traffic bits, pendingDeletion, and the rebind epoch we last sent under
	state atomic.Uint32

	remoteIndexId uint32
	localIndexId  uint32
	remotes       *remoteList

	// vpnAddrs is a list of vpn addresses assigned to this host that are within our own vpn networks
	// The host may have other vpn addresses that are outside our
	// vpn networks but were removed because they are not usable
	vpnAddrs []netip.Addr

	// networks is a combination of specific vpn addresses (not prefixes!) and full unsafe networks assigned to this host.
	networks   *bart.Table[networkType]
	relayState relayState

	// HandshakePacket records the packets used to create this hostinfo
	// We need these to avoid replayed handshake packets creating new hostinfos which causes churn
	HandshakePacket map[uint8][]byte

	// lastHandshakeTime records the time the remote side told us about at the stage when the handshake was completed locally
	// Stage 1 packet will contain it if I am a responder, stage 2 packet if I am an initiator
	// This is used to avoid an attack where a handshake packet is replayed after some time
	lastHandshakeTime uint64

	lastRoam       time.Time
	lastRoamRemote netip.AddrPort

	// lastUsed tracks the last time ConnectionManager checked the tunnel and it was in use.
	// This value will be behind against actual tunnel utilization in the hot path.
	// This should only be used by the ConnectionManagers ticker routine.
	lastUsed time.Time
}

type packetSender struct {
	UdpAddr   netip.AddrPort
	relayHI   *hostInfo // relayHI is the host info object of the relay
	relay     *relay    // relay contains the rest of the relay information, including the PeerIP of the host trying to communicate with us.
	IsRelayed bool      // IsRelayed is true if the packet was sent through a relay
}

func (v packetSender) String() string {
	if v.IsRelayed {
		return fmt.Sprintf("%s (relayed)", v.UdpAddr)
	}
	return v.UdpAddr.String()
}

type cachedPacket struct {
	messageType    header.MessageType
	messageSubType header.MessageSubType
	packet         []byte
}

func newHostMap(l *slog.Logger) *hostMap {
	return &hostMap{
		Indexes:       map[uint32]*hostInfo{},
		Relays:        map[uint32]*hostInfo{},
		RemoteIndexes: map[uint32]*hostInfo{},
		Hosts:         map[netip.Addr]*hostInfo{},
		moreHosts:     map[netip.Addr][]*hostInfo{},
		l:             l,
	}
}

// unlockedSetHostsForAddr stores the per-address hostinfo list (list[0] is the primary). An empty
// list removes the address. This is the one place Hosts and moreHosts are written together, keep
// it that way. Callers must hold the write lock.
func (hm *hostMap) unlockedSetHostsForAddr(addr netip.Addr, list []*hostInfo) {
	if len(list) == 0 {
		delete(hm.Hosts, addr)
		delete(hm.moreHosts, addr)
		return
	}
	hm.Hosts[addr] = list[0]
	if len(list) > 1 {
		hm.moreHosts[addr] = list
	} else {
		delete(hm.moreHosts, addr)
	}
}

// unlockedGetHostList returns every hostinfo holding addr, primary first, or nil if we have no
// tunnel for addr. The common single-hostinfo case builds a fresh one element list, so keep this
// off the packet hot path; the primary is a direct Hosts read. Callers must hold the lock (read
// or write).
func (hm *hostMap) unlockedGetHostList(addr netip.Addr) []*hostInfo {
	if list, ok := hm.moreHosts[addr]; ok {
		return list
	}
	if h, ok := hm.Hosts[addr]; ok {
		return []*hostInfo{h}
	}
	return nil
}

// removeHostInfo returns list with hi removed (order preserved), or list unchanged if hi is
// absent. It deletes in place: every mutator holds the hostmap write lock and no reader ever
// retains a slice across a mutation (readers iterate under RLock), so there is no snapshot to
// invalidate.
func removeHostInfo(list []*hostInfo, hi *hostInfo) []*hostInfo {
	idx := slices.Index(list, hi)
	if idx < 0 {
		return list
	}
	return slices.Delete(list, idx, idx+1)
}

// DeleteHostInfo will fully unlink the hostinfo and return true if no other hostinfo still holds
// any of its vpn addrs, meaning we no longer have a tunnel to the peer
func (hm *hostMap) DeleteHostInfo(hostinfo *hostInfo) bool {
	// Delete the host itself, ensuring it's not modified anymore
	hm.Lock()
	final := hm.unlockedDeleteHostInfo(hostinfo)
	hm.Unlock()

	return final
}

// unlockedMakePrimary reports whether hostinfo is (now) the primary for each of its addresses,
// false only when it is no longer in the hostmap at all.
func (hm *hostMap) unlockedMakePrimary(hostinfo *hostInfo) bool {
	// A hostinfo that is no longer in the hostmap must not be re-inserted here. Callers can race
	// tunnel teardown, deciding to promote under the read lock and only taking the write lock
	// after a delete fully unlinked the hostinfo (connection manager swapPrimary, getOrAddRelay). Every
	// live hostinfo is registered in Indexes by unlockedAddHostInfo, so this is a membership test.
	if hm.Indexes[hostinfo.localIndexId] != hostinfo {
		return false
	}

	// Move hostinfo to the front (primary) of each of its address lists. The lists are
	// independent per address, so this can never leave a dangling entry the way promoting
	// against a single shared chain could.
	for _, addr := range hostinfo.vpnAddrs {
		if hm.Hosts[addr] == hostinfo {
			// Already primary for this address, the list is already in the right order
			continue
		}
		list := removeHostInfo(hm.unlockedGetHostList(addr), hostinfo)
		list = append([]*hostInfo{hostinfo}, list...)
		hm.unlockedSetHostsForAddr(addr, list)
	}
	return true
}

// unlockedDeleteHostInfo removes hostinfo from every one of its address lists and from the index
// maps. It returns true if this was the last hostinfo for all of its addresses (we no longer have
// any tunnel to the peer), which the caller uses to decide whether to clear learned lighthouse
// state and disestablish relays.
func (hm *hostMap) unlockedDeleteHostInfo(hostinfo *hostInfo) bool {
	hostinfo.paths.mu.Lock()
	if p := hostinfo.paths.pending; p != nil {
		hostinfo.paths.complete(p, PathCheckResult{Sent: p.route.TunnelPath, Err: ErrPathChanged})
	}
	hostinfo.paths.retired = true
	hostinfo.paths.mu.Unlock()
	// Remove this hostinfo from each of its address lists. The lists are independent, so a
	// sibling is never promoted to an address it does not own and no other list is touched.
	final := true
	for _, addr := range hostinfo.vpnAddrs {
		if list, ok := hm.moreHosts[addr]; ok {
			list = removeHostInfo(list, hostinfo)
			hm.unlockedSetHostsForAddr(addr, list)
			if len(list) > 0 {
				final = false
			}
		} else if existing, ok := hm.Hosts[addr]; ok {
			if existing == hostinfo {
				// Common case, the only hostinfo for this address. moreHosts has no entry to clean up.
				delete(hm.Hosts, addr)
			} else {
				// We don't hold this address but another hostinfo does, we still have a tunnel to the peer
				final = false
			}
		}
	}

	// Go maps never shrink their buckets, replace fully drained maps so a node that churned
	// through a large peer count gives the memory back. Same idiom as the index maps below.
	if len(hm.Hosts) == 0 {
		hm.Hosts = map[netip.Addr]*hostInfo{}
	}
	if len(hm.moreHosts) == 0 {
		hm.moreHosts = map[netip.Addr][]*hostInfo{}
	}

	// The remote index uses index ids outside our control so lets make sure we are only removing
	// the remote index pointer here if it points to the hostinfo we are deleting
	hostinfo2, ok := hm.RemoteIndexes[hostinfo.remoteIndexId]
	if ok && hostinfo2 == hostinfo {
		delete(hm.RemoteIndexes, hostinfo.remoteIndexId)
		if len(hm.RemoteIndexes) == 0 {
			hm.RemoteIndexes = map[uint32]*hostInfo{}
		}
	}

	delete(hm.Indexes, hostinfo.localIndexId)
	if len(hm.Indexes) == 0 {
		hm.Indexes = map[uint32]*hostInfo{}
	}

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Hostmap hostInfo deleted",
			"hostMap", structuredMap{"mapTotalSize": len(hm.Hosts),
				"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId},
		)
	}

	if final {
		// I have lost connectivity to my peers. My relay tunnel is likely broken. Mark the next
		// hops as requested so that new relay tunnels are created in the future.
		hm.unlockedDisestablishVpnAddrRelayFor(hostinfo)
	}
	// Clean up any local relay indexes for which I am acting as a relay hop
	for _, localRelayIdx := range hostinfo.relayState.localIndexes() {
		delete(hm.Relays, localRelayIdx)
	}

	return final
}

func (hm *hostMap) QueryIndex(index uint32) *hostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Indexes[index]
}

func (hm *hostMap) QueryRelayIndex(index uint32) *hostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Relays[index]
}

func (hm *hostMap) QueryReverseIndex(index uint32) *hostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.RemoteIndexes[index]
}

func (hm *hostMap) QueryVpnAddr(addr netip.Addr) *hostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Hosts[addr]
}

func (hm *hostMap) QueryVpnAddrsRelayFor(targetIps []netip.Addr, relayHostIp netip.Addr) (*hostInfo, *relay, error) {
	hm.RLock()
	defer hm.RUnlock()

	// This runs per relayed packet, so check the primary with a single map probe and only consult
	// moreHosts when the primary can't relay for us.
	h, ok := hm.Hosts[relayHostIp]
	if !ok {
		return nil, nil, errors.New("unable to find host")
	}

	for _, targetIp := range targetIps {
		r, ok := h.relayState.mappingByAddr(targetIp)
		if ok && r.State == relayEstablished {
			return h, r, nil
		}
	}

	if list, ok := hm.moreHosts[relayHostIp]; ok {
		// list[0] is the primary we already checked
		for _, h := range list[1:] {
			for _, targetIp := range targetIps {
				r, ok := h.relayState.mappingByAddr(targetIp)
				if ok && r.State == relayEstablished {
					return h, r, nil
				}
			}
		}
	}

	return nil, nil, errors.New("unable to find host with relay")
}

func (hm *hostMap) unlockedDisestablishVpnAddrRelayFor(hi *hostInfo) {
	for _, relayHostIp := range hi.relayState.relayAddresses() {
		for _, h := range hm.unlockedGetHostList(relayHostIp) {
			h.relayState.setStateByAddr(hi.vpnAddrs[0], relayDisestablished)
		}
	}
	for _, rs := range hi.relayState.mappings() {
		if rs.Type == relayTypeForwarding {
			for _, h := range hm.unlockedGetHostList(rs.PeerAddr) {
				h.relayState.setStateByAddr(hi.vpnAddrs[0], relayDisestablished)
			}
		}
	}
}

// unlockedAddHostInfo assumes you have a write-lock and will add a hostinfo object to the hostmap Indexes and RemoteIndexes maps.
// If an entry exists for the Hosts table (vpnIp -> hostinfo) then the provided hostinfo will be made primary
func (hm *hostMap) unlockedAddHostInfo(hostinfo *hostInfo, f *packetEngine) {
	for _, addr := range hostinfo.vpnAddrs {
		hm.unlockedAddForAddress(addr, hostinfo)
	}

	hm.Indexes[hostinfo.localIndexId] = hostinfo
	hm.RemoteIndexes[hostinfo.remoteIndexId] = hostinfo

	hostinfo.markOut(f.rebindEpoch.Load())
	if f.paths.checks != nil {
		f.paths.checks.Add(hostinfo, pathTick)
	}
	if f.connectionManager != nil { // f.connectionManager is only nil in some unit tests
		f.connectionManager.trafficTimer.Add(hostinfo.localIndexId, f.connectionManager.checkInterval)
	}

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Hostmap vpnIp added",
			"hostMap", structuredMap{"vpnAddrs": hostinfo.vpnAddrs, "mapTotalSize": len(hm.Hosts),
				"hostinfo": structuredMap{"existing": true, "localIndexId": hostinfo.localIndexId, "vpnAddrs": hostinfo.vpnAddrs}},
		)
	}
}

func (hm *hostMap) unlockedAddForAddress(vpnAddr netip.Addr, hostinfo *hostInfo) {
	existing, ok := hm.Hosts[vpnAddr]
	if !ok {
		// Common case, the first hostinfo for this address. moreHosts stays empty.
		hm.Hosts[vpnAddr] = hostinfo
		return
	}

	// The new hostinfo becomes the primary for this address. Remove any stale copy of it first so
	// we never hold a duplicate, then prepend.
	list, ok := hm.moreHosts[vpnAddr]
	if !ok {
		list = []*hostInfo{existing}
	}
	list = removeHostInfo(list, hostinfo)
	list = append([]*hostInfo{hostinfo}, list...)
	hm.unlockedSetHostsForAddr(vpnAddr, list)

	// Enforce the per-address cap by fully retiring the oldest hostinfo once we exceed it.
	// Deleting it removes it from all of its addresses and the index maps, matching prior behavior.
	if len(list) > maxHostInfosPerVPNAddr {
		hm.unlockedDeleteHostInfo(list[len(list)-1])
	}
}

// replayWindowBits within hostInfo.state, everything above stateEpochShift is the epoch
const (
	stateIn uint32 = 1 << iota
	stateOut
	statePendingDeletion

	stateFlags = stateIn | stateOut | statePendingDeletion
	// The epoch is the top 29 bits, it would take 2^29 rebinds to wrap and we will never get there
	stateEpochShift = 3
)

// markIn records inbound traffic
func (i *hostInfo) markIn() {
	if i.state.Load()&stateIn == 0 {
		i.state.Or(stateIn)
	}
}

// markOut records a send and reports whether the epoch moved, meaning we want a punch from the far side
func (i *hostInfo) markOut(epoch uint32) bool {
	e := epoch << stateEpochShift
	for {
		old := i.state.Load()
		if old&stateOut != 0 && old&^stateFlags == e {
			return false
		}

		if i.state.CompareAndSwap(old, old&stateFlags|stateOut|e) {
			return old&^stateFlags != e
		}
	}
}

// markOutOnly records a send without consuming the rebind epoch, for paths that cannot act on a requery
func (i *hostInfo) markOutOnly() {
	if i.state.Load()&stateOut == 0 {
		i.state.Or(stateOut)
	}
}

// takeTraffic clears both traffic bits, leaving the epoch alone, and reports what they were
func (i *hostInfo) takeTraffic() (in bool, out bool) {
	old := i.state.And(^(stateIn | stateOut))
	return old&stateIn != 0, old&stateOut != 0
}

func (i *hostInfo) setPendingDeletion(v bool) {
	if v {
		i.state.Or(statePendingDeletion)
	} else {
		i.state.And(^statePendingDeletion)
	}
}

func (i *hostInfo) isPendingDeletion() bool {
	return i.state.Load()&statePendingDeletion != 0
}

func (i *hostInfo) GetCert() *cert.CachedCertificate {
	if i.connectionState != nil {
		return i.connectionState.peerCert
	}
	return nil
}

func (i *hostInfo) GetRemote() netip.AddrPort {
	if p := i.remote.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}

func (i *hostInfo) SetRemote(remote netip.AddrPort) {
	// We copy here because we likely got this remote from a source that reuses the object
	if i.GetRemote() != remote {
		i.remote.Store(&remote)
		i.remotes.LearnRemote(i.vpnAddrs[0], remote)
	}
}

// buildNetworks fills in the networks field of hostInfo. It accepts a cert.Certificate so you never ever mix the network types up.
func (i *hostInfo) buildNetworks(myVpnNetworksTable *bart.Lite, c cert.Certificate) {
	if len(c.Networks()) == 1 && len(c.UnsafeNetworks()) == 0 {
		if myVpnNetworksTable.Contains(c.Networks()[0].Addr()) {
			return // Simple case, no BART needed
		}
	}

	i.networks = new(bart.Table[networkType])
	for _, network := range c.UnsafeNetworks() {
		// Mark overlap so packet identity validation cannot let this peer impersonate
		// overlay addresses assigned to other nodes.
		if myVpnNetworksTable.LookupPrefix(network) {
			// The unsafe network is inside one of our vpn networks, all of it is overlap.
			// Ex: vpn network 10.1.0.0/16, unsafe network 10.1.2.0/24, all of 10.1.2.0/24 is overlap
			i.networks.Insert(network, networkTypeUnsafeVPNOverlap)
		} else {
			// Any of our vpn networks inside the unsafe network are the overlap, the rest is unsafe.
			// Ex: vpn network 10.1.0.0/16, unsafe network 10.0.0.0/8, 10.1.0.0/16 is overlap and the rest of 10.0.0.0/8 is unsafe.
			// On the other hand, an unsafe network assignment of 192.168.0.0/16 would have no overlap.
			i.networks.Insert(network, networkTypeUnsafe)
			for overlap := range myVpnNetworksTable.Subnets(network) {
				i.networks.Insert(overlap, networkTypeUnsafeVPNOverlap)
			}
		}
	}

	// Insert the peer's own addresses last so an overlap of the same prefix can't replace them
	for _, network := range c.Networks() {
		nprefix := netip.PrefixFrom(network.Addr(), network.Addr().BitLen())
		if myVpnNetworksTable.Contains(network.Addr()) {
			i.networks.Insert(nprefix, networkTypeVPN)
		} else {
			i.networks.Insert(nprefix, networkTypeVPNPeer)
		}
	}
}

// logger returns a derived slog.Logger with per-hostinfo fields pre-bound.
func (i *hostInfo) logger(l *slog.Logger) *slog.Logger {
	if i == nil {
		return l
	}

	li := l.With(
		"vpnAddrs", i.vpnAddrs,
		"localIndex", i.localIndexId,
		"remoteIndex", i.remoteIndexId,
	)

	if connState := i.connectionState; connState != nil {
		if peerCert := connState.peerCert; peerCert != nil {
			li = li.With("certName", peerCert.Certificate.Name())
		}
	}

	return li
}
