package nebula

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/cert"
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
	VirtualAddresses  []netip.Addr
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
		State:            NodeState(state),
		OverlayAddresses: cloneAddresses(n.engine.myVpnAddrs),
		VirtualAddresses: cloneAddresses(n.virtualAddrs),
		TransportAddress: transportAddr,
	}
	slices.SortFunc(out.OverlayAddresses, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.SortFunc(out.VirtualAddresses, func(a, b netip.Addr) int { return a.Compare(b) })
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

// Err reports the transport or userspace-stack failure that caused the Node
// to shut down. Explicit Close and a Node that is still running return nil.
func (n *Node) Err() error {
	if err := n.engine.fatalErr.Load(); err != nil {
		return *err
	}
	return nil
}

type PeerState uint8

const (
	PeerStateConnecting PeerState = iota + 1
	PeerStateEstablished
)

// PeerSnapshot is a detached view of one logical Nebula peer. A connecting
// peer has a nil Certificate and an invalid CurrentEndpoint.
type PeerSnapshot struct {
	Addresses        []netip.Addr
	State            PeerState
	HandshakePending bool
	CurrentEndpoint  netip.AddrPort
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
	seenEstablished := make(map[*hostInfo]struct{}, capacity)
	if filter.IsValid() {
		if h := hostMap.Hosts[filter]; h != nil {
			seenEstablished[h] = struct{}{}
			established = append(established, h)
		}
	} else {
		for _, h := range hostMap.Hosts {
			if len(h.vpnAddrs) == 0 || hostMap.Hosts[h.vpnAddrs[0]] != h {
				continue
			}
			if _, ok := seenEstablished[h]; ok {
				continue
			}
			seenEstablished[h] = struct{}{}
			established = append(established, h)
		}
	}
	n.handshake.RLock()
	capacity = len(n.handshake.vpnIps)
	if filter.IsValid() {
		capacity = 1
	}
	pending := make([]*handshakeHostInfo, 0, capacity)
	seenPending := make(map[*handshakeHostInfo]struct{}, capacity)
	if filter.IsValid() {
		if hh := n.handshake.vpnIps[filter]; hh != nil {
			seenPending[hh] = struct{}{}
			pending = append(pending, hh)
		}
		for h := range seenEstablished {
			for _, addr := range h.vpnAddrs {
				if hh := n.handshake.vpnIps[addr]; hh != nil {
					if _, ok := seenPending[hh]; !ok {
						seenPending[hh] = struct{}{}
						pending = append(pending, hh)
					}
				}
			}
		}
	} else {
		for _, hh := range n.handshake.vpnIps {
			if _, ok := seenPending[hh]; !ok {
				seenPending[hh] = struct{}{}
				pending = append(pending, hh)
			}
		}
	}
	n.handshake.RUnlock()
	hostMap.RUnlock()

	peers := make([]PeerSnapshot, 0, len(established)+len(pending))
	peerByAddress := make(map[netip.Addr]int)
	for _, h := range established {
		addresses := cloneAddresses(h.vpnAddrs)
		slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		known, relays := copyPeerRemotes(h.remotes, hostMap.GetPreferredRanges())
		peer := PeerSnapshot{
			Addresses:       addresses,
			State:           PeerStateEstablished,
			CurrentEndpoint: unmapAddrPort(h.GetRemote()),
			KnownEndpoints:  known,
			RelayCandidates: relays,
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

	for _, hh := range pending {
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
		known, relays := copyPeerRemotes(hh.hostinfo.remotes, hostMap.GetPreferredRanges())
		hh.Unlock()
		slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })

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
		peers = append(peers, PeerSnapshot{
			Addresses:        addresses,
			State:            PeerStateConnecting,
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
// is established. Canceling ctx does not cancel a shared handshake.
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
	n.engine.hostMap.RLock()
	if n.engine.hostMap.Hosts[addr] != nil {
		n.engine.hostMap.RUnlock()
		return nil
	}
	if err := ctx.Err(); err != nil {
		n.engine.hostMap.RUnlock()
		return err
	}
	n.handshake.StartHandshake(addr, nil)
	n.engine.hostMap.RUnlock()

	interval := n.handshake.config.tryInterval / 4
	if interval <= 0 || interval > 25*time.Millisecond {
		interval = 25 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		established, pending := n.peerConnectionState(addr)
		if established {
			return nil
		}
		if !pending {
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
	result := DisconnectResult{HandshakesCanceled: n.cancelPendingHandshakes(func(addrs []netip.Addr) bool {
		return matchesTarget(addrs)
	})}
	tunnels := n.collectTunnels(func(h *hostInfo) bool { return matchesTarget(h.vpnAddrs) })
	sortTunnelsRelayLast(tunnels)
	for _, h := range tunnels {
		if n.disconnectTunnel(h, options.LocalOnly) {
			result.TunnelsClosed++
		}
	}
	return result, nil
}

// DisconnectAll cancels pending handshakes and closes all established
// tunnels. Tunnels carrying relay traffic are closed last so notifications for
// direct peers can continue to use them.
func (n *Node) DisconnectAll(options DisconnectAllOptions) (DisconnectResult, error) {
	if err := n.requireStarted(); err != nil {
		return DisconnectResult{}, err
	}

	lighthouses := make(map[netip.Addr]struct{})
	if options.KeepLighthouses {
		for _, addr := range n.lighthouse.GetLighthouses() {
			lighthouses[addr.Unmap()] = struct{}{}
		}
	}
	keep := func(addrs []netip.Addr) bool {
		for _, addr := range addrs {
			if _, ok := lighthouses[addr.Unmap()]; ok {
				return true
			}
		}
		return false
	}
	result := DisconnectResult{HandshakesCanceled: n.cancelPendingHandshakes(func(addrs []netip.Addr) bool {
		return !keep(addrs)
	})}
	tunnels := n.collectTunnels(func(h *hostInfo) bool { return !keep(h.vpnAddrs) })
	sortTunnelsRelayLast(tunnels)
	for _, h := range tunnels {
		if n.disconnectTunnel(h, options.LocalOnly) {
			result.TunnelsClosed++
		}
	}
	return result, nil
}

func sortTunnelsRelayLast(tunnels []*hostInfo) {
	relayAddresses := make(map[netip.Addr]struct{})
	relayTunnels := make(map[*hostInfo]bool, len(tunnels))
	for _, h := range tunnels {
		relayTunnels[h] = len(h.relayState.CopyRelayForIps()) > 0
		for _, addr := range h.relayState.CopyRelayIps() {
			relayAddresses[addr.Unmap()] = struct{}{}
		}
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
		if a.localIndexId < b.localIndexId {
			return -1
		}
		if a.localIndexId > b.localIndexId {
			return 1
		}
		return 0
	})
}

func (n *Node) validatePeerAddress(addr netip.Addr) error {
	if !addr.IsValid() || !containsOverlayAddressNetwork(n.engine.myVpnNetworks, addr) || n.engine.myVpnAddrsTable.Contains(addr) {
		return fmt.Errorf("%w: %s is not a remote overlay address", ErrPeerUnavailable, addr)
	}
	return nil
}

func (n *Node) peerConnectionState(addr netip.Addr) (established, pending bool) {
	hostMap := n.engine.hostMap
	hostMap.RLock()
	n.handshake.RLock()
	established = hostMap.Hosts[addr] != nil
	pending = n.handshake.vpnIps[addr] != nil
	n.handshake.RUnlock()
	hostMap.RUnlock()
	return
}

func (n *Node) collectTunnels(include func(*hostInfo) bool) []*hostInfo {
	n.engine.hostMap.RLock()
	tunnels := make([]*hostInfo, 0, len(n.engine.hostMap.Indexes))
	for _, h := range n.engine.hostMap.Indexes {
		if include(h) {
			tunnels = append(tunnels, h)
		}
	}
	n.engine.hostMap.RUnlock()
	return tunnels
}

func (n *Node) cancelPendingHandshakes(include func([]netip.Addr) bool) int {
	n.handshake.RLock()
	pending := make([]*handshakeHostInfo, 0, len(n.handshake.vpnIps))
	seen := make(map[*handshakeHostInfo]struct{}, len(n.handshake.vpnIps))
	for _, hh := range n.handshake.vpnIps {
		if _, ok := seen[hh]; !ok {
			seen[hh] = struct{}{}
			pending = append(pending, hh)
		}
	}
	n.handshake.RUnlock()

	canceled := 0
	for _, hh := range pending {
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
	var remote netip.AddrPort
	var relayHostInfo *hostInfo
	var relayRoute *relay
	if !localOnly && h.connectionState != nil {
		remote = h.GetRemote()
		if !remote.IsValid() {
			for _, relayAddr := range h.relayState.CopyRelayIps() {
				var err error
				relayHostInfo, relayRoute, err = n.engine.hostMap.QueryVpnAddrsRelayFor(h.vpnAddrs, relayAddr)
				if err == nil {
					break
				}
			}
		}
	}
	if !n.engine.closeTunnel(h) {
		return false
	}
	if !localOnly && h.connectionState != nil {
		n.engine.sendCloseTunnelWithRoute(h, remote, relayHostInfo, relayRoute)
	}
	return true
}

func copyPeerRemotes(remotes *remoteList, preferred []netip.Prefix) ([]netip.AddrPort, []netip.Addr) {
	if remotes == nil {
		return nil, nil
	}
	known := remotes.CopyAddrs(preferred)
	for i := range known {
		known[i] = unmapAddrPort(known[i])
	}
	slices.SortFunc(known, func(a, b netip.AddrPort) int { return a.Compare(b) })
	remotes.RLock()
	relays := cloneAddresses(remotes.relays)
	remotes.RUnlock()
	slices.SortFunc(relays, func(a, b netip.Addr) int { return a.Compare(b) })
	return known, relays
}

func unmapAddrPort(addr netip.AddrPort) netip.AddrPort {
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}
