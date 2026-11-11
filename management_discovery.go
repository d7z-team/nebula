package nebula

import (
	"context"
	"net/netip"
	"slices"
)

// DiscoverySnapshot describes a detached copy of the node's discovery and relay
// configuration. Dynamic endpoints returned by EndpointProvider are omitted
// because reading a snapshot must not invoke user code or perform network I/O.
type DiscoverySnapshot struct {
	IsLighthouse        bool
	Lighthouses         []netip.Addr
	ConfiguredEndpoints []netip.AddrPort
	IsRelay             bool
	UsesRelays          bool
	AdvertisedRelays    []netip.Addr
}

// PeerDiscoverySnapshot is a detached copy of the lighthouse cache for a peer.
// It does not trigger a lighthouse query.
type PeerDiscoverySnapshot struct {
	Addresses []netip.Addr
	Endpoints []netip.AddrPort
	Relays    []netip.Addr
	Static    bool
}

// Discovery returns a stable, detached snapshot of the local discovery
// configuration. It is safe to call before Start and after Close.
func (n *Node) Discovery() DiscoverySnapshot {
	lighthouses := cloneAddresses(n.lighthouse.GetLighthouses())
	slices.SortFunc(lighthouses, func(a, b netip.Addr) int { return a.Compare(b) })

	configuredEndpoints := make([]netip.AddrPort, 0, len(n.lighthouse.GetAdvertiseAddrs()))
	for _, endpoint := range n.lighthouse.GetAdvertiseAddrs() {
		if !endpoint.IsValid() {
			continue
		}
		configuredEndpoints = append(configuredEndpoints, netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()))
	}
	slices.SortFunc(configuredEndpoints, func(a, b netip.AddrPort) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return int(a.Port()) - int(b.Port())
	})

	advertisedRelays := cloneAddresses(n.lighthouse.GetRelaysForMe())
	slices.SortFunc(advertisedRelays, func(a, b netip.Addr) int { return a.Compare(b) })

	return DiscoverySnapshot{
		IsLighthouse:        n.lighthouse.amLighthouse,
		Lighthouses:         lighthouses,
		ConfiguredEndpoints: configuredEndpoints,
		IsRelay:             n.engine.relayManager.GetAmRelay(),
		UsesRelays:          n.engine.relayManager.GetUseRelays(),
		AdvertisedRelays:    advertisedRelays,
	}
}

// PeerDiscovery returns a detached snapshot of a peer's cached discovery
// records. It never queries a lighthouse. The boolean is false when addr is
// invalid, outside the overlay, or absent from the cache.
func (n *Node) PeerDiscovery(addr netip.Addr) (PeerDiscoverySnapshot, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() || !n.lighthouse.myVpnNetworksTable.Contains(addr) {
		return PeerDiscoverySnapshot{}, false
	}

	n.lighthouse.RLock()
	remotes := n.lighthouse.addrMap[addr]
	n.lighthouse.RUnlock()
	if remotes == nil {
		return PeerDiscoverySnapshot{}, false
	}

	// Rebuild with the node's dialing policy so this read cannot change the
	// ordering subsequently observed by the data path. The detached result is
	// sorted below to give management callers a stable representation.
	remotes.Rebuild(n.engine.hostMap.GetPreferredRanges())
	remotes.RLock()
	addresses := cloneAddresses(remotes.vpnAddrs)
	endpoints := slices.Clone(remotes.addrs)
	relays := cloneAddresses(remotes.relays)
	remotes.RUnlock()
	for i := range endpoints {
		endpoints[i] = unmapAddrPort(endpoints[i])
	}

	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.SortFunc(endpoints, func(a, b netip.AddrPort) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return int(a.Port()) - int(b.Port())
	})
	slices.SortFunc(relays, func(a, b netip.Addr) int { return a.Compare(b) })

	n.lighthouse.RLock()
	static := false
	for _, peerAddr := range addresses {
		if _, ok := n.lighthouse.staticList[peerAddr]; ok {
			static = true
			break
		}
	}
	n.lighthouse.RUnlock()

	return PeerDiscoverySnapshot{
		Addresses: addresses,
		Endpoints: endpoints,
		Relays:    relays,
		Static:    static,
	}, true
}

// RefreshPeer reliably queues a lighthouse query for addr when discovery is
// applicable. It is an idempotent success for lighthouse nodes, configured
// lighthouse peers, and nodes without a lighthouse. It never waits for, or
// guarantees, a lighthouse reply.
func (n *Node) RefreshPeer(ctx context.Context, addr netip.Addr) error {
	if err := n.requireStarted(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addr = addr.Unmap()
	if err := n.validatePeerAddress(addr); err != nil {
		return err
	}
	return n.lighthouse.queryServerContext(ctx, addr)
}

// AdvertiseNow obtains fresh dynamic endpoints and sends a standard Nebula
// host update to every configured lighthouse. It is an idempotent success on
// lighthouse nodes and nodes without a lighthouse. If EndpointProvider fails,
// configured static endpoints are still sent and its error is returned.
// Success does not imply a remote acknowledgement.
func (n *Node) AdvertiseNow(ctx context.Context) error {
	if err := n.requireStarted(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return n.lighthouse.sendUpdateContext(ctx)
}
