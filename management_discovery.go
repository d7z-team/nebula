package nebula

import (
	"context"
	"math"
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
	DefaultPathPolicy   PeerPathPolicy
	AdvertisedRelays    []netip.Addr
}

// PeerDiscoverySnapshot contains a peer's cached candidates, including static
// endpoints, discovery reports and unexpired managed introductions.
type PeerDiscoverySnapshot struct {
	Addresses []netip.Addr
	Endpoints []netip.AddrPort
	Relays    []netip.Addr
	Static    bool
}

// Discovery returns a stable, detached snapshot of the local discovery
// configuration. It is safe to call before Start and after Close.
func (n *Node) Discovery() DiscoverySnapshot {
	lighthouses := cloneAddresses(n.lighthouse.lighthouses)
	slices.SortFunc(lighthouses, netip.Addr.Compare)

	configuredEndpoints := make([]netip.AddrPort, 0, len(n.lighthouse.advertiseAddrs))
	for _, endpoint := range n.lighthouse.advertiseAddrs {
		if !endpoint.IsValid() {
			continue
		}
		configuredEndpoints = append(configuredEndpoints, netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()))
	}
	slices.SortFunc(configuredEndpoints, netip.AddrPort.Compare)

	advertisedRelays := cloneAddresses(n.lighthouse.relaysForMe)
	slices.SortFunc(advertisedRelays, netip.Addr.Compare)

	return DiscoverySnapshot{
		IsLighthouse:        n.lighthouse.amLighthouse,
		Lighthouses:         lighthouses,
		ConfiguredEndpoints: configuredEndpoints,
		IsRelay:             n.engine.servesRelays,
		DefaultPathPolicy:   n.engine.paths.config.Load().Default.clone(),
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
	if remotes == nil {
		n.lighthouse.RUnlock()
		return PeerDiscoverySnapshot{}, false
	}
	c := remotes.candidates()
	static := false
	for _, addr := range c.addresses {
		if _, ok := n.lighthouse.staticList[addr]; ok {
			static = true
			break
		}
	}
	n.lighthouse.RUnlock()

	addresses := cloneAddresses(c.addresses)
	slices.SortFunc(addresses, netip.Addr.Compare)
	endpoints, relays := c.copyPaths()
	return PeerDiscoverySnapshot{Addresses: addresses, Endpoints: endpoints, Relays: relays, Static: static}, true
}

// Management callers receive detached slices in address order.
func (c *remoteCandidates) copyPaths() ([]netip.AddrPort, []netip.Addr) {
	if c == nil {
		return nil, nil
	}
	endpoints := make([]netip.AddrPort, len(c.endpoints))
	copy(endpoints, c.endpoints)
	slices.SortFunc(endpoints, netip.AddrPort.Compare)
	return endpoints, cloneAddresses(c.relays)
}

// RefreshPeer requests managed introduction when enabled and queues a standard
// lighthouse query when applicable. It returns before peer replies arrive.
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

// SetPeerEndpoints replaces the static underlay candidates for an overlay address.
// An empty slice clears the static entry. If the peer is an allowed exit for a
// restricted or bootstrapping node, the new endpoint set takes effect on return.
func (n *Node) SetPeerEndpoints(addr netip.Addr, endpoints []netip.AddrPort) error {
	if err := n.requireStarted(); err != nil {
		return err
	}
	addr = addr.Unmap()
	if err := n.validatePeerAddress(addr); err != nil {
		return err
	}
	c := n.engine.control
	if c == nil {
		return n.lighthouse.setStaticEndpoints(addr, endpoints)
	}
	pm := &n.engine.paths
	if err := pm.submit.Acquire(n.ctx, math.MaxInt64); err != nil {
		return ErrNodeClosed
	}
	defer pm.submit.Release(math.MaxInt64)
	if err := n.lighthouse.setStaticEndpoints(addr, endpoints); err != nil {
		return err
	}
	cfg := *pm.config.Load()
	if cfg.network.exits != nil && slices.Contains(cfg.network.direct, addr) {
		p := *cfg.network
		p.exits = c.exitEndpoints(&p)
		cfg.network = &p
		pm.config.Store(&cfg)
	}
	return nil
}
