package nebula

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/ratelimit"
	"golang.org/x/sync/semaphore"
)

// PathMode constrains both directions of a peer's tunnel.
type PathMode uint8

const (
	Auto PathMode = iota
	DirectOnly
	RelayOnly
	// PathBlocked appears in snapshots when certificate address overrides have no common path.
	PathBlocked
)

// PeerPathPolicy limits both ingress and egress. Relays are ordered overlay identities.
type PeerPathPolicy struct {
	Mode            PathMode
	Relays          []netip.Addr
	MonitorInterval time.Duration
}

func (p PeerPathPolicy) clone() PeerPathPolicy {
	p.Relays = slices.Clone(p.Relays)
	return p
}

var (
	ErrPathPolicy  = errors.New("tunnel path denied by policy")
	ErrPathTimeout = errors.New("tunnel path probe timed out")
	errWritePolicy = fmt.Errorf("%w: route invalid at submission", ErrPathPolicy)
	ErrPathChanged = errors.New("tunnel path changed")
	errPathBudget  = errors.New("path control budget exhausted")
)

// The runtime policy map is replaced atomically. Probe settings are fixed at New.
type pathPolicies struct {
	network *networkPolicy
	Default PeerPathPolicy
	Peers   map[netip.Addr]PeerPathPolicy
}

type pathManager struct {
	probes    PathProbeOptions
	selection PathSelectionOptions
	config    atomic.Pointer[pathPolicies]
	checks    *timerWheel[*hostInfo]
	// Writers hold a shared permit across the final policy check and UDP submission.
	// Policy readers elsewhere use the immutable config without taking this lock.
	ctx                        context.Context
	submit                     *semaphore.Weighted
	controlBudget, probeBudget *ratelimit.Limiter
}

func (p PeerPathPolicy) validate(n *Node, peer netip.Addr) (PeerPathPolicy, error) {
	if p.Mode > RelayOnly || p.MonitorInterval < 0 || (!peer.IsValid() && p.MonitorInterval != 0) || (p.Mode == DirectOnly && len(p.Relays) > 0) {
		return p, fmt.Errorf("%w: invalid mode, interval or relay list", ErrPathPolicy)
	}
	p = p.clone()
	for i, addr := range p.Relays {
		addr = addr.Unmap()
		if err := n.validatePeerAddress(addr); err != nil {
			return p, err
		}
		if addr == peer || slices.Contains(p.Relays[:i], addr) {
			return p, fmt.Errorf("%w: invalid relay %v for %v", ErrPathPolicy, addr, peer)
		}
		p.Relays[i] = addr
	}
	return p, nil
}

func (p *pathManager) init(n *Node, opts PathOptions) error {
	d, err := opts.Default.validate(n, netip.Addr{})
	if err != nil {
		return err
	}
	cfg := pathPolicies{Default: d, Peers: make(map[netip.Addr]PeerPathPolicy, len(opts.Peers))}
	for addr, v := range opts.Peers {
		addr = addr.Unmap()
		if err := n.validatePeerAddress(addr); err != nil {
			return err
		}
		if _, ok := cfg.Peers[addr]; ok {
			return fmt.Errorf("%w: duplicate peer %v", ErrPathPolicy, addr)
		}
		v, err = v.validate(n, addr)
		if err != nil {
			return err
		}
		cfg.Peers[addr] = v
	}
	p.ctx, p.submit = n.ctx, semaphore.NewWeighted(math.MaxInt64)
	if err := opts.normalizeTuning(); err != nil {
		return err
	}
	p.probes, p.selection = opts.Probes, opts.Selection
	// Every scheduled item has a delay of exactly one tick.
	p.checks = newTimerWheel[*hostInfo](p.probes.TickInterval, p.probes.TickInterval)
	p.config.Store(&cfg)
	p.controlBudget, err = ratelimit.New(p.probes.ControlBudget.Burst, p.probes.ControlBudget.Every)
	if err != nil {
		return fmt.Errorf("path control budget: %w", err)
	}
	p.probeBudget, err = ratelimit.New(p.probes.ProbeBudget.Burst, p.probes.ProbeBudget.Every)
	if err != nil {
		return fmt.Errorf("path probe budget: %w", err)
	}
	return nil
}

// PeerPathPolicy returns the explicit override for this overlay address and
// whether one exists. It can be read before Start, independently of any tunnel.
func (n *Node) PeerPathPolicy(peer netip.Addr) (PeerPathPolicy, bool) {
	policy, ok := n.engine.paths.config.Load().Peers[peer.Unmap()]
	return policy.clone(), ok
}

// SetPeerPathPolicy replaces the local override for one overlay address.
// A nil policy clears that override. Managed topology constraints also apply.
func (n *Node) SetPeerPathPolicy(ctx context.Context, peer netip.Addr, policy *PeerPathPolicy) error {
	peer = peer.Unmap()
	if err := n.validatePeerAddress(peer); err != nil {
		return err
	}
	var v PeerPathPolicy
	var err error
	if policy != nil {
		v, err = policy.validate(n, peer)
		if err != nil {
			return err
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pm := &n.engine.paths
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	defer cancel()
	defer stop()
	if err := pm.submit.Acquire(ctx, math.MaxInt64); err != nil {
		if n.ctx.Err() != nil {
			return ErrNodeClosed
		}
		return err
	}
	defer pm.submit.Release(math.MaxInt64)
	if n.ctx.Err() != nil {
		return ErrNodeClosed
	}
	cfg := *pm.config.Load()
	cfg.Peers = maps.Clone(cfg.Peers)
	if policy == nil {
		delete(cfg.Peers, peer)
	} else {
		cfg.Peers[peer] = v
	}
	pm.config.Store(&cfg)
	if h := n.engine.hostMap.QueryVpnAddr(peer); h != nil {
		h.paths.mu.Lock()
		// Let an established end-to-end session verify a newly permitted exit first.
		h.paths.policyVersion++
		h.paths.samples = nil
		h.paths.standby = tunnelRoute{}
		h.paths.nextActive, h.paths.nextBackup = time.Time{}, time.Time{}
		h.paths.buildUntil = time.Time{}
		now := time.Now()
		h.paths.demand = now
		h.paths.recoverAfter = time.Time{}
		h.paths.mu.Unlock()
	}
	return nil
}

// matchesIdentity accepts any authenticated address of the same overlay peer.
func matchesIdentity(list []netip.Addr, addr netip.Addr, aliases []netip.Addr) bool {
	if slices.Contains(list, addr) {
		return true
	}
	for _, alias := range aliases {
		if slices.Contains(list, alias) {
			return true
		}
	}
	return false
}

// Every explicit alias constraint applies. The default applies only without an override.
func (cfg *pathPolicies) allows(ids []netip.Addr, relay netip.Addr, remotes *remoteList, aliases ...netip.Addr) bool {
	match := func(v PeerPathPolicy) bool {
		if !relay.IsValid() {
			return v.Mode != RelayOnly
		}
		if v.Mode == DirectOnly || matchesIdentity(ids, relay, aliases) {
			return false
		}
		if len(v.Relays) > 0 {
			return matchesIdentity(v.Relays, relay, aliases)
		}
		if v.Mode != RelayOnly {
			return true
		}
		return remotes != nil && matchesIdentity(remotes.candidates().relays, relay, aliases)
	}
	if cfg.network != nil {
		p := cfg.network.peerPathPolicy(ids)
		if p.Mode == PathBlocked || !match(p) {
			return false
		}
	}
	override := false
	for _, id := range ids {
		if v, ok := cfg.Peers[id]; ok {
			override = true
			if !match(v) {
				return false
			}
		}
	}
	return override || match(cfg.Default)
}

// relayIdentities includes alternate certificate addresses once the adjacency is authenticated.
func (hm *hostMap) relayIdentities(addr netip.Addr) []netip.Addr {
	if !addr.IsValid() {
		return nil
	}
	if leg := hm.QueryVpnAddr(addr); leg != nil {
		return leg.vpnAddrs
	}
	return nil
}

func (cfg *pathPolicies) effectivePolicy(ids []netip.Addr, hm *hostMap) PeerPathPolicy {
	v := cfg.localPolicy(ids, hm)
	if cfg.network == nil {
		return v
	}
	m := cfg.network.peerPathPolicy(ids)
	if m.Mode == PathBlocked || (m.Mode != Auto && v.Mode != Auto && m.Mode != v.Mode) {
		return PeerPathPolicy{Mode: PathBlocked}
	}
	if m.Mode != Auto {
		v.Mode = m.Mode
	}
	if len(m.Relays) > 0 {
		if len(v.Relays) == 0 {
			v.Relays = m.Relays
		} else {
			v.Relays = slices.DeleteFunc(slices.Clone(v.Relays), func(a netip.Addr) bool { return !matchesIdentity(m.Relays, a, hm.relayIdentities(a)) })
			if len(v.Relays) == 0 && v.Mode == RelayOnly {
				v.Mode = PathBlocked
			}
		}
	}
	return v
}

func (cfg *pathPolicies) localPolicy(ids []netip.Addr, hm *hostMap) PeerPathPolicy {
	var v PeerPathPolicy
	var constrained, found bool
	for _, id := range ids {
		next, ok := cfg.Peers[id]
		if !ok {
			continue
		}
		found = true
		if next.Mode != Auto {
			if v.Mode == Auto {
				v.Mode = next.Mode
			} else if v.Mode != next.Mode {
				v.Mode = PathBlocked
			}
		}
		if len(next.Relays) > 0 {
			if !constrained {
				v.Relays, constrained = next.Relays, true
			} else {
				v.Relays = slices.DeleteFunc(slices.Clone(v.Relays), func(addr netip.Addr) bool {
					return !matchesIdentity(next.Relays, addr, hm.relayIdentities(addr))
				})
			}
		}
		if next.MonitorInterval > 0 && (v.MonitorInterval == 0 || next.MonitorInterval < v.MonitorInterval) {
			v.MonitorInterval = next.MonitorInterval
		}
	}
	if !found {
		return cfg.Default
	}
	if constrained && len(v.Relays) == 0 {
		if v.Mode == RelayOnly {
			v.Mode = PathBlocked
		} else if v.Mode == Auto {
			v.Mode = DirectOnly
		}
	}
	return v
}

type tunnelRoute struct {
	owner        netip.Addr
	ingressIndex uint32
	TunnelPath
	leg           *hostInfo
	relayFor      netip.Addr // Terminal peer named by a direct CreateRelay control message.
	local, remote uint32
}

func receivedRoute(v packetSender) tunnelRoute {
	r := tunnelRoute{TunnelPath: TunnelPath{Endpoint: v.UdpAddr}}
	if v.IsRelayed {
		r.Circuit = v.relay.Circuit
		r.leg = v.relayHI
		r.Relay = r.leg.vpnAddrs[0]
		r.local, r.remote = v.relay.LocalIndex, v.relay.RemoteIndex
	}
	return r
}

func (f *packetEngine) allowed(h *hostInfo, r tunnelRoute) bool {
	cfg := f.paths.config.Load()
	if cfg.network != nil && h.connectionState != nil && cfg.network.denies(h.GetCert()) {
		return false
	}
	if r.relayFor.IsValid() {
		ids := []netip.Addr{r.relayFor}
		var remotes *remoteList
		if end := f.hostMap.QueryVpnAddr(r.relayFor); end != nil {
			ids, remotes = end.vpnAddrs, end.remotes
		} else {
			f.lightHouse.RLock()
			remotes = f.lightHouse.addrMap[r.relayFor]
			f.lightHouse.RUnlock()
		}
		if !cfg.allows(ids, h.vpnAddrs[0], remotes, h.vpnAddrs...) {
			return false
		}
	}
	var aliases []netip.Addr
	if r.leg != nil {
		aliases = r.leg.vpnAddrs
		if !cfg.allows(aliases, netip.Addr{}, r.leg.remotes) {
			return false
		}
	}
	if h.connectionState == nil && len(h.vpnAddrs) == 1 {
		if known := f.hostMap.QueryVpnAddr(h.vpnAddrs[0]); known != nil {
			h = known
		}
	}
	return cfg.allows(h.vpnAddrs, r.Relay, h.remotes, aliases...)
}

func (f *packetEngine) routeLive(h *hostInfo, r tunnelRoute) bool {
	if !r.Endpoint.IsValid() || (f.control != nil && !f.control.policy().allowsEndpoint(r.Endpoint)) || !f.allowed(h, r) {
		return false
	}
	if r.leg == nil {
		return true
	}
	if r.leg.GetRemote() != r.Endpoint || f.hostMap.QueryRelayIndex(r.local) != r.leg {
		return false
	}
	entry, ok := r.leg.relayState.mappingByIndex(r.local)
	return ok && entry.State == relayEstablished && entry.Type == relayTypeTerminal && entry.RemoteIndex == r.remote && entry.Circuit == r.Circuit && slices.Contains(h.vpnAddrs, entry.PeerAddr) && !r.leg.paths.failedDirect(r.Endpoint, f.paths.selection.FailureThreshold)
}

func (f *packetEngine) writePath(h *hostInfo, r tunnelRoute, packet []byte, control bool, ingress *hostInfo) error {
	if c := f.control; c != nil && !control && c.policy().local.BytesPerSecond > 0 {
		return c.shaper.submit(c, h, r, packet, ingress)
	}
	return f.submitPath(h, r, packet, control, ingress)
}

func (f *packetEngine) submitPath(h *hostInfo, r tunnelRoute, packet []byte, control bool, ingress *hostInfo) error {
	if err := f.paths.submit.Acquire(f.paths.ctx, 1); err != nil {
		return ErrNodeClosed
	}
	defer f.paths.submit.Release(1)
	if p := f.paths.config.Load().network; p != nil && p.bootstrapOnly && !control {
		return errWritePolicy
	}
	if (r.leg != nil && !f.routeLive(h, r)) || (h != nil && r.leg == nil && !f.allowed(h, r)) || (ingress != nil && !f.allowed(ingress, tunnelRoute{})) {
		return errWritePolicy
	}
	if control {
		if _, ok := f.paths.controlBudget.Allow(); !ok {
			return errPathBudget
		}
	}
	if ingress != nil && r.ingressIndex != 0 {
		if p := f.paths.config.Load().network; p != nil && !p.allowsTransit(ingress.vpnAddrs[0], h.vpnAddrs[0]) {
			return errWritePolicy
		}
		if f.hostMap.QueryRelayIndex(r.ingressIndex) != ingress || f.hostMap.QueryRelayIndex(r.local) != h || h.GetRemote() != r.Endpoint {
			return errWritePolicy
		}
		target, ok := h.relayState.mappingByIndex(r.local)
		if !ok || target.State != relayEstablished || target.RemoteIndex != r.remote {
			return errWritePolicy
		}
	}
	var err error
	if c := f.control; control && c != nil && c.policy().local.BytesPerSecond > 0 {
		err = c.shaper.writeControl(c, packet, r.Endpoint)
	} else {
		err = f.writeDatagram(packet, r.Endpoint)
	}
	if err == nil && ingress != nil {
		f.forwardedDatagrams.Add(1)
	}
	return err
}

func (f *packetEngine) handshakeAllowed(ids []netip.Addr, v packetSender, remotes *remoteList) bool {
	if v.IsRelayed && !slices.Contains(ids, v.relay.PeerAddr) {
		return false
	}
	return f.allowed(&hostInfo{vpnAddrs: ids, remotes: remotes}, receivedRoute(v))
}
