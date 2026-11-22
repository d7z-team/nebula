package nebula

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/header"
)

const pathTick = 125 * time.Millisecond
const probePrefix = "NBP\x01"
const probeSize = len(probePrefix) + 16

func isPathProbe(payload []byte) bool {
	return len(payload) == probeSize && string(payload[:len(probePrefix)]) == probePrefix
}

func (f *packetEngine) finishReply(h *hostInfo, rx tunnelRoute, data []byte, allowed bool) {
	s := &h.paths
	s.mu.Lock()
	p := s.pending
	s.mu.Unlock()
	if p == nil || !bytes.Equal(data, p.id[:]) {
		return
	}
	live := f.routeLive(h, p.route)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != p {
		return
	}
	result := PathCheckResult{Sent: p.route.TunnelPath, Received: rx.TunnelPath, SamePath: p.route == rx, At: now, RTT: now.Sub(p.start)}
	switch {
	case !live || p.epoch != f.rebindEpoch.Load() || p.policyVersion != s.policyVersion:
		result.Err = ErrPathChanged
	case !allowed:
		result.Err = ErrPathPolicy
		if s.active == p.route || !s.active.Endpoint.IsValid() {
			if s.reason != "return path denied" {
				s.recoverAfter = time.Time{}
			}
			s.active = tunnelRoute{}
			s.reason = "return path denied"
			s.changed = now
			s.nextBackup = now
		}
	case !p.deadline.IsZero() && now.After(p.deadline):
		result.Err = ErrPathTimeout
		s.record(p.route, result)
	default:
		s.record(p.route, result)
		if result.SamePath && p.route.leg == nil && (s.active == p.route || s.active.leg != nil) {
			h.SetRemote(p.route.Endpoint)
		}
	}
	s.complete(p, result)
}

// Keep blocking transport submissions within the node's shutdown and Wait lifecycle.
func (n *Node) runPathWork(work func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != NodeStateRunning {
		return false
	}
	n.workers.Go(work)
	return true
}

func (n *Node) startProbe(h *hostInfo, r tunnelRoute, maintenance bool) (*pathProbe, error) {
	f := n.engine
	if !f.routeLive(h, r) {
		return nil, ErrPeerUnavailable
	}
	s := &h.paths
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return nil, ErrPathChanged
	}
	if p := s.pending; p != nil {
		s.mu.Unlock()
		return p, nil
	}
	if maintenance {
		if _, ok := f.paths.background.Allow(); !ok {
			s.mu.Unlock()
			return nil, errPathBudget
		}
	}
	now := time.Now()
	s.syncEpoch(f.rebindEpoch.Load(), now)
	p := &pathProbe{route: r, start: now, policyVersion: s.policyVersion, epoch: s.epoch, done: make(chan struct{})}
	copy(p.id[:], probePrefix)
	rand.Read(p.id[len(probePrefix):])
	rto := time.Second
	if q := s.samples[r]; q != nil && q.SRTT > 0 {
		rto = min(5*time.Second, max(300*time.Millisecond, q.SRTT+4*q.deviation))
	}
	s.pending = p
	s.mu.Unlock()
	// A transport may block in WriteTo. Other checks and canceled callers must still progress.
	if !n.runPathWork(func() {
		_, err := f.sendOnRoute(header.Test, header.TestRequest, h, r, p.id[:], make([]byte, 12), make([]byte, mtu))
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pending != p {
			return
		}
		if err != nil {
			s.complete(p, PathCheckResult{Sent: r.TunnelPath, Err: err})
			if errors.Is(err, errPathBudget) {
				s.nextActive, s.nextBackup = time.Time{}, time.Time{}
			}
			return
		}
		p.deadline = time.Now().Add(rto)
	}) {
		s.mu.Lock()
		if s.pending == p {
			s.complete(p, PathCheckResult{Sent: r.TunnelPath, Err: ErrNodeClosed})
		}
		s.mu.Unlock()
		return nil, ErrNodeClosed
	}
	return p, nil
}

var errProbeRoutePending = errors.New("probe route not ready")

// resolveProbeRoute resolves the requested endpoint or schedules setup of a relay mapping.
func (n *Node) resolveProbeRoute(h *hostInfo, want TunnelPath) (tunnelRoute, error) {
	f := n.engine
	cfg := f.paths.config.Load()
	aliases := f.hostMap.relayIdentities(want.Relay)
	if !cfg.allows(h.vpnAddrs, want.Relay, h.remotes, aliases...) {
		return tunnelRoute{}, ErrPathPolicy
	}
	if !want.Relay.IsValid() {
		if want.Endpoint != h.GetRemote() && !slices.Contains(h.remotes.candidates().endpoints, want.Endpoint) {
			return tunnelRoute{}, errProbeRoutePending
		}
		return tunnelRoute{TunnelPath: want}, nil
	}
	if leg, r, err := f.hostMap.QueryVpnAddrsRelayFor(h.vpnAddrs, want.Relay); err == nil && r.Type == relayTypeTerminal {
		route := receivedRoute(packetSender{UdpAddr: leg.GetRemote(), IsRelayed: true, relayHI: leg, relay: r})
		if want.Endpoint.IsValid() && want.Endpoint != route.Endpoint {
			return tunnelRoute{}, errProbeRoutePending
		}
		if f.routeLive(h, route) {
			return route, nil
		}
	}
	known := cfg.policy(h.vpnAddrs, f.hostMap).Relays
	if len(known) == 0 {
		known = h.remotes.candidates().relays
	}
	used := h.relayState.relayAddresses()
	if !matchesIdentity(known, want.Relay, aliases) && !matchesIdentity(used, want.Relay, aliases) {
		return tunnelRoute{}, fmt.Errorf("%w: unknown relay: %s", ErrPeerUnavailable, want.Relay)
	}
	s := &h.paths
	s.mu.Lock()
	due := !s.mappingPending && !time.Now().Before(s.nextBuild)
	if due {
		s.mappingPending = true
	}
	s.mu.Unlock()
	if due && !n.runPathWork(func() {
		f.ensureRelay(h, want.Relay)
		s.mu.Lock()
		s.mappingPending = false
		s.nextBuild = time.Now().Add(300 * time.Millisecond)
		s.mu.Unlock()
	}) {
		return tunnelRoute{}, ErrNodeClosed
	}
	return tunnelRoute{}, errProbeRoutePending
}

// CheckPeerPath waits for a fresh authenticated round trip. A zero path selects the current exit.
func (n *Node) CheckPeerPath(ctx context.Context, peer netip.Addr, want TunnelPath) (PathCheckResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return PathCheckResult{}, err
	}
	peer = peer.Unmap()
	if err := n.requireStarted(); err != nil {
		return PathCheckResult{}, err
	}
	if err := n.validatePeerAddress(peer); err != nil {
		return PathCheckResult{}, err
	}
	if want.Endpoint.IsValid() {
		want.Endpoint = unmapAddrPort(want.Endpoint)
	}
	want.Relay = want.Relay.Unmap()
	h := n.engine.hostMap.QueryVpnAddr(peer)
	if h == nil && want != (TunnelPath{}) {
		ids := []netip.Addr{peer}
		cfg := n.engine.paths.config.Load()
		policy := cfg.policy(ids, n.engine.hostMap)
		if !want.Relay.IsValid() && policy.Mode == RelayOnly || want.Relay.IsValid() && policy.Mode == DirectOnly {
			return PathCheckResult{}, ErrPathPolicy
		}
		if len(policy.Relays) > 0 && want.Relay.IsValid() && !cfg.allows(ids, want.Relay, nil, n.engine.hostMap.relayIdentities(want.Relay)...) {
			return PathCheckResult{}, ErrPathPolicy
		}
	}
	if h == nil || want == (TunnelPath{}) {
		if err := n.ConnectPeer(ctx, peer); err != nil {
			return PathCheckResult{}, err
		}
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
	for {
		h := n.engine.hostMap.QueryVpnAddr(peer)
		if h == nil {
			return PathCheckResult{}, ErrPeerUnavailable
		}
		var r tunnelRoute
		var err error
		if want == (TunnelPath{}) {
			r = n.engine.currentRoute(h)
		} else {
			r, err = n.resolveProbeRoute(h, want)
			if err != nil && err != errProbeRoutePending {
				return PathCheckResult{}, err
			}
		}
		var p *pathProbe
		var done <-chan struct{}
		poll := retry.C
		if r.Endpoint.IsValid() {
			p, err = n.startProbe(h, r, true)
			if err == nil {
				done = p.done
				poll = nil
			} else if !errors.Is(err, errPathBudget) {
				return PathCheckResult{}, err
			}
		}
		select {
		case <-ctx.Done():
			return PathCheckResult{}, ctx.Err()
		case <-n.ctx.Done():
			return PathCheckResult{}, ErrNodeClosed
		case <-timeout.C:
			return PathCheckResult{}, ErrPeerUnavailable
		case <-poll:
		case <-done:
			result := p.result
			if p.route == r && !errors.Is(result.Err, errPathBudget) && !(want == (TunnelPath{}) && errors.Is(result.Err, ErrPathChanged)) {
				return result, result.Err
			}
		}
	}
}

func (n *Node) runPathChecks() {
	tick := time.NewTicker(pathTick)
	defer tick.Stop()
	var lastSweep time.Time
	var lastGrant uint32
	var hosts []*hostInfo
	for {
		select {
		case <-n.ctx.Done():
			return
		case now := <-tick.C:
			f := n.engine
			cfg := f.paths.config.Load()
			if now.Sub(lastSweep) >= 10*time.Second {
				lastSweep = now
				f.hostMap.expirePendingRelays(now)
				for addr, policy := range cfg.Peers {
					if policy.MonitorInterval > 0 && f.hostMap.QueryVpnAddr(addr) == nil {
						f.Handshake(addr)
					}
				}
			}
			wheel := f.paths.checks
			wheel.Advance(now)
			hosts = hosts[:0]
			for {
				h, ok := wheel.Purge()
				if !ok {
					break
				}
				if f.hostMap.QueryIndex(h.localIndexId) == h {
					hosts = append(hosts, h)
				}
			}
			// Continue after the last admitted peer even when many checks become due together.
			slices.SortFunc(hosts, func(a, b *hostInfo) int { return cmp.Compare(a.localIndexId-lastGrant-1, b.localIndexId-lastGrant-1) })
			for _, h := range hosts {
				if n.checkSession(h, now) {
					lastGrant = h.localIndexId
				}
				wheel.Add(h, pathTick)
			}
			clear(hosts)
		}
	}
}

// servicePending attributes a reply timeout only after a successful transport submission.
func (f *packetEngine) servicePending(h *hostInfo, now time.Time) bool {
	s := &h.paths
	s.mu.Lock()
	p := s.pending
	s.mu.Unlock()
	if p == nil {
		return false
	}

	live := f.routeLive(h, p.route)
	s.mu.Lock()
	var failedLeg *hostInfo
	if s.pending == p {
		result := PathCheckResult{Sent: p.route.TunnelPath, At: now}
		if !live || p.epoch != f.rebindEpoch.Load() || p.policyVersion != s.policyVersion {
			result.Err = ErrPathChanged
			s.complete(p, result)
		} else if !p.deadline.IsZero() && !now.Before(p.deadline) {
			result.Err = ErrPathTimeout
			s.record(p.route, result)
			s.complete(p, result)
			failedLeg = p.route.leg
			if s.active.leg == nil && s.active.Endpoint.IsValid() {
				h.SetRemote(s.active.Endpoint)
			}
		}
	}
	s.mu.Unlock()
	if failedLeg != nil {
		failedLeg.verifyNeighbor(now.Add(-time.Second), now)
	}
	return true
}

func (n *Node) checkSession(h *hostInfo, now time.Time) bool {
	f := n.engine
	if f.servicePending(h, now) {
		return false
	}
	s := &h.paths
	cfg := f.paths.config.Load()
	if f.hostMap.QueryVpnAddr(h.vpnAddrs[0]) != h {
		return false
	}
	policy := cfg.policy(h.vpnAddrs, f.hostMap)
	s.mu.Lock()
	initial, alt := s.active, s.standby
	s.mu.Unlock()
	valid := f.routeLive(h, initial)
	altLive := !valid && f.routeLive(h, alt)
	s.mu.Lock()
	if initial != s.active {
		s.mu.Unlock()
		return false
	}
	s.syncEpoch(f.rebindEpoch.Load(), now)
	if !valid && s.active.Endpoint.IsValid() {
		s.active = tunnelRoute{}
		s.reason = "path unavailable"
		if q := s.samples[alt]; altLive && alt == s.standby && q.readyForFailover(now) {
			s.active, s.standby = alt, tunnelRoute{}
			s.reason = "failover"
		}
		s.changed = now
	}
	if s.neighborCheck {
		ep := h.GetRemote()
		r := tunnelRoute{TunnelPath: TunnelPath{Endpoint: ep}}
		q := s.samples[r]
		s.neighborCheck = false
		if ep.IsValid() && (q == nil || (!now.Before(q.RetryAfter) && now.Sub(q.LastSuccess) >= time.Second)) {
			s.mu.Unlock()
			_, err := n.startProbe(h, r, false)
			return err == nil
		}
	}
	active := s.active
	busy := now.Sub(s.demand) < time.Minute
	if !busy && policy.MonitorInterval == 0 {
		s.mu.Unlock()
		return false
	}
	roam := s.roam
	degraded := !active.Endpoint.IsValid() || (s.samples[active] != nil && s.samples[active].Degraded)
	checkActive := active.Endpoint.IsValid() && !now.Before(s.nextActive)
	checkBackup := !now.Before(s.nextBackup)
	standby := s.standby
	cursor := s.cursor
	if !checkActive && !checkBackup {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()

	r := active
	if !checkActive {
		options := f.backupCandidates(h, policy, active, standby, roam, degraded, cursor)
		if len(options) == 0 {
			s.mu.Lock()
			s.nextBackup = now.Add(time.Second)
			refresh := now.After(s.nextDiscovery)
			if refresh {
				s.nextDiscovery = now.Add(time.Minute)
			}
			s.mu.Unlock()
			if refresh {
				f.lightHouse.QueryServer(h.vpnAddrs[0])
			}
			return false
		}
		var err error
		choice := cursor
		if standby.Endpoint.IsValid() && cursor%4 == 3 {
			choice = cursor / 4
		}
		r, err = n.resolveProbeRoute(h, options[choice%len(options)])
		if err != nil {
			s.mu.Lock()
			s.cursor++
			s.nextBackup = now.Add(500 * time.Millisecond)
			s.mu.Unlock()
			return false
		}
	}
	s.mu.Lock()
	q := s.samples[r]
	// A new end-to-end handshake repairs stale keys or a stock endpoint's
	// incompatible return path. A failed shared adjacency is repaired once at R.
	last := s.last
	recoverSession := !active.Endpoint.IsValid() && !now.Before(s.recoverAfter) && last.Sent == r.TunnelPath &&
		(errors.Is(last.Err, ErrPathPolicy) || (q != nil && q.failures >= 3))
	cooling := q != nil && now.Before(q.RetryAfter)
	if cooling {
		s.cursor++
		s.nextBackup = now.Add(time.Second)
	}
	s.mu.Unlock()
	if recoverSession && (r.leg == nil || errors.Is(last.Err, ErrPathPolicy) || r.leg.verifyNeighbor(last.At, now)) {
		s.mu.Lock()
		s.recoverAfter = now.Add(30 * time.Second)
		s.mu.Unlock()
		n.handshake.StartHandshake(h.vpnAddrs[0], nil)
		return false
	}
	if cooling {
		return false
	}
	if _, err := n.startProbe(h, r, true); err != nil {
		return false
	}
	s.mu.Lock()
	period := 10 * time.Second
	if !busy && policy.MonitorInterval > 0 {
		period = min(policy.MonitorInterval, time.Duration(1<<61))
	}
	if checkActive {
		s.nextActive = now.Add(period - period/10 + mathrand.N(period/5+1))
	} else {
		s.cursor++
		s.nextBackup = now.Add(3*period - period/5 + mathrand.N(period/2+1))
		if !active.Endpoint.IsValid() || degraded {
			s.nextBackup = now.Add(time.Second)
		}
	}
	s.mu.Unlock()
	return true
}

// backupCandidates preserves configured relay order. Healthy direct endpoints are
// probed on migration or recovery because a legacy peer may roam on a TestRequest.
func (f *packetEngine) backupCandidates(h *hostInfo, policy PeerPathPolicy, active, standby tunnelRoute, roam netip.AddrPort, degraded bool, cursor int) []TunnelPath {
	if f.routeLive(h, standby) && (!active.Endpoint.IsValid() || cursor%4 != 3) {
		return []TunnelPath{standby.TunnelPath}
	}
	cfg := f.paths.config.Load()
	c := h.remotes.candidates()
	relays := policy.Relays
	if len(relays) == 0 {
		relays = slices.Clip(c.relays)
		for _, known := range h.relayState.relayAddresses() {
			if !slices.Contains(relays, known) {
				relays = append(relays, known)
			}
		}
	}
	var options []TunnelPath
	if cfg.allows(h.vpnAddrs, netip.Addr{}, h.remotes) {
		for _, ep := range c.endpoints {
			path := TunnelPath{Endpoint: ep}
			if path != active.TunnelPath && (degraded || ep == roam || active.leg != nil) {
				options = append(options, path)
			}
		}
	}
	for _, addr := range relays {
		if addr != active.Relay && cfg.allows(h.vpnAddrs, addr, h.remotes, f.hostMap.relayIdentities(addr)...) {
			options = append(options, TunnelPath{Relay: addr})
		}
	}
	return options
}
