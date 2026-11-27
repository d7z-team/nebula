package nebula

import (
	"errors"
	"slices"
	"time"
)

// Node.mu protects the registered paths and the hysteresis choice for each peer.
type peerPaths struct {
	sessions     []*session
	active       *session
	lastCanary   time.Time
	nextEndpoint int
}

func (n *Node) removeSessionLocked(s *session) {
	paths := n.peers[s.peer]
	if paths == nil {
		return
	}
	if i := slices.Index(paths.sessions, s); i >= 0 {
		paths.sessions = slices.Delete(paths.sessions, i, i+1)
	}
	if paths.active == s {
		paths.active = nil
	}
	if len(paths.sessions) == 0 {
		delete(n.peers, s.peer)
		if c, ok := n.conflicts[s.peer]; ok && c.confirmedAt.IsZero() {
			delete(n.conflicts, s.peer)
			n.admissions++
		}
	}
}

func (s *session) cost() time.Duration {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	rtt, jitter := s.rtt, s.jitter
	if s.q != nil {
		v := s.q.ConnectionStats()
		if v.SmoothedRTT > 0 {
			rtt = v.SmoothedRTT
			jitter = v.MeanDeviation
		}
	}
	if rtt == 0 {
		rtt = 10 * time.Millisecond
	}
	base := rtt + 2*jitter + time.Duration(s.failures)*time.Second + time.Duration(float64(500*time.Millisecond)*s.loss)
	switch s.kind {
	case "tcp":
		base += 25 * time.Millisecond
	case "relay":
		base += 75 * time.Millisecond
	}
	return base
}

func (n *Node) preferredSession(peer PeerID, direct bool) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.preferredSessionLocked(n.peers[peer], direct, nil)
}

// preferredSessionLocked applies health scores and hysteresis without changing the selection.
func (n *Node) preferredSessionLocked(paths *peerPaths, direct bool, packet *innerPacket) *session {
	if paths == nil {
		return nil
	}
	var best *session
	var lowest, activeCost time.Duration
	for _, s := range paths.sessions {
		if s.closed.Load() || direct && len(s.path) > 0 || !n.sessionAllowedLocked(s) {
			continue
		}
		if packet != nil && !packet.authorizedOn(n.policy.Load(), s.localIdentity, s.remoteIdentity) {
			continue
		}
		cost := s.cost()
		if s == paths.active {
			activeCost = cost
		}
		if best == nil || cost < lowest {
			best, lowest = s, cost
		}
	}
	if !direct && activeCost > 0 && activeCost <= lowest+lowest/5 {
		return paths.active
	}
	return best
}

// directEndpointLocked returns a reusable connection, or the number of usable
// outgoing alternatives in the same transport and address family.
func (n *Node) directEndpointLocked(peer PeerID, ep Endpoint) (*session, int) {
	match := func(paths *peerPaths) (*session, int) {
		outgoing := 0
		for _, s := range paths.sessions {
			if s.kind != ep.Network || s.closed.Load() || !n.sessionAllowedLocked(s) {
				continue
			}
			remote := s.remoteEndpoint()
			// A physical endpoint dial authenticates a server. An inbound QUIC
			// path authenticated the remote client and can serve a known peer.
			if remote == ep.Address && (s.outgoing || peer != (PeerID{}) && s.q != nil) {
				return s, 0
			}
			if s.outgoing && remote.Addr().BitLen() == ep.Address.Addr().BitLen() {
				outgoing++
			}
		}
		return nil, outgoing
	}
	if peer != (PeerID{}) {
		if paths := n.peers[peer]; paths != nil {
			return match(paths)
		}
	} else {
		for _, paths := range n.peers {
			if s, _ := match(paths); s != nil {
				return s, 0
			}
		}
	}
	return nil, 0
}

// Return the first neighbor to reconsider when a dial slot becomes available.
func (n *Node) dialNeighborsLocked(next int) int {
	p := n.policy.Load()
	if n.state != running || !n.ready(p) {
		return next
	}
	targets := p.members[n.id].Links
	for range targets {
		next %= len(targets)
		peer := targets[next]
		if n.attempts[peer] == nil && n.modeLocked(peer) != Blocked && n.preferredSessionLocked(n.peers[peer], false, nil) == nil {
			select {
			case n.neighborDialSlots <- struct{}{}:
				n.startDialLocked(peer, n.neighborDialSlots)
			default:
				return next
			}
		}
		next++
	}
	return next
}

func (n *Node) maintain() {
	maintenance := time.NewTicker(n.o.MaintenanceInterval)
	defer maintenance.Stop()
	probes := time.NewTicker(n.o.Probe.scanInterval())
	defer probes.Stop()

	nextNeighbor := 0
	upkeep := func() {
		n.prunePaths()
		n.mu.Lock()
		n.expirePublicationsLocked(time.Now())
		nextNeighbor = n.dialNeighborsLocked(nextNeighbor)
		n.mu.Unlock()
	}
	upkeep()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-maintenance.C:
			upkeep()
		case <-probes.C:
			n.mu.Lock()
			n.probes.rescan = true
			n.dispatchProbesLocked()
			n.mu.Unlock()
		}
	}
}

// Establish a missing path before considering it for active traffic.
func (n *Node) probeAlternatePaths(s *session, failures int) {
	n.mu.Lock()
	if !n.usableLocked(s) {
		n.mu.Unlock()
		return
	}
	paths := n.peers[s.peer]
	elapsed := time.Since(paths.lastCanary)
	// Compare by division so very long configured intervals cannot overflow.
	due := elapsed >= 5*time.Second && elapsed/5 >= n.o.Probe.Interval
	if failures == 1 {
		due = elapsed >= n.o.Probe.Interval
	}
	if !due {
		n.mu.Unlock()
		return
	}
	paths.lastCanary = time.Now()
	start := paths.nextEndpoint
	var eps []Endpoint
	direct := n.modeLocked(s.peer).allowsDirect()
	if direct {
		eps = n.endpointsLocked(s.peer)
	}
	n.mu.Unlock()
	// A healthy inbound TCP connection already reaches this address. A
	// reverse dial to the sole listener in its family adds no alternate IP.
	tcpCandidates := 0
	if failures == 0 && s.kind == "tcp" && !s.outgoing {
		for _, ep := range eps {
			if ep.Network == "tcp" && ep.Address.Addr().BitLen() == s.endpoint.Addr().BitLen() {
				tcpCandidates++
			}
		}
	}
	var hadCandidate bool
	for i := range eps {
		index := (start + i) % len(eps)
		ep := eps[index]
		if tcpCandidates == 1 && ep.Network == "tcp" && ep.Address.Addr() == s.endpoint.Addr() {
			continue
		}
		if ep.Network == "udp" && n.transports[ep.Address.Addr().Is6()] == nil {
			continue
		}
		n.mu.Lock()
		matched, outgoing := n.directEndpointLocked(s.peer, ep)
		if matched != nil || failures == 0 && outgoing >= maxDirectPerFamily {
			n.mu.Unlock()
			continue
		}
		paths.nextEndpoint = (index + 1) % len(eps)
		n.mu.Unlock()
		hadCandidate = true
		_, err := n.dialEndpoint(n.ctx, s.peer, ep)
		if err == errOutboundEndpointDenied {
			continue
		}
		if ep.Network == "udp" && err != nil && !errors.Is(err, ErrPathPolicy) {
			n.retryUDPAfterRendezvous(s.peer, ep, eps)
		}
		break
	}
	if !hadCandidate && direct && s.kind == "relay" && n.preferredSession(s.peer, true) == nil {
		_, _ = n.dialDirect(n.ctx, s.peer)
	}
	if s.kind != "relay" && failures == 0 {
		return
	}
	n.mu.Lock()
	relays := 0
	if paths := n.peers[s.peer]; paths != nil {
		for _, s := range paths.sessions {
			if s.kind == "relay" && n.usableLocked(s) {
				relays++
			}
		}
	}
	n.mu.Unlock()
	if relays < 2 {
		_ = n.dialRelay(s.peer, 1)
	}
}

// Prefer a newly learned NAT mapping. The failed endpoint may also work once
// both peers have opened their UDP filters.
func (n *Node) retryUDPAfterRendezvous(peer PeerID, failed Endpoint, previous []Endpoint) {
	if !n.rendezvous(n.ctx, peer) {
		return
	}
	n.mu.Lock()
	updated := n.endpointsLocked(peer)
	n.mu.Unlock()
	var retry Endpoint
	for _, ep := range updated {
		if n.outboundUDP(ep) == nil {
			continue
		}
		if !slices.Contains(previous, ep) {
			retry = ep
			break
		}
		if ep == failed {
			retry = ep
		}
	}
	if retry.Valid() {
		_, _ = n.dialEndpoint(n.ctx, peer, retry)
	}
}

// RecommendedMTU returns a route MTU in bytes for the given inner address family.
// A nonpositive limit selects MaxIPSize. An established path also caps the
// result at its remote receive limit and QUIC budget, subject to the IPv6
// minimum. Without a path only local limits apply. An IPv6 limit below 1280 yields zero.
func (n *Node) RecommendedMTU(peer PeerID, ipv6 bool, limit int) int {
	if limit <= 0 || limit > n.o.MaxIPSize {
		limit = n.o.MaxIPSize
	}
	if ipv6 && limit < 1280 {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.preferredSessionLocked(n.peers[peer], false, nil); s != nil {
		limit = min(limit, s.remoteIPLimit)
		if b := int(s.budget.Load()); b > 0 {
			if ipv6 {
				b = max(1280, b)
			}
			limit = min(limit, b)
		}
	}
	return limit
}
