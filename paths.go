package nebula

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"time"

	quic "github.com/quic-go/quic-go"
)

type attempt struct {
	done    chan struct{}
	err     error
	session *session
}

type directDial struct {
	peer     PeerID
	endpoint Endpoint
}

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

func (n *Node) selectSession(peer PeerID, direct bool) *session {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.selectSessionLocked(peer, direct)
}

func (n *Node) selectSessionLocked(peer PeerID, direct bool) *session {
	paths := n.peers[peer]
	if paths == nil {
		return nil
	}
	best := n.preferredSessionLocked(paths, direct, nil)
	if !direct {
		paths.active = best
	}
	return best
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
		if packet != nil && (!s.localIdentity.AllowsIP(packet.source) || !s.remoteIdentity.AllowsIP(packet.destination)) {
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
	if direct {
		return best
	}
	if activeCost > 0 && activeCost <= lowest+lowest/5 {
		return paths.active
	}
	return best
}

// ConnectPeer waits for a usable path to the member owning either overlay address.
// Canceling ctx ends this wait. The node owns the shared dial attempt.
func (n *Node) ConnectPeer(ctx context.Context, address netip.Addr) error {
	return n.connectPeer(ctx, n.policy.Load().owners[address])
}

func (n *Node) connectPeer(ctx context.Context, peer PeerID) error {
	if peer == (PeerID{}) || peer == n.id {
		return ErrPeerUnavailable
	}
	n.mu.Lock()
	if err := n.state.runningError(); err != nil {
		n.mu.Unlock()
		return err
	}
	if n.modeLocked(peer) == Blocked {
		n.mu.Unlock()
		return ErrPathPolicy
	}
	if n.selectSessionLocked(peer, false) != nil {
		n.mu.Unlock()
		return nil
	}
	a := n.attempts[peer]
	if a == nil {
		a = &attempt{done: make(chan struct{})}
		n.attempts[peer] = a
		n.wg.Go(func() {
			err := n.establishPath(peer)
			n.mu.Lock()
			a.err = err
			if err != nil {
				n.lastConnectError = err.Error()
			}
			delete(n.attempts, peer)
			close(a.done)
			n.mu.Unlock()
		})
	}
	n.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.ctx.Done():
		return ErrNodeClosed
	case <-a.done:
		return a.err
	}
}

func (n *Node) establishPath(peer PeerID) error {
	n.mu.Lock()
	mode := n.modeLocked(peer)
	n.mu.Unlock()
	if mode == Blocked {
		return ErrPathPolicy
	}
	var directErr, relayErr error
	if mode.allowsDirect() {
		_, directErr = n.dialDirect(n.ctx, peer)
		if directErr == nil {
			return nil
		}
	}
	if mode.allowsRelay() {
		for _, path := range n.routes(peer) {
			ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout*time.Duration(len(path)))
			_, err := n.startCircuit(ctx, path)
			cancel()
			if err == nil {
				return nil
			}
			relayErr = err
		}
	}
	return errors.Join(ErrPeerUnavailable, directErr, relayErr)
}

func (n *Node) endpointsLocked(peer PeerID) []Endpoint {
	eps := slices.Clone(n.policy.Load().members[peer].Endpoints)
	if a := n.discovered[peer]; time.Now().Before(a.Expires) {
		eps = append(eps, a.Endpoints...)
	}
	return eps
}

func (n *Node) dialDirect(ctx context.Context, peer PeerID) (*session, error) {
	n.mu.Lock()
	eps := n.endpointsLocked(peer)
	mode := n.modeLocked(peer)
	n.mu.Unlock()
	if !mode.allowsDirect() {
		return nil, ErrPathPolicy
	}
	var last error
	tried := make(map[Endpoint]bool)
	for pass := 0; pass < 2; pass++ {
		for _, kind := range []string{"udp", "tcp"} {
			for _, e := range eps {
				if e.Network != kind || tried[e] {
					continue
				}
				tried[e] = true
				s, err := n.dialEndpoint(ctx, peer, e)
				if err == nil {
					return s, nil
				}
				last = err
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
		}
		if pass == 0 {
			if n.lookup(ctx, peer) {
				// Both peers have had a chance to open their UDP filters.
				maps.DeleteFunc(tried, func(e Endpoint, _ bool) bool { return e.Network == "udp" })
			}
			n.mu.Lock()
			eps = n.endpointsLocked(peer)
			n.mu.Unlock()
		}
	}
	return nil, errors.Join(ErrPeerUnavailable, last)
}

func (n *Node) dialEndpoint(ctx context.Context, peer PeerID, e Endpoint) (*session, error) {
	n.mu.Lock()
	mode := n.modeLocked(peer)
	if !mode.allowsDirect() || !n.endpointAllowedLocked(e.Network, e.Address, false) {
		n.mu.Unlock()
		return nil, ErrPathPolicy
	}
	if paths := n.peers[peer]; paths != nil {
		for _, s := range paths.sessions {
			if s.matchesTransport(e.Network, e.Address) && !s.closed.Load() && n.sessionAllowedLocked(s) {
				n.mu.Unlock()
				return s, nil
			}
		}
	}
	key := directDial{peer, e}
	if pending := n.directDials[key]; pending != nil {
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			return pending.session, pending.err
		}
	}
	a := &attempt{done: make(chan struct{})}
	n.directDials[key] = a
	n.mu.Unlock()
	dctx, cancel := context.WithTimeout(ctx, n.o.DialTimeout)
	defer cancel()
	if e.Network == "udp" {
		if transport := n.transports[e.Address.Addr().Is6()]; transport == nil {
			a.err = ErrPeerUnavailable
		} else {
			var q *quic.Conn
			q, a.err = transport.Dial(dctx, net.UDPAddrFromAddrPort(e.Address), n.tlsConfig(peer, false), n.quicConfig())
			if a.err == nil {
				a.session, a.err = n.attachQUIC(q, peer)
			}
		}
	} else {
		var c net.Conn
		network := "tcp4"
		if e.Address.Addr().Is6() {
			network = "tcp6"
		}
		c, a.err = n.o.DialTCP(dctx, network, e.Address.String())
		if a.err == nil {
			a.session, a.err = n.attachTLS(dctx, c, peer, nil, true, nil)
		}
	}
	if a.err != nil {
		n.dialFailures.Add(1)
	}
	n.mu.Lock()
	delete(n.directDials, key)
	close(a.done)
	n.mu.Unlock()
	return a.session, a.err
}

func (n *Node) maintain() {
	tick := time.NewTicker(n.o.Interval)
	defer tick.Stop()
	for {
		n.prunePaths()
		n.mu.Lock()
		ss := n.sessionListLocked()
		var targets []PeerID
		p := n.policy.Load()
		if n.ready(p) {
			targets = append(targets, p.members[n.id].Links...)
		}
		n.mu.Unlock()
		for _, a := range targets {
			if n.selectSession(a, false) == nil {
				n.tryTask(n.backgroundSlots, func() { _ = n.connectPeer(n.ctx, a) })
			}
		}
		for _, s := range ss {
			n.tryTask(n.backgroundSlots, func() { n.probeSession(s) })
		}
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (n *Node) probeSession(s *session) {
	if !s.probing.CompareAndSwap(false, true) {
		return
	}
	defer s.probing.Store(false)
	if time.Since(s.lastProbe) < n.o.Interval*3/4 {
		return
	}
	s.lastProbe = time.Now()
	s.refreshBudget()
	var nonce [8]byte
	rand.Read(nonce[:])
	at := time.Now()
	b, err := s.request(n.ctx, opPing, nonce[:], 8)
	rtt := time.Since(at)
	s.healthMu.Lock()
	if s.q != nil {
		q := s.q.ConnectionStats()
		if q.PacketsSent > s.sent {
			var lost uint64
			if q.PacketsLost > s.lost {
				lost = q.PacketsLost - s.lost
			}
			sample := min(1.0, float64(lost)/float64(q.PacketsSent-s.sent))
			s.loss = (s.loss + sample) / 2
		}
		s.sent, s.lost = q.PacketsSent, q.PacketsLost
	}
	if err != nil || !slices.Equal(b, nonce[:]) {
		s.failures++
	} else {
		s.failures = 0
		if s.rtt != 0 {
			s.jitter = (3*s.jitter + (rtt - s.rtt).Abs()) / 4
			s.rtt = (3*s.rtt + rtt) / 4
		} else {
			s.rtt = rtt
		}
	}
	failures := s.failures
	s.healthMu.Unlock()
	if failures >= 3 {
		s.close()
		return
	}
	if failures == 0 {
		ad := n.advert(s)
		body, _ := json.Marshal(ad)
		b, err = s.request(n.ctx, opHello, body, maxControlFrame)
		var remote advert
		if err == nil && json.Unmarshal(b, &remote) == nil {
			n.observe(s, remote)
		}
	}
	n.probeAlternatePaths(s, failures)
}

// Establish a missing path before considering it for active traffic.
func (n *Node) probeAlternatePaths(s *session, failures int) {
	n.mu.Lock()
	paths := n.peers[s.peer]
	interval := max(5*n.o.Interval, 5*time.Second)
	if failures == 1 {
		interval = n.o.Interval
	}
	if paths == nil || time.Since(paths.lastCanary) < interval {
		n.mu.Unlock()
		return
	}
	paths.lastCanary = time.Now()
	var candidate Endpoint
	direct := n.modeLocked(s.peer).allowsDirect()
	if direct {
		eps := n.endpointsLocked(s.peer)
		for i := range eps {
			index := (paths.nextEndpoint + i) % len(eps)
			ep := eps[index]
			if ep.Network == "udp" && n.transports[ep.Address.Addr().Is6()] == nil {
				continue
			}
			if !slices.ContainsFunc(paths.sessions, func(other *session) bool {
				return other.matchesTransport(ep.Network, ep.Address) && !other.closed.Load()
			}) {
				candidate = ep
				paths.nextEndpoint = (index + 1) % len(eps)
				break
			}
		}
	}
	n.mu.Unlock()
	if candidate.Valid() {
		if _, err := n.dialEndpoint(n.ctx, s.peer, candidate); err != nil && candidate.Network == "udp" && n.lookup(n.ctx, s.peer) {
			_, _ = n.dialEndpoint(n.ctx, s.peer, candidate)
		}
	} else if direct && s.kind == "relay" && n.selectSession(s.peer, true) == nil {
		_, _ = n.dialDirect(n.ctx, s.peer)
	}
	if s.kind != "relay" && failures == 0 {
		return
	}
	for _, path := range n.routes(s.peer) {
		if !n.hasCircuit(s.peer, path) {
			ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout*time.Duration(len(path)))
			n.startCircuit(ctx, path)
			cancel()
			break
		}
	}
}

func (n *Node) hasCircuit(peer PeerID, route []PeerID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	paths := n.peers[peer]
	return paths != nil && slices.ContainsFunc(paths.sessions, func(s *session) bool {
		return !s.closed.Load() && s.kind == "relay" && slices.Equal(s.path, route)
	})
}

// RecommendedMTU returns a route MTU in bytes for the given inner address family.
// A nonpositive limit selects MaxIPSize. With no known QUIC budget it returns
// the capped limit. An IPv6 limit below 1280 yields zero.
func (n *Node) RecommendedMTU(address netip.Addr, ipv6 bool, limit int) int {
	peer := n.policy.Load().owners[address]
	if limit <= 0 || limit > n.o.MaxIPSize {
		limit = n.o.MaxIPSize
	}
	if ipv6 && limit < 1280 {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.preferredSessionLocked(n.peers[peer], false, nil); s != nil && s.q != nil {
		if b := int(s.budget.Load()); b > 0 {
			if ipv6 {
				b = max(1280, b)
			}
			limit = min(limit, b)
		}
	}
	return limit
}
