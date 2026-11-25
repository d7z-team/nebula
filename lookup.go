package nebula

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// IPMatch identifies the owner of a primary address or a gateway advertising Prefix.
// Endpoints are optional physical connection hints. A peer with no advertised
// endpoints may be reached through an authorized circuit or an existing session.
// ValidUntil bounds the signed discovery information.
type IPMatch struct {
	Peer       PeerID
	Prefix     netip.Prefix
	Endpoints  []Endpoint
	ValidUntil time.Time
}

type query struct {
	ID      string        `json:"id"`
	IP      netip.Addr    `json:"ip"`
	Target  *PeerID       `json:"target,omitempty"` // Set only for live NAT rendezvous.
	Origin  statement     `json:"origin"`
	Visited []PeerID      `json:"visited"`
	Budget  time.Duration `json:"budget"`
}

type ipResolution struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	deadline time.Time
	answered map[PeerID]bool
	err      error
}

const maxLookupAnswers = 64

// ResolveIP looks up a primary address or a downstream unicast destination over
// existing neighbors. It returns current signed matches, most specific first.
// Any cache hit returns immediately, even if another gateway advertises a more
// specific prefix. Network results can also be partial. Discovery does not dial
// peers or authorize downstream traffic.
func (n *Node) ResolveIP(ctx context.Context, ip netip.Addr) ([]IPMatch, error) {
	return n.resolveIP(ctx, ip, false)
}

// RefreshIP queries existing neighbors for a downstream unicast address even
// when a cached route matches. It returns currently valid matches seen in the
// bounded search, most specific first, including this node's own advertisement.
// Neighbors may answer from their caches. Missing replies do not withdraw routes.
func (n *Node) RefreshIP(ctx context.Context, ip netip.Addr) ([]IPMatch, error) {
	return n.resolveIP(ctx, ip, true)
}

func (n *Node) resolveIP(ctx context.Context, ip netip.Addr, refresh bool) ([]IPMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	err := n.state.runningError()
	p := n.policy.Load()
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !n.ready(p) {
		return nil, ErrPathPolicy
	}
	if !p.discoveryAddress(ip) || refresh && p.cluster.Subnet(ip).IsValid() {
		return nil, ErrInvalidPacketAddress
	}
	if !refresh {
		if hits := n.ipMatches(ip, nil); len(hits) > 0 {
			return hits, nil
		}
	}
	until := n.exchangeDeadline(ctx)
	for {
		round, err := n.awaitResolution(ctx, ip, until)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n.ctx.Err() != nil {
			return nil, ErrNodeClosed
		}
		if round == nil {
			return nil, err
		}
		var peers map[PeerID]bool
		if refresh {
			peers = round.answered
		}
		if hits := n.ipMatches(ip, peers); len(hits) > 0 {
			return hits, nil
		}
		// A later caller can use its remaining budget after a shorter shared round times out.
		if err == context.DeadlineExceeded && round.deadline.Before(until) && time.Now().Before(until) {
			continue
		}
		if err == nil {
			err = ErrPeerUnavailable
		}
		return nil, err
	}
}

func (n *Node) ipMatches(ip netip.Addr, peers map[PeerID]bool) []IPMatch {
	answers := n.cachedAnswers(query{IP: ip}, peers)
	out := make([]IPMatch, len(answers))
	for i, answer := range answers {
		out[i] = answer.match
		out[i].Endpoints = slices.Clone(answer.match.Endpoints)
	}
	slices.SortFunc(out, func(a, b IPMatch) int {
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return b.Prefix.Bits() - a.Prefix.Bits()
		}
		return comparePeer(a.Peer, b.Peer)
	})
	return out
}

func (n *Node) awaitResolution(ctx context.Context, ip netip.Addr, until time.Time) (*ipResolution, error) {
	n.mu.Lock()
	if err := n.state.runningError(); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	call := n.resolutions[ip]
	if call == nil {
		search, cancel := context.WithDeadline(n.ctx, until)
		call = &ipResolution{done: make(chan struct{}), cancel: cancel, deadline: until}
		n.resolutions[ip] = call
		n.wg.Go(func() {
			call.answered = n.runLookup(search, ip, nil)
			n.mu.Lock()
			call.err = search.Err()
			// Socket deadlines can wake the last branch before the context timer runs.
			if call.err == nil && !time.Now().Before(until) {
				call.err = context.DeadlineExceeded
			}
			if n.resolutions[ip] == call {
				delete(n.resolutions, ip)
			}
			close(call.done)
			n.mu.Unlock()
			cancel()
		})
	}
	call.waiters++
	n.mu.Unlock()
	select {
	case <-ctx.Done():
		n.mu.Lock()
		call.waiters--
		if call.waiters == 0 && n.resolutions[ip] == call {
			delete(n.resolutions, ip)
			call.cancel()
		}
		n.mu.Unlock()
		return nil, ctx.Err()
	case <-n.ctx.Done():
		return nil, ErrNodeClosed
	case <-call.done:
		return call, call.err
	}
}

func (p *topologyView) discoveryAddress(ip netip.Addr) bool {
	if ip.Zone() != "" || !isTunnelUnicast(ip) || p.cluster.InAnycastPool(ip) {
		return false
	}
	return ip != p.directedBroadcast
}

func (i introduction) match(q query, id PeerID, clusterIP bool) netip.Prefix {
	if q.Target != nil && *q.Target != id {
		return netip.Prefix{}
	}
	if q.IP == id.IPv4() || q.IP == id.IPv6() {
		return netip.PrefixFrom(q.IP, q.IP.BitLen())
	}
	if clusterIP || q.Target != nil {
		return netip.Prefix{}
	}
	return longestPrefix(q.IP, i.RoutedPrefixes)
}

func longestPrefix(ip netip.Addr, prefixes []netip.Prefix) netip.Prefix {
	var best netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Contains(ip) && prefix.Bits() > best.Bits() {
			best = prefix
		}
	}
	return best
}

type lookupAnswer struct {
	match  IPMatch
	record statement
}

// A nil peer set accepts all matches. A refresh reads only records from
// peers that answered its round.
func (n *Node) cachedAnswers(q query, peers map[PeerID]bool) []lookupAnswer {
	// Live rendezvous requires a reply from the target itself.
	if q.Target != nil && *q.Target != n.id {
		return nil
	}
	p := n.policy.Load()
	primary := p.cluster.Subnet(q.IP).IsValid()
	var local cachedIntroduction
	localCandidate := q.IP == n.id.IPv4() || q.IP == n.id.IPv6() || !primary && len(p.members[n.id].RoutedPrefixes) > 0
	if localCandidate && (peers == nil || peers[n.id]) {
		local = n.localIntroduction(p)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.ready(p) {
		return nil
	}
	now := time.Now()
	var answers []lookupAnswer
	add := func(id PeerID, intro learnedIntroduction) {
		if len(intro.record) == 0 || !now.Before(intro.authorizedUntil) || n.modes[id] == Blocked {
			return
		}
		if prefix := intro.match(q, id, primary); prefix.IsValid() {
			answers = append(answers, lookupAnswer{IPMatch{id, prefix, intro.Endpoints, intro.authorizedUntil}, intro.record})
		}
	}
	cred := n.cred.Load()
	if local.cred == cred.Object.Leaf {
		end := local.Expires
		if cred.until.Before(end) {
			end = cred.until
		}
		add(n.id, learnedIntroduction{introduction: local.introduction, record: local.record, authorizedUntil: end})
	}
	switch {
	case q.Target != nil:
		return answers
	case peers != nil:
		for id := range peers {
			if intro, ok := n.discovered[id]; ok {
				add(id, intro)
			}
		}
	case primary:
		if owner, ok := n.discoveredOwners[q.IP]; ok {
			add(owner, n.discovered[owner])
		}
	default:
		for id, intro := range n.discovered {
			add(id, intro)
		}
	}
	return answers
}

func (n *Node) runLookup(ctx context.Context, ip netip.Addr, target *PeerID) map[PeerID]bool {
	origin := n.localIntroduction(n.policy.Load()).record
	if len(origin) == 0 || ctx.Err() != nil {
		return map[PeerID]bool{}
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	q := query{ID: hex.EncodeToString(nonce[:]), IP: ip, Target: target, Origin: origin, Visited: []PeerID{n.id}}
	return n.forwardLookup(ctx, q, nil)
}

// Each branch streams bounded, individual CMS records so one large chain
// cannot crowd other gateways out of the same control frame.
func (n *Node) forwardLookup(ctx context.Context, q query, yield func(statement) bool) map[PeerID]bool {
	clusterIP := n.Cluster().Subnet(q.IP).IsValid()
	seen := make(map[PeerID]bool)
	send := func(id PeerID, record statement) bool {
		if seen[id] {
			return true
		}
		seen[id] = true
		return (yield == nil || yield(record)) && !clusterIP && len(seen) < maxLookupAnswers
	}
	// At the origin, only our own advertisement can answer for a downstream
	// prefix without a neighbor reply. Other cached routes remain available to ResolveIP.
	var cachedPeers map[PeerID]bool
	if yield == nil && !clusterIP {
		cachedPeers = map[PeerID]bool{n.id: true}
	}
	for _, answer := range n.cachedAnswers(q, cachedPeers) {
		if !send(answer.match.Peer, answer.record) {
			return seen
		}
	}
	if ctx.Err() != nil || len(q.Visited) >= maxCircuitNodes {
		return seen
	}
	n.mu.Lock()
	var neighbors []*session
	for id, paths := range n.peers {
		if slices.Contains(q.Visited, id) {
			continue
		}
		if s := n.preferredSessionLocked(paths, true, nil); s != nil {
			neighbors = append(neighbors, s)
			if q.Target != nil && id == *q.Target {
				neighbors[0], neighbors[len(neighbors)-1] = s, neighbors[0]
			}
		}
	}
	n.mu.Unlock()
	if len(neighbors) == 0 {
		return seen
	}
	ctx, cancel := context.WithCancel(ctx)
	jobs := make(chan *session, len(neighbors))
	for _, s := range neighbors {
		jobs <- s
	}
	close(jobs)
	results := make(chan statement)
	var workers sync.WaitGroup
	for range min(4, len(neighbors)) {
		workers.Go(func() {
			for s := range jobs {
				if ctx.Err() != nil {
					return
				}
				n.queryNeighbor(ctx, s, q, results)
			}
		})
	}
	go func() { workers.Wait(); close(results) }()
	for record := range results {
		if ctx.Err() != nil {
			continue
		}
		id, ok := n.learnIntroduction(ctx, record, &q)
		if !ok {
			continue
		}
		n.mu.Lock()
		i := n.discovered[id]
		n.mu.Unlock()
		if prefix := i.match(q, id, clusterIP); prefix.IsValid() && time.Now().Before(i.authorizedUntil) {
			if !send(id, i.record) {
				cancel()
			}
		}
	}
	cancel()
	return seen
}

func (n *Node) queryNeighbor(ctx context.Context, s *session, q query, results chan<- statement) {
	if !n.usable(s) {
		return
	}
	deadline, _ := ctx.Deadline()
	q.Budget = time.Until(deadline)
	body, err := json.Marshal(q)
	if err != nil || len(body) > maxControlFrame || q.Budget <= 0 {
		return
	}
	c, err := s.openRequest(ctx, opLookup, body)
	if err != nil {
		return
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	for range maxLookupAnswers {
		record, err := readFrame(c, maxControlFrame)
		if err != nil || len(record) == 0 {
			return
		}
		select {
		case results <- record:
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) handleLookup(s *session, c net.Conn, b []byte) {
	var q query
	if json.Unmarshal(b, &q) != nil || len(q.ID) != 32 || len(q.Visited) == 0 || len(q.Visited) >= maxCircuitNodes || q.Visited[len(q.Visited)-1] != s.peer || slices.Contains(q.Visited, n.id) || q.Budget <= 0 || !n.policy.Load().discoveryAddress(q.IP) {
		return
	}
	if q.Target != nil && q.IP != q.Target.IPv4() {
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, min(q.Budget, n.o.DialTimeout))
	defer cancel()
	origin, ok := n.learnIntroduction(ctx, q.Origin, nil)
	if !ok || origin != q.Visited[0] {
		return
	}
	n.mu.Lock()
	now := time.Now()
	for k, t := range n.queries {
		if !now.Before(t) {
			delete(n.queries, k)
		}
	}
	if _, seen := n.queries[q.ID]; seen || len(n.queries) >= 1024 {
		n.mu.Unlock()
		return
	}
	n.queries[q.ID] = now.Add(time.Minute)
	n.mu.Unlock()
	// A probe to the origin would disclose our physical source address even
	// when the signed introduction contains no endpoints.
	if q.Target != nil && *q.Target == n.id && !n.o.Transport.HideEndpoints {
		n.punch(origin)
	}
	q.Visited = append(q.Visited, n.id)
	n.forwardLookup(ctx, q, func(record statement) bool { return writeFrame(c, record) == nil })
}
