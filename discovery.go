package nebula

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

type advert struct {
	Observed  netip.AddrPort
	Record    statement
	Seen      int64 `json:",omitempty"`
	Inventory []string
}

type introduction struct {
	Endpoints []Endpoint
	Expires   time.Time
}

type cachedIntroduction struct {
	intro  introduction
	record statement
	cred   *x509.Certificate
	policy *topologyView
}
type observer struct {
	peer PeerID
	ipv6 bool
}
type observation struct {
	endpoint netip.AddrPort
	expires  time.Time
}

func (n *Node) advert(s *session) advert {
	p := n.policy.Load()
	a := advert{}
	if s != nil && s.q != nil {
		a.Observed = addrPort(s.q.RemoteAddr())
	}
	if !n.memberOf(p) {
		return a
	}
	eps := slices.Clone(n.o.AdvertiseEndpoints)
	eps = append(eps, p.members[n.id].Endpoints...)
	for _, pc := range []net.PacketConn{n.o.UDP4, n.o.UDP6} {
		if pc != nil {
			eps = append(eps, Endpoint{"udp", addrPort(pc.LocalAddr())})
		}
	}
	for _, l := range []net.Listener{n.o.TCP4, n.o.TCP6} {
		if l != nil {
			eps = append(eps, Endpoint{"tcp", addrPort(l.Addr())})
		}
	}
	now := time.Now()
	n.mu.Lock()
	if s != nil {
		if d := n.discovered[s.peer]; now.Before(d.Expires) {
			a.Seen = d.Expires.UnixNano()
		}
	}
	observedStart := len(eps)
	for observer, entry := range n.observations {
		if !now.Before(entry.expires) {
			delete(n.observations, observer)
			continue
		}
		eps = append(eps, Endpoint{Network: "udp", Address: entry.endpoint})
	}
	slices.SortFunc(eps[observedStart:], func(a, b Endpoint) int { return a.Address.Compare(b.Address) })
	for k, e := range n.events {
		if !now.Before(e.expires) {
			delete(n.events, k)
		} else if s != nil {
			a.Inventory = append(a.Inventory, k)
		}
	}
	n.mu.Unlock()
	// The inventory fits in one frame without a signed introduction.
	if !n.ready(p) {
		return a
	}
	var out []Endpoint
	for _, ep := range eps {
		if len(out) < 16 && ep.Valid() && !p.containsIP(ep.Address.Addr()) && !slices.Contains(out, ep) {
			out = append(out, ep)
		}
	}
	n.introMu.Lock()
	cache := &n.introCache
	signer := n.cred.Load().Object
	if cache.policy != p || cache.cred != signer.Leaf || now.Add(10*time.Second).After(cache.intro.Expires) || !slices.Equal(out, cache.intro.Endpoints) {
		intro := introduction{out, now.Add(time.Minute)}
		record, err := n.signStatement("introduction", intro, signer)
		if err == nil {
			*cache = cachedIntroduction{intro, record, signer.Leaf, p}
		} else {
			*cache = cachedIntroduction{}
		}
	}
	if s == nil || s.acknowledgedIntro.Load() != cache.intro.Expires.UnixNano() {
		a.Record = cache.record
	}
	n.introMu.Unlock()
	if s != nil && len(a.Inventory) > 0 {
		ids := a.Inventory
		a.Inventory = nil
		base, _ := json.Marshal(a)
		// Each lowercase SHA-256 ID costs two quotes and one comma.
		count := max(0, (maxControlFrame-len(base)-2)/67)
		if count < len(ids) {
			slices.Sort(ids)
			start := int((s.inventoryOffset.Add(uint64(count)) - uint64(count)) % uint64(len(ids)))
			for i := 0; i < count; i++ {
				a.Inventory = append(a.Inventory, ids[(start+i)%len(ids)])
			}
		} else {
			a.Inventory = ids
		}
	}
	return a
}

func (n *Node) learn(record statement) (PeerID, bool) {
	p := n.policy.Load()
	a, body, end, err := n.verifyStatement(n.ctx, "introduction", record, p)
	if err != nil || a == n.id {
		return a, false
	}
	var v introduction
	now := time.Now()
	if json.Unmarshal(body, &v) != nil || !now.Before(v.Expires) || v.Expires.After(now.Add(65*time.Second)) || len(v.Endpoints) > 16 {
		return a, false
	}
	for _, e := range v.Endpoints {
		if !e.Valid() || p.containsIP(e.Address.Addr()) {
			return a, false
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.policy.Load() != p {
		return a, false
	}
	if end.Before(v.Expires) {
		v.Expires = end
	}
	old := n.discovered[a]
	if old.Expires.After(v.Expires) {
		// Independently valid introductions may arrive out of order during rendezvous.
		return a, true
	}
	for _, e := range old.Endpoints {
		delete(n.introduced[e], a)
		if len(n.introduced[e]) == 0 {
			delete(n.introduced, e)
		}
	}
	for _, e := range v.Endpoints {
		if n.introduced[e] == nil {
			n.introduced[e] = make(map[PeerID]time.Time)
		}
		n.introduced[e][a] = v.Expires
	}
	n.discovered[a] = v
	return a, true
}

func (n *Node) observe(s *session, a advert) {
	p := n.policy.Load()
	if !n.memberOf(p) {
		return
	}
	s.acknowledgedIntro.Store(a.Seen)
	if len(a.Record) > 0 {
		n.learn(a.Record)
	}
	if s.q != nil && a.Observed.IsValid() && !p.containsIP(a.Observed.Addr()) {
		n.mu.Lock()
		if p == n.policy.Load() && n.usableLocked(s) {
			n.observations[observer{s.peer, a.Observed.Addr().Is6()}] = observation{a.Observed, time.Now().Add(time.Minute)}
		}
		n.mu.Unlock()
	}
	if len(a.Inventory) > maxEvents {
		return
	}
	for _, id := range a.Inventory {
		if len(id) != 64 {
			continue
		}
		n.mu.Lock()
		_, known := n.events[id]
		n.mu.Unlock()
		if !known {
			n.tryTask(n.backgroundSlots, func() {
				record, err := s.request(n.ctx, opGetEvent, []byte(id), pki.MaxDocument)
				if err == nil {
					n.acceptEvent(n.ctx, s, record)
				}
			})
		}
	}
}

type query struct {
	ID      string
	Target  PeerID
	Origin  statement
	Visited []PeerID
}

func (n *Node) lookup(ctx context.Context, target PeerID) bool {
	if !n.ready(n.policy.Load()) {
		return false
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	q := query{hex.EncodeToString(nonce[:]), target, n.advert(nil).Record, []PeerID{n.id}}
	_, found := n.relayQuery(ctx, q)
	return found
}

func (n *Node) relayQuery(ctx context.Context, q query) (statement, bool) {
	n.mu.Lock()
	ss := n.sessionListLocked()
	n.mu.Unlock()
	b, _ := json.Marshal(q)
	count := 0
	for _, s := range ss {
		if len(s.path) > 0 || slices.Contains(q.Visited, s.peer) || !n.usable(s) {
			continue
		}
		count++
		if count > 4 {
			break
		}
		out, err := s.request(ctx, opLookup, b, maxControlFrame)
		if err != nil {
			continue
		}
		var record statement
		if json.Unmarshal(out, &record) != nil {
			continue
		}
		if a, ok := n.learn(record); ok && a == q.Target {
			n.punch(a)
			return record, true
		}
	}
	return nil, false
}

func (n *Node) handleLookup(s *session, c net.Conn, b []byte) {
	var q query
	if json.Unmarshal(b, &q) != nil || len(q.ID) != 32 || len(q.Visited) == 0 || len(q.Visited) >= maxCircuitNodes || q.Visited[len(q.Visited)-1] != s.peer || slices.Contains(q.Visited, n.id) {
		return
	}
	origin, ok := n.learn(q.Origin)
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
	var record statement
	if q.Target == n.id {
		n.punch(origin)
		record = n.advert(nil).Record
	} else {
		q.Visited = append(q.Visited, n.id)
		var found bool
		record, found = n.relayQuery(n.ctx, q)
		if !found {
			return
		}
	}
	out, _ := json.Marshal(record)
	writeFrame(c, out)
}

func (n *Node) punch(a PeerID) {
	n.mu.Lock()
	mode := n.modeLocked(a)
	eps := n.endpointsLocked(a)
	n.mu.Unlock()
	if !mode.allowsDirect() {
		return
	}
	for _, ep := range eps {
		if transport := n.transports[ep.Address.Addr().Is6()]; transport != nil && ep.Network == "udp" && n.endpointAllowed("udp", ep.Address, false) {
			transport.WriteTo([]byte{0}, net.UDPAddrFromAddrPort(ep.Address))
		}
	}
}
