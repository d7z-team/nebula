package nebula

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

type advert struct {
	Observed  netip.AddrPort `json:"observed"`
	Record    statement      `json:"record"`
	Seen      int64          `json:"seen,omitempty"`
	Inventory []string       `json:"inventory"`
}

type introduction struct {
	Endpoints      []Endpoint     `json:"endpoints"`
	RoutedPrefixes []netip.Prefix `json:"routedPrefixes,omitempty"`
	Expires        time.Time      `json:"expires"`
}

type learnedIntroduction struct {
	introduction
	record          statement
	authorizedUntil time.Time
}

type cachedIntroduction struct {
	introduction
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
	var a advert
	if s.q != nil {
		a.Observed = s.remoteEndpoint()
	}
	if !n.memberOf(p) {
		return a
	}
	now := time.Now()
	n.mu.Lock()
	if d := n.discovered[s.peer]; now.Before(d.authorizedUntil) {
		a.Seen = d.Expires.UnixNano()
	}
	n.mu.Unlock()
	intro := n.localIntroduction(p)
	if s.acknowledgedIntro.Load() != intro.Expires.UnixNano() {
		a.Record = intro.record
	}
	n.addPublicationInventory(s, &a)
	return a
}

func (n *Node) endpointsLocked(peer PeerID) []Endpoint {
	eps := slices.Clone(n.policy.Load().members[peer].Endpoints)
	if a := n.discovered[peer]; time.Now().Before(a.authorizedUntil) {
		eps = append(eps, a.Endpoints...)
	}
	return eps
}

func (n *Node) introductionEndpoints(p *topologyView, now time.Time) []Endpoint {
	if n.o.HideEndpoints {
		return nil
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
	n.mu.Lock()
	observedStart := len(eps)
	for observer, entry := range n.observations {
		if !now.Before(entry.expires) {
			delete(n.observations, observer)
			continue
		}
		eps = append(eps, Endpoint{Network: "udp", Address: entry.endpoint})
	}
	n.mu.Unlock()
	slices.SortFunc(eps[observedStart:], func(a, b Endpoint) int { return a.Address.Compare(b.Address) })
	var out []Endpoint
	for _, ep := range eps {
		if len(out) < 16 && ep.Valid() && !p.isOverlayAddress(ep.Address.Addr()) && !slices.Contains(out, ep) {
			out = append(out, ep)
		}
	}
	return out
}

func (n *Node) localIntroduction(p *topologyView) cachedIntroduction {
	if !n.ready(p) {
		return cachedIntroduction{}
	}
	now := time.Now()
	endpoints := n.introductionEndpoints(p, now)
	n.introMu.Lock()
	defer n.introMu.Unlock()
	cache := &n.introCache
	signer := n.cred.Load().Object
	if cache.policy != p || cache.cred != signer.Leaf || now.Add(10*time.Second).After(cache.Expires) || !slices.Equal(endpoints, cache.Endpoints) {
		intro := introduction{Endpoints: endpoints, Expires: now.Add(time.Minute)}
		scope, _, err := pki.CertificateScope(signer.Leaf)
		if err != nil {
			return cachedIntroduction{}
		}
		for _, active := range p.members[n.id].RoutedPrefixes {
			for _, grant := range scope.RoutedPrefixes {
				if !active.Overlaps(grant) {
					continue
				}
				prefix := active
				if grant.Bits() > active.Bits() {
					prefix = grant
				}
				if !slices.Contains(intro.RoutedPrefixes, prefix) {
					intro.RoutedPrefixes = append(intro.RoutedPrefixes, prefix)
				}
			}
		}
		record, err := n.signStatement("introduction", intro, signer)
		if err == nil {
			*cache = cachedIntroduction{intro, record, signer.Leaf, p}
		} else {
			*cache = cachedIntroduction{}
		}
	}
	return *cache
}

func (n *Node) learnIntroduction(ctx context.Context, record statement, reply *query) (PeerID, bool) {
	p := n.policy.Load()
	identity, body, end, err := n.verifyStatement(ctx, "introduction", record, p)
	a := identity.ID
	if err != nil || a == n.id {
		return a, false
	}
	var v introduction
	now := time.Now()
	if json.Unmarshal(body, &v) != nil || !now.Before(v.Expires) || v.Expires.After(now.Add(65*time.Second)) || len(v.Endpoints) > 16 {
		return a, false
	}
	if reply != nil && !v.match(*reply, a, p.cluster.Subnet(reply.IP).IsValid()).IsValid() {
		return a, false
	}
	for _, prefix := range v.RoutedPrefixes {
		if !identity.AllowsRoute(prefix) {
			return a, false
		}
	}
	for _, e := range v.Endpoints {
		if !e.Valid() || p.isOverlayAddress(e.Address.Addr()) {
			return a, false
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.policy.Load() != p || n.modes[a] == Blocked || n.conflictingOwnerLocked(a) {
		return a, false
	}
	if v.Expires.Before(end) {
		end = v.Expires
	}
	old := n.discovered[a]
	if now.Before(old.authorizedUntil) && old.Expires.After(v.Expires) {
		// Independently valid introductions may arrive out of order during rendezvous.
		return a, true
	}
	n.forgetIntroductionLocked(a, old)
	for _, e := range v.Endpoints {
		if n.introduced[e] == nil {
			n.introduced[e] = make(map[PeerID]time.Time)
		}
		n.introduced[e][a] = end
	}
	n.discovered[a] = learnedIntroduction{v, record, end}
	n.discoveredOwners[a.IPv4()] = a
	n.discoveredOwners[a.IPv6()] = a
	return a, true
}

// Remove the derived indexes together when replacing or expiring a signed introduction.
func (n *Node) forgetIntroductionLocked(peer PeerID, old learnedIntroduction) {
	delete(n.discovered, peer)
	for _, addr := range []netip.Addr{peer.IPv4(), peer.IPv6()} {
		if n.discoveredOwners[addr] == peer {
			delete(n.discoveredOwners, addr)
		}
	}
	for _, e := range old.Endpoints {
		delete(n.introduced[e], peer)
		if len(n.introduced[e]) == 0 {
			delete(n.introduced, e)
		}
	}
}

func (n *Node) receiveAdvert(s *session, a advert) {
	p := n.policy.Load()
	if !n.memberOf(p) {
		return
	}
	s.acknowledgedIntro.Store(a.Seen)
	if len(a.Record) > 0 {
		n.learnIntroduction(n.ctx, a.Record, nil)
	}
	if !n.o.HideEndpoints && s.q != nil && a.Observed.IsValid() && !p.isOverlayAddress(a.Observed.Addr()) {
		n.mu.Lock()
		if p == n.policy.Load() && n.usableLocked(s) {
			n.observations[observer{s.peer, a.Observed.Addr().Is6()}] = observation{a.Observed, time.Now().Add(time.Minute)}
		}
		n.mu.Unlock()
	}
	n.fetchMissingPublications(s, a.Inventory)
}

func (n *Node) rendezvous(ctx context.Context, target PeerID) bool {
	ctx, cancel := context.WithTimeout(ctx, n.o.DialTimeout)
	defer cancel()
	if n.runLookup(ctx, target.IPv4(), &target) {
		n.punch(target)
		return true
	}
	return false
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
