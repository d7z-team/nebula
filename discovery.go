package nebula

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"
)

type advert struct {
	Observed  netip.AddrPort `json:"observed"`
	Record    statement      `json:"record"`
	Seen      int64          `json:"seen,omitempty"`
	Inventory []string       `json:"inventory"`
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
	var learned []Endpoint
	if a := n.discovered[peer]; time.Now().Before(a.authorizedUntil) {
		learned = a.Endpoints
	}
	eps := slices.Concat(n.policy.Load().members[peer].Endpoints, learned)
	seen := make(map[Endpoint]bool, len(eps))
	return slices.DeleteFunc(eps, func(ep Endpoint) bool {
		if seen[ep] {
			return true
		}
		seen[ep] = true
		return false
	})
}

func (n *Node) observedEndpoints(now time.Time) []Endpoint {
	n.mu.Lock()
	eps := make([]Endpoint, 0, len(n.observations))
	for observer, entry := range n.observations {
		if now.Before(entry.expires) {
			eps = append(eps, Endpoint{"udp", entry.endpoint})
		} else {
			delete(n.observations, observer)
		}
	}
	n.mu.Unlock()
	slices.SortFunc(eps, func(a, b Endpoint) int { return a.Address.Compare(b.Address) })
	return eps
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
	if !n.o.HideEndpoints && s.q != nil && p.physicalEndpoint(Endpoint{"udp", a.Observed}) {
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
