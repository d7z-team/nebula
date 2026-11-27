package nebula

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"time"
)

type advert struct {
	Observed netip.AddrPort     `json:"observed"`
	Record   signedIntroduction `json:"record"`
	Seen     int64              `json:"seen,omitempty"`
}

type observer struct {
	peer PeerID
	ipv6 bool
}
type observation struct {
	endpoint netip.AddrPort
	expires  time.Time
}

func (n *Node) advert(s *session) (advert, time.Time) {
	p := n.policy.Load()
	var a advert
	if s.q != nil {
		a.Observed = s.remoteEndpoint()
	}
	if !n.memberOf(p) {
		return a, time.Time{}
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
	return a, intro.Expires
}

// exchangeAdvert schedules renewal from the expiry of the actual signed record.
// Different paths may have last received different versions of the record.
func (n *Node) exchangeAdvert(s *session) {
	a, expires := n.advert(s)
	body, _ := json.Marshal(a)
	reply, err := s.request(s.ctx, opHello, body, maxControlFrame)
	var remote advert
	var next time.Time
	if err == nil && json.Unmarshal(reply, &remote) == nil {
		n.receiveAdvert(s, remote)
		next = expires.Add(-introductionRefreshLead)
	}
	now := time.Now()
	if !next.After(now) {
		next = now.Add(n.o.Probe.scanInterval())
	}
	n.mu.Lock()
	s.nextHello = next
	n.mu.Unlock()
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

func (n *Node) receiveAdvert(s *session, a advert) {
	p := n.policy.Load()
	if !n.memberOf(p) {
		return
	}
	s.acknowledgedIntro.Store(a.Seen)
	if len(a.Record) > 0 {
		n.learnIntroduction(n.ctx, a.Record, nil)
	}
	if !n.o.Transport.HideEndpoints && s.q != nil && n.mayAdvertise(p, EndpointCandidate{Endpoint{"udp", a.Observed}, EndpointFromObservation, s.peer}) {
		n.mu.Lock()
		if p == n.policy.Load() && n.usableLocked(s) {
			n.observations[observer{s.peer, a.Observed.Addr().Is6()}] = observation{a.Observed, time.Now().Add(time.Minute)}
		}
		n.mu.Unlock()
	}
}

func (n *Node) rendezvous(ctx context.Context, target PeerID) bool {
	ctx, cancel := context.WithTimeout(ctx, n.o.DialTimeout)
	defer cancel()
	if len(n.runLookup(ctx, netip.Addr{}, &target)) > 0 {
		n.punch(target)
		return true
	}
	return false
}

// outboundUDP selects a usable socket for an active UDP rendezvous candidate.
func (n *Node) outboundUDP(ep Endpoint) *udpTransport {
	transport := n.transports[ep.Address.Addr().Is6()]
	if ep.Network != "udp" || transport == nil || !n.allowOutbound(ep) || !n.endpointAllowed("udp", ep.Address, false) {
		return nil
	}
	return transport
}

func (n *Node) punch(peer PeerID) {
	n.mu.Lock()
	mode := n.modeLocked(peer)
	eps := n.endpointsLocked(peer)
	n.mu.Unlock()
	if !mode.allowsDirect() {
		return
	}
	for _, ep := range eps {
		if transport := n.outboundUDP(ep); transport != nil {
			_, _ = transport.WriteTo([]byte{0}, net.UDPAddrFromAddrPort(ep.Address))
		}
	}
}
