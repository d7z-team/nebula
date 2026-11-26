package nebula

import (
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

// IPObservation describes a local fact about an address. Unknown fields are zero.
// Source distinguishes topology, session, introduction and conflict.
// LastSeen on a signed introduction is a local receipt time, not a liveness check.
type IPObservation struct {
	Addresses               pki.Addresses
	Peer                    PeerID
	Instance                InstanceID
	Match                   string // primary, anycast or routed
	Prefix                  netip.Prefix
	Source, Decision        string
	NodeSHA256, GrantSHA256 string
	Usage                   x509.ExtKeyUsage
	FirstSeen, LastSeen     time.Time
	Transport               string
	Circuit                 []PeerID       // End-to-end relay path observed on this node.
	Advertised              []Endpoint     // Endpoints disclosed in a verified introduction.
	Endpoint                netip.AddrPort // Locally observed direct path, when available.
}

const (
	evidenceLifetime = 10 * time.Minute
	sessionSource    = "session"
	rejectedInstance = "instance conflict"
)

type claimObservation struct {
	IPObservation
	routes []netip.Prefix
}

func (w instanceClaim) observation(peer PeerID, source, decision string) IPObservation {
	node, grant := sha256.Sum256(w.node.Raw), sha256.Sum256(w.chain[0].Raw)
	return IPObservation{Addresses: w.addresses, Peer: peer, Instance: w.instance, NodeSHA256: hex.EncodeToString(node[:]), GrantSHA256: hex.EncodeToString(grant[:]), Usage: w.usage, Source: source, Decision: decision}
}

func (s *session) observation(decision string) IPObservation {
	w := s.handshakeClaim()
	o := w.observation(s.peer, sessionSource, decision)
	o.Circuit = s.path
	o.Transport, o.Endpoint = s.kind, s.remoteEndpoint()
	o.FirstSeen, o.LastSeen = s.registeredAt, s.lastAlive
	return o
}

func (intro *learnedIntroduction) observation(peer PeerID, decision string) IPObservation {
	return IPObservation{
		Addresses: intro.Addresses, Peer: peer, Instance: intro.Instance, NodeSHA256: hex.EncodeToString(intro.nodeHash[:]), GrantSHA256: hex.EncodeToString(intro.grantHash[:]),
		Usage: x509.ExtKeyUsageCodeSigning, Source: "introduction", Decision: decision,
		FirstSeen: intro.firstSeen, LastSeen: intro.lastSeen, Advertised: intro.Endpoints,
	}
}

// Only the compact history expires. A live admission hold is independent of it.
func (n *Node) recordObservationLocked(o IPObservation, routes []netip.Prefix) {
	now := time.Now()
	n.evidence = slices.DeleteFunc(n.evidence, func(e claimObservation) bool { return now.Sub(e.LastSeen) > evidenceLifetime })
	for i := range n.evidence {
		e := &n.evidence[i]
		if e.Peer == o.Peer && e.Instance == o.Instance && e.NodeSHA256 == o.NodeSHA256 && e.GrantSHA256 == o.GrantSHA256 && e.Usage == o.Usage && e.Source == o.Source && e.Decision == o.Decision {
			o.FirstSeen = e.FirstSeen
			n.evidence = slices.Delete(n.evidence, i, i+1)
			break
		}
	}
	if o.FirstSeen.IsZero() {
		o.FirstSeen = now
	}
	o.LastSeen = now
	if len(n.evidence) >= 256 {
		n.evidence = slices.Delete(n.evidence, 0, 1)
	}
	n.evidence = append(n.evidence, claimObservation{o, slices.Clone(routes)})
}

// InspectIP returns a local snapshot of configured grants, verified
// introductions, paths and recent rejected claims for an overlay address.
// It performs no network I/O and does not authorize a discovered route.
func (n *Node) InspectIP(ip netip.Addr) []IPObservation {
	if !ip.IsValid() {
		return nil
	}
	n.mu.Lock()
	cfg := n.policy.Load()
	now := time.Now()
	match := "routed"
	if cfg.cluster.InAnycastPool(ip) {
		match = "anycast"
	} else if cfg.cluster.Subnet(ip).IsValid() {
		match = "primary"
	}
	host := netip.PrefixFrom(ip, ip.BitLen())
	prefixFor := func(id PeerID, pair pki.Addresses, routes []netip.Prefix) netip.Prefix {
		if match == "routed" {
			return longestPrefix(ip, routes)
		}
		if ip == pair.IPv4 || ip == pair.IPv6 || slices.Contains(cfg.members[id].AnycastIPs, ip) {
			return host
		}
		return netip.Prefix{}
	}
	var rows []IPObservation
	add := func(o IPObservation, prefix netip.Prefix) {
		if prefix.IsValid() {
			o.Match, o.Prefix = match, prefix
			o.Circuit = slices.Clone(o.Circuit)
			o.Advertised = slices.Clone(o.Advertised)
			rows = append(rows, o)
		}
	}
	for id, m := range cfg.members {
		o := IPObservation{Addresses: m.addresses(), Peer: id, Source: "topology", Decision: "configured"}
		if id == n.id {
			o.Instance = n.instance
		}
		add(o, prefixFor(id, o.Addresses, m.RoutedPrefixes))
	}
	for peer, paths := range n.peers {
		for _, s := range paths.sessions {
			if !s.closed.Load() && n.sessionAllowedLocked(s) {
				add(s.observation("accepted"), prefixFor(peer, s.remoteIdentity.Addresses, cfg.members[peer].RoutedPrefixes))
			}
		}
	}
	for peer, intro := range n.discovered {
		if prefix := prefixFor(peer, intro.Addresses, intro.RoutedPrefixes); prefix.IsValid() && now.Before(intro.authorizedUntil) {
			add(intro.observation(peer, "discovered"), prefix)
		}
	}
	for _, e := range n.evidence {
		if now.Sub(e.LastSeen) <= evidenceLifetime {
			routes := cfg.members[e.Peer].RoutedPrefixes
			if e.Source == "introduction" {
				routes = e.routes
			}
			add(e.IPObservation, prefixFor(e.Peer, e.Addresses, routes))
		}
	}
	for peer, c := range n.conflicts {
		if c.confirmedAt.IsZero() {
			continue
		}
		for _, w := range c.claims {
			decision := "held out"
			if w.instance == c.keep {
				decision = "retained"
				if c.selected {
					decision = "selected"
				}
			}
			o := w.observation(peer, "conflict", decision)
			o.FirstSeen, o.LastSeen = c.since, c.confirmedAt
			add(o, prefixFor(peer, w.addresses, cfg.members[peer].RoutedPrefixes))
		}
	}
	n.mu.Unlock()
	slices.SortFunc(rows, func(a, b IPObservation) int {
		return cmp.Or(comparePeer(a.Peer, b.Peer), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Decision, b.Decision), a.FirstSeen.Compare(b.FirstSeen), cmp.Compare(a.GrantSHA256, b.GrantSHA256), cmp.Compare(a.NodeSHA256, b.NodeSHA256))
	})
	return rows
}
