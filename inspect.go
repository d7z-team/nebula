package nebula

import (
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"
)

// IPObservation describes a local fact about an address. Unknown fields are zero.
// Source distinguishes topology, session, certificate, introduction and conflict.
// A certificate seen during TLS verification alone does not prove possession.
// LastSeen on a signed introduction is a local receipt time, not a liveness check.
type IPObservation struct {
	Peer                PeerID
	Instance            InstanceID
	Match               string // primary, anycast or routed
	Prefix              netip.Prefix
	Source, Decision    string
	CertificateSHA256   string
	Usage               x509.ExtKeyUsage
	FirstSeen, LastSeen time.Time
	Transport           string
	Circuit             []PeerID       // End-to-end relay path observed on this node.
	Advertised          []Endpoint     // Endpoints disclosed in a verified introduction.
	Endpoint            netip.AddrPort // Locally observed direct path, when available.
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

func certificateObservation(peer PeerID, instance InstanceID, leaf *x509.Certificate, usage x509.ExtKeyUsage, source, decision string) IPObservation {
	hash := sha256.Sum256(leaf.Raw)
	return IPObservation{Peer: peer, Instance: instance, CertificateSHA256: hex.EncodeToString(hash[:]), Usage: usage, Source: source, Decision: decision}
}

func (s *session) observation(decision string) IPObservation {
	w := s.handshakeClaim()
	o := certificateObservation(s.peer, s.instance, w.chain[0], w.usage, sessionSource, decision)
	o.Circuit = s.path
	o.Transport, o.Endpoint = s.kind, s.remoteEndpoint()
	o.FirstSeen, o.LastSeen = s.registeredAt, s.lastAlive
	return o
}

func (intro *learnedIntroduction) observation(peer PeerID, decision string) IPObservation {
	return IPObservation{
		Peer: peer, Instance: intro.Instance, CertificateSHA256: hex.EncodeToString(intro.fingerprint[:]),
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
		if e.Peer == o.Peer && e.Instance == o.Instance && e.CertificateSHA256 == o.CertificateSHA256 && e.Usage == o.Usage && e.Source == o.Source && e.Decision == o.Decision {
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
	prefixFor := func(id PeerID, routes []netip.Prefix) netip.Prefix {
		if match == "routed" {
			return longestPrefix(ip, routes)
		}
		if ip == id.IPv4() || ip == id.IPv6() || slices.Contains(cfg.members[id].AnycastIPs, ip) {
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
		o := IPObservation{Peer: id, Source: "topology", Decision: "configured"}
		if id == n.id {
			o.Instance = n.instance
		}
		add(o, prefixFor(id, m.RoutedPrefixes))
	}
	for peer, paths := range n.peers {
		prefix := prefixFor(peer, cfg.members[peer].RoutedPrefixes)
		if !prefix.IsValid() {
			continue
		}
		for _, s := range paths.sessions {
			if !s.closed.Load() && n.sessionAllowedLocked(s) {
				add(s.observation("accepted"), prefix)
			}
		}
	}
	for peer, intro := range n.discovered {
		if prefix := prefixFor(peer, intro.RoutedPrefixes); prefix.IsValid() && now.Before(intro.authorizedUntil) {
			add(intro.observation(peer, "discovered"), prefix)
		}
	}
	for _, e := range n.evidence {
		if now.Sub(e.LastSeen) <= evidenceLifetime {
			routes := cfg.members[e.Peer].RoutedPrefixes
			if e.Source == "introduction" {
				routes = e.routes
			}
			add(e.IPObservation, prefixFor(e.Peer, routes))
		}
	}
	for peer, c := range n.conflicts {
		prefix := prefixFor(peer, cfg.members[peer].RoutedPrefixes)
		if c.confirmedAt.IsZero() || !prefix.IsValid() {
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
			o := certificateObservation(peer, w.instance, w.chain[0], w.usage, "conflict", decision)
			o.FirstSeen, o.LastSeen = c.since, c.confirmedAt
			add(o, prefix)
		}
	}
	n.mu.Unlock()
	slices.SortFunc(rows, func(a, b IPObservation) int {
		return cmp.Or(comparePeer(a.Peer, b.Peer), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Decision, b.Decision), a.FirstSeen.Compare(b.FirstSeen), cmp.Compare(a.CertificateSHA256, b.CertificateSHA256))
	})
	return rows
}
