package nebula

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

const maxIntroductionEndpoints = 16

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
	record     statement
	cred       *x509.Certificate
	policy     *topologyView
	candidates []Endpoint // Includes observations omitted from the signed record for size.
}

// Keep configured endpoints ahead of listener addresses and optional observations.
func (n *Node) introductionEndpoints(p *topologyView, observed []Endpoint) ([]Endpoint, int) {
	if n.o.HideEndpoints {
		return nil, 0
	}
	var endpoints []Endpoint
	add := func(candidates ...Endpoint) {
		for _, ep := range candidates {
			if len(endpoints) == maxIntroductionEndpoints {
				return
			}
			if p.physicalEndpoint(ep) && !slices.Contains(endpoints, ep) {
				endpoints = append(endpoints, ep)
			}
		}
	}
	add(n.o.AdvertiseEndpoints...)
	add(p.members[n.id].Endpoints...)
	for _, pc := range []net.PacketConn{n.o.UDP4, n.o.UDP6} {
		if pc != nil {
			add(Endpoint{"udp", addrPort(pc.LocalAddr())})
		}
	}
	for _, l := range []net.Listener{n.o.TCP4, n.o.TCP6} {
		if l != nil {
			add(Endpoint{"tcp", addrPort(l.Addr())})
		}
	}
	fixed := len(endpoints)
	add(observed...)
	return endpoints, fixed
}

func (n *Node) buildIntroduction(p *topologyView, signer tls.Certificate, endpoints []Endpoint, expires time.Time) (introduction, error) {
	intro := introduction{Endpoints: endpoints, Expires: expires.UTC()}
	scope, _, err := pki.CertificateScope(signer.Leaf)
	if err != nil {
		return introduction{}, err
	}
	seen := make(map[netip.Prefix]bool)
	for _, active := range p.members[n.id].RoutedPrefixes {
		for _, grant := range scope.RoutedPrefixes {
			if !active.Overlaps(grant) {
				continue
			}
			prefix := active
			if grant.Bits() > active.Bits() {
				prefix = grant
			}
			if !seen[prefix] {
				seen[prefix] = true
				intro.RoutedPrefixes = append(intro.RoutedPrefixes, prefix)
			}
		}
	}
	return intro, nil
}

func (n *Node) validateIntroduction(p *topologyView, signer tls.Certificate) error {
	endpoints, _ := n.introductionEndpoints(p, nil)
	// A future refresh can use all nine fractional digits of RFC 3339.
	expires := time.Unix(time.Now().Unix(), 999999999)
	intro, err := n.buildIntroduction(p, signer, endpoints, expires)
	if err != nil {
		return err
	}
	if err := n.checkIntroductionSize(p, signer, intro); err != nil {
		return fmt.Errorf("local introduction (CMS limit %d bytes): %w", pki.MaxDocument, err)
	}
	return nil
}

func (n *Node) checkIntroductionSize(p *topologyView, signer tls.Certificate, intro introduction) error {
	body, err := n.statementBody(intro)
	if err != nil {
		return err
	}
	return pki.CheckObjectSize(p.cluster.Network(), "introduction", body, signer)
}

func (n *Node) localIntroduction(p *topologyView) cachedIntroduction {
	if !n.ready(p) {
		return cachedIntroduction{}
	}
	now := time.Now()
	endpoints, fixed := n.introductionEndpoints(p, n.observedEndpoints(now))
	n.introMu.Lock()
	defer n.introMu.Unlock()
	cache := &n.introCache
	signer := n.cred.Load().Object
	if cache.policy == p && cache.cred == signer.Leaf && now.Add(10*time.Second).Before(cache.Expires) && slices.Equal(endpoints, cache.candidates) {
		return *cache
	}
	intro, err := n.buildIntroduction(p, signer, endpoints, now.Add(time.Minute))
	if err != nil {
		return cachedIntroduction{}
	}
	record, err := n.signStatement("introduction", intro, signer)
	if errors.Is(err, pki.ErrDocumentTooLarge) && len(endpoints) > fixed {
		// The fixed prefix fits and the full list overflowed. Find how many
		// observations fit between them before invoking the signer again.
		count := sort.Search(len(endpoints)-fixed-1, func(i int) bool {
			intro.Endpoints = endpoints[:fixed+i+1]
			return n.checkIntroductionSize(p, signer, intro) != nil
		})
		intro.Endpoints = endpoints[:fixed+count]
		record, err = n.signStatement("introduction", intro, signer)
	}
	if err != nil {
		return cachedIntroduction{}
	}
	*cache = cachedIntroduction{introduction: intro, record: record, cred: signer.Leaf, policy: p, candidates: endpoints}
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
	if json.Unmarshal(body, &v) != nil || !now.Before(v.Expires) || v.Expires.After(now.Add(65*time.Second)) || len(v.Endpoints) > maxIntroductionEndpoints {
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
		if !p.physicalEndpoint(e) {
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
