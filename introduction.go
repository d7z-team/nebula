package nebula

import (
	"context"
	"crypto/sha256"
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
	"weak"

	"gopkg.d7z.net/nebula/pki"
)

const (
	maxIntroductionEndpoints = 16
	introductionLifetime     = time.Minute
	introductionRefreshLead  = 10 * time.Second
	introductionClockSkew    = 5 * time.Second
)

type introduction struct {
	pki.Addresses
	Instance       InstanceID     `json:"instance"`
	Endpoints      []Endpoint     `json:"endpoints"`
	RoutedPrefixes []netip.Prefix `json:"routedPrefixes,omitempty"`
	Expires        time.Time      `json:"expires"`
}

type learnedIntroduction struct {
	introduction
	record              signedIntroduction
	authorizedUntil     time.Time
	grantHash, nodeHash [sha256.Size]byte
	firstSeen, lastSeen time.Time
}

type cachedIntroduction struct {
	introduction
	record     signedIntroduction
	grantLeaf  *x509.Certificate // Each reload parses a fresh grant leaf, including node-only renewals.
	policy     weak.Pointer[topologyView]
	candidates []Endpoint // Includes observations omitted from the signed record for size.
}

func (n *Node) mayAdvertise(p *topologyView, c EndpointCandidate) bool {
	allow := n.o.Transport.AllowAdvertiseEndpoint
	return p.physicalEndpoint(c.Endpoint) && (allow == nil || allow(c))
}

// Keep configured endpoints ahead of listener addresses and optional observations.
func (n *Node) introductionEndpoints(p *topologyView, includeObserved bool) ([]Endpoint, int) {
	if n.o.Transport.HideEndpoints {
		return nil, 0
	}
	var endpoints []Endpoint
	add := func(c EndpointCandidate) {
		if len(endpoints) < maxIntroductionEndpoints && n.mayAdvertise(p, c) && !slices.Contains(endpoints, c.Endpoint) {
			endpoints = append(endpoints, c.Endpoint)
		}
	}
	for _, ep := range n.o.Transport.AdvertiseEndpoints {
		add(EndpointCandidate{Endpoint: ep, Source: EndpointFromConfig})
	}
	for _, ep := range p.members[n.id].Endpoints {
		add(EndpointCandidate{Endpoint: ep, Source: EndpointFromTopology})
	}
	for _, pc := range []net.PacketConn{n.o.Transport.UDP4, n.o.Transport.UDP6} {
		if pc != nil {
			add(EndpointCandidate{Endpoint: Endpoint{"udp", addrPort(pc.LocalAddr())}, Source: EndpointFromListener})
		}
	}
	for _, l := range []net.Listener{n.o.Transport.TCP4, n.o.Transport.TCP6} {
		if l != nil {
			add(EndpointCandidate{Endpoint: Endpoint{"tcp", addrPort(l.Addr())}, Source: EndpointFromListener})
		}
	}
	fixed := len(endpoints)
	if !includeObserved {
		return endpoints, fixed
	}
	var observed []EndpointCandidate
	now := time.Now()
	n.mu.Lock()
	for source, entry := range n.observations {
		if !now.Before(entry.expires) {
			delete(n.observations, source)
		} else if fixed < maxIntroductionEndpoints {
			observed = append(observed, EndpointCandidate{Endpoint{"udp", entry.endpoint}, EndpointFromObservation, source.peer})
		}
	}
	n.mu.Unlock()
	slices.SortFunc(observed, func(a, b EndpointCandidate) int { return a.Endpoint.Address.Compare(b.Endpoint.Address) })
	for _, c := range observed {
		add(c)
	}
	return endpoints, fixed
}

func (n *Node) buildIntroduction(p *topologyView, id pki.Identity, endpoints []Endpoint, expires time.Time) introduction {
	intro := introduction{Addresses: id.Addresses, Instance: n.instance, Endpoints: endpoints, Expires: expires.UTC()}
	seen := make(map[netip.Prefix]bool)
	for _, active := range p.members[n.id].RoutedPrefixes {
		for _, grant := range id.RoutedPrefixes {
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
	return intro
}

type signedIntroduction []byte

type introductionEnvelope struct {
	Publisher PeerID       `json:"publisher"`
	Value     introduction `json:"value"`
}

func (n *Node) signIntroduction(value introduction, signer tls.Certificate) (signedIntroduction, error) {
	b, err := json.Marshal(introductionEnvelope{n.id, value})
	if err != nil {
		return nil, err
	}
	return pki.SignObject(n.Cluster().Network(), "introduction", b, signer)
}

func (n *Node) checkLocalIntroductionBudget(p *topologyView, cred *credentials) error {
	endpoints, _ := n.introductionEndpoints(p, false)
	// A future refresh can use all nine fractional digits of RFC 3339.
	expires := time.Unix(time.Now().Unix(), 999999999)
	intro := n.buildIntroduction(p, cred.identity, endpoints, expires)
	if err := n.checkIntroductionSize(p, cred.cmsSigner, intro); err != nil {
		return fmt.Errorf("local introduction (CMS limit %d bytes): %w", pki.MaxDocument, err)
	}
	return nil
}

func (n *Node) checkIntroductionSize(p *topologyView, signer tls.Certificate, intro introduction) error {
	body, err := json.Marshal(introductionEnvelope{n.id, intro})
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
	endpoints, fixed := n.introductionEndpoints(p, true)
	n.introMu.Lock()
	defer n.introMu.Unlock()
	cache := &n.introCache
	cred := n.cred.Load()
	signer := cred.cmsSigner
	policy := weak.Make(p)
	if cache.policy == policy && cache.grantLeaf == signer.Leaf && now.Add(introductionRefreshLead).Before(cache.Expires) && slices.Equal(endpoints, cache.candidates) {
		return *cache
	}
	intro := n.buildIntroduction(p, cred.identity, endpoints, now.Add(introductionLifetime))
	record, err := n.signIntroduction(intro, signer)
	if errors.Is(err, pki.ErrDocumentTooLarge) && len(endpoints) > fixed {
		// The fixed prefix fits and the full list overflowed. Find how many
		// observations fit between them before invoking the signer again.
		count := sort.Search(len(endpoints)-fixed-1, func(i int) bool {
			intro.Endpoints = endpoints[:fixed+i+1]
			return n.checkIntroductionSize(p, signer, intro) != nil
		})
		intro.Endpoints = endpoints[:fixed+count]
		record, err = n.signIntroduction(intro, signer)
	}
	if err != nil {
		return cachedIntroduction{}
	}
	*cache = cachedIntroduction{introduction: intro, record: record, grantLeaf: signer.Leaf, policy: policy, candidates: endpoints}
	return *cache
}

func (n *Node) verifyIntroduction(ctx context.Context, p *topologyView, record signedIntroduction, reply *query) (pki.Identity, learnedIntroduction, error) {
	body, chain, err := pki.VerifyObjectSignature(record, p.cluster.Network(), "introduction")
	if err != nil {
		return pki.Identity{}, learnedIntroduction{}, err
	}
	identity, nodePath, grantPaths, err := pki.VerifyObjectSigner(chain, n.o.Auth.RootCA, p.cluster, time.Now())
	if err != nil {
		return pki.Identity{}, learnedIntroduction{}, err
	}
	if _, ok := p.members[n.id]; !ok {
		return identity, learnedIntroduction{}, ErrPathPolicy
	}
	check := ChainCheck{Member: identity.ID, Local: identity.ID == n.id, Purpose: NodeIdentity, Usage: x509.ExtKeyUsageClientAuth}
	nodeEnd, err := n.chainDeadline(ctx, check, [][]*x509.Certificate{nodePath})
	if err != nil {
		return identity, learnedIntroduction{}, err
	}
	check.Purpose, check.Usage = ClusterGrant, x509.ExtKeyUsageCodeSigning
	grantEnd, err := n.chainDeadline(ctx, check, grantPaths)
	if err != nil {
		return identity, learnedIntroduction{}, err
	}
	var envelope introductionEnvelope
	if json.Unmarshal(body, &envelope) != nil || envelope.Publisher != identity.ID {
		return identity, learnedIntroduction{}, ErrPathPolicy
	}
	intro := envelope.Value
	now := time.Now()
	if intro.Addresses != identity.Addresses || intro.Instance == (InstanceID{}) || len(intro.Endpoints) > maxIntroductionEndpoints {
		return identity, learnedIntroduction{}, ErrPathPolicy
	}
	if !now.Before(intro.Expires) || intro.Expires.After(now.Add(introductionLifetime+introductionClockSkew)) {
		return identity, learnedIntroduction{}, ErrPathPolicy
	}
	if reply != nil && !intro.match(*reply, identity.ID, p.cluster.Subnet(reply.IP).IsValid()).IsValid() {
		return identity, learnedIntroduction{}, ErrPathPolicy
	}
	for _, prefix := range intro.RoutedPrefixes {
		if !identity.AllowsRoute(prefix) {
			return identity, learnedIntroduction{}, ErrPathPolicy
		}
	}
	for _, ep := range intro.Endpoints {
		if !p.physicalEndpoint(ep) {
			return identity, learnedIntroduction{}, ErrPathPolicy
		}
	}
	return identity, learnedIntroduction{
		introduction:    intro,
		record:          record,
		authorizedUntil: earlierDeadline(intro.Expires, earlierDeadline(nodeEnd, grantEnd)),
		grantHash:       sha256.Sum256(chain[0].Raw),
		nodeHash:        sha256.Sum256(nodePath[0].Raw),
		firstSeen:       now,
		lastSeen:        now,
	}, nil
}

func (n *Node) learnIntroduction(ctx context.Context, record signedIntroduction, reply *query) (PeerID, bool) {
	p := n.policy.Load()
	identity, intro, err := n.verifyIntroduction(ctx, p, record, reply)
	peer := identity.ID
	if err != nil {
		return peer, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.policy.Load() != p || n.modes[peer] == Blocked {
		return peer, false
	}
	bound, _ := n.deliveryInstanceLocked(peer)
	if peer == n.id {
		bound = n.instance
	}
	if n.addressConflictLocked(identity) {
		n.recordObservationLocked(intro.observation(peer, "address conflict"), intro.RoutedPrefixes)
		return peer, false
	}
	if bound != (InstanceID{}) && bound != intro.Instance {
		n.recordObservationLocked(intro.observation(peer, "instance mismatch"), intro.RoutedPrefixes)
		return peer, false
	}
	if peer == n.id {
		return peer, false
	}
	old := n.discovered[peer]
	oldValid := intro.lastSeen.Before(old.authorizedUntil)
	if oldValid && old.Expires.After(intro.Expires) {
		if old.Instance != intro.Instance {
			n.recordObservationLocked(intro.observation(peer, "different signed instance"), intro.RoutedPrefixes)
			return peer, false
		}
		return peer, true
	}
	if old.Instance == intro.Instance && old.grantHash == intro.grantHash && old.nodeHash == intro.nodeHash {
		intro.firstSeen = old.firstSeen
		if slices.Equal(old.record, record) {
			intro.lastSeen = old.lastSeen
		}
	} else if oldValid && old.Instance != intro.Instance {
		n.recordObservationLocked(old.observation(peer, "different signed instance"), old.RoutedPrefixes)
	}
	n.forgetIntroductionLocked(peer, old)
	for _, ep := range intro.Endpoints {
		if n.introduced[ep] == nil {
			n.introduced[ep] = make(map[PeerID]time.Time)
		}
		n.introduced[ep][peer] = intro.authorizedUntil
	}
	n.discovered[peer] = intro
	n.discoveredOwners[intro.IPv4] = peer
	n.discoveredOwners[intro.IPv6] = peer
	return peer, true
}

// Remove the derived indexes together when replacing or expiring a signed introduction.
func (n *Node) forgetIntroductionLocked(peer PeerID, old learnedIntroduction) {
	delete(n.discovered, peer)
	for _, addr := range []netip.Addr{old.IPv4, old.IPv6} {
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
