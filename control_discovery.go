package nebula

import (
	"crypto/ed25519"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"
)

const (
	maxQueries         = 256
	maxIntroCandidates = 6
	introLifetime      = 30 * time.Second
)

type introduction struct {
	Certificate string           `json:"certificate"`
	Request     string           `json:"request"`
	Origin      netip.Addr       `json:"origin"`
	Target      netip.Addr       `json:"target"`
	Endpoints   []netip.AddrPort `json:"endpoints,omitempty"`
	Relays      []netip.Addr     `json:"relays,omitempty"`
	Expires     int64            `json:"expires"`
	Signature   []byte           `json:"signature,omitempty"`
}

type lookupRequest struct {
	prev, origin, target netip.Addr
	answered             bool
	expires              time.Time
}

func (c *controlPlane) introduction(id string, target netip.Addr) *introduction {
	if len(c.opts.Publisher) != ed25519.PrivateKeySize {
		return nil
	}
	f := c.n.engine
	p := c.policy()
	if !slices.Equal(p.local.Publisher, c.opts.Publisher.Public().(ed25519.PublicKey)) {
		return nil
	}
	fp, err := f.GetCertState().GetDefaultCertificate().Fingerprint()
	if err != nil || p.revoked[fp] || (p.local.Certificate != "" && fp != p.local.Certificate) {
		return nil
	}
	m := introduction{Certificate: fp, Request: id, Origin: f.myVpnAddrs[0], Target: target, Expires: time.Now().Add(introLifetime).Unix()}
	if p.local.Restricted {
		m.Relays = p.relays
	} else {
		lh := c.n.lighthouse
		eps := append(slices.Clone(p.local.Endpoints), lh.advertiseAddrs...)
		// An authenticated direct neighbor can report the NAT mapping it saw.
		// Only configured neighbors or bootstrap peers contribute to our own report.
		c.mu.Lock()
		for a, peer := range c.peers {
			if peer.observedSelf.IsValid() && (slices.Contains(p.direct, a) || slices.Contains(c.opts.Bootstrap, a)) {
				eps = append(eps, peer.observedSelf)
			}
		}
		c.mu.Unlock()
		if lh.endpointProvider != nil {
			select {
			case <-lh.ctx.Done():
				return nil
			case <-lh.updateGate:
			}
			more, err := lh.endpointProvider(lh.ctx)
			lh.updateGate <- struct{}{}
			if err == nil {
				eps = append(eps, more...)
			}
		}
		for _, ep := range eps {
			if ep.IsValid() && ep.Port() != 0 && ep.Addr().Zone() == "" && !ep.Addr().Is4In6() && !ep.Addr().IsUnspecified() && !ep.Addr().IsMulticast() && !f.myVpnNetworksTable.Contains(ep.Addr()) && !slices.Contains(m.Endpoints, ep) {
				m.Endpoints = append(m.Endpoints, ep)
				if len(m.Endpoints) == maxIntroCandidates {
					break
				}
			}
		}
		m.Relays = slices.Clone(lh.relaysForMe)
	}
	m.Relays = m.Relays[:min(maxIntroCandidates, len(m.Relays))]
	m.Signature = ed25519.Sign(c.opts.Publisher, signedBytes(c.opts.Network, "introduction", m))
	return &m
}

func (c *controlPlane) lookup(target netip.Addr) {
	if c.policy().config.Revision == 0 || len(c.opts.Publisher) == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	if len(c.peers) == 0 || len(c.queries) >= maxQueries {
		c.mu.Unlock()
		return
	}
	for _, q := range c.queries {
		if !q.prev.IsValid() && q.target == target && now.Before(q.expires) {
			c.mu.Unlock()
			return
		}
	}
	id := randomID()
	c.queries[id] = lookupRequest{origin: c.n.engine.myVpnAddrs[0], target: target, expires: now.Add(5 * time.Second)}
	c.mu.Unlock()
	if req := c.introduction(id, target); req != nil {
		c.forwardLookup(netip.Addr{}, req, 16)
	}
}

func (c *controlPlane) forwardLookup(prev netip.Addr, m *introduction, hops int) {
	peers := c.neighbors(prev)
	if slices.Contains(peers, m.Target) {
		peers = []netip.Addr{m.Target}
	}
	// Vary the bounded fanout on successive, independently identified searches.
	offset := 0
	if len(peers) > 4 {
		offset = rand.IntN(len(peers))
	}
	for i := 0; i < min(len(peers), 4); i++ {
		a := peers[(offset+i)%len(peers)]
		c.send(a, controlFrame{Kind: "lookup", Intro: m, Offset: hops})
	}
}

func (c *controlPlane) handleIntro(from netip.Addr, kind string, m introduction, hops int) {
	now := time.Now()
	if m.Origin == m.Target || len(m.Request) != 32 || m.Expires <= now.Unix() || m.Expires > now.Add(introLifetime+time.Second).Unix() || len(m.Endpoints) > maxIntroCandidates || len(m.Relays) > maxIntroCandidates || hops < 0 || hops > 16 {
		return
	}
	p := c.policy()
	member := p.config.Members[m.Origin]
	if len(m.Certificate) != 64 || p.revoked[m.Certificate] || (member.Certificate != "" && member.Certificate != m.Certificate) {
		return
	}
	if h := c.n.engine.hostMap.QueryVpnAddr(m.Origin); h != nil && !h.GetCert().MatchesFingerprint(func(s string) bool { return s == m.Certificate }) {
		return
	}
	pk := member.Publisher
	sig := m.Signature
	m.Signature = nil
	if len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, signedBytes(c.opts.Network, "introduction", m), sig) {
		return
	}
	m.Signature = sig
	self := c.n.engine.myVpnAddrs[0]
	c.mu.Lock()
	q, seen := c.queries[m.Request]
	if kind == "lookup" {
		if seen || len(c.queries) >= maxQueries || m.Origin == self {
			c.mu.Unlock()
			return
		}
		c.queries[m.Request] = lookupRequest{prev: from, origin: m.Origin, target: m.Target, expires: time.Unix(m.Expires, 0)}
	} else {
		if !seen || q.answered || q.target != m.Origin || q.origin != m.Target || now.After(q.expires) {
			c.mu.Unlock()
			return
		}
		q.answered = true
		c.queries[m.Request] = q
	}
	c.mu.Unlock()
	if kind == "lookup" && m.Target != self {
		if hops > 1 {
			c.forwardLookup(from, &m, hops-1)
		}
		return
	}
	if kind == "answer" && q.prev.IsValid() {
		c.send(q.prev, controlFrame{Kind: "answer", Intro: &m})
		return
	}
	if m.Target != self || c.n.validatePeerAddress(m.Origin) != nil {
		return
	}
	r := c.n.lighthouse.getOrCreateRemotes([]netip.Addr{m.Origin})
	eps := slices.DeleteFunc(slices.Clone(m.Endpoints), func(e netip.AddrPort) bool {
		return !e.IsValid() || e.Port() == 0 || e.Addr().IsMulticast() || e.Addr().IsUnspecified() || c.n.engine.myVpnNetworksTable.Contains(e.Addr())
	})
	r.Lock()
	if c.policy() != p {
		r.Unlock()
		return
	}
	r.introCert = m.Certificate
	r.introduced = eps
	r.introRelays = slices.Clone(m.Relays)
	r.introExpiry = time.Unix(m.Expires, 0)
	r.cached = nil
	r.Unlock()
	select {
	case c.n.handshake.trigger <- m.Origin:
	default:
	}
	if kind == "lookup" {
		if answer := c.introduction(m.Request, m.Origin); answer != nil {
			c.send(from, controlFrame{Kind: "answer", Intro: answer})
		}
	}
	if c.n.engine.paths.config.Load().allows([]netip.Addr{m.Origin}, netip.Addr{}, r) {
		for _, ep := range eps {
			c.n.punchy.Schedule(ep, m.Origin)
		}
	}
}
