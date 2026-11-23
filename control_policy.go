package nebula

import (
	"net/netip"
	"slices"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/control"
)

// networkPolicy is immutable after publication alongside the node's local path policies.
type networkPolicy struct {
	config        control.Config
	digest        string
	document      []byte
	local         control.Member
	bootstrapOnly bool
	relays        []netip.Addr
	direct        []netip.Addr
	exits         map[netip.AddrPort]bool
	revoked       map[string]bool
}

func (c *controlPlane) compileNetworkPolicy(cfg control.Config, digest string, b []byte) *networkPolicy {
	p := &networkPolicy{config: cfg, digest: digest, document: slices.Clone(b), revoked: map[string]bool{}}
	for _, fp := range cfg.Revoked {
		p.revoked[fp] = true
	}
	var listed bool
	p.local, listed = cfg.Members[c.n.engine.myVpnAddrs[0]]
	p.bootstrapOnly = !listed
	p.direct = p.local.Links
	if p.bootstrapOnly {
		p.direct = c.opts.Bootstrap
	}
	for _, a := range p.local.Links {
		if cfg.Members[a].Transit {
			p.relays = append(p.relays, a)
		}
	}
	p.exits = c.exitEndpoints(p)
	return p
}

func (c *controlPlane) exitEndpoints(p *networkPolicy) map[netip.AddrPort]bool {
	if !p.bootstrapOnly && !p.local.Restricted {
		return nil
	}
	exits := make(map[netip.AddrPort]bool)
	for _, a := range p.direct {
		for _, ep := range p.config.Members[a].Endpoints {
			exits[ep] = true
		}
		lh := c.n.lighthouse
		lh.RLock()
		r := lh.addrMap[a]
		lh.RUnlock()
		if r != nil {
			r.RLock()
			for _, ep := range r.staticEndpoints[a] {
				exits[ep] = true
			}
			r.RUnlock()
		}
	}
	return exits
}

// Include signed candidates in both initial handshakes and path recovery.
func (p *networkPolicy) endpoints(addr netip.Addr, known []netip.AddrPort) []netip.AddrPort {
	if p == nil || len(p.config.Members[addr].Endpoints) == 0 {
		return known
	}
	merged := slices.Clone(known)
	for _, ep := range p.config.Members[addr].Endpoints {
		if !slices.Contains(merged, ep) {
			merged = append(merged, ep)
		}
	}
	return merged
}

func (p *networkPolicy) allowsEndpoint(ep netip.AddrPort) bool {
	return p == nil || p.exits == nil || p.exits[ep]
}

func (p *networkPolicy) allowsTransit(from, to netip.Addr) bool {
	return p.local.Transit && (len(p.direct) == 0 || (slices.Contains(p.direct, from) && slices.Contains(p.direct, to)))
}

func (p *networkPolicy) denies(cc *cert.CachedCertificate) bool {
	return p != nil && cc != nil && cc.MatchesFingerprint(func(s string) bool { return p.revoked[s] })
}

func (p *networkPolicy) peerPathPolicy(ids []netip.Addr) PeerPathPolicy {
	if matchesIdentity(p.direct, ids[0], ids) {
		return PeerPathPolicy{Mode: DirectOnly}
	}
	if p.bootstrapOnly {
		return PeerPathPolicy{Mode: PathBlocked}
	}
	relays := p.relays
	if p.local.Restricted {
		if len(relays) == 0 {
			return PeerPathPolicy{Mode: PathBlocked}
		}
		return PeerPathPolicy{Mode: RelayOnly, Relays: relays}
	}
	return PeerPathPolicy{Mode: Auto, Relays: relays}
}
