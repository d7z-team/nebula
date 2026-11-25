package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"slices"
)

// Cluster is an immutable address plan from a cluster CA. Its zero value is invalid.
type Cluster struct {
	certificate             string
	network                 string
	ipv4, ipv6              netip.Prefix
	pools, excluded, routes []netip.Prefix
}

// Network returns the certified mesh network name.
func (c Cluster) Network() string { return c.network }

// MemberPrefixes returns the two prefixes defining the logical mesh link.
func (c Cluster) MemberPrefixes() (ipv4, ipv6 netip.Prefix) { return c.ipv4, c.ipv6 }

// AnycastPools returns a copy of the reserved service address pools.
func (c Cluster) AnycastPools() []netip.Prefix { return slices.Clone(c.pools) }

// AllowsRoute reports whether the cluster CA delegates the downstream prefix.
func (c Cluster) AllowsRoute(p netip.Prefix) bool { return covers(c.routes, p) }

func covers(ranges []netip.Prefix, p netip.Prefix) bool {
	return p.IsValid() && !p.Addr().Is4In6() && p == p.Masked() && slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return p.Bits() >= r.Bits() && r.Contains(p.Addr()) })
}

// Subnet returns the logical subnet containing addr, or a zero prefix.
func (c Cluster) Subnet(addr netip.Addr) netip.Prefix {
	p := c.ipv6
	if addr.Is4() {
		p = c.ipv4
	}
	if p.Contains(addr) {
		return p
	}
	return netip.Prefix{}
}

// Broadcast returns the directed broadcast of an IPv4 subnet with at least two host bits.
func Broadcast(p netip.Prefix) netip.Addr {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() > 30 {
		return netip.Addr{}
	}
	return lastAddress(p)
}

func lastAddress(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> uint(i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// MemberAddresses yields assignable primaries in a canonical range within a member prefix.
// The caller reserves a free pair and checks any narrower issuing CA constraints.
func (c Cluster) MemberAddresses(within netip.Prefix) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		subnet := c.Subnet(within.Addr())
		if !subnet.IsValid() || within != within.Masked() || within.Bits() < subnet.Bits() {
			return
		}
		first, broadcast := within.Addr(), Broadcast(subnet)
		if reservedSubnetAddress(subnet, first) {
			first = first.Next()
		}
	addresses:
		for a := first; within.Contains(a) && a != broadcast; a = a.Next() {
			for _, ranges := range [][]netip.Prefix{c.pools, c.excluded} {
				for _, p := range ranges {
					if p.Contains(a) {
						a = lastAddress(p)
						continue addresses
					}
				}
			}
			if !yield(a) {
				return
			}
		}
	}
}

func reservedSubnetAddress(p netip.Prefix, a netip.Addr) bool {
	return p.IsValid() && p.Bits() < a.BitLen()-1 && (p.Masked().Addr() == a || Broadcast(p) == a)
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
}

// InAnycastPool reports whether addr is reserved for service instances.
func (c Cluster) InAnycastPool(a netip.Addr) bool { return contains(c.pools, a) }

// ValidAnycast reports whether addr can be assigned to a service instance.
func (c Cluster) ValidAnycast(a netip.Addr) bool {
	return c.InAnycastPool(a) && !reservedSubnetAddress(c.Subnet(a), a) && !contains(c.excluded, a)
}

// ValidateMember checks both primary addresses against the CA's allocation rules.
// The issuer or configuration store is responsible for reserving unique addresses.
func (c Cluster) ValidateMember(id PeerID) error {
	for _, a := range []netip.Addr{id.IPv4(), id.IPv6()} {
		p := c.Subnet(a)
		if !p.IsValid() || !a.IsGlobalUnicast() || a.Is4In6() || reservedSubnetAddress(p, a) || c.InAnycastPool(a) || contains(c.excluded, a) {
			return fmt.Errorf("invalid primary address %s in cluster %q", a, c.network)
		}
	}
	return nil
}

// ReadClusterCA reads the signed address plan. VerifyChain establishes trust in the CA.
func ReadClusterCA(cert *x509.Certificate) (Cluster, error) {
	if cert == nil {
		return Cluster{}, errors.New("cluster CA required")
	}
	parsed, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return Cluster{}, err
	}
	scope, _, err := CertificateScope(parsed)
	if err != nil {
		return Cluster{}, err
	}
	return clusterAddressPlan(parsed, scope)
}

// Validate the same address plan on an issuance template and on a parsed certificate.
func clusterAddressPlan(parsed *x509.Certificate, scope Scope) (Cluster, error) {
	if !scope.Cluster || !parsed.IsCA || !parsed.BasicConstraintsValid || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Cluster{}, errors.New("cluster CA profile required")
	}
	c := Cluster{certificate: string(parsed.Raw), network: scope.Network, pools: scope.AnycastPools, routes: scope.RoutedPrefixes}
	for _, r := range parsed.PermittedIPRanges {
		p := constraintPrefix(r)
		dst := &c.ipv6
		if p.Addr().Is4() {
			dst = &c.ipv4
		}
		if !validUnicastPrefix(p) || dst.IsValid() {
			return Cluster{}, fmt.Errorf("invalid or repeated member prefix for address family: %v", r)
		}
		*dst = p
	}
	if !c.ipv4.IsValid() || !c.ipv6.IsValid() {
		return Cluster{}, errors.New("cluster CA requires one IPv4 and one IPv6 member prefix")
	}
	for _, r := range parsed.ExcludedIPRanges {
		p := constraintPrefix(r)
		if !p.IsValid() {
			return Cluster{}, fmt.Errorf("invalid excluded IP range %v", r)
		}
		c.excluded = append(c.excluded, p)
	}
	for _, pool := range c.pools {
		for _, subnet := range []netip.Prefix{c.ipv4, c.ipv6} {
			if pool.Overlaps(subnet) && pool.Bits() < subnet.Bits() {
				return Cluster{}, fmt.Errorf("anycast pool %s spans member subnet %s", pool, subnet)
			}
		}
	}
	return c, nil
}

func constraintPrefix(r *net.IPNet) netip.Prefix {
	addr, ok := netip.AddrFromSlice(r.IP)
	bits, size := r.Mask.Size()
	if !ok || addr.BitLen() != size {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, bits)
}

// checkDelegatedRanges validates a delegated CA before signing and on each candidate
// verification path. Below the cluster CA, both families must be explicit.
func checkDelegatedRanges(child *x509.Certificate, parents []*x509.Certificate, belowCluster bool) error {
	var v4, v6 bool
	for _, r := range child.PermittedIPRanges {
		p := constraintPrefix(r)
		if !p.IsValid() || belowCluster && !validUnicastPrefix(p) {
			return fmt.Errorf("invalid delegated prefix %v", r)
		}
		v4 = v4 || p.Addr().Is4()
		v6 = v6 || p.Addr().Is6()
		if err := checkPermittedRange(p, parents); err != nil {
			return err
		}
	}
	if belowCluster && !(v4 && v6) {
		return errors.New("member issuer requires explicit IPv4 and IPv6 ranges")
	}
	return nil
}

func checkPermittedRange(p netip.Prefix, parents []*x509.Certificate) error {
	for _, c := range parents {
		for _, r := range c.ExcludedIPRanges {
			if p.Overlaps(constraintPrefix(r)) {
				return fmt.Errorf("issuer excludes addresses in %s", p)
			}
		}
		if len(c.PermittedIPRanges) > 0 && !slices.ContainsFunc(c.PermittedIPRanges, func(r *net.IPNet) bool {
			allowed := constraintPrefix(r)
			return allowed.Contains(p.Addr()) && allowed.Bits() <= p.Bits()
		}) {
			return fmt.Errorf("IP range %s exceeds issuer permission", p)
		}
	}
	return nil
}

func validUnicastPrefix(p netip.Prefix) bool {
	if !p.IsValid() || p != p.Masked() || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() {
		return false
	}
	for _, special := range nonUnicastRanges {
		if special.Overlaps(p) {
			return false
		}
	}
	return true
}

var nonUnicastRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("::ffff:0:0/96"),
}

func (c Cluster) validateIdentity(i Identity) error {
	if i.Network != c.network || i.Cluster || len(i.AnycastPools) > 0 {
		return errors.New("unexpected leaf scope")
	}
	if err := c.ValidateMember(i.ID); err != nil {
		return err
	}
	for _, a := range i.AnycastIPs {
		if !c.ValidAnycast(a) {
			return fmt.Errorf("invalid service address %s", a)
		}
	}
	return nil
}
