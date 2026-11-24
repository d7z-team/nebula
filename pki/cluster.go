package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
)

// Cluster is an immutable address plan from a cluster CA. Its zero value is invalid.
type Cluster struct {
	certificate                      string
	network                          string
	subnets, pools, excluded, routes []netip.Prefix
}

// Network returns the certified mesh network name.
func (c Cluster) Network() string { return c.network }

// Subnets returns a copy of the logical member subnets.
func (c Cluster) Subnets() []netip.Prefix { return slices.Clone(c.subnets) }

// AnycastPools returns a copy of the reserved service address pools.
func (c Cluster) AnycastPools() []netip.Prefix { return slices.Clone(c.pools) }

// AllowsRoute reports whether the cluster CA delegates the downstream prefix.
func (c Cluster) AllowsRoute(p netip.Prefix) bool { return covers(c.routes, p) }

func covers(ranges []netip.Prefix, p netip.Prefix) bool {
	return p.IsValid() && !p.Addr().Is4In6() && p == p.Masked() && slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return p.Bits() >= r.Bits() && r.Contains(p.Addr()) })
}

// Subnet returns the logical subnet containing addr, or a zero prefix.
func (c Cluster) Subnet(addr netip.Addr) netip.Prefix {
	for _, p := range c.subnets {
		if p.Contains(addr) {
			return p
		}
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

// MemberAddresses lazily yields assignable primary addresses in a certified
// subnet. The caller must atomically reserve a free pair in its own store.
func (c Cluster) MemberAddresses(subnet netip.Prefix) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		if !slices.Contains(c.subnets, subnet) {
			return
		}
		first, broadcast := subnet.Addr(), Broadcast(subnet)
		if reservedSubnetAddress(subnet, first) {
			first = first.Next()
		}
	addresses:
		for a := first; subnet.Contains(a) && a != broadcast; a = a.Next() {
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
	return clusterFromScope(parsed, scope)
}

// Both entry points supply a certificate parsed from DER and its signed scope.
func clusterFromScope(parsed *x509.Certificate, scope Scope) (Cluster, error) {
	if !scope.Cluster || !parsed.IsCA || !parsed.BasicConstraintsValid || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Cluster{}, errors.New("cluster CA profile required")
	}
	c := Cluster{certificate: string(parsed.Raw), network: scope.Network, pools: scope.AnycastPools, routes: scope.RoutedPrefixes}
	v4, v6 := false, false
	for _, r := range parsed.PermittedIPRanges {
		p, err := netip.ParsePrefix(r.String())
		if err != nil || !validUnicastPrefix(p) || slices.ContainsFunc(c.subnets, p.Overlaps) {
			return Cluster{}, fmt.Errorf("invalid or overlapping cluster subnet %v", r)
		}
		v4 = v4 || p.Addr().Is4()
		v6 = v6 || p.Addr().Is6()
		c.subnets = append(c.subnets, p)
	}
	if !v4 || !v6 {
		return Cluster{}, errors.New("cluster CA requires IPv4 and IPv6 member subnets")
	}
	for _, r := range parsed.ExcludedIPRanges {
		p, err := netip.ParsePrefix(r.String())
		if err != nil {
			return Cluster{}, err
		}
		c.excluded = append(c.excluded, p)
	}
	for _, pool := range c.pools {
		for _, subnet := range c.subnets {
			if pool.Overlaps(subnet) && pool.Bits() < subnet.Bits() {
				return Cluster{}, fmt.Errorf("anycast pool %s spans member subnet %s", pool, subnet)
			}
		}
	}
	return c, nil
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
