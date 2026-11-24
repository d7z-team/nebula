package pki

import (
	"crypto/x509/pkix"
	"iter"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClusterAllocation(t *testing.T) {
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	now := time.Now()
	key, err := GenerateKey("ed25519")
	require.NoError(t, err)
	profile := CAProfile{
		Subject: pkix.Name{CommonName: "Address plan"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Scope:        &Scope{Network: "lab", Cluster: true, AnycastPools: []netip.Prefix{p("10.0.0.4/31"), p("fd00::/80"), p("192.0.2.200/32")}},
		PermittedIPs: []netip.Prefix{p("10.0.0.0/29"), p("10.0.1.0/31"), p("10.0.2.0/32"), p("fd00::/64"), p("fd01::/127"), p("fd02::/128")},
	}
	cert, err := CreateRoot(key, profile)
	require.NoError(t, err)
	c, err := ReadClusterCA(cert)
	require.NoError(t, err)
	for subnet, want := range map[string][]netip.Addr{
		"10.0.0.0/29": {a("10.0.0.1"), a("10.0.0.2"), a("10.0.0.3"), a("10.0.0.6")},
		"10.0.1.0/31": {a("10.0.1.0"), a("10.0.1.1")}, "10.0.2.0/32": {a("10.0.2.0")},
		"fd01::/127": {a("fd01::"), a("fd01::1")}, "fd02::/128": {a("fd02::")},
	} {
		require.Equal(t, want, slices.Collect(c.MemberAddresses(p(subnet))))
	}
	next, stop := iter.Pull(c.MemberAddresses(p("fd00::/64")))
	first, ok := next()
	stop()
	require.True(t, ok)
	require.Equal(t, a("fd00::1:0:0:0"), first)
	for _, pair := range [][2]string{{"10.0.0.0", "fd01::1"}, {"10.0.0.7", "fd01::1"}, {"10.0.0.4", "fd01::1"}, {"10.0.0.1", "fd00::"}, {"10.0.0.1", "fd00::1"}, {"10.0.0.1", "fd03::1"}} {
		id, err := NewPeerID(a(pair[0]), a(pair[1]))
		require.NoError(t, err)
		require.Error(t, c.ValidateMember(id))
	}
	require.True(t, c.ValidAnycast(a("192.0.2.200")))
	require.False(t, c.ValidAnycast(a("fd00::")))
	c.Subnets()[0] = p("0.0.0.0/0")
	c.AnycastPools()[0] = p("0.0.0.0/0")
	require.False(t, c.Subnet(a("10.1.1.1")).IsValid())
	require.False(t, c.InAnycastPool(a("10.1.1.1")))
	for _, bad := range [][]netip.Prefix{{p("10.0.0.0/8")}, {p("10.0.0.0/8"), p("10.0.0.0/24"), p("fd00::/64")}, {p("224.0.0.0/4"), p("fd00::/64")}} {
		profile.PermittedIPs = bad
		_, err := CreateRoot(key, profile)
		require.Error(t, err)
	}
}
