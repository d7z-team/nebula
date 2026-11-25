package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"iter"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type countingSigner struct {
	crypto.Signer
	calls int
}

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, digest, opts)
}

func TestClusterAllocation(t *testing.T) {
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	now := time.Now()
	key, err := GenerateKey("ed25519")
	require.NoError(t, err)
	profile := CAProfile{
		Subject: pkix.Name{CommonName: "Address plan"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Scope:        &Scope{Network: "lab", Cluster: true, AnycastPools: []netip.Prefix{p("10.0.0.4/31"), p("fd00::/80"), p("192.0.2.200/32")}},
		PermittedIPs: []netip.Prefix{p("10.0.0.0/29"), p("fd00::/64")},
	}
	cert, err := CreateRoot(key, profile)
	require.NoError(t, err)
	c, err := ReadClusterCA(cert)
	require.NoError(t, err)
	for subnet, want := range map[string][]netip.Addr{
		"10.0.0.0/29": {a("10.0.0.1"), a("10.0.0.2"), a("10.0.0.3"), a("10.0.0.6")},
		"10.0.0.2/31": {a("10.0.0.2"), a("10.0.0.3")}, "10.0.0.3/32": {a("10.0.0.3")},
		"fd00::1:0:0:0/127": {a("fd00::1:0:0:0"), a("fd00::1:0:0:1")}, "fd00::1:0:0:1/128": {a("fd00::1:0:0:1")},
		"10.0.0.0/24": nil, "10.2.0.0/16": nil,
	} {
		require.Equal(t, want, slices.Collect(c.MemberAddresses(p(subnet))))
	}
	next, stop := iter.Pull(c.MemberAddresses(p("fd00::/64")))
	first, ok := next()
	stop()
	require.True(t, ok)
	require.Equal(t, a("fd00::1:0:0:0"), first)
	for _, pair := range [][2]string{{"10.0.0.0", "fd00::1:0:0:1"}, {"10.0.0.7", "fd00::1:0:0:1"}, {"10.0.0.4", "fd00::1:0:0:1"}, {"10.0.0.1", "fd00::"}, {"10.0.0.1", "fd00::1"}, {"10.0.0.1", "fd03::1"}} {
		id, err := NewPeerID(a(pair[0]), a(pair[1]))
		require.NoError(t, err)
		require.Error(t, c.ValidateMember(id))
	}
	require.True(t, c.ValidAnycast(a("192.0.2.200")))
	require.False(t, c.ValidAnycast(a("fd00::")))
	v4, v6 := c.MemberPrefixes()
	require.Equal(t, p("10.0.0.0/29"), v4)
	require.Equal(t, p("fd00::/64"), v6)
	c.AnycastPools()[0] = p("0.0.0.0/0")
	require.False(t, c.Subnet(a("10.1.1.1")).IsValid())
	require.False(t, c.InAnycastPool(a("10.1.1.1")))
	// Exclusions in an externally supplied cluster CA also apply inside an allocation range.
	profile.MaxPathLen = 1
	constrained, err := caTemplate(profile)
	require.NoError(t, err)
	_, hole, err := net.ParseCIDR("10.0.0.2/31")
	require.NoError(t, err)
	constrained.ExcludedIPRanges = []*net.IPNet{hole}
	der, err := x509.CreateCertificate(rand.Reader, constrained, constrained, key.Public(), key)
	require.NoError(t, err)
	external, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	plan, err := ReadClusterCA(external)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{a("10.0.0.1")}, slices.Collect(plan.MemberAddresses(p("10.0.0.0/30"))))
	issuer := Issuer{Chain: []*x509.Certificate{external}, Signer: key}
	siteKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	csr, err := CreateCSR(siteKey, pkix.Name{CommonName: "site"})
	require.NoError(t, err)
	site := CAProfile{
		Subject: csr.Subject, NotBefore: external.NotBefore, NotAfter: external.NotAfter,
		PermittedIPs: []netip.Prefix{p("10.0.0.0/30"), p("fd00::/96")},
	}
	_, err = issuer.IssueCA(csr, site, sha256.Sum256(csr.RawSubjectPublicKeyInfo))
	require.ErrorContains(t, err, "issuer excludes")
	for _, small := range [][2]string{{"10.9.0.0/31", "fd01::/127"}, {"10.9.0.0/32", "fd01::/128"}} {
		profile.PermittedIPs = []netip.Prefix{p(small[0]), p(small[1])}
		cert, err := CreateRoot(key, profile)
		require.NoError(t, err)
		plan, err := ReadClusterCA(cert)
		require.NoError(t, err)
		for _, subnet := range profile.PermittedIPs {
			got := slices.Collect(plan.MemberAddresses(subnet))
			require.Len(t, got, 1<<(subnet.Addr().BitLen()-subnet.Bits()))
			require.Equal(t, subnet.Addr(), got[0])
		}
	}
	signer := &countingSigner{Signer: key}
	for _, bad := range [][]netip.Prefix{{p("10.0.0.0/8")}, {p("10.0.0.0/8"), p("192.0.2.0/24"), p("fd00::/64")}, {p("224.0.0.0/4"), p("fd00::/64")}} {
		profile.PermittedIPs = bad
		_, err := CreateRoot(signer, profile)
		require.Error(t, err)
	}
	require.Zero(t, signer.calls, "validate the cluster plan before invoking the signing key")
}
