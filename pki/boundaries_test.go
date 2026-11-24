package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIssuanceBoundaries(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, err := GenerateKey("ed25519")
	require.NoError(t, err)
	profile := CAProfile{
		Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Scope:        &Scope{Network: "mesh", Cluster: true},
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd42::/64")},
		MaxPathLen:   1,
	}
	root, err := CreateRoot(key, profile)
	require.NoError(t, err)
	issuer := Issuer{Chain: []*x509.Certificate{root}, Signer: key}
	interKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	req, err := CreateCSR(interKey, pkix.Name{CommonName: "issuer"})
	require.NoError(t, err)
	interProfile := CAProfile{Subject: req.Subject, NotBefore: now.Add(-20 * time.Minute), NotAfter: now.Add(20 * time.Minute), MaxPathLen: 0}
	approvedSPKI, err := x509.MarshalPKIXPublicKey(interKey.Public())
	require.NoError(t, err)
	approvedHash := sha256.Sum256(approvedSPKI)
	_, err = issuer.IssueCA(req, interProfile, sha256.Sum256(root.RawSubjectPublicKeyInfo))
	require.ErrorContains(t, err, "fingerprint")
	inter, err := issuer.IssueCA(req, interProfile, approvedHash)
	require.NoError(t, err)
	interIssuer := Issuer{Chain: []*x509.Certificate{inter, root}, Signer: interKey}
	_, err = interIssuer.IssueCA(req, interProfile, approvedHash)
	require.Error(t, err)
	tooDeep := interProfile
	tooDeep.MaxPathLen = math.MaxInt
	_, err = issuer.IssueCA(req, tooDeep, approvedHash)
	require.Error(t, err)

	leafKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"requested.test"}, Subject: pkix.Name{CommonName: "unapproved"}}, leafKey)
	require.NoError(t, err)
	req, err = x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	enroll := Enrollment{Name: "publisher", IPv4: netip.MustParseAddr("10.0.0.1"), IPv6: netip.MustParseAddr("fd42::1"), Scope: Scope{Network: "mesh"}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	peer, err := NewPeerID(enroll.IPv4, enroll.IPv6)
	require.NoError(t, err)
	leaf, err := interIssuer.IssueLeaf(req, enroll)
	require.NoError(t, err)
	require.Empty(t, leaf.DNSNames)
	require.Equal(t, enroll.Name, leaf.Subject.CommonName)
	require.Equal(t, enroll.Usages, leaf.ExtKeyUsage)
	require.False(t, leaf.IsCA)
	t.Run("issuer usages", func(t *testing.T) {
		template := *inter
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		der, err := x509.CreateCertificate(rand.Reader, &template, root, interKey.Public(), key)
		require.NoError(t, err)
		limited, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		issuing := Issuer{Chain: []*x509.Certificate{limited, root}, Signer: interKey}
		_, err = issuing.IssueLeaf(req, enroll)
		require.NoError(t, err)
		both := enroll
		both.Usages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageClientAuth}
		_, err = issuing.IssueLeaf(req, both)
		require.ErrorContains(t, err, "clientAuth")
	})
	for _, tc := range []struct {
		name   string
		change func(*Enrollment)
	}{
		{"before-parent", func(e *Enrollment) { e.NotBefore = inter.NotBefore.Add(-time.Second) }},
		{"after-parent", func(e *Enrollment) { e.NotAfter = inter.NotAfter.Add(time.Second) }},
		{"same-DER-second", func(e *Enrollment) { e.NotBefore = now; e.NotAfter = now.Add(time.Millisecond) }},
		{"zoned-address", func(e *Enrollment) { e.IPv6 = netip.MustParseAddr("fe80::1%eth0") }},
		{"missing-usage", func(e *Enrollment) { e.Usages = nil }},
		{"other-approved-key", func(e *Enrollment) { e.PublicKeyHash = approvedHash }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := enroll
			tc.change(&e)
			_, err := interIssuer.IssueLeaf(req, e)
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name string
		ca   Issuer
	}{
		{"wrong-key", Issuer{[]*x509.Certificate{inter, root}, key}},
		{"non-CA", Issuer{[]*x509.Certificate{leaf}, leafKey}},
	} {
		t.Run(tc.name, func(t *testing.T) { _, err := tc.ca.IssueLeaf(req, enroll); require.Error(t, err) })
	}
	noCertSign := *inter
	noCertSign.KeyUsage = x509.KeyUsageCRLSign
	der, err = x509.CreateCertificate(rand.Reader, &noCertSign, root, interKey.Public(), key)
	require.NoError(t, err)
	bad, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	_, err = (Issuer{[]*x509.Certificate{bad, root}, interKey}).IssueLeaf(req, enroll)
	require.Error(t, err)
	broken := *req
	broken.Signature = bytes.Clone(req.Signature)
	broken.Signature[0] ^= 1
	_, err = interIssuer.IssueLeaf(&broken, enroll)
	require.Error(t, err)

	cluster, err := ReadClusterCA(root)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chain := []*x509.Certificate{leaf, inter}
	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"before", leaf.NotBefore.Add(-time.Nanosecond), false}, {"not-before", leaf.NotBefore, true}, {"not-after", leaf.NotAfter, true}, {"after", leaf.NotAfter.Add(time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyChain(chain, roots, cluster, peer, x509.ExtKeyUsageCodeSigning, tc.at)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		roots *x509.CertPool
		usage x509.ExtKeyUsage
	}{
		{"missing-intermediate", chain[:1], roots, x509.ExtKeyUsageCodeSigning}, {"untrusted", chain, x509.NewCertPool(), x509.ExtKeyUsageCodeSigning}, {"other-usage", chain, roots, x509.ExtKeyUsageServerAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyChain(tc.chain, tc.roots, cluster, peer, tc.usage, now)
			require.Error(t, err)
		})
	}

	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw, inter.Raw}, PrivateKey: leafKey}
	body := make([]byte, MaxDocument-2048)
	wire, err := SignObject("mesh", "event", body, cert)
	require.NoError(t, err)
	maxBody := len(body) + MaxDocument - len(wire)
	for _, delta := range []int{-1, 0, 1} {
		data := make([]byte, maxBody+delta)
		wire, err := SignObject("mesh", "event", data, cert)
		if delta > 0 {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Len(t, wire, MaxDocument+delta)
		got, _, err := VerifyObjectSignature(wire, "mesh", "event")
		require.NoError(t, err)
		require.Equal(t, data, got)
		if delta == 0 {
			_, _, err = VerifyObjectSignature(append(wire, 0), "mesh", "event")
			require.Error(t, err)
		}
	}
}

func TestDualStackScopeAndDelegation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	prefix, addr := netip.MustParsePrefix, netip.MustParseAddr
	scope := Scope{
		Cluster: true, Network: "production", RoutedPrefixes: []netip.Prefix{prefix("192.168.0.0/16"), prefix("2001:db8::/32")},
		AnycastPools: []netip.Prefix{prefix("192.0.2.0/24")},
	}
	profile := CAProfile{
		Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		MaxPathLen:   1,
		Scope:        &scope,
		PermittedIPs: []netip.Prefix{prefix("10.0.0.0/8"), prefix("fd42::/64")},
	}
	rootKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	root, err := CreateRoot(rootKey, profile)
	require.NoError(t, err)
	issuer := Issuer{Chain: []*x509.Certificate{root}, Signer: rootKey}
	key, err := GenerateKey("ed25519")
	require.NoError(t, err)
	req, err := CreateCSR(key, pkix.Name{})
	require.NoError(t, err)
	restricted := Scope{
		Network: "production", RoutedPrefixes: []netip.Prefix{prefix("192.168.2.0/24")},
		AnycastPools: []netip.Prefix{prefix("192.0.2.192/28")},
	}
	profile.Subject = pkix.Name{CommonName: "issuer"}
	profile.Scope = &restricted
	profile.PermittedIPs = []netip.Prefix{prefix("10.1.2.0/27"), prefix("fd42::/120")}
	profile.MaxPathLen = 0
	inter, err := issuer.IssueCA(req, profile, sha256.Sum256(req.RawSubjectPublicKeyInfo))
	require.NoError(t, err)
	delegated := Issuer{Chain: []*x509.Certificate{inter, root}, Signer: key}
	leafKey, err := GenerateKey("p256")
	require.NoError(t, err)
	req, err = CreateCSR(leafKey, pkix.Name{})
	require.NoError(t, err)
	// .31 is a primary address on the cluster subnet. The issuer's /27 limits its SANs.
	enrollment := Enrollment{
		IPv4: addr("10.1.2.31"), IPv6: addr("fd42::7"),
		Scope:  Scope{Network: restricted.Network, RoutedPrefixes: restricted.RoutedPrefixes, AnycastIPs: []netip.Addr{addr("192.0.2.200")}},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo),
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute),
	}
	id, err := NewPeerID(enrollment.IPv4, enrollment.IPv6)
	require.NoError(t, err)
	require.Equal(t, append(enrollment.IPv4.AsSlice(), enrollment.IPv6.AsSlice()...), id[:])
	cert, err := delegated.IssueLeaf(req, enrollment)
	require.NoError(t, err)
	identity, err := ReadIdentity(cert)
	require.NoError(t, err)
	require.Equal(t, enrollment.AnycastIPs, identity.AnycastIPs)
	cluster, err := ReadClusterCA(root)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chain := []*x509.Certificate{cert, inter}
	_, err = VerifyChain(chain, roots, cluster, id, x509.ExtKeyUsageServerAuth, now)
	require.NoError(t, err)
	_, err = VerifyChain(chain, roots, Cluster{}, id, x509.ExtKeyUsageServerAuth, now)
	require.Error(t, err)
	other := id
	other[19]++
	_, err = VerifyChain(chain, roots, cluster, other, x509.ExtKeyUsageServerAuth, now)
	require.Error(t, err)
	template := *cert
	// Rebuild the SAN in reverse order through the standard X.509 encoder.
	ext, err := enrollment.extension()
	require.NoError(t, err)
	template.ExtraExtensions = []pkix.Extension{ext}
	template.IPAddresses = []net.IP{enrollment.IPv6.AsSlice(), enrollment.IPv4.AsSlice()}
	der, err := x509.CreateCertificate(rand.Reader, &template, inter, leafKey.Public(), key)
	require.NoError(t, err)
	chain[0], err = x509.ParseCertificate(der)
	require.NoError(t, err)
	_, err = VerifyChain(chain, roots, cluster, id, x509.ExtKeyUsageServerAuth, now)
	require.NoError(t, err)
	for name, ips := range map[string][]net.IP{
		"missing-v6": {enrollment.IPv4.AsSlice()}, "missing-v4": {enrollment.IPv6.AsSlice()},
		"third-address": {enrollment.IPv4.AsSlice(), enrollment.IPv6.AsSlice(), net.ParseIP("fd42::8")},
		"two-v4":        {enrollment.IPv4.AsSlice(), addr("10.1.2.4").AsSlice()},
		"mapped-v6":     {enrollment.IPv4.AsSlice(), addr("::ffff:10.1.2.4").AsSlice()},
	} {
		t.Run(name, func(t *testing.T) {
			bad := *cert
			bad.IPAddresses = ips
			_, err := ReadIdentity(&bad)
			require.Error(t, err)
		})
	}
	for name, modify := range map[string]func(*Enrollment){
		"network":     func(e *Enrollment) { e.Network = "other" },
		"route":       func(e *Enrollment) { e.RoutedPrefixes = scope.RoutedPrefixes },
		"san":         func(e *Enrollment) { e.IPv6 = addr("fd43::7") },
		"issuer-vip":  func(e *Enrollment) { e.AnycastIPs = []netip.Addr{addr("192.0.2.10")} },
		"cluster-vip": func(e *Enrollment) { e.AnycastIPs = []netip.Addr{addr("198.51.100.1")} },
	} {
		t.Run(name, func(t *testing.T) {
			e := enrollment
			modify(&e)
			_, err := delegated.IssueLeaf(req, e)
			require.Error(t, err)
			// An external issuer can sign such a leaf. A relying party must reject its path.
			ext, err := e.extension()
			require.NoError(t, err)
			out := *cert
			out.ExtraExtensions = []pkix.Extension{ext}
			out.IPAddresses = []net.IP{e.IPv4.AsSlice(), e.IPv6.AsSlice()}
			der, err := x509.CreateCertificate(rand.Reader, &out, inter, leafKey.Public(), key)
			require.NoError(t, err)
			external, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			peer, err := NewPeerID(e.IPv4, e.IPv6)
			require.NoError(t, err)
			_, err = VerifyChain([]*x509.Certificate{external, inter}, roots, cluster, peer, x509.ExtKeyUsageServerAuth, now)
			require.Error(t, err)
		})
	}
}
