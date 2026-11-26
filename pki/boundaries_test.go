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
	root, anchor, err := testClusterCA(t, key, profile)
	require.NoError(t, err)
	issuer := Issuer{Chain: []*x509.Certificate{root}, Signer: key}
	interKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	siteCSR, err := CreateCSR(interKey, pkix.Name{CommonName: "issuer"})
	require.NoError(t, err)
	interProfile := CAProfile{PermittedIPs: profile.PermittedIPs, Subject: siteCSR.Subject, NotBefore: now.Add(-20 * time.Minute), NotAfter: now.Add(20 * time.Minute), MaxPathLen: 0}
	approvedSPKI, err := x509.MarshalPKIXPublicKey(interKey.Public())
	require.NoError(t, err)
	approvedHash := sha256.Sum256(approvedSPKI)
	_, err = issuer.IssueCA(siteCSR, interProfile, sha256.Sum256(root.RawSubjectPublicKeyInfo))
	require.ErrorContains(t, err, "fingerprint")
	inter, err := issuer.IssueCA(siteCSR, interProfile, approvedHash)
	require.NoError(t, err)
	interIssuer := Issuer{Chain: []*x509.Certificate{inter, root}, Signer: interKey}
	_, err = interIssuer.IssueCA(siteCSR, interProfile, approvedHash)
	require.Error(t, err)
	tooDeep := interProfile
	tooDeep.MaxPathLen = math.MaxInt
	_, err = issuer.IssueCA(siteCSR, tooDeep, approvedHash)
	require.Error(t, err)

	leafKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"requested.test"}, Subject: pkix.Name{CommonName: "unapproved"}}, leafKey)
	require.NoError(t, err)
	req, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	enroll := Enrollment{Name: "publisher", IPv4: netip.MustParseAddr("10.0.0.1"), IPv6: netip.MustParseAddr("fd42::1"), Scope: Scope{Network: "mesh"}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	peer, err := NewPeerID(req.PublicKey)
	require.NoError(t, err)
	leaf, err := interIssuer.IssueGrant(req, enroll)
	require.NoError(t, err)
	require.Empty(t, leaf.DNSNames)
	require.Equal(t, enroll.Name, leaf.Subject.CommonName)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, leaf.ExtKeyUsage)
	require.False(t, leaf.IsCA)
	t.Run("issuer usages", func(t *testing.T) {
		template := *inter
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		der, err := x509.CreateCertificate(rand.Reader, &template, root, interKey.Public(), key)
		require.NoError(t, err)
		limited, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		issuing := Issuer{Chain: []*x509.Certificate{limited, root}, Signer: interKey}
		_, err = issuing.IssueGrant(req, enroll)
		require.NoError(t, err)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		der, err = x509.CreateCertificate(rand.Reader, &template, root, interKey.Public(), key)
		require.NoError(t, err)
		issuing.Chain[0], err = x509.ParseCertificate(der)
		require.NoError(t, err)
		_, err = issuing.IssueGrant(req, enroll)
		require.Error(t, err)
	})
	for _, tc := range []struct {
		name   string
		change func(*Enrollment)
	}{
		{"before-parent", func(e *Enrollment) { e.NotBefore = inter.NotBefore.Add(-time.Second) }},
		{"after-parent", func(e *Enrollment) { e.NotAfter = inter.NotAfter.Add(time.Second) }},
		{"same-DER-second", func(e *Enrollment) { e.NotBefore = now; e.NotAfter = now.Add(time.Millisecond) }},
		{"zoned-address", func(e *Enrollment) { e.IPv6 = netip.MustParseAddr("fe80::1%eth0") }},
		{"other-approved-key", func(e *Enrollment) { e.PublicKeyHash = approvedHash }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := enroll
			tc.change(&e)
			_, err := interIssuer.IssueGrant(req, e)
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
		t.Run(tc.name, func(t *testing.T) { _, err := tc.ca.IssueGrant(req, enroll); require.Error(t, err) })
	}
	noCertSign := *inter
	noCertSign.KeyUsage = x509.KeyUsageCRLSign
	der, err = x509.CreateCertificate(rand.Reader, &noCertSign, root, interKey.Public(), key)
	require.NoError(t, err)
	bad, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	_, err = (Issuer{[]*x509.Certificate{bad, root}, interKey}).IssueGrant(req, enroll)
	require.Error(t, err)
	broken := *req
	broken.Signature = bytes.Clone(req.Signature)
	broken.Signature[0] ^= 1
	_, err = interIssuer.IssueGrant(&broken, enroll)
	require.Error(t, err)

	cluster, err := ReadClusterCA(root)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	chain := []*x509.Certificate{leaf, inter, root}
	// The leaf fits the parent and is signed by the intermediate's key in
	// every case. Check the delegation itself on externally issued paths.
	for name, ranges := range map[string][]netip.Prefix{
		"no-issuer-ranges": nil, "single-family": {profile.PermittedIPs[0]},
		"excess-delegation": {profile.PermittedIPs[1], profile.PermittedIPs[0], netip.MustParsePrefix("192.0.2.0/24")},
	} {
		t.Run(name, func(t *testing.T) {
			site := interProfile
			site.PermittedIPs = ranges
			_, err := issuer.IssueCA(siteCSR, site, approvedHash)
			require.Error(t, err)
			tmpl, err := caTemplate(site)
			require.NoError(t, err)
			der, err := x509.CreateCertificate(rand.Reader, tmpl, root, interKey.Public(), key)
			require.NoError(t, err)
			external, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			externalIssuer := Issuer{Chain: []*x509.Certificate{external, root}, Signer: interKey}
			_, err = externalIssuer.IssueGrant(req, enroll)
			require.Error(t, err)
			_, err = VerifyGrant([]*x509.Certificate{leaf, external, root}, roots, cluster, peer, now)
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"before", leaf.NotBefore.Add(-time.Nanosecond), false}, {"not-before", leaf.NotBefore, true}, {"not-after", leaf.NotAfter, true}, {"after", leaf.NotAfter.Add(time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyGrant(chain, roots, cluster, peer, tc.at)
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
	}{
		{"missing-intermediate", chain[:1], roots}, {"untrusted", chain, x509.NewCertPool()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyGrant(tc.chain, tc.roots, cluster, peer, now)
			require.Error(t, err)
		})
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
		MaxPathLen:   2,
		Scope:        &scope,
		PermittedIPs: []netip.Prefix{prefix("10.0.0.0/8"), prefix("fd42::/64")},
	}
	rootKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	root, anchor, err := testClusterCA(t, rootKey, profile)
	require.NoError(t, err)
	issuer := Issuer{Chain: []*x509.Certificate{root}, Signer: rootKey}
	regionKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	regionCSR, err := CreateCSR(regionKey, pkix.Name{CommonName: "region"})
	require.NoError(t, err)
	profile.Subject, profile.MaxPathLen, profile.Scope = regionCSR.Subject, 1, nil
	profile.PermittedIPs = []netip.Prefix{prefix("10.1.3.0/24"), prefix("10.1.2.0/24"), prefix("fd42::/96")}
	region, err := issuer.IssueCA(regionCSR, profile, sha256.Sum256(regionCSR.RawSubjectPublicKeyInfo))
	require.NoError(t, err)
	regional := Issuer{Chain: []*x509.Certificate{region, root}, Signer: regionKey}
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
	approved := sha256.Sum256(req.RawSubjectPublicKeyInfo)
	beyondRegion := profile
	beyondRegion.PermittedIPs = []netip.Prefix{prefix("10.1.0.0/16"), prefix("fd42::/120")}
	_, err = regional.IssueCA(req, beyondRegion, approved)
	require.ErrorContains(t, err, "exceeds issuer permission")
	inter, err := regional.IssueCA(req, profile, approved)
	require.NoError(t, err)
	delegated := Issuer{Chain: []*x509.Certificate{inter, region, root}, Signer: key}
	leafKey, err := GenerateKey("p256")
	require.NoError(t, err)
	req, err = CreateCSR(leafKey, pkix.Name{})
	require.NoError(t, err)
	// .31 is a primary address on the cluster subnet. The issuer's /27 limits its SANs.
	enrollment := Enrollment{
		IPv4: addr("10.1.2.31"), IPv6: addr("fd42::7"),
		Scope:         Scope{Network: restricted.Network, RoutedPrefixes: restricted.RoutedPrefixes, AnycastIPs: []netip.Addr{addr("192.0.2.200")}},
		PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo),
		NotBefore:     now.Add(-time.Minute), NotAfter: now.Add(time.Minute),
	}
	id, err := NewPeerID(req.PublicKey)
	require.NoError(t, err)
	require.Equal(t, enrollment.PublicKeyHash[:], id[:])
	cert, err := delegated.IssueGrant(req, enrollment)
	require.NoError(t, err)
	identity, err := ReadIdentity(cert)
	require.NoError(t, err)
	require.Equal(t, enrollment.AnycastIPs, identity.AnycastIPs)
	cluster, err := ReadClusterCA(root)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	chain := []*x509.Certificate{cert, inter, region, root}
	_, err = VerifyGrant(chain, roots, cluster, id, now)
	require.NoError(t, err)
	_, err = VerifyGrant(chain, roots, Cluster{}, id, now)
	require.Error(t, err)
	other := id
	other[19]++
	_, err = VerifyGrant(chain, roots, cluster, other, now)
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
	_, err = VerifyGrant(chain, roots, cluster, id, now)
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
			_, err := delegated.IssueGrant(req, e)
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
			peer, err := NewPeerID(req.PublicKey)
			require.NoError(t, err)
			_, err = VerifyGrant([]*x509.Certificate{external, inter, region, root}, roots, cluster, peer, now)
			require.Error(t, err)
		})
	}
}

func TestNodeAndGrantProof(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, err := GenerateKey("ed25519")
	require.NoError(t, err)
	root, err := CreateRoot(key, CAProfile{Subject: pkix.Name{CommonName: "Identity Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxPathLen: 1})
	require.NoError(t, err)
	authority := Issuer{Chain: []*x509.Certificate{root}, Signer: key}
	siteKey, err := GenerateKey("p256")
	require.NoError(t, err)
	csr, err := CreateCSR(siteKey, pkix.Name{})
	require.NoError(t, err)
	ca, err := authority.IssueCA(csr, CAProfile{Subject: pkix.Name{CommonName: "Cluster"}, Scope: &Scope{Network: "private", Cluster: true}, PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00::/64")}, NotBefore: root.NotBefore, NotAfter: root.NotAfter}, sha256.Sum256(csr.RawSubjectPublicKeyInfo))
	require.NoError(t, err)
	cluster, err := ReadClusterCA(ca)
	require.NoError(t, err)
	issuer := Issuer{Chain: []*x509.Certificate{ca, root}, Signer: siteKey}
	nodeKey, err := GenerateKey("ed25519")
	require.NoError(t, err)
	csr, err = CreateCSR(nodeKey, pkix.Name{CommonName: "private-host"})
	require.NoError(t, err)
	hash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	node, err := authority.IssueNode(csr, hash, now, root.NotAfter)
	require.NoError(t, err)
	grant, err := issuer.IssueGrant(csr, Enrollment{Scope: Scope{Network: "private"}, IPv4: netip.MustParseAddr("10.0.0.1"), IPv6: netip.MustParseAddr("fd00::1"), PublicKeyHash: hash, NotBefore: now, NotAfter: root.NotAfter})
	require.NoError(t, err)
	other, err := authority.IssueNode(csr, hash, now, root.NotAfter)
	require.NoError(t, err)
	for _, identity := range []*x509.Certificate{node, other} {
		id, _, paths, err := VerifyObjectSigner([]*x509.Certificate{grant, ca, identity}, root, cluster, now)
		require.NoError(t, err)
		require.Equal(t, PeerID(hash), id.ID)
		require.Equal(t, grant.Raw, paths[0][0].Raw)
	}
	_, err = issuer.IssueNode(csr, hash, now, root.NotAfter)
	require.Error(t, err)
	template := *node
	template.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	forged, err := x509.CreateCertificate(rand.Reader, &template, ca, nodeKey.Public(), siteKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(forged)
	require.NoError(t, err)
	_, err = VerifyNode(leaf, root, x509.ExtKeyUsageServerAuth, now)
	require.Error(t, err)
	wire, err := SignObject("private", "publication", []byte("ready"), tls.Certificate{Certificate: [][]byte{grant.Raw, ca.Raw, node.Raw}, PrivateKey: nodeKey})
	require.NoError(t, err)
	// A relay can re-encode the unsigned CMS certificate bag. Even a valid
	// renewal for the same key must not replace the identity used at signing.
	cms, err := parseCMS(wire)
	require.NoError(t, err)
	for i, c := range cms.Certificates {
		if bytes.Equal(c.FullBytes, node.Raw) {
			cms.Certificates[i] = raw(other.Raw)
		}
	}
	tampered, err := wrapCMS(cms)
	require.NoError(t, err)
	_, _, err = VerifyObjectSignature(tampered, "private", "publication")
	require.Error(t, err)
}
