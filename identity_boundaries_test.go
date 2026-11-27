package nebula

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"gopkg.d7z.net/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestAuthorizedPKIXPaths(t *testing.T) {
	f := newFixture(t, "")
	now := time.Now().Truncate(time.Second)
	profile := pki.CAProfile{Subject: pkix.Name{CommonName: "second root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxPathLen: 1}
	rootKey, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	root, err := pki.CreateRoot(rootKey, profile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	roots.AddCert(f.root.Chain[0])
	key, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	req, err := pki.CreateCSR(key, pkix.Name{CommonName: "intermediate"})
	require.NoError(t, err)
	v4, v6 := f.cluster.MemberPrefixes()
	profile.PermittedIPs = []netip.Prefix{v4, v6}
	profile.Subject = req.Subject
	profile.MaxPathLen = 0
	profile.NotBefore = now.Add(-time.Minute)
	profile.NotAfter = now.Add(10 * time.Minute)
	issuer := pki.Issuer{Chain: []*x509.Certificate{f.ca}, Signer: f.key}
	inter, err := issuer.IssueCA(req, profile, sha256.Sum256(req.RawSubjectPublicKeyInfo))
	require.NoError(t, err)
	templateCA := *inter
	templateCA.ExtraExtensions = inter.Extensions
	altDER, err := x509.CreateCertificate(rand.Reader, &templateCA, root, key.Public(), rootKey)
	require.NoError(t, err)
	alt, err := x509.ParseCertificate(altDER)
	require.NoError(t, err)
	leafKey := labKey(f.ips[0])
	req, err = pki.CreateCSR(leafKey, pkix.Name{})
	require.NoError(t, err)
	enroll := pki.Enrollment{Name: "host-1", Scope: pki.Scope{Network: "lab"}, IPv4: f.ips[0], IPv6: f.cfg.Members[0].IPv6, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Minute)}
	leaf, err := (pki.Issuer{Chain: []*x509.Certificate{inter, f.ca}, Signer: key}).IssueGrant(req, enroll)
	require.NoError(t, err)
	chain := []*x509.Certificate{leaf, inter, alt, f.ca}
	paths, err := pki.VerifyGrant(chain, roots, f.cluster, f.cfg.Members[0].ID, now)
	require.NoError(t, err)
	require.Len(t, paths, 1)
	require.True(t, paths[0][2].Equal(f.ca))
	view, err := f.cfg.compile(f.cluster)
	require.NoError(t, err)
	n := &Node{id: f.cfg.Members[0].ID, roots: roots}
	cutoff := now.Add(time.Minute)
	accepted := root
	n.o.Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		require.True(t, c.Local)
		require.Equal(t, leaf.Raw, c.Chain[0].Raw)
		if !accepted.Equal(c.Chain[len(c.Chain)-1]) {
			return time.Time{}, errors.New("root denied")
		}
		return cutoff, nil
	}
	_, err = n.authorizeGrant(t.Context(), view, n.id, chain)
	require.ErrorIs(t, err, ErrPathPolicy)
	accepted = f.root.Chain[0]
	until, err := n.authorizeGrant(t.Context(), view, n.id, chain)
	require.NoError(t, err)
	require.Equal(t, cutoff, until)
	cutoff = now.Add(time.Hour)
	until, err = n.authorizeGrant(t.Context(), view, n.id, chain)
	require.NoError(t, err)
	require.Equal(t, leaf.NotAfter, until)

	// Both issuers are trusted in this cluster and use the same leaf serial.
	template := *leaf
	template.ExtraExtensions = leaf.Extensions
	der, err := x509.CreateCertificate(rand.Reader, &template, f.ca, leafKey.Public(), f.key)
	require.NoError(t, err)
	direct, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Zero(t, leaf.SerialNumber.Cmp(direct.SerialNumber))
	withdrawn := errors.New("issuer and serial withdrawn")
	n.o.Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if c.Chain[1].Equal(f.ca) && c.Chain[0].SerialNumber.Cmp(direct.SerialNumber) == 0 {
			return time.Time{}, withdrawn
		}
		return time.Time{}, nil
	}
	_, err = n.authorizeGrant(t.Context(), view, n.id, []*x509.Certificate{direct, f.ca})
	require.ErrorIs(t, err, withdrawn)
	_, err = n.authorizeGrant(t.Context(), view, n.id, chain)
	require.NoError(t, err)
}

func TestCredentialBudget(t *testing.T) {
	f := newFixture(t, "")
	set := f.opts[0].Auth.Certificates
	leaf, err := x509.ParseCertificate(set.Grant[0])
	require.NoError(t, err)
	// Large noncritical extensions keep the DER length fields and Ed25519
	// signature size constant throughout the +/- one byte cases.
	pad := 22 << 10
	encode := func(n int) []byte {
		leaf.ExtraExtensions = append(slices.Clip(leaf.Extensions), pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 3}, Value: make([]byte, n)})
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, leaf.PublicKey, f.key)
		require.NoError(t, err)
		return der
	}
	pad += (24 << 10) - len(encode(pad)) - len(leaf.RawIssuer) - len(set.Node.Certificate[0]) - len(set.Grant[1])
	for _, delta := range []int{-1, 0, 1} {
		set.Grant = [][]byte{encode(pad + delta), f.ca.Raw}
		require.Equal(t, (24<<10)+delta, len(set.Grant[0])+len(leaf.RawIssuer)+len(set.Node.Certificate[0])+len(set.Grant[1]))
		_, err := prepareCertificates(set)
		if delta > 0 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
