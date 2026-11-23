package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestAuthorizedPKIXPaths(t *testing.T) {
	f := newFixture(t, "tcp")
	now := time.Now().Truncate(time.Second)
	profile := pki.CAProfile{Subject: pkix.Name{CommonName: "second root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxPathLen: 1}
	rootKey, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	root, err := pki.CreateRoot(rootKey, profile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	roots.AddCert(f.ca)
	key, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	req, err := pki.CreateCSR(key, pkix.Name{CommonName: "intermediate"})
	require.NoError(t, err)
	profile.Subject = req.Subject
	profile.MaxPathLen = 0
	profile.NotBefore = now.Add(-time.Minute)
	profile.NotAfter = now.Add(10 * time.Minute)
	var intermediates []*x509.Certificate
	for _, issuer := range []pki.Issuer{{Chain: []*x509.Certificate{f.ca}, Signer: f.key}, {Chain: []*x509.Certificate{root}, Signer: rootKey}} {
		inter, err := issuer.IssueCA(req, profile)
		require.NoError(t, err)
		intermediates = append(intermediates, inter)
	}
	leafKey, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	req, err = pki.CreateCSR(leafKey, pkix.Name{})
	require.NoError(t, err)
	enroll := pki.Enrollment{Name: "host-1", Scope: pki.Scope{Network: "lab"}, IPv4: f.ips[0], IPv6: labPeer(f.ips[0]).IPv6(), Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Minute)}
	leaf, err := (pki.Issuer{Chain: intermediates[:1], Signer: key}).IssueLeaf(req, enroll)
	require.NoError(t, err)
	chain := append([]*x509.Certificate{leaf}, intermediates...)
	paths, err := pki.VerifyChain(chain, roots, "lab", labPeer(f.ips[0]), x509.ExtKeyUsageClientAuth, now)
	require.NoError(t, err)
	require.Len(t, paths, 2)
	view, err := f.cfg.compile()
	require.NoError(t, err)
	n := &Node{id: labPeer(f.ips[0]), o: Options{Roots: roots}}
	cutoff := now.Add(time.Minute)
	var accepted *x509.Certificate
	n.o.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
		require.True(t, c.Local)
		require.Equal(t, leaf.Raw, c.Chain[0].Raw)
		if accepted == nil || !accepted.Equal(c.Chain[len(c.Chain)-1]) {
			return time.Time{}, errors.New("root denied")
		}
		return cutoff, nil
	}
	for _, accepted = range []*x509.Certificate{root, f.ca} {
		until, err := n.authorizeChain(t.Context(), view, n.id, chain, x509.ExtKeyUsageClientAuth)
		require.NoError(t, err)
		require.Equal(t, cutoff, until)
	}
	cutoff = now.Add(time.Hour)
	until, err := n.authorizeChain(t.Context(), view, n.id, chain, x509.ExtKeyUsageClientAuth)
	require.NoError(t, err)
	require.Equal(t, leaf.NotAfter, until)
	accepted = nil
	_, err = n.authorizeChain(t.Context(), view, n.id, chain, x509.ExtKeyUsageClientAuth)
	require.ErrorIs(t, err, ErrPathPolicy)

	// Serial numbers are scoped to the issuer. Exercise the host policy with
	// the same leaf key, subject and serial signed by two different issuers.
	template := *leaf
	template.ExtraExtensions = leaf.Extensions
	template.SerialNumber = big.NewInt(17)
	for _, issuer := range []pki.Issuer{{Chain: []*x509.Certificate{f.ca}, Signer: f.key}, {Chain: []*x509.Certificate{root}, Signer: rootKey}} {
		der, err := x509.CreateCertificate(rand.Reader, &template, issuer.Chain[0], leafKey.Public(), issuer.Signer)
		require.NoError(t, err)
		other, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		n.o.CheckChain = func(_ context.Context, check ChainCheck) (time.Time, error) {
			if check.Chain[0].SerialNumber.Cmp(big.NewInt(17)) == 0 && check.Chain[1].Equal(f.ca) {
				return time.Time{}, errors.New("issuer and serial withdrawn")
			}
			return time.Time{}, nil
		}
		_, err = n.authorizeChain(t.Context(), view, n.id, []*x509.Certificate{other}, x509.ExtKeyUsageClientAuth)
		if issuer.Chain[0] == f.ca {
			require.ErrorIs(t, err, ErrPathPolicy)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestCredentialAndFrameBudgets(t *testing.T) {
	f := newFixture(t, "tcp")
	set := f.opts[0].Certificates
	leaf, err := x509.ParseCertificate(set.Client.Certificate[0])
	require.NoError(t, err)
	// Large noncritical extensions keep the DER length fields and Ed25519
	// signature size constant throughout the +/- one byte cases.
	pad := 22 << 10
	encode := func(n int) []byte {
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 3}, Value: make([]byte, n)}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, leaf.PublicKey, f.key)
		require.NoError(t, err)
		return der
	}
	pad += (24 << 10) - len(encode(pad)) - len(leaf.RawIssuer)
	for _, delta := range []int{-1, 0, 1} {
		set.Client.Certificate = [][]byte{encode(pad + delta)}
		require.Equal(t, (24<<10)+delta, len(set.Client.Certificate[0])+len(leaf.RawIssuer))
		_, err := prepareCertificates(set)
		if delta > 0 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
	f.start()
	for _, delta := range []int{-1, 0, 1} {
		_, err := f.nodes[0].Publish(t.Context(), "app/test", make([]byte, maxEventPayload+delta))
		if delta > 0 {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		var wire bytes.Buffer
		payload := bytes.Repeat([]byte{42}, maxControlFrame+delta)
		require.NoError(t, writeFrame(&wire, payload))
		got, err := readFrame(&wire, maxControlFrame)
		if delta > 0 {
			require.Error(t, err)
			require.Equal(t, len(payload), wire.Len())
		} else {
			require.NoError(t, err)
			require.Equal(t, payload, got)
		}
	}
}

func TestPathQueriesPreserveSelection(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
	}
	f.start()
	n, peer := f.nodes[0], f.ips[1]
	require.NoError(t, n.ConnectPeer(t.Context(), peer))
	n.mu.Lock()
	n.peers[labPeer(peer)].active = nil
	n.mu.Unlock()
	status := n.Paths()
	require.Len(t, status, 1)
	require.True(t, status[0].Active)
	require.Equal(t, 1280, n.RecommendedMTU(peer, true, 1280))
	n.mu.Lock()
	active := n.peers[labPeer(peer)].active
	n.mu.Unlock()
	require.Nil(t, active)
}
