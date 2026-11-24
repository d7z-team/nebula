package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIssuanceAndCMS(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	profile := CAProfile{
		Subject: pkix.Name{CommonName: "offline"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Scope:        &Scope{Network: "mesh", Cluster: true},
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd42::/64")},
		MaxPathLen:   1,
	}
	root, err := CreateRoot(key, profile)
	require.NoError(t, err)
	_, interKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	req, err := CreateCSR(interKey, pkix.Name{CommonName: "issuer"})
	require.NoError(t, err)
	profile.Scope = nil
	profile.Subject = req.Subject
	profile.MaxPathLen = 0
	inter, err := (Issuer{[]*x509.Certificate{root}, key}).IssueCA(req, profile, sha256.Sum256(req.RawSubjectPublicKeyInfo))
	require.NoError(t, err)
	issuer := Issuer{[]*x509.Certificate{inter, root}, interKey}
	cluster, err := ReadClusterCA(root)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pq, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	pq65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pq87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	for name, signer := range map[string]crypto.Signer{"ECDSA": key, "RSA": rsaKey, "Ed25519": interKey, "MLDSA44": pq, "MLDSA65": pq65, "MLDSA87": pq87} {
		t.Run(name, func(t *testing.T) {
			req, err := CreateCSR(signer, pkix.Name{CommonName: name})
			require.NoError(t, err)
			enrollment := Enrollment{Name: name, IPv4: netip.MustParseAddr("10.0.0.1"), IPv6: netip.MustParseAddr("fd42::1"), Scope: Scope{Network: "mesh"}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
			peer, err := NewPeerID(enrollment.IPv4, enrollment.IPv6)
			require.NoError(t, err)
			leaf, err := issuer.IssueLeaf(req, enrollment)
			require.NoError(t, err)
			crt := tls.Certificate{Certificate: [][]byte{leaf.Raw, inter.Raw}, PrivateKey: signer}
			wire, err := SignObject("team", "publication", []byte("original publisher"), crt)
			require.NoError(t, err)
			body, chain, err := VerifyObjectSignature(wire, "team", "publication")
			require.NoError(t, err)
			require.Equal(t, "original publisher", string(body))
			_, err = VerifyChain(chain, roots, cluster, peer, x509.ExtKeyUsageCodeSigning, now)
			require.NoError(t, err)
			_, _, err = VerifyObjectSignature(wire, "other", "publication")
			require.Error(t, err)
			_, _, err = VerifyObjectSignature(wire, "team", "introduction")
			require.Error(t, err)
			changed := bytes.Replace(wire, []byte("original"), []byte("modified"), 1)
			_, _, err = VerifyObjectSignature(changed, "team", "publication")
			require.Error(t, err)
			t.Run("document limit", func(t *testing.T) {
				data := make([]byte, MaxDocument)
				chainOnly := tls.Certificate{Certificate: crt.Certificate}
				limit := sort.Search(len(data), func(i int) bool {
					err := CheckObjectSize("team", "publication", data[:i+1], chainOnly)
					if err != nil {
						require.ErrorIs(t, err, ErrDocumentTooLarge)
					}
					return err != nil
				})
				require.Positive(t, limit)
				require.Less(t, limit, len(data))
				wire, err := SignObject("team", "publication", data[:limit], crt)
				require.NoError(t, err)
				got, _, err := VerifyObjectSignature(wire, "team", "publication")
				require.NoError(t, err)
				require.Equal(t, data[:limit], got)
				_, _, err = VerifyObjectSignature(append(wire, 0), "team", "publication")
				require.Error(t, err)
				// ECDSA integers have variable DER length. Other signatures fill
				// the preflight budget exactly.
				if name != "ECDSA" {
					require.Len(t, wire, MaxDocument)
					_, err = SignObject("team", "publication", data[:limit+1], crt)
					require.ErrorIs(t, err, ErrDocumentTooLarge)
				}
			})
			if name == "ECDSA" {
				exe, err := exec.LookPath("openssl")
				if err != nil {
					return
				}
				dir := t.TempDir()
				caPath := filepath.Join(dir, "root.pem")
				require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600))
				cmd := exec.Command(exe, "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any", "-CAfile", caPath)
				cmd.Stdin = bytes.NewReader(wire)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
				require.Contains(t, string(out), "original publisher")
			}
		})
	}
}
