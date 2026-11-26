// Package pki supports X.509 certificate issuance and verification and CMS signatures for mesh objects.
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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"time"
)

func ValidName(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-_.") == ""
}

// ParseCertificatesPEM reads one or more PEM certificates in the order supplied.
func ParseCertificatesPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(b)) > 0 {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("expected PEM certificate")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	if len(out) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	return out, nil
}

// ParseChain parses a leaf-first TLS chain with one DER certificate per element.
func ParseChain(der [][]byte) ([]*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	chain := make([]*x509.Certificate, len(der))
	for i, b := range der {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		chain[i] = c
	}
	return chain, nil
}

// VerifyGrant builds ordinary PKIX paths and checks the expected identity, usage and mesh delegation on each path.
func VerifyGrant(chain []*x509.Certificate, roots *x509.CertPool, cluster Cluster, peer PeerID, now time.Time) ([][]*x509.Certificate, error) {
	_, paths, err := verifyGrantIdentity(chain, roots, cluster, peer, now)
	return paths, err
}

func verifyGrantIdentity(chain []*x509.Certificate, roots *x509.CertPool, cluster Cluster, peer PeerID, now time.Time) (Identity, [][]*x509.Certificate, error) {
	if roots == nil || len(chain) == 0 || chain[0] == nil {
		return Identity{}, nil, errors.New("chain and explicit roots required")
	}
	pool := x509.NewCertPool()
	for _, ca := range chain[1:] {
		if ca == nil || !ca.IsCA {
			return Identity{}, nil, errors.New("invalid intermediate CA")
		}
		pool.AddCert(ca)
	}
	leaf := chain[0]
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, CurrentTime: now})
	if err != nil {
		return Identity{}, nil, err
	}
	identity, err := ReadIdentity(leaf)
	if err != nil {
		return Identity{}, nil, err
	}
	if identity.ID != peer {
		return Identity{}, nil, errors.New("unexpected grant key")
	}
	if err := cluster.validateIdentity(identity); err != nil {
		return Identity{}, nil, err
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return Identity{}, nil, errors.New("mesh leaf missing required extended key usage")
	}
	var accepted [][]*x509.Certificate
	for _, path := range paths {
		// The pinned cluster CA must be the direct child of the ordinary root.
		if len(path) < 3 || string(path[len(path)-2].Raw) != cluster.certificate || ValidateRoot(path[len(path)-1]) != nil {
			continue
		}
		ca, err := checkDelegation(&identity.Scope, path[1:])
		if err == nil && ca == path[len(path)-2] {
			accepted = append(accepted, path)
		}
	}
	if len(accepted) == 0 {
		return Identity{}, nil, errors.New("mesh chain not authorized")
	}
	return identity, accepted, nil
}

// GenerateKey creates a software signing key suitable for PKCS#8 export.
// Issuance also accepts externally generated crypto.Signer keys.
func GenerateKey(algorithm string) (crypto.Signer, error) {
	switch algorithm {
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "ml-dsa-44":
		return mldsa.GenerateKey(mldsa.MLDSA44())
	default:
		return nil, errors.New("unsupported key generation algorithm")
	}
}

func ParseKeyPEM(b []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected PKCS#8 PRIVATE KEY")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("signing key required")
	}
	return signer, nil
}

func MatchesKey(key crypto.PrivateKey, c *x509.Certificate) bool {
	signer, ok := key.(crypto.Signer)
	if !ok || c == nil {
		return false
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(c.PublicKey)
}

const nodeCommonName = "mesh node"

var nodeUsage = append(slices.Clone(meshOID), 1)

// ValidateRoot checks the profile of the ordinary, self-signed identity trust anchor.
func ValidateRoot(root *x509.Certificate) error {
	if root == nil || !root.IsCA || root.CheckSignatureFrom(root) != nil || !bytes.Equal(root.RawSubject, root.RawIssuer) || len(root.PermittedIPRanges)+len(root.ExcludedIPRanges) != 0 {
		return errors.New("ordinary self-signed root required")
	}
	if _, present, err := CertificateScope(root); err != nil || present {
		return errors.New("ordinary root must be free of mesh scope")
	}
	return nil
}

// VerifyNode verifies a node leaf issued directly by the configured root.
func VerifyNode(leaf, root *x509.Certificate, usage x509.ExtKeyUsage, now time.Time) (PeerID, error) {
	if err := ValidateRoot(root); err != nil {
		return PeerID{}, err
	}
	if leaf == nil || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		leaf.Subject.CommonName != nodeCommonName || len(leaf.Subject.Names) != 1 ||
		len(leaf.UnknownExtKeyUsage) != 1 || !leaf.UnknownExtKeyUsage[0].Equal(nodeUsage) ||
		len(leaf.ExtKeyUsage) != 2 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		(usage != x509.ExtKeyUsageClientAuth && usage != x509.ExtKeyUsageServerAuth) {
		return PeerID{}, errors.New("invalid node certificate profile")
	}
	// Keep the wire leaf free of SANs, issuer URLs and deployment-specific extensions.
	for _, e := range leaf.Extensions {
		oid := e.Id
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 29 {
			switch oid[3] {
			case 14, 15, 19, 35, 37:
				continue
			}
		}
		return PeerID{}, errors.New("unexpected node certificate extension")
	}
	// Verify builds the direct path using this root alone and no intermediates.
	if leaf.Equal(root) {
		return PeerID{}, errors.New("node certificate is not root-issued")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return PeerID{}, err
	}
	return NewPeerID(leaf.PublicKey)
}
