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

func ParseCertificates(b []byte) ([]*x509.Certificate, error) {
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

// ParseChain parses the DER certificates presented by a TLS endpoint.
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

// VerifyChain builds ordinary PKIX paths and checks the expected identity, usage and mesh delegation on each path.
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, network string, peer PeerID, usage x509.ExtKeyUsage, now time.Time) ([][]*x509.Certificate, error) {
	if roots == nil || len(chain) == 0 || chain[0] == nil {
		return nil, errors.New("chain and explicit roots required")
	}
	pool := x509.NewCertPool()
	for _, ca := range chain[1:] {
		if ca == nil {
			return nil, errors.New("nil intermediate")
		}
		pool.AddCert(ca)
	}
	paths, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, DNSName: peer.IPv4().String(), KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now})
	if err != nil {
		return nil, err
	}
	identity, accepted, err := VerifiedPeer(paths, network, usage)
	if err != nil {
		return nil, err
	}
	if identity.ID != peer {
		return nil, errors.New("unexpected mesh address pair")
	}
	return accepted, nil
}

// VerifiedPeer validates the mesh profile of one PKIX-authenticated peer.
// paths must be the verified candidate chains from the same X.509 or TLS verification.
func VerifiedPeer(paths [][]*x509.Certificate, network string, usage x509.ExtKeyUsage) (Identity, [][]*x509.Certificate, error) {
	if len(paths) == 0 || len(paths[0]) == 0 {
		return Identity{}, nil, errors.New("no verified chain")
	}
	leaf := paths[0][0]
	identity, err := ReadIdentity(leaf)
	if err != nil {
		return Identity{}, nil, err
	}
	if identity.Network != network {
		return Identity{}, nil, errors.New("unexpected mesh network")
	}
	if !slices.Contains(leaf.ExtKeyUsage, usage) {
		return Identity{}, nil, errors.New("mesh leaf missing required extended key usage")
	}
	var accepted [][]*x509.Certificate
	for _, path := range paths {
		if len(path) > 0 && path[0].Equal(leaf) && checkDelegation(identity.Scope, path[1:]) == nil {
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
