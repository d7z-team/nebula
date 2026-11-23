// Package demo prepares ephemeral credentials and loopback sockets for the examples.
package demo

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

func NewIssuer() (pki.Issuer, error) {
	key, err := pki.GenerateKey("ed25519")
	if err != nil {
		return pki.Issuer{}, err
	}
	now := time.Now()
	root, err := pki.CreateRoot(key, pki.CAProfile{
		Subject: pkix.Name{CommonName: "Demo CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	})
	if err != nil {
		return pki.Issuer{}, err
	}
	return pki.Issuer{Chain: []*x509.Certificate{root}, Signer: key}, nil
}

// Enrollment builds the issuer's authorization from the approved key and addresses.
func Enrollment(approved crypto.PublicKey, v4, v6 netip.Addr, routes []netip.Prefix) (pki.Enrollment, error) {
	spki, err := x509.MarshalPKIXPublicKey(approved)
	if err != nil {
		return pki.Enrollment{}, err
	}
	now := time.Now()
	return pki.Enrollment{
		PublicKeyHash: sha256.Sum256(spki), IPv4: v4, IPv6: v6,
		Scope:     pki.Scope{Network: "demo", RoutedPrefixes: routes},
		Usages:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
	}, nil
}
