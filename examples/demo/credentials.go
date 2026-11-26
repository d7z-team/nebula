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

// NewIssuers creates the ordinary root and its demo cluster authority.
func NewIssuers() (root, cluster pki.Issuer, err error) {
	key, err := pki.GenerateKey("ed25519")
	if err != nil {
		return root, cluster, err
	}
	now := time.Now()
	anchor, err := pki.CreateRoot(key, pki.CAProfile{Subject: pkix.Name{CommonName: "Demo Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), MaxPathLen: 2})
	if err != nil {
		return root, cluster, err
	}
	root = pki.Issuer{Chain: []*x509.Certificate{anchor}, Signer: key}
	key, err = pki.GenerateKey("ed25519")
	if err != nil {
		return root, cluster, err
	}
	csr, err := pki.CreateCSR(key, pkix.Name{})
	if err != nil {
		return root, cluster, err
	}
	cert, err := root.IssueCA(csr, pki.CAProfile{
		Scope: &pki.Scope{
			Network: "demo", Cluster: true,
			RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			AnycastPools:   []netip.Prefix{netip.MustParsePrefix("10.13.0.192/27")},
		},
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd13::/64")},
		MaxPathLen:   1, Subject: pkix.Name{CommonName: "Demo CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}, sha256.Sum256(csr.RawSubjectPublicKeyInfo))
	if err != nil {
		return root, cluster, err
	}
	return root, pki.Issuer{Chain: []*x509.Certificate{cert, anchor}, Signer: key}, nil
}

// Enrollment builds the issuer's authorization from the approved key and addresses.
func Enrollment(approved crypto.PublicKey, v4, v6 netip.Addr, routes []netip.Prefix) (pki.Enrollment, error) {
	id, err := pki.NewPeerID(approved)
	if err != nil {
		return pki.Enrollment{}, err
	}
	now := time.Now()
	return pki.Enrollment{
		PublicKeyHash: id, IPv4: v4, IPv6: v6,
		Scope:     pki.Scope{Network: "demo", RoutedPrefixes: routes},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
	}, nil
}
