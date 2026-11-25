// Command pki issues and verifies a dual-stack member certificate in memory.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/examples/demo"
	"code.d7z.net/d7z-team/nebula/pki"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	issuer, err := demo.NewIssuer()
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	root := issuer.Chain[0]
	siteKey, err := pki.GenerateKey("ed25519")
	if err != nil {
		return err
	}
	siteCSR, err := pki.CreateCSR(siteKey, pkix.Name{CommonName: "Demo site"})
	if err != nil {
		return err
	}
	approved, err := x509.MarshalPKIXPublicKey(siteKey.Public())
	if err != nil {
		return err
	}
	site, err := issuer.IssueCA(siteCSR, pki.CAProfile{
		Subject: siteCSR.Subject, NotBefore: root.NotBefore, NotAfter: root.NotAfter,
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/27"), netip.MustParsePrefix("fd13::/120")},
		Scope:        &pki.Scope{Network: "demo"},
	}, sha256.Sum256(approved))
	if err != nil {
		return err
	}
	siteIssuer := pki.Issuer{Chain: []*x509.Certificate{site, root}, Signer: siteKey}
	key, err := pki.GenerateKey("ed25519")
	if err != nil {
		return err
	}
	id, err := pki.NewPeerID(netip.MustParseAddr("10.13.0.1"), netip.MustParseAddr("fd13::1"))
	if err != nil {
		return err
	}
	// The issuer approves the known public key independently of the submitted CSR.
	enrollment, err := demo.Enrollment(key.Public(), id.IPv4(), id.IPv6(), nil)
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, pkix.Name{CommonName: "alice"})
	if err != nil {
		return err
	}
	enrollment.Name = "alice"
	leaf, err := siteIssuer.IssueLeaf(csr, enrollment)
	if err != nil {
		return fmt.Errorf("issue leaf: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	cluster, err := pki.ReadClusterCA(root)
	if err != nil {
		return err
	}
	_, err = pki.VerifyChain([]*x509.Certificate{leaf, site}, roots, cluster, id, x509.ExtKeyUsageServerAuth, time.Now())
	if err != nil {
		return fmt.Errorf("verify server identity: %w", err)
	}
	fmt.Printf("verified %s on demo for serverAuth\n", id)
	return nil
}
