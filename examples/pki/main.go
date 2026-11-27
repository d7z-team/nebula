// Command pki issues and verifies a node identity and a dual-stack cluster grant in memory.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/netip"
	"time"

	"gopkg.d7z.net/nebula/examples/demo"
	"gopkg.d7z.net/nebula/pki"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	authority, issuer, err := demo.NewIssuers()
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	clusterCA := issuer.Chain[0]
	siteKey, err := pki.GenerateKey("ed25519")
	if err != nil {
		return err
	}
	siteCSR, err := pki.CreateCSR(siteKey, pkix.Name{CommonName: "Demo site"})
	if err != nil {
		return err
	}
	siteID, err := pki.NewPeerID(siteKey.Public())
	if err != nil {
		return err
	}
	site, err := issuer.IssueCA(siteCSR, pki.CAProfile{
		Subject: siteCSR.Subject, NotBefore: clusterCA.NotBefore, NotAfter: clusterCA.NotAfter,
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/27"), netip.MustParsePrefix("fd13::/120")},
		Scope:        &pki.Scope{Network: "demo"},
	}, siteID)
	if err != nil {
		return err
	}
	siteIssuer := pki.Issuer{Chain: []*x509.Certificate{site, clusterCA}, Signer: siteKey}
	key, err := pki.GenerateKey("ed25519")
	if err != nil {
		return err
	}
	// The issuer approves the known public key independently of the submitted CSR.
	enrollment, err := demo.Enrollment(key.Public(), netip.MustParseAddr("10.13.0.1"), netip.MustParseAddr("fd13::1"), nil)
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, pkix.Name{CommonName: "alice"})
	if err != nil {
		return err
	}
	node, err := authority.IssueNode(csr, enrollment.PublicKeyHash, enrollment.NotBefore, enrollment.NotAfter)
	if err != nil {
		return err
	}
	id, err := pki.VerifyNode(node, authority.Chain[0], x509.ExtKeyUsageServerAuth, time.Now())
	if err != nil {
		return err
	}
	enrollment.Name = "alice"
	leaf, err := siteIssuer.IssueGrant(csr, enrollment)
	if err != nil {
		return fmt.Errorf("issue leaf: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(authority.Chain[0])
	cluster, err := pki.ReadClusterCA(clusterCA)
	if err != nil {
		return err
	}
	_, err = pki.VerifyGrant([]*x509.Certificate{leaf, site, clusterCA}, roots, cluster, id, time.Now())
	if err != nil {
		return fmt.Errorf("verify cluster grant: %w", err)
	}
	fmt.Printf("verified %s on demo with its cluster grant\n", id)
	return nil
}
