// Command pki issues and verifies a dual-stack member certificate in memory.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/examples/internal/demo"
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
	leaf, err := issuer.IssueLeaf(csr, enrollment)
	if err != nil {
		return fmt.Errorf("issue leaf: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(issuer.Chain[0])
	_, err = pki.VerifyChain([]*x509.Certificate{leaf}, roots, "demo", id, x509.ExtKeyUsageServerAuth, time.Now())
	if err != nil {
		return fmt.Errorf("verify server identity: %w", err)
	}
	fmt.Printf("verified %s on demo for serverAuth\n", id)
	return nil
}
