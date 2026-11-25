package pki_test

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/examples/demo"
	"code.d7z.net/d7z-team/nebula/pki"
)

func ExampleVerifyObjectSignature() {
	host := demo.NewHost(1)
	opts, err := demo.NodeOptions(host)
	if err != nil {
		panic(err)
	}
	// The receiving application pins the cluster CA and approves this publisher.
	cluster, err := pki.ReadClusterCA(opts[0].Auth.ClusterCA)
	if err != nil {
		panic(err)
	}
	publisher, err := pki.NewPeerID(host.IPv4, host.IPv6)
	if err != nil {
		panic(err)
	}
	report, cert := []byte("ready"), opts[0].Auth.Certificates.Client
	// Check the envelope against the wire budget before asking the signer to sign.
	if err := pki.CheckObjectSize(cluster.Network(), "report", report, cert); err != nil {
		panic(err)
	}
	wire, err := pki.SignObject(cluster.Network(), "report", report, cert)
	if err != nil {
		panic(err)
	}
	body, chain, err := pki.VerifyObjectSignature(wire, cluster.Network(), "report")
	if err != nil {
		panic(err)
	}
	// Authorize reports only from the configured publisher. Use the content
	// after its signing chain, EKU and exact identity have been verified.
	_, err = pki.VerifyChain(chain, opts[0].Auth.Roots, cluster, publisher, x509.ExtKeyUsageCodeSigning, time.Now())
	if err != nil {
		panic(err)
	}
	fmt.Printf("report from %s: %s\n", publisher, body)
	// Output: report from 10.13.0.1@fd13::1: ready
}

func ExampleNewPeerID() {
	id, err := pki.NewPeerID(netip.MustParseAddr("10.13.0.1"), netip.MustParseAddr("fd13::1"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(id)
	// Output: 10.13.0.1@fd13::1
}
