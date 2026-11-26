package pki_test

import (
	"crypto/tls"
	"fmt"
	"slices"
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
	publisher := host.ID
	credentials := opts[0].Auth.Certificates
	report, cert := []byte("ready"), tls.Certificate{PrivateKey: credentials.Node.PrivateKey, Certificate: slices.Concat(credentials.Grant, credentials.Node.Certificate)}
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
	id, _, _, err := pki.VerifyObjectSigner(chain, opts[0].Auth.RootCA, cluster, time.Now())
	if err != nil {
		panic(err)
	}
	if id.ID != publisher {
		panic("unexpected publisher")
	}
	fmt.Printf("verified report: %s\n", body)
	// Output: verified report: ready
}
