// Command peer connects nodes and looks up mesh addresses using credentials from disk.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/pki"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx)
	stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	rootsFile := flag.String("root", "root.pem", "ordinary root certificate")
	pinFile := flag.String("cluster-ca", "ca.pem", "pinned cluster CA certificate in PEM")
	certFile := flag.String("cert", "node.pem", "one root-issued node certificate in PEM")
	keyFile := flag.String("key", "node.key", "private key shared by the node certificate and cluster grant")
	viewFile := flag.String("topology", "topology.json", "approved topology JSON")
	grantFile := flag.String("grant", "grant.pem", "PEM chain from the grant leaf through the cluster CA")
	var listen, endpoint netip.AddrPort
	var resolve netip.Addr
	flag.TextVar(&listen, "listen", netip.MustParseAddrPort("127.0.0.1:0"), "local UDP address and port")
	flag.TextVar(&endpoint, "connect", netip.AddrPort{}, "connect to this physical UDP endpoint after startup")
	flag.TextVar(&resolve, "resolve", netip.Addr{}, "print signed matches for an overlay or downstream IP and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments (see -h)")
	}

	readCertificates := func(path string) ([]*x509.Certificate, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		certs, err := pki.ParseCertificatesPEM(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return certs, nil
	}
	roots, err := readCertificates(*rootsFile)
	if err != nil {
		return err
	}
	if len(roots) != 1 {
		return errors.New("one ordinary root required")
	}
	opts := nebula.Options{Auth: nebula.AuthOptions{RootCA: roots[0]}}
	grant, err := readCertificates(*grantFile)
	if err != nil {
		return err
	}
	for _, c := range grant {
		opts.Auth.Certificates.Grant = append(opts.Auth.Certificates.Grant, c.Raw)
	}
	pin, err := readCertificates(*pinFile)
	if err != nil {
		return err
	}
	if len(pin) != 1 {
		return fmt.Errorf("%s must contain exactly one cluster CA", *pinFile)
	}
	opts.Auth.ClusterCA = pin[0]
	opts.Auth.Certificates.Node, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	view, err := os.ReadFile(*viewFile)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(view))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&opts.Topology); err != nil {
		return fmt.Errorf("%s: %w", *viewFile, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%s: unexpected data after topology", *viewFile)
	}
	return runNode(ctx, opts, listen, endpoint, resolve)
}

func runNode(ctx context.Context, opts nebula.Options, listen, endpoint netip.AddrPort, resolve netip.Addr) error {
	network := "udp4"
	if listen.Addr().Is6() {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return err
	}
	if network == "udp4" {
		opts.Transport.UDP4 = socket
	} else {
		opts.Transport.UDP6 = socket
	}
	node, err := nebula.New(ctx, opts)
	if err != nil {
		socket.Close()
		return err
	}
	defer node.Close()
	if err := node.Start(); err != nil {
		return err
	}
	fmt.Printf("listening on %s as %s\n", socket.LocalAddr(), node.ID())
	if !endpoint.IsValid() && !resolve.IsValid() {
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if endpoint.IsValid() {
		id, err := node.ConnectEndpoint(ctx, nebula.Endpoint{Network: "udp", Address: endpoint})
		if err != nil {
			return err
		}
		fmt.Printf("connected to %s at %s\n", id, endpoint)
	}
	if resolve.IsValid() {
		matches, err := node.ResolveIP(ctx, resolve)
		if err != nil {
			return err
		}
		for _, m := range matches {
			fmt.Printf("%s via %s (%s)\n", resolve, m.Peer, m.Prefix)
		}
	}
	return nil
}
