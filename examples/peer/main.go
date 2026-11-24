// Command peer exchanges signed requests and application receipts between two
// processes using certificates and a host-approved topology loaded from disk.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/pki"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	rootsFile := flag.String("roots", "ca.pem", "trusted root PEM bundle")
	pinFile := flag.String("cluster-ca", "ca.pem", "pinned cluster CA certificate in PEM")
	certFile := flag.String("cert", "node.pem", "member PEM chain, leaf first")
	keyFile := flag.String("key", "node.key", "member private key")
	viewFile := flag.String("topology", "topology.json", "approved topology JSON")
	message := flag.String("send", "", "send a request and wait for its receipt (default: serve requests)")
	var listen netip.AddrPort
	var peer netip.Addr
	flag.TextVar(&listen, "listen", netip.MustParseAddrPort("127.0.0.1:0"), "local UDP address and port")
	flag.TextVar(&peer, "peer", netip.Addr{}, "expected peer's overlay IPv4 or IPv6 address")
	flag.Parse()
	if !peer.IsValid() || flag.NArg() != 0 {
		return errors.New("specify the other member's overlay address with -peer (see -h)")
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
	opts := nebula.Options{Roots: x509.NewCertPool()}
	for _, root := range roots {
		opts.Roots.AddCert(root)
	}
	pin, err := readCertificates(*pinFile)
	if err != nil {
		return err
	}
	if len(pin) != 1 {
		return fmt.Errorf("%s must contain exactly one cluster CA", *pinFile)
	}
	opts.ClusterCA = pin[0]
	opts.Certificates.Client, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	view, err := os.ReadFile(*viewFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(view, &opts.Topology); err != nil {
		return fmt.Errorf("%s: %w", *viewFile, err)
	}
	return exchange(ctx, opts, listen, peer, *message)
}

func exchange(ctx context.Context, opts nebula.Options, listen netip.AddrPort, peer netip.Addr, message string) error {
	network := "udp4"
	if listen.Addr().Is6() {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return err
	}
	if network == "udp4" {
		opts.UDP4 = socket
	} else {
		opts.UDP6 = socket
	}
	node, err := nebula.New(ctx, opts)
	if err != nil {
		socket.Close()
		return err
	}
	defer node.Close()
	expected, ok := node.LookupPeer(peer)
	if !ok || expected == node.ID() {
		return fmt.Errorf("expected a remote member at %s", peer)
	}
	const request, receipt = "app/peer/request", "app/peer/receipt"
	topic := request
	if message != "" {
		topic = receipt
	}
	sub, err := node.Subscribe(topic)
	if err != nil {
		return err
	}
	if err := node.Start(); err != nil {
		return err
	}
	fmt.Printf("listening on %s as %s\n", socket.LocalAddr(), node.ID())
	var id string
	if message != "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := node.ConnectPeer(ctx, peer); err != nil {
			return fmt.Errorf("connect to %s: %w", peer, err)
		}
		id, err = node.Publish(ctx, request, []byte(message))
		if err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-sub.Events():
			if !ok {
				return ctx.Err()
			}
			if event.Origin != expected {
				continue
			}
			if topic == receipt {
				if string(event.Payload) == id {
					fmt.Printf("receipt from %s for %s\n", event.Origin, id)
					return nil
				}
				continue
			}
			fmt.Printf("request from %s: %q\n", event.Origin, event.Payload)
			if _, err := node.Publish(ctx, receipt, []byte(event.ID)); err != nil {
				return err
			}
		}
	}
}
