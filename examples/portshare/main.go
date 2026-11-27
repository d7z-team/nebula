// Command portshare serves HTTPS, HTTP/3 and a mesh node on the same loopback port.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"
	"code.d7z.net/d7z-team/nebula/portshare"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	port := flag.Uint("port", 0, "loopback TCP and UDP port (0 selects an available port)")
	maxHandshakes := flag.Int("max-inbound-handshakes", 0, "mesh node concurrent inbound handshakes (0 uses the node default)")
	flag.Parse()
	if err := run(*port, *maxHandshakes); err != nil {
		log.Fatal(err)
	}
}

func run(port uint, maxHandshakes int) error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	tcp := portshare.NewTCP(listener)
	defer tcp.Close()
	addr := listener.Addr().(*net.TCPAddr).AddrPort()
	socket, err := net.ListenPacket("udp4", addr.String())
	if err != nil {
		return err
	}
	udp := portshare.NewUDP(socket)
	defer udp.Close()

	server, client := demo.NewHost(1), demo.NewHost(2)
	server.Endpoints = []nebula.Endpoint{{Network: "udp", Address: addr}, {Network: "tcp", Address: addr}}
	options, err := demo.NodeOptions(server, client)
	if err != nil {
		return err
	}
	options[0].Transport.UDP4, options[0].Transport.TCP4 = udp.Mesh(), tcp.Mesh()
	options[0].MaxInboundHandshakes = maxHandshakes
	options[1].Transport.UDP4, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer options[1].Transport.UDP4.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var peer *nebula.Node
	for _, o := range options {
		peer, err = nebula.New(ctx, o)
		if err != nil {
			return err
		}
		defer peer.Close()
		if err := peer.Start(); err != nil {
			return err
		}
	}

	names := []string{"shop.example", "api.example"}
	cert, roots, err := websiteCertificate(names)
	if err != nil {
		return err
	}
	handler := http.NewServeMux()
	for _, name := range names {
		handler.HandleFunc(name+"/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, name) })
	}
	webTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	https := &http.Server{TLSConfig: webTLS.Clone(), Handler: handler}
	h3 := &http3.Server{TLSConfig: webTLS.Clone(), Handler: handler}
	defer https.Close()
	defer h3.Close()
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	go func() { stop(https.ServeTLS(tcp.Other(), "", "")) }()
	go func() { stop(h3.Serve(udp.Other())) }()

	if err := peer.ConnectPeer(ctx, server.IPv4); err != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	fmt.Printf("mesh peer %s connected on %s\n", server.IPv4, addr)
	h2Client := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: names[0]}, ForceAttemptHTTP2: true}
	defer h2Client.CloseIdleConnections()
	h3Client := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: names[1]}}
	defer h3Client.Close()
	for i, tr := range []http.RoundTripper{h2Client, h3Client} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr.String()+"/", nil)
		if err != nil {
			return err
		}
		req.Host = names[i]
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return errors.Join(err, context.Cause(ctx))
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK || resp.ProtoMajor != i+2 || string(body) != req.Host {
			return fmt.Errorf("unexpected %s response for %s: %s %q", resp.Proto, req.Host, resp.Status, body)
		}
		fmt.Printf("%s %s served on %s\n", resp.Proto, body, addr)
	}
	return nil
}

// The website has its own credentials and trust store, separate from the mesh CA.
func websiteCertificate(names []string) (tls.Certificate, *x509.CertPool, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: names,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots, nil
}
