// Command quickstart connects two mesh nodes on loopback using demo certificates.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"code.d7z.net/d7z-team/nebula"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: quickstart CERTIFICATE_DIRECTORY")
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func run(dir string) error {
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid demo CA")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	alice := netip.MustParseAddr("fd13::1")
	bob := netip.MustParseAddr("fd13::2")
	topology := nebula.Topology{
		Network: "demo", Networks: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd13::/64")},
	}
	var opts []nebula.Options
	for i, name := range []string{"alice", "bob"} {
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key"))
		if err != nil {
			return err
		}
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		defer pc.Close()
		topology.Members = append(topology.Members, nebula.Member{
			IPv4:      netip.MustParseAddr(fmt.Sprintf("10.13.0.%d", i+1)),
			IPv6:      netip.MustParseAddr(fmt.Sprintf("fd13::%d", i+1)),
			Endpoints: []nebula.Endpoint{{Network: "udp", Address: pc.LocalAddr().(*net.UDPAddr).AddrPort()}},
		})
		if name == "bob" {
			topology.Members[i].Topics = []string{"app/demo"}
		}
		opts = append(opts, nebula.Options{Roots: roots, UDP4: pc,
			Certificates: nebula.LocalCertificates{Client: pair}})
	}

	nodes := make(map[netip.Addr]*nebula.Node)
	for _, o := range opts {
		o.Topology = topology
		n, err := nebula.New(ctx, o)
		if err != nil {
			return err
		}
		defer n.Close()
		if err := n.Start(); err != nil {
			return err
		}
		nodes[n.ID().IPv6()] = n
	}
	sub, err := nodes[alice].Subscribe("app/demo/hello")
	if err != nil {
		return err
	}
	defer sub.Close()
	if err := nodes[bob].ConnectPeer(ctx, alice); err != nil {
		return err
	}
	if _, err := nodes[bob].Publish(ctx, "app/demo/hello", []byte("hello")); err != nil {
		return err
	}
	select {
	case e, ok := <-sub.Events():
		if !ok {
			return fmt.Errorf("subscription closed")
		}
		fmt.Printf("%s from %v\n", e.Payload, e.Origin)
	case <-ctx.Done():
		return ctx.Err()
	}

	received := make(chan []byte, 1)
	rx, err := nodes[alice].OpenIPPort(func(b []byte) {
		select {
		case received <- bytes.Clone(b):
		case <-ctx.Done():
		}
	})
	if err != nil {
		return err
	}
	defer rx.Close()
	tx, err := nodes[bob].OpenIPPort(func([]byte) {})
	if err != nil {
		return err
	}
	defer tx.Close()

	// IPv6 Next Header 59 marks a packet with no upper-layer payload.
	packet := make([]byte, 40)
	packet[0], packet[6], packet[7] = 0x60, 59, 64
	copy(packet[8:24], bob.AsSlice())
	copy(packet[24:40], alice.AsSlice())
	if err := tx.WriteIP(netip.Addr{}, packet); err != nil {
		return err
	}
	select {
	case b := <-received:
		if !bytes.Equal(b, packet) {
			return fmt.Errorf("unexpected IP packet")
		}
		fmt.Printf("IPv6 %s -> %s (%d bytes)\n", bob, alice, len(b))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
