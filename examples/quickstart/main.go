// Command quickstart connects two mesh nodes on loopback using demo certificates.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/examples/internal/demo"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	a, b := demo.NewHost(1), demo.NewHost(2)
	b.Topics = []string{"app/demo"}
	nodes, err := demo.NewNodes(context.Background(), "udp", a, b)
	if err != nil {
		return err
	}
	alice, bob := nodes[0], nodes[1]
	defer alice.Close()
	defer bob.Close()
	for _, n := range nodes {
		if err := n.Start(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sub, err := alice.Subscribe("app/demo/hello")
	if err != nil {
		return err
	}
	defer sub.Close()
	if err := bob.ConnectPeer(ctx, a.IPv6); err != nil {
		return err
	}
	id, err := bob.Publish(ctx, "app/demo/hello", []byte("hello"))
	if err != nil {
		return err
	}
	select {
	case e, ok := <-sub.Events():
		if !ok {
			return fmt.Errorf("subscription closed")
		}
		if e.ID != id || e.Origin != bob.ID() || string(e.Payload) != "hello" {
			return fmt.Errorf("unexpected event %s from %s", e.ID, e.Origin)
		}
		fmt.Printf("%s from %v\n", e.Payload, e.Origin)
	case <-ctx.Done():
		return fmt.Errorf("wait for event: %w", ctx.Err())
	}

	received := make(chan []byte, 1)
	rx, err := alice.OpenIPPort(func(b []byte) {
		select {
		case received <- bytes.Clone(b):
		case <-ctx.Done():
		}
	})
	if err != nil {
		return err
	}
	defer rx.Close()
	tx, err := bob.OpenIPPort(func([]byte) {})
	if err != nil {
		return err
	}
	defer tx.Close()

	// IPv6 Next Header 59 marks a packet with no upper-layer payload.
	packet := make([]byte, 40)
	packet[0], packet[6], packet[7] = 0x60, 59, 64
	copy(packet[8:24], b.IPv6.AsSlice())
	copy(packet[24:40], a.IPv6.AsSlice())
	if err := tx.WriteIP(netip.Addr{}, packet); err != nil {
		return err
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, packet) {
			return fmt.Errorf("unexpected IP packet")
		}
		fmt.Printf("IPv6 %s -> %s (%d bytes)\n", b.IPv6, a.IPv6, len(got))
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for IP packet: %w", ctx.Err())
	}
}
