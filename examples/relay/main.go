// Command relay carries a request and reply through an authenticated three-node circuit.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/internal/demo"
	"code.d7z.net/d7z-team/nebula/pki"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	a, r, b := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	var circuit []nebula.PeerID
	for _, member := range []demo.Host{a, r, b} {
		id, err := pki.NewPeerID(member.IPv4, member.IPv6)
		if err != nil {
			return err
		}
		circuit = append(circuit, id)
	}
	a.Restricted = true
	b.Restricted = true
	r.Transit = true
	a.Links = []nebula.PeerID{circuit[1]}
	b.Links = []nebula.PeerID{circuit[1]}
	r.Links = []nebula.PeerID{circuit[0], circuit[2]}
	nodes, err := demo.NewNodes(context.Background(), "udp", a, r, b)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		defer node.Close()
	}
	if err := nodes[0].SetPeerPathPolicy(b.IPv4, nebula.RelayOnly); err != nil {
		return err
	}
	if err := nodes[2].SetPeerPathPolicy(a.IPv4, nebula.RelayOnly); err != nil {
		return err
	}
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := nodes[0].ConnectPeer(ctx, b.IPv6); err != nil {
		return fmt.Errorf("connect A to B through R: %w", err)
	}
	paths := nodes[0].Paths()
	if !slices.ContainsFunc(paths, func(path nebula.PathStatus) bool {
		return path.Peer == nodes[2].ID() && path.Active && path.Transport == "relay" && slices.Equal(path.Circuit, circuit)
	}) {
		return fmt.Errorf("unexpected active circuit: %v", paths)
	}
	fmt.Println("active circuit: A -> R -> B")

	// Only A and B attach IP ports. R forwards the encrypted circuit.
	inboxA, inboxB := make(chan []byte, 1), make(chan []byte, 1)
	receive := func(inbox chan<- []byte) func([]byte) {
		return func(packet []byte) {
			select {
			case inbox <- bytes.Clone(packet):
			case <-ctx.Done():
			}
		}
	}
	portA, err := nodes[0].OpenIPPort(receive(inboxA))
	if err != nil {
		return err
	}
	defer portA.Close()
	portB, err := nodes[2].OpenIPPort(receive(inboxB))
	if err != nil {
		return err
	}
	defer portB.Close()
	exchange := func(port *nebula.IPPort, inbox <-chan []byte, src, dst netip.Addr, body string) error {
		packet := make([]byte, 40+len(body))
		packet[0], packet[6], packet[7] = 0x60, 253, 64 // Experimental IPv6 next header.
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(body)))
		copy(packet[8:24], src.AsSlice())
		copy(packet[24:40], dst.AsSlice())
		copy(packet[40:], body)
		if err := port.WriteIP(netip.Addr{}, packet); err != nil {
			return err
		}
		select {
		case got := <-inbox:
			if !bytes.Equal(got, packet) {
				return fmt.Errorf("unexpected packet at %s", dst)
			}
		case <-ctx.Done():
			return fmt.Errorf("wait for %q at %s: %w", body, dst, ctx.Err())
		}
		return nil
	}
	if err := exchange(portA, inboxB, a.IPv6, b.IPv6, "request"); err != nil {
		return err
	}
	if err := exchange(portB, inboxA, b.IPv6, a.IPv6, "reply"); err != nil {
		return err
	}
	fmt.Println("IP request and reply delivered")
	return nil
}
