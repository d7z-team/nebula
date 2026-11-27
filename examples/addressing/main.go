// Command addressing sends broadcast, multicast and anycast packets over the same mesh.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/examples/demo"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, first, second := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	group, vip := netip.MustParseAddr("239.13.0.1"), netip.MustParseAddr("10.13.0.200")
	first.AnycastIPs, second.AnycastIPs = []netip.Addr{vip}, []netip.Addr{vip}
	first.MulticastGroups = []netip.Addr{group}
	options, err := demo.NodeOptions(client, first, second)
	if err != nil {
		return err
	}
	for i := range options {
		options[i].Topology.EnableBroadcast = true
		options[i].Topology.EnableMulticast = true
	}
	nodes, err := demo.Listen(ctx, "udp", options)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		defer n.Close()
	}
	type receipt struct{ member, destination netip.Addr }
	received := make(chan receipt, 8)
	var tx *nebula.IPPort
	for i, n := range nodes {
		port, err := n.OpenIPPort(nebula.IPPortOptions{Deliver: func(_ nebula.PeerID, b []byte) {
			dst := netip.AddrFrom4([4]byte(b[16:20]))
			select {
			case received <- receipt{n.Addresses().IPv4, dst}:
			case <-ctx.Done():
			}
		}})
		if err != nil {
			return err
		}
		if i == 0 {
			tx = port
		}
		if err := n.Start(); err != nil {
			return err
		}
	}
	for _, message := range []struct {
		dst        netip.Addr
		recipients map[netip.Addr]bool
	}{
		{netip.MustParseAddr("10.13.0.255"), map[netip.Addr]bool{first.IPv4: true, second.IPv4: true}},
		{group, map[netip.Addr]bool{first.IPv4: true}},
		{vip, map[netip.Addr]bool{first.IPv4: true}},
	} {
		// The raw port accepts complete IP packets; use protocol 253 for this demo.
		packet := make([]byte, 20)
		packet[0], packet[8], packet[9] = 0x45, 64, 253
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], client.IPv4.AsSlice())
		copy(packet[16:20], message.dst.AsSlice())
		var sum uint32
		for i := 0; i < len(packet); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i:]))
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
		var via nebula.PeerID
		if message.dst == vip {
			via = nodes[1].ID()
		}
		if err := tx.WriteIP(via, packet); err != nil {
			return err
		}
		for len(message.recipients) > 0 {
			select {
			case r := <-received:
				if r.destination != message.dst || !message.recipients[r.member] {
					return fmt.Errorf("unexpected delivery %+v", r)
				}
				delete(message.recipients, r.member)
				fmt.Printf("%s received by %s\n", r.destination, r.member)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
