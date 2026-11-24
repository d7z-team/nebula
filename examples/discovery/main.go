// Command discovery finds a member through one physical neighbor and exchanges IP packets.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	neighbor, client, gateway := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	gateway.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	gateway.CertificateRoutes = gateway.RoutedPrefixes
	options, err := demo.NodeOptions(neighbor, client, gateway)
	if err != nil {
		return err
	}
	for i := range options {
		options[i].Topology.Members = []nebula.Member{options[i].Topology.Members[i]}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes, err := demo.Listen(ctx, "udp", options)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		defer n.Close()
	}
	for _, n := range nodes {
		if err := n.Start(); err != nil {
			return err
		}
	}
	ep := options[0].Topology.Members[0].Endpoints[0]
	for _, node := range nodes[1:] {
		id, err := node.ConnectEndpoint(ctx, ep)
		if err != nil {
			return err
		}
		fmt.Printf("%s connected to %s\n", node.ID(), id)
	}
	dst := netip.MustParseAddr("172.30.0.42")
	var matches []nebula.IPMatch
	for {
		matches, err = nodes[1].ResolveIP(ctx, dst)
		if err == nil {
			break
		}
		if !errors.Is(err, nebula.ErrPeerUnavailable) {
			return err
		}
		// A newly connected member may still be registering at the neighbor.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	target := matches[0]
	fmt.Printf("%s via %s (%s)\n", dst, target.Peer, target.Prefix)
	if err := nodes[1].ConnectPeerID(ctx, target.Peer); err != nil {
		return err
	}
	if err := demo.ExchangeIPv6(ctx, nodes[1], nodes[2], target.Peer); err != nil {
		return err
	}
	fmt.Printf("IPv6 reply from %s\n", target.Peer)
	return nil
}
