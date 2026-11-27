// Command discovery finds a member through one physical neighbor and exchanges IP packets.
package main

import (
	"context"
	"errors"
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
	neighbor, client, gateway := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	gateway.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	gateway.CertificateRoutes = gateway.RoutedPrefixes
	options, err := demo.NodeOptions(neighbor, client, gateway)
	if err != nil {
		return err
	}
	for i := range options {
		options[i].Auth.TrustedEntrypoints = []nebula.PeerID{neighbor.ID}
		options[i].Topology.Members = []nebula.Member{options[i].Topology.Members[i]}
		// Publish the configured topology endpoint and accept NAT reports from our neighbor.
		options[i].Transport.AllowAdvertiseEndpoint = func(c nebula.EndpointCandidate) bool {
			return c.Source == nebula.EndpointFromTopology ||
				c.Source == nebula.EndpointFromObservation && c.Observer == neighbor.ID
		}
		// All three demo nodes use loopback for physical connections.
		options[i].Transport.AllowOutboundEndpoint = func(ep nebula.Endpoint) bool {
			return ep.Address.Addr().IsLoopback()
		}
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
	for _, row := range nodes[1].InspectIP(target.Addresses.IPv4) {
		fmt.Printf("%s %s: peer=%s instance=%s node-sha256=%s grant-sha256=%s\n",
			row.Source, row.Decision, row.Peer, row.Instance, row.NodeSHA256, row.GrantSHA256)
	}
	return nil
}
