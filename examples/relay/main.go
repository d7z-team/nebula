// Command relay carries an IP request and reply through a relay with unpublished endpoints.
package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"
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
	r.Restricted = true
	r.Transit = true
	a.Links = []nebula.PeerID{circuit[1]}
	b.Links = []nebula.PeerID{circuit[1]}
	r.Links = []nebula.PeerID{circuit[0], circuit[2]}
	options, err := demo.NodeOptions(a, r, b)
	if err != nil {
		return err
	}
	options[1].HideEndpoints = true
	nodes, err := demo.Listen(context.Background(), "udp", options)
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
	// R opens both authorized adjacencies. Either side can then open a circuit stream.
	for _, neighbor := range []nebula.PeerID{circuit[0], circuit[2]} {
		if err := nodes[1].ConnectPeerID(ctx, neighbor); err != nil {
			return err
		}
	}
	if err := nodes[0].ConnectPeer(ctx, b.IPv6); err != nil {
		return fmt.Errorf("connect A to B through R: %w", err)
	}
	path, ok := nodes[0].PreferredPath(nodes[2].ID())
	if !ok || !slices.Equal(path.Circuit, circuit) {
		return fmt.Errorf("unexpected path to B: %v", path)
	}
	next := path.Circuit[1]
	matches, err := nodes[0].ResolveIP(ctx, next.IPv4())
	if err != nil {
		return err
	}
	if len(matches) != 1 || matches[0].Peer != next || len(matches[0].Endpoints) != 0 {
		return fmt.Errorf("unexpected introduction for R: %v", matches)
	}
	fmt.Printf("active circuit: A -> R -> B, next hop %s advertises no endpoints\n", next)

	if err := demo.ExchangeIPv6(ctx, nodes[0], nodes[2], circuit[2]); err != nil {
		return err
	}
	fmt.Println("IP request and reply delivered")
	return nil
}
