package nebula_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/examples/demo"
	"gopkg.d7z.net/nebula/pki"
)

func ExampleIPPort_WriteIP() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := demo.NewHost(1), demo.NewHost(2)
	opts, err := demo.NodeOptions(a, b)
	if err != nil {
		panic(err)
	}
	opts[1].MaxIPSize = 1280
	nodes, err := demo.Listen(ctx, "tcp", opts)
	if err != nil {
		panic(err)
	}
	for _, n := range nodes {
		defer func() { _ = n.Close() }()
	}
	for _, n := range nodes {
		if err := n.Start(); err != nil {
			panic(err)
		}
	}

	result := make(chan nebula.TransmitResult, 1)
	port, err := nodes[0].OpenIPPort(nebula.IPPortOptions{
		Deliver:         func(nebula.PeerID, []byte) {},
		ObserveTransmit: func(r nebula.TransmitResult) { result <- r },
	})
	if err != nil {
		panic(err)
	}
	packet := make([]byte, 1281)
	packet[0], packet[6], packet[7] = 0x60, 253, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], a.IPv6.AsSlice())
	copy(packet[24:40], b.IPv6.AsSlice())
	if err := port.WriteIP(nebula.PeerID{}, packet); err != nil {
		panic(err)
	}
	fmt.Println("queued")
	select {
	case r := <-result:
		fmt.Println("exceeds peer limit:", errors.Is(r.Err, nebula.ErrPacketTooLarge))
	case <-ctx.Done():
		panic(ctx.Err())
	}
	// Output:
	// queued
	// exceeds peer limit: true
}

func ExampleTopology_Validate() {
	// A host can preflight its approved topology before binding any sockets.
	topology := nebula.Topology{
		Network: "demo",
		Members: []nebula.Member{demo.NewHost(1).Member},
	}
	_, issuer, err := demo.NewIssuers()
	if err != nil {
		panic(err)
	}
	cluster, err := pki.ReadClusterCA(issuer.Chain[0])
	if err != nil {
		panic(err)
	}
	if err := topology.Validate(cluster); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("approved member:", topology.Members[0].IPv4, topology.Members[0].IPv6)
	// Output: approved member: 10.13.0.1 fd13::1
}

func ExampleNode_ResolveIP() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, gateway := demo.NewHost(1), demo.NewHost(2)
	gateway.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	gateway.CertificateRoutes = gateway.RoutedPrefixes
	opts, err := demo.NodeOptions(client, gateway)
	if err != nil {
		panic(err)
	}
	opts[0].Auth.TrustedEntrypoints = []nebula.PeerID{gateway.ID}
	opts[0].Topology.Members = []nebula.Member{client.Member}
	nodes, err := demo.Listen(ctx, "tcp", opts)
	if err != nil {
		panic(err)
	}
	for _, node := range nodes {
		defer func() { _ = node.Close() }()
	}
	for _, node := range nodes {
		if err := node.Start(); err != nil {
			panic(err)
		}
	}
	ep := opts[1].Topology.Members[1].Endpoints[0]
	if _, err := nodes[0].ConnectEndpoint(ctx, ep); err != nil {
		panic(err)
	}
	matches, err := nodes[0].ResolveIP(ctx, netip.MustParseAddr("172.30.0.42"))
	if err != nil {
		panic(err)
	}
	for _, m := range matches {
		fmt.Println(m.Peer == gateway.ID, m.Prefix)
	}
	// Output: true 172.30.0.0/24
}
