package nebula_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"
	"code.d7z.net/d7z-team/nebula/pki"
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
		defer n.Close()
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
	const config = `{
   "network": "demo",
   "members": [
     {"ipv4":"10.13.0.1","ipv6":"fd13::1","restricted":true,"links":["10.13.0.2@fd13::2"]},
     {"ipv4":"10.13.0.2","ipv6":"fd13::2","links":["10.13.0.1@fd13::1"]}
   ]
 }`
	var topology nebula.Topology
	if err := json.Unmarshal([]byte(config), &topology); err != nil {
		fmt.Println(err)
		return
	}
	issuer, err := demo.NewIssuer()
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
	fmt.Println("approved neighbor:", topology.Members[0].Links[0])
	// Output: approved neighbor: 10.13.0.2@fd13::2
}
