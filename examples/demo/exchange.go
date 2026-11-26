package demo

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"

	"code.d7z.net/d7z-team/nebula"
)

// ExchangeIPv6 sends a request to the selected identity through the client IP
// port, then sends a reply from the server and checks it at the client.
func ExchangeIPv6(ctx context.Context, client, server *nebula.Node, target nebula.PeerID) error {
	inboxA, inboxB := make(chan []byte, 1), make(chan []byte, 1)
	receive := func(inbox chan<- []byte) func(nebula.PeerID, []byte) {
		return func(_ nebula.PeerID, packet []byte) {
			select {
			case inbox <- bytes.Clone(packet):
			case <-ctx.Done():
			}
		}
	}
	portA, err := client.OpenIPPort(nebula.IPPortOptions{Deliver: receive(inboxA)})
	if err != nil {
		return err
	}
	defer portA.Close()
	portB, err := server.OpenIPPort(nebula.IPPortOptions{Deliver: receive(inboxB)})
	if err != nil {
		return err
	}
	defer portB.Close()
	exchange := func(port *nebula.IPPort, inbox <-chan []byte, src, dest netip.Addr, dst nebula.PeerID, body string) error {
		packet := make([]byte, 40+len(body))
		packet[0], packet[6], packet[7] = 0x60, 253, 64 // Experimental IPv6 next header.
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(body)))
		copy(packet[8:24], src.AsSlice())
		copy(packet[24:40], dest.AsSlice())
		copy(packet[40:], body)
		if err := port.WriteIP(dst, packet); err != nil {
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
	if err := exchange(portA, inboxB, client.Addresses().IPv6, server.Addresses().IPv6, target, "request"); err != nil {
		return err
	}
	return exchange(portB, inboxA, server.Addresses().IPv6, client.Addresses().IPv6, client.ID(), "reply")
}
