// Command anycast drains a TCP service while keeping its existing flow on the same member.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/examples/demo"
	"gopkg.d7z.net/nebula/nebulagvisor"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, a, b := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	vip := netip.MustParseAddr("10.13.0.200")
	a.AnycastIPs, b.AnycastIPs = []netip.Addr{vip}, []netip.Addr{vip}
	options, err := demo.NodeOptions(client, a, b)
	if err != nil {
		return err
	}
	nodes, err := demo.Listen(ctx, "udp", options)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		defer n.Close()
	}
	service := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(vip.AsSlice()), Port: 8080}
	local := tcpip.AddrFromSlice(client.IPv4.AsSlice())
	var bindings sync.Map // Local TCP port -> member, for this one client and service.
	resolve := func(dst netip.Addr, packet []byte) (nebula.PeerID, error) {
		ip := header.IPv4(packet)
		if dst != vip || ip.SourceAddress() != local || ip.TransportProtocol() != tcp.ProtocolNumber || ip.More() || ip.FragmentOffset() != 0 {
			return nebula.PeerID{}, nebula.ErrNextHopRequired
		}
		h := header.TCP(ip.Payload())
		if len(h) >= header.TCPMinimumSize && h.DestinationPort() == service.Port {
			if peer, ok := bindings.Load(h.SourcePort()); ok {
				return peer.(nebula.PeerID), nil
			}
		}
		return nebula.PeerID{}, nebula.ErrNextHopRequired
	}
	var clientStack *stack.Stack
	var services []*gonet.TCPListener
	for i, n := range nodes {
		s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
		defer s.Destroy()
		var opts nebulagvisor.Options
		if i == 0 {
			clientStack, opts.ResolveNextHop = s, resolve
		}
		ep, err := nebulagvisor.NewEndpoint(n, opts)
		if err != nil {
			return err
		}
		if e := s.CreateNIC(1, ep); e != nil {
			ep.Close()
			return fmt.Errorf("create NIC: %s", e)
		}
		defer s.RemoveNIC(1)
		addr := n.Addresses().IPv4
		primary := tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(addr.AsSlice()), PrefixLen: n.Cluster().Subnet(addr).Bits()}
		if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: primary}, stack.AddressProperties{}); e != nil {
			return fmt.Errorf("assign primary: %s", e)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: primary.Subnet(), NIC: 1}})
		if i > 0 {
			if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: service.Addr.WithPrefix()}, stack.AddressProperties{PEB: stack.NeverPrimaryEndpoint}); e != nil {
				return fmt.Errorf("assign VIP: %s", e)
			}
			listener, err := gonet.ListenTCP(s, service, ipv4.ProtocolNumber)
			if err != nil {
				return err
			}
			defer listener.Close()
			stop := context.AfterFunc(ctx, listener.Shutdown)
			defer stop()
			services = append(services, listener)
		}
		if err := n.Start(); err != nil {
			return err
		}
	}
	// The application knows the connection tuple before it sends the SYN.
	dial := func(port uint16, peer nebula.PeerID) (*gonet.TCPConn, error) {
		bindings.Store(port, peer)
		return gonet.DialTCPWithBind(ctx, clientStack, tcpip.FullAddress{Addr: local, Port: port}, service, ipv4.ProtocolNumber)
	}
	old, err := dial(41001, nodes[1].ID())
	if err != nil {
		return err
	}
	defer old.Close()
	first, err := services[0].Accept()
	if err != nil {
		return err
	}
	defer first.Close()
	if err := exchange(old, first, 'A'); err != nil {
		return err
	}
	services[0].Close()
	probe, err := dial(41002, nodes[1].ID())
	if err == nil {
		probe.Close()
		return fmt.Errorf("draining instance accepted a new connection")
	}
	var dialErr *net.OpError
	if !errors.As(err, &dialErr) || dialErr.Err.Error() != (&tcpip.ErrConnectionRefused{}).String() {
		return fmt.Errorf("targeted TCP probe: %w", err)
	}
	fresh, err := dial(41003, nodes[2].ID())
	if err != nil {
		return err
	}
	defer fresh.Close()
	second, err := services[1].Accept()
	if err != nil {
		return err
	}
	defer second.Close()
	if err := exchange(fresh, second, 'B'); err != nil {
		return err
	}
	if err := exchange(old, first, 'A'); err != nil {
		return err
	}
	fmt.Println("A declined the targeted TCP probe; the existing flow reached A and the new flow reached B")

	options[0].Topology.Members[1].AnycastIPs = nil
	if err := nodes[0].ApplyTopology(ctx, options[0].Topology); err != nil {
		return err
	}
	// The old binding still names A. Its service socket remains open.
	if _, err := old.Write([]byte{'x'}); err == nil {
		first.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		var buf [1]byte
		_, err := first.Read(buf[:])
		if err == nil {
			return fmt.Errorf("A received data after VIP withdrawal")
		}
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			return fmt.Errorf("reading A after VIP withdrawal: %w", err)
		}
	}
	if err := exchange(fresh, second, 'B'); err != nil {
		return err
	}
	fmt.Println("A lost VIP authority; B still served its own connection")
	return nil
}

func exchange(client, server net.Conn, instance byte) error {
	deadline := time.Now().Add(3 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	if _, err := client.Write([]byte{'?'}); err != nil {
		return err
	}
	var buf [1]byte
	if _, err := io.ReadFull(server, buf[:]); err != nil {
		return err
	}
	if buf[0] != '?' {
		return fmt.Errorf("unexpected request %q", buf)
	}
	if _, err := server.Write([]byte{instance}); err != nil {
		return err
	}
	if _, err := io.ReadFull(client, buf[:]); err != nil {
		return err
	}
	if buf[0] != instance {
		return fmt.Errorf("expected instance %c, got %q", instance, buf)
	}
	return nil
}
