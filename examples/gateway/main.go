// Command gateway routes IPv4 and IPv6 between a mesh client and a downstream LAN.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"code.d7z.net/d7z-team/nebula/examples/internal/demo"
	"code.d7z.net/d7z-team/nebula/nebulagvisor"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	client, gw := demo.NewHost(1), demo.NewHost(2)
	lan4, lan6 := netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("2001:db8:42::/64")
	gw.CertificateRoutes = []netip.Prefix{lan4, lan6}
	gw.RoutedPrefixes = []netip.Prefix{lan4, lan6}
	nodes, err := demo.NewNodes(context.Background(), "tcp", client, gw)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nodes[0].ConnectPeer(ctx, gw.IPv4); err != nil {
		return fmt.Errorf("connect to gateway: %w", err)
	}

	stackOptions := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	}
	clientStack, router, host := stack.New(stackOptions), stack.New(stackOptions), stack.New(stackOptions)
	defer clientStack.Destroy()
	defer router.Destroy()
	defer host.Destroy()
	const vpn, lan tcpip.NICID = 1, 2
	for i, s := range []*stack.Stack{clientStack, router} {
		ep, err := nebulagvisor.NewEndpoint(nodes[i], nebulagvisor.Options{})
		if err != nil {
			return err
		}
		if err := addNIC(s, vpn, ep, nodes[i].ID().IPv4(), nodes[i].ID().IPv6()); err != nil {
			return err
		}
		defer s.RemoveNIC(vpn)
	}
	gw4, gw6 := netip.MustParseAddr("172.30.0.1"), netip.MustParseAddr("2001:db8:42::1")
	host4, host6 := netip.MustParseAddr("172.30.0.20"), netip.MustParseAddr("2001:db8:42::20")
	routerLAN, hostLAN := pipe.New("", "", 1500)
	if err := addNIC(router, lan, routerLAN, gw4, gw6); err != nil {
		return err
	}
	defer router.RemoveNIC(lan)
	if err := addNIC(host, lan, hostLAN, host4, host6); err != nil {
		return err
	}
	defer host.RemoveNIC(lan)
	for _, id := range []tcpip.NICID{vpn, lan} {
		for _, family := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			if _, e := router.SetNICForwarding(id, family, true); e != nil {
				return fmt.Errorf("enable forwarding on NIC %d: %s", id, e)
			}
		}
	}

	overlay4, overlay6 := netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd13::/64")
	var onLink netip.Addr
	clientStack.SetRouteTable([]tcpip.Route{
		route(overlay4, onLink, vpn), route(overlay6, onLink, vpn),
		route(lan4, gw.IPv4, vpn), route(lan6, gw.IPv6, vpn),
	})
	router.SetRouteTable([]tcpip.Route{
		route(overlay4, onLink, vpn), route(overlay6, onLink, vpn),
		route(lan4, onLink, lan), route(lan6, onLink, lan),
	})
	host.SetRouteTable([]tcpip.Route{
		route(lan4, onLink, lan), route(lan6, onLink, lan),
		route(overlay4, gw4, lan), route(overlay6, gw6, lan),
	})
	deadline, _ := ctx.Deadline()
	if err := echo(clientStack, host, client.IPv4, host4, deadline); err != nil {
		return fmt.Errorf("IPv4 echo: %w", err)
	}
	if err := echo(clientStack, host, client.IPv6, host6, deadline); err != nil {
		return fmt.Errorf("IPv6 echo: %w", err)
	}
	return nil
}

func addNIC(s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint, ips ...netip.Addr) error {
	if e := s.CreateNIC(id, ep); e != nil {
		ep.Close()
		return fmt.Errorf("create NIC %d: %s", id, e)
	}
	for _, ip := range ips {
		family := ipv4.ProtocolNumber
		if ip.Is6() {
			family = ipv6.ProtocolNumber
		}
		address := tcpip.ProtocolAddress{Protocol: family, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}
		if e := s.AddProtocolAddress(id, address, stack.AddressProperties{}); e != nil {
			s.RemoveNIC(id)
			return fmt.Errorf("assign %s to NIC %d: %s", ip, id, e)
		}
	}
	return nil
}

func route(dst netip.Prefix, via netip.Addr, nic tcpip.NICID) tcpip.Route {
	prefix := tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(dst.Addr().AsSlice()), PrefixLen: dst.Bits()}
	r := tcpip.Route{Destination: prefix.Subnet(), NIC: nic}
	if via.IsValid() {
		r.Gateway = tcpip.AddrFromSlice(via.AsSlice())
	}
	return r
}

func echo(client, host *stack.Stack, src, dst netip.Addr, deadline time.Time) error {
	family := ipv4.ProtocolNumber
	if dst.Is6() {
		family = ipv6.ProtocolNumber
	}
	service := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(dst.AsSlice()), Port: 8000}
	server, err := gonet.DialUDP(host, &service, nil, family)
	if err != nil {
		return err
	}
	defer server.Close()
	conn, err := gonet.DialUDP(client, nil, &service, family)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := server.SetDeadline(deadline); err != nil {
		return err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	payload := []byte("hello through the gateway")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, 128)
	n, peer, err := server.ReadFrom(buf)
	if err != nil {
		return err
	}
	observed := peer.(*net.UDPAddr).AddrPort().Addr().Unmap()
	if observed != src || !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("unexpected request from %s", peer)
	}
	if _, err = server.WriteTo(buf[:n], peer); err != nil {
		return err
	}
	n, err = conn.Read(buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("unexpected reply from %s", dst)
	}
	fmt.Printf("echo %s -> %s, downstream saw %s\n", src, dst, observed)
	return nil
}
