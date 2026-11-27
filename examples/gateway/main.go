// Command gateway routes IPv4 and IPv6 through a site gateway and a default exit.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/examples/demo"
	"gopkg.d7z.net/nebula/nebulagvisor"

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
	client, site, exit := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	site.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("2001:db8:42::/64")}
	exit.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	site.CertificateRoutes, exit.CertificateRoutes = site.RoutedPrefixes, exit.RoutedPrefixes
	// Each gateway has an independent downstream network in this example.
	gateways := []struct {
		demo.Host
		lan4, lan6 netip.Prefix
	}{
		{site, site.RoutedPrefixes[0], site.RoutedPrefixes[1]},
		{exit, netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:99::/64")},
	}
	options, err := demo.NodeOptions(client, site, exit)
	if err != nil {
		return err
	}
	options[0].Auth.TrustedEntrypoints = []nebula.PeerID{site.ID, exit.ID}
	for i := range options {
		options[i].Topology.Members = []nebula.Member{options[i].Topology.Members[i]}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes, err := demo.Listen(ctx, "tcp", options)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		defer func() { _ = n.Close() }()
	}
	for _, n := range nodes {
		if err := n.Start(); err != nil {
			return err
		}
	}
	// Discover the default exit first, then refresh after the site gateway joins.
	// Only install gateways and prefixes approved by the application.
	view := options[0].Topology
	for i, gw := range slices.Backward(gateways) {
		if _, err := nodes[0].ConnectEndpoint(ctx, options[i+1].Topology.Members[0].Endpoints[0]); err != nil {
			return err
		}
		for _, lan := range []netip.Prefix{gw.lan4, gw.lan6} {
			matches, err := nodes[0].RefreshIP(ctx, lan.Addr().Next().Next())
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(matches, func(m nebula.IPMatch) bool {
				return m.Peer == gw.ID && slices.Contains(gw.RoutedPrefixes, m.Prefix)
			}) {
				return fmt.Errorf("missing approved gateway for %s", lan)
			}
		}
		view.Members = append(view.Members, gw.Member)
	}
	if err := nodes[0].ApplyTopology(ctx, view); err != nil {
		return err
	}

	stackOptions := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	}
	const vpn, lan tcpip.NICID = 1, 2
	overlay4, overlay6 := nodes[0].Cluster().MemberPrefixes()
	var onLink netip.Addr
	clientStack := stack.New(stackOptions)
	defer clientStack.Destroy()
	clientNIC, err := nebulagvisor.NewEndpoint(nodes[0], nebulagvisor.Options{
		ObserveReceive: func(from nebula.PeerID, packet []byte) { fmt.Printf("IPv%d reply via %s\n", packet[0]>>4, from) },
	})
	if err != nil {
		return err
	}
	if err := addNIC(clientStack, vpn, clientNIC, netip.PrefixFrom(client.IPv4, overlay4.Bits()), netip.PrefixFrom(client.IPv6, overlay6.Bits())); err != nil {
		return err
	}
	defer clientStack.RemoveNIC(vpn)
	routes := []tcpip.Route{route(overlay4, onLink, vpn), route(overlay6, onLink, vpn)}
	for _, gw := range gateways {
		routes = append(routes, route(gw.RoutedPrefixes[0], gw.IPv4, vpn), route(gw.RoutedPrefixes[1], gw.IPv6, vpn))
	}
	clientStack.SetRouteTable(routes)
	deadline, _ := ctx.Deadline()
	for i, gw := range gateways {
		router, host := stack.New(stackOptions), stack.New(stackOptions)
		defer router.Destroy()
		defer host.Destroy()
		mesh, err := nebulagvisor.NewEndpoint(nodes[i+1], nebulagvisor.Options{})
		if err != nil {
			return err
		}
		if err := addNIC(router, vpn, mesh, netip.PrefixFrom(gw.IPv4, overlay4.Bits()), netip.PrefixFrom(gw.IPv6, overlay6.Bits())); err != nil {
			return err
		}
		defer router.RemoveNIC(vpn)
		lan4, lan6 := gw.lan4, gw.lan6
		gw4, gw6 := lan4.Addr().Next(), lan6.Addr().Next()
		dst4, dst6 := gw4.Next(), gw6.Next()
		left, right := pipe.New("", "", 1500)
		if err := addNIC(router, lan, left, netip.PrefixFrom(gw4, lan4.Bits()), netip.PrefixFrom(gw6, lan6.Bits())); err != nil {
			return err
		}
		defer router.RemoveNIC(lan)
		if err := addNIC(host, lan, right, netip.PrefixFrom(dst4, lan4.Bits()), netip.PrefixFrom(dst6, lan6.Bits())); err != nil {
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
		router.SetRouteTable([]tcpip.Route{route(overlay4, onLink, vpn), route(overlay6, onLink, vpn), route(lan4, onLink, lan), route(lan6, onLink, lan)})
		host.SetRouteTable([]tcpip.Route{route(lan4, onLink, lan), route(lan6, onLink, lan), route(overlay4, gw4, lan), route(overlay6, gw6, lan)})
		if err := echo(clientStack, host, client.IPv4, dst4, deadline); err != nil {
			return err
		}
		if err := echo(clientStack, host, client.IPv6, dst6, deadline); err != nil {
			return err
		}
	}
	return nil
}

func addNIC(s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint, ips ...netip.Prefix) error {
	if e := s.CreateNIC(id, ep); e != nil {
		ep.Close()
		return fmt.Errorf("create NIC %d: %s", id, e)
	}
	for _, ip := range ips {
		family := ipv4.ProtocolNumber
		if ip.Addr().Is6() {
			family = ipv6.ProtocolNumber
		}
		address := tcpip.ProtocolAddress{Protocol: family, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(ip.Addr().AsSlice()), PrefixLen: ip.Bits()}}
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
	defer func() { _ = server.Close() }()
	conn, err := gonet.DialUDP(client, nil, &service, family)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
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
