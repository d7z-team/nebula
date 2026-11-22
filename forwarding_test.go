package nebula_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/nebulagvisor"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func newStack(t *testing.T) *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	t.Cleanup(s.Destroy)
	return s
}

func addr(ip string) tcpip.Address { return tcpip.AddrFromSlice(netip.MustParseAddr(ip).AsSlice()) }

func addNIC(t *testing.T, s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint, addresses ...string) {
	t.Helper()
	require.Nil(t, s.CreateNIC(id, ep))
	for _, ip := range addresses {
		a := addr(ip)
		proto := ipv4.ProtocolNumber
		if a.BitLen() == 128 {
			proto = ipv6.ProtocolNumber
		}
		require.Nil(t, s.AddProtocolAddress(id, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: a.WithPrefix()}, stack.AddressProperties{}))
	}
}

func route(prefix, via string, nic tcpip.NICID) tcpip.Route {
	p := netip.MustParsePrefix(prefix)
	a := tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(p.Addr().AsSlice()), PrefixLen: p.Bits()}
	r := tcpip.Route{Destination: a.Subnet(), NIC: nic}
	if via != "" {
		r.Gateway = addr(via)
	}
	return r
}

func tcpPair(t *testing.T, client, server *stack.Stack, destination string, proto tcpip.NetworkProtocolNumber) (net.Conn, net.Conn) {
	t.Helper()
	l, err := gonet.ListenTCP(server, tcpip.FullAddress{Addr: addr(destination)}, proto)
	require.NoError(t, err)
	defer l.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{Addr: addr(destination), Port: uint16(l.Addr().(*net.TCPAddr).Port)}, proto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	accepted, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = accepted.Close() })
	return c, accepted
}

func roundTrip(t *testing.T, a, b net.Conn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))
	for _, pair := range [][2]net.Conn{{a, b}, {b, a}} {
		_, err := pair[0].Write([]byte("over the wire"))
		require.NoError(t, err)
		buf := make([]byte, len("over the wire"))
		_, err = io.ReadFull(pair[1], buf)
		require.NoError(t, err)
		require.Equal(t, "over the wire", string(buf))
	}
}

// Observe what actually reaches the downstream wire after the Nebula hop.
type observedLAN struct {
	stack.LinkEndpoint
	ttl4, ttl6 atomic.Uint32
}

func (lan *observedLAN) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		raw := pkt.NetworkHeader().Slice()
		switch pkt.NetworkProtocolNumber {
		case ipv4.ProtocolNumber:
			lan.ttl4.Store(uint32(header.IPv4(raw).TTL()))
		case ipv6.ProtocolNumber:
			lan.ttl6.Store(uint32(header.IPv6(raw).HopLimit()))
		}
	}
	return lan.LinkEndpoint.WritePackets(pkts)
}

func TestNodeGVisorForwardingAndDetach(t *testing.T) {
	client, gateway := nebula.NewTestNICNodes(t)
	a, g, h := newStack(t), newStack(t), newStack(t)
	epA, err := nebulagvisor.NewEndpoint(client, nebulagvisor.Options{})
	require.NoError(t, err)
	epG, err := nebulagvisor.NewEndpoint(gateway, nebulagvisor.Options{})
	require.NoError(t, err)
	const vpn, lan tcpip.NICID = 7, 3
	gLAN, hLAN := pipe.New("", "", 1500)
	addNIC(t, a, vpn, epA, "10.42.0.2", "fd00:42::2")
	addNIC(t, g, vpn, epG, "10.42.0.1", "fd00:42::1")
	observed := &observedLAN{LinkEndpoint: gLAN}
	addNIC(t, g, lan, observed, "172.30.0.1", "2001:db8:42::1")
	addNIC(t, h, lan, hLAN, "172.30.0.20", "2001:db8:42::20")
	for _, proto := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		for _, id := range []tcpip.NICID{lan, vpn} {
			_, e := g.SetNICForwarding(id, proto, true)
			require.Nil(t, e)
		}
	}
	a.SetRouteTable([]tcpip.Route{route("10.42.0.0/24", "", vpn), route("fd00:42::/64", "", vpn),
		route("0.0.0.0/0", "10.42.0.1", vpn), route("::/0", "10.42.0.1", vpn)})
	g.SetRouteTable([]tcpip.Route{route("10.42.0.0/24", "", vpn), route("fd00:42::/64", "", vpn),
		route("172.30.0.0/24", "", lan), route("2001:db8:42::/64", "", lan)})
	h.SetRouteTable([]tcpip.Route{route("172.30.0.0/24", "", lan), route("2001:db8:42::/64", "", lan),
		route("0.0.0.0/0", "172.30.0.1", lan), route("::/0", "2001:db8:42::1", lan)})

	for _, tc := range []struct {
		host, client string
		proto        tcpip.NetworkProtocolNumber
	}{
		{"172.30.0.20", "10.42.0.2", ipv4.ProtocolNumber}, {"2001:db8:42::20", "fd00:42::2", ipv6.ProtocolNumber},
	} {
		c, accepted := tcpPair(t, a, h, tc.host, tc.proto)
		require.Equal(t, tc.client, accepted.RemoteAddr().(*net.TCPAddr).IP.String())
		roundTrip(t, c, accepted)
		// Also originate a new flow on the independent downstream host.
		server, err := gonet.DialUDP(a, &tcpip.FullAddress{Addr: addr(tc.client), Port: 7010}, nil, tc.proto)
		require.NoError(t, err)
		defer server.Close()
		downstream, err := gonet.DialUDP(h, nil, &tcpip.FullAddress{Addr: addr(tc.client), Port: 7010}, tc.proto)
		require.NoError(t, err)
		defer downstream.Close()
		deadline := time.Now().Add(3 * time.Second)
		require.NoError(t, server.SetDeadline(deadline))
		require.NoError(t, downstream.SetDeadline(deadline))
		_, err = downstream.Write([]byte("from LAN"))
		require.NoError(t, err)
		buf := make([]byte, 100)
		n, remote, err := server.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, tc.host, remote.(*net.UDPAddr).IP.String())
		_, err = server.WriteTo(buf[:n], remote)
		require.NoError(t, err)
		n, err = downstream.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "from LAN", string(buf[:n]))
	}

	require.EqualValues(t, ipv4.DefaultTTL-1, observed.ttl4.Load())
	require.EqualValues(t, ipv6.DefaultTTL-1, observed.ttl6.Load())
	c, accepted := tcpPair(t, h, g, "172.30.0.1", ipv4.ProtocolNumber)
	require.Nil(t, g.RemoveNIC(vpn))
	require.False(t, epG.IsAttached())
	roundTrip(t, c, accepted)
	retry, err := nebulagvisor.NewEndpoint(gateway, nebulagvisor.Options{})
	require.NoError(t, err)
	require.NotNil(t, g.CreateNIC(lan, retry)) // Existing NIC ID.
	retry.Close()
	next, err := nebulagvisor.NewEndpoint(gateway, nebulagvisor.Options{})
	require.NoError(t, err)
	addNIC(t, g, vpn, next, "10.42.0.1")
	require.NoError(t, gateway.Close())
	require.NoError(t, gateway.Wait())
	roundTrip(t, c, accepted)
}

func TestNodeNativeEndpointDiagnostics(t *testing.T) {
	a, _ := nebula.NewTestNICNodes(t)
	_, err := nebulagvisor.NewEndpoint(a, nebulagvisor.Options{MTU: 1279})
	require.Error(t, err)
	ep, err := nebulagvisor.NewEndpoint(a, nebulagvisor.Options{})
	require.NoError(t, err)
	t.Cleanup(ep.Close)
	ep.SetMTU(1)
	require.EqualValues(t, 1280, ep.MTU())

	// A raw caller supplies complete IP bytes but no routed overlay gateway.
	raw := make([]byte, 20)
	raw[0], raw[3], raw[8], raw[9] = 0x45, 20, 64, 253
	copy(raw[12:], netip.MustParseAddr("10.42.0.2").AsSlice())
	copy(raw[16:], netip.MustParseAddr("192.0.2.20").AsSlice())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	n, e := ep.WritePackets(list)
	require.Zero(t, n)
	require.IsType(t, &tcpip.ErrHostUnreachable{}, e)
	require.Equal(t, nebula.ErrMissingGateway.Error(), ep.Stats().LastDrop.Reason)
}
