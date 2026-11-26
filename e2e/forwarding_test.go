package e2e_test

import (
	"bytes"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/nebulagvisor"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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
	client, gateway := forwardingPair(t)
	a, g, h := newStack(t), newStack(t), newStack(t)
	var ingress4, ingress6 atomic.Bool
	epA, err := nebulagvisor.NewEndpoint(client, nebulagvisor.Options{ObserveReceive: func(from nebula.PeerID, packet []byte) {
		if from != gateway.ID() {
			return
		}
		switch packet[0] >> 4 {
		case 4:
			if header.IPv4(packet).SourceAddress() == addr("172.30.0.20") {
				ingress4.Store(true)
			}
		case 6:
			if header.IPv6(packet).SourceAddress() == addr("2001:db8:42::20") {
				ingress6.Store(true)
			}
		}
	}})
	require.NoError(t, err)
	epG, err := nebulagvisor.NewEndpoint(gateway, nebulagvisor.Options{})
	require.NoError(t, err)
	const vpn, lan tcpip.NICID = 7, 3
	gLAN, hLAN := pipe.New("", "", 1500)
	addNIC(t, a, vpn, epA, "10.13.0.2", "fd42::2")
	addNIC(t, g, vpn, epG, "10.13.0.1", "fd42::1")
	observed := &observedLAN{LinkEndpoint: gLAN}
	addNIC(t, g, lan, observed, "172.30.0.1", "2001:db8:42::1")
	addNIC(t, h, lan, hLAN, "172.30.0.20", "2001:db8:42::20")
	for _, proto := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		for _, id := range []tcpip.NICID{lan, vpn} {
			_, e := g.SetNICForwarding(id, proto, true)
			require.Nil(t, e)
		}
	}
	default4 := route("0.0.0.0/0", "10.13.0.1", vpn)
	default6 := route("::/0", "fd42::1", vpn)
	default4.MTU = uint32(client.RecommendedMTU(gateway.ID(), false, int(epA.MTU())))
	default6.MTU = uint32(client.RecommendedMTU(gateway.ID(), true, int(epA.MTU())))
	require.Less(t, default4.MTU, uint32(1280))
	require.EqualValues(t, 1280, default6.MTU)
	a.SetRouteTable([]tcpip.Route{route("10.13.0.0/24", "", vpn), route("fd42::/64", "", vpn), default4, default6})
	g.SetRouteTable([]tcpip.Route{
		route("10.13.0.0/24", "", vpn), route("fd42::/64", "", vpn),
		route("172.30.0.0/24", "", lan), route("2001:db8:42::/64", "", lan),
	})
	h.SetRouteTable([]tcpip.Route{
		route("172.30.0.0/24", "", lan), route("2001:db8:42::/64", "", lan),
		route("0.0.0.0/0", "172.30.0.1", lan), route("::/0", "2001:db8:42::1", lan),
	})

	for _, tc := range []struct {
		host, client string
		proto        tcpip.NetworkProtocolNumber
	}{
		{"172.30.0.20", "10.13.0.2", ipv4.ProtocolNumber}, {"2001:db8:42::20", "fd42::2", ipv6.ProtocolNumber},
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
		_, err = downstream.Write(bytes.Repeat([]byte("x"), 1200))
		require.NoError(t, err)
		buf := make([]byte, 1300)
		n, remote, err := server.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, tc.host, remote.(*net.UDPAddr).IP.String())
		_, err = server.WriteTo(buf[:n], remote)
		require.NoError(t, err)
		n, err = downstream.Read(buf)
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte("x"), 1200), buf[:n])
	}

	require.True(t, ingress4.Load() && ingress6.Load())
	require.EqualValues(t, ipv4.DefaultTTL-1, observed.ttl4.Load())
	require.EqualValues(t, ipv6.DefaultTTL-1, observed.ttl6.Load())
	gatewayStats := epG.Stats()
	require.Positive(t, gatewayStats.SentBytes)
	require.Positive(t, gatewayStats.ReceivedBytes)
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
	addNIC(t, g, vpn, next, "10.13.0.1")
	require.NoError(t, gateway.Close())
	roundTrip(t, c, accepted)
}

func TestNodeNativeEndpointDiagnostics(t *testing.T) {
	a, gateway := forwardingPair(t)
	_, err := nebulagvisor.NewEndpoint(a, nebulagvisor.Options{MTU: 1279})
	require.Error(t, err)
	var lookups atomic.Int32
	ep, err := nebulagvisor.NewEndpoint(a, nebulagvisor.Options{ResolveNextHop: func(netip.Addr, []byte) (nebula.PeerID, error) {
		lookups.Add(1)
		return nebula.PeerID{}, nebula.ErrNextHopRequired
	}})
	require.NoError(t, err)
	t.Cleanup(ep.Close)
	ep.SetMTU(1)
	require.EqualValues(t, 1280, ep.MTU())

	// A raw caller supplies complete IP bytes but no routed overlay gateway.
	raw := make([]byte, 20)
	raw[0], raw[3], raw[8], raw[9] = 0x45, 20, 64, 253
	copy(raw[12:], netip.MustParseAddr("10.13.0.2").AsSlice())
	copy(raw[16:], netip.MustParseAddr("192.0.2.20").AsSlice())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	n, e := ep.WritePackets(list)
	require.Zero(t, n)
	require.IsType(t, &tcpip.ErrHostUnreachable{}, e)
	require.EqualValues(t, 1, lookups.Load())
	pkt.EgressRoute.NextHop = addr("10.13.0.99")
	n, e = ep.WritePackets(list)
	require.Zero(t, n)
	require.IsType(t, &tcpip.ErrHostUnreachable{}, e)

	require.NoError(t, a.SetPeerPathPolicy(gateway.ID(), nebula.Blocked))
	pkt.EgressRoute.NextHop = tcpip.AddrFromSlice(gateway.Addresses().IPv4.AsSlice())
	n, e = ep.WritePackets(list)
	require.Zero(t, n)
	require.IsType(t, &tcpip.ErrNotPermitted{}, e)
	require.EqualValues(t, 1, lookups.Load())
}
