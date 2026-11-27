package e2e_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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

func gvisorAddr(ip netip.Addr) tcpip.Address { return tcpip.AddrFromSlice(ip.AsSlice()) }

func addr(ip string) tcpip.Address { return gvisorAddr(netip.MustParseAddr(ip)) }

func addNIC(t *testing.T, s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint, addresses ...string) {
	t.Helper()
	require.Nil(t, s.CreateNIC(id, ep))
	for _, ip := range addresses {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			a := netip.MustParseAddr(ip)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		a := gvisorAddr(p.Addr())
		proto := ipv4.ProtocolNumber
		if a.BitLen() == 128 {
			proto = ipv6.ProtocolNumber
		}
		require.Nil(t, s.AddProtocolAddress(id, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: a, PrefixLen: p.Bits()}}, stack.AddressProperties{}))
	}
}

func route(prefix, via string, nic tcpip.NICID) tcpip.Route {
	p := netip.MustParsePrefix(prefix)
	a := tcpip.AddressWithPrefix{Address: gvisorAddr(p.Addr()), PrefixLen: p.Bits()}
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
	defer func() { _ = l.Close() }()
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
