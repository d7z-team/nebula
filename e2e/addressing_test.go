package e2e_test

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/pki"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestGroupDatagrams(t *testing.T) {
	l := newLab(t)
	a := l.host("lan", "192.0.2.1", "", "udp", true)
	b := l.host("lan", "192.0.2.2", "", "udp", true)
	r := l.host("lan", "192.0.2.3", "", "udp", true)
	l.link(a, r)
	l.link(r, b)
	l.top.Members[r.index].Transit = true
	l.top.EnableBroadcast, l.top.EnableMulticast = true, true
	l.top.Members[b.index].MulticastGroups = []netip.Addr{netip.MustParseAddr("239.1.2.3"), netip.MustParseAddr("ff02::123")}
	// Independent site issuers contribute addresses to the same logical link.
	for _, h := range []*host{a, b} {
		key, err := pki.GenerateKey("ed25519")
		require.NoError(t, err)
		csr, err := pki.CreateCSR(key, pkix.Name{CommonName: h.ip.String()})
		require.NoError(t, err)
		root := l.issuer.Chain[0]
		m := l.top.Members[h.index]
		site, err := l.issuer.IssueCA(csr, pki.CAProfile{
			Subject: csr.Subject, NotBefore: root.NotBefore, NotAfter: root.NotAfter,
			PermittedIPs: []netip.Prefix{netip.PrefixFrom(m.IPv4, 31).Masked(), netip.PrefixFrom(m.IPv6, 127).Masked()},
		}, sha256.Sum256(csr.RawSubjectPublicKeyInfo))
		require.NoError(t, err)
		h.options.Auth.Certificates = l.issueCredentials(h, pki.Issuer{Chain: []*x509.Certificate{site, root}, Signer: key})
	}
	l.start()
	require.NoError(t, a.node.SetPeerPathPolicy(b.node.ID(), nebula.RelayOnly))
	l.connect(a, b, "relay")
	sender, receiver := l.business(a), l.business(b)
	for i, dst := range []string{"255.255.255.255", "10.13.0.255", "239.1.2.3", "ff02::123", "ff02::1"} {
		t.Run(dst, func(t *testing.T) {
			ip := netip.MustParseAddr(dst)
			proto, src := ipv4.ProtocolNumber, a.ip
			if ip.Is6() {
				proto, src = ipv6.ProtocolNumber, a.node.Addresses().IPv6
			}
			if ip.IsMulticast() {
				require.Nil(t, receiver.JoinGroup(proto, 1, addr(dst)))
			}
			port := uint16(7000 + i)
			sink, err := gonet.DialUDP(receiver, &tcpip.FullAddress{NIC: 1, Port: port}, nil, proto)
			require.NoError(t, err)
			defer func() { _ = sink.Close() }()
			var wq waiter.Queue
			ep, e := sender.NewEndpoint(udp.ProtocolNumber, proto, &wq)
			require.Nil(t, e)
			conn := gonet.NewUDPConn(&wq, ep)
			defer func() { _ = conn.Close() }()
			ep.SocketOptions().SetBroadcast(true)
			require.Nil(t, ep.Bind(tcpip.FullAddress{NIC: 1, Addr: gvisorAddr(src)}))
			_, err = conn.WriteTo([]byte(dst), net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
			require.NoError(t, err)
			require.NoError(t, sink.SetReadDeadline(time.Now().Add(3*time.Second)))
			buf := make([]byte, 64)
			n, from, err := sink.ReadFrom(buf)
			require.NoError(t, err)
			require.Equal(t, dst, string(buf[:n]))
			require.Equal(t, src, from.(*net.UDPAddr).AddrPort().Addr().Unmap())
		})
	}
}

func TestAnycastService(t *testing.T) {
	l := newLab(t)
	client := l.host("wan", "192.0.2.1", "", "udp", true)
	servers := []*host{l.host("wan", "192.0.2.2", "", "udp", true), l.host("wan", "192.0.2.3", "", "udp", true)}
	vips := []netip.Addr{netip.MustParseAddr("192.0.2.200"), netip.MustParseAddr("fd42::c8")}
	for _, h := range servers {
		l.top.Members[h.index].AnycastIPs = vips
	}
	var selected atomic.Int32
	client.nicOptions.ResolveNextHop = func(dst netip.Addr, _ []byte) (nebula.PeerID, error) {
		if !slices.Contains(vips, dst) {
			return nebula.PeerID{}, nebula.ErrNextHopRequired
		}
		return servers[selected.Load()].node.ID(), nil
	}
	l.start()
	clientStack := l.business(client)
	clientStack.SetRouteTable(append(clientStack.GetRouteTable(), route("192.0.2.200/32", "", 1)))
	backends := []*stack.Stack{l.business(servers[0]), l.business(servers[1])}
	for i, vip := range vips {
		proto := ipv4.ProtocolNumber
		if vip.Is6() {
			proto = ipv6.ProtocolNumber
		}
		service := tcpip.FullAddress{Addr: gvisorAddr(vip), Port: uint16(8000 + i)}
		conn, err := gonet.DialUDP(clientStack, nil, &service, proto)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		sockets := make([]*gonet.UDPConn, len(backends))
		for j, backend := range backends {
			socket, err := gonet.DialUDP(backend, &service, nil, proto)
			require.NoError(t, err)
			defer func() { _ = socket.Close() }()
			sockets[j] = socket
		}
		for j, socket := range sockets {
			selected.Store(int32(j))
			deadline := time.Now().Add(4 * time.Second)
			require.NoError(t, conn.SetDeadline(deadline))
			require.NoError(t, socket.SetDeadline(deadline))
			_, err = conn.Write([]byte{byte(j)})
			require.NoError(t, err)
			var buf [1]byte
			n, from, err := socket.ReadFrom(buf[:])
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.Equal(t, byte(j), buf[0])
			_, err = socket.WriteTo(buf[:n], from)
			require.NoError(t, err)
			n, from, err = conn.ReadFrom(buf[:])
			require.NoError(t, err)
			require.Equal(t, 1, n)
			require.Equal(t, byte(j), buf[0])
			require.Equal(t, vip, from.(*net.UDPAddr).AddrPort().Addr().Unmap())
		}
	}
}

func TestAnycastTCPPathChange(t *testing.T) {
	l := newLab(t)
	client := l.host("wan", "192.0.2.1", "", "udp", true)
	relay := l.host("wan", "192.0.2.2", "", "udp", true)
	instance := l.host("wan", "192.0.2.3", "", "udp", true)
	l.link(client, relay)
	l.link(relay, instance)
	l.top.Members[relay.index].Transit = true
	vip := netip.MustParseAddr("10.13.0.200")
	l.top.Members[instance.index].AnycastIPs = []netip.Addr{vip}
	id := l.top.Members[instance.index].ID
	client.nicOptions.ResolveNextHop = func(netip.Addr, []byte) (nebula.PeerID, error) { return id, nil }
	var direct, relayed atomic.Bool
	client.nicOptions.ObserveTransmit = func(r nebula.TransmitResult) {
		if r.Peer != id || r.Destination != vip || r.Err != nil {
			return
		}
		if r.Transport == "udp" && r.Endpoint.IsValid() && len(r.Circuit) == 0 {
			direct.Store(true)
		}
		if r.Transport == "relay" && slices.Equal(r.Circuit, []nebula.PeerID{l.top.Members[client.index].ID, l.top.Members[relay.index].ID, id}) {
			relayed.Store(true)
		}
	}
	l.start()
	l.connect(client, instance, "udp")
	c, s := tcpPair(t, l.business(client), l.business(instance), vip.String(), ipv4.ProtocolNumber)
	roundTrip(t, c, s)
	require.Eventually(t, direct.Load, time.Second, time.Millisecond)
	require.NoError(t, client.node.SetPeerPathPolicy(instance.node.ID(), nebula.RelayOnly))
	l.connect(client, instance, "relay")
	roundTrip(t, c, s)
	require.Eventually(t, relayed.Load, time.Second, time.Millisecond)
}

func TestRelayTCPWithDuplicateInstance(t *testing.T) {
	l := newLab(t)
	client := l.host("west", "192.0.2.1", "", "udp", true)
	relay := l.host("west", "192.0.2.2", "", "udp", true)
	l.addUnderlay(relay, "east", "2001:db8::2", "", "udp", true)
	server := l.host("east", "2001:db8::3", "", "udp", true)
	l.link(client, relay)
	l.link(relay, server)
	l.top.Members[relay.index].Transit = true
	duplicate := &host{index: server.index, ip: server.ip, options: nebula.Options{Auth: nebula.AuthOptions{RootCA: l.root.Chain[0], ClusterCA: l.issuer.Chain[0]}}}
	l.addUnderlay(duplicate, "west", "192.0.2.4", "", "udp", false)
	l.start()
	l.connect(client, server, "relay")
	clientStack := l.business(client)
	c, s := tcpPair(t, clientStack, l.business(server), server.ip.String(), ipv4.ProtocolNumber)
	other, r := tcpPair(t, clientStack, l.business(relay), relay.ip.String(), ipv4.ProtocolNumber)
	roundTrip(t, c, s)
	duplicate.options.Topology = l.top
	duplicate.options.Auth.Certificates = server.options.Auth.Certificates
	var err error
	duplicate.node, err = nebula.New(t.Context(), duplicate.options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = duplicate.node.Close() })
	var misdelivered atomic.Int32
	_, err = duplicate.node.OpenIPPort(nebula.IPPortOptions{Deliver: func(nebula.PeerID, []byte) { misdelivered.Add(1) }})
	require.NoError(t, err)
	require.NoError(t, duplicate.node.Start())
	ep := nebula.Endpoint{Network: "udp", Address: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.4"), meshPort)}
	_, err = client.node.ConnectEndpoint(t.Context(), ep)
	require.ErrorIs(t, err, nebula.ErrInstanceConflict)
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(client.node.InspectIP(server.ip), func(o nebula.IPObservation) bool {
			return o.Source == "conflict" && o.Decision == "held out" && o.Instance == duplicate.node.ControlStatus().Instance
		})
	}, 4*time.Second, 10*time.Millisecond)
	roundTrip(t, c, s)
	roundTrip(t, other, r)
	require.Zero(t, misdelivered.Load())
	p, ok := client.node.PreferredPath(server.node.ID())
	require.True(t, ok)
	require.Equal(t, server.node.ControlStatus().Instance, p.Instance)
	require.NoError(t, server.node.Close())
	require.Eventually(t, func() bool {
		_, ok := client.node.PreferredPath(server.node.ID())
		return !ok
	}, 4*time.Second, 10*time.Millisecond)
	holds := client.node.InstanceConflicts()
	require.Len(t, holds, 1)
	require.Equal(t, server.node.ID(), holds[0].Peer)
	raw := make([]byte, 20)
	raw[0], raw[3], raw[8], raw[9] = 0x45, 20, 64, 253
	copy(raw[12:16], client.ip.AsSlice())
	copy(raw[16:20], server.ip.AsSlice())
	require.IsType(t, &tcpip.ErrNotPermitted{}, clientStack.WriteRawPacket(1, ipv4.ProtocolNumber, buffer.MakeWithData(raw)))
	roundTrip(t, other, r)
}
