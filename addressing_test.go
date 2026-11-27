package nebula

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.d7z.net/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestClusterGroupRecipients(t *testing.T) {
	f := newFixture(t, "", "", "")
	a := netip.MustParseAddr
	all := []PeerID{f.cfg.Members[0].ID, f.cfg.Members[1].ID, f.cfg.Members[2].ID}
	subscribers := all[1:2]
	f.cfg.Members[1].MulticastGroups = []netip.Addr{a("224.0.0.22"), a("ff02::123"), a("ff05::123"), a("239.1.1.1"), a("239.1.1.1")}
	f.cfg.EnableMulticast, f.cfg.EnableBroadcast = true, true
	view, err := f.cfg.compile(f.cluster)
	require.NoError(t, err)
	for dst, want := range map[string][]PeerID{
		"255.255.255.255": all, "10.13.0.255": all, "224.0.0.1": all, "ff02::1": all,
		"224.0.0.22": subscribers, "ff02::123": subscribers, "ff05::123": subscribers, "239.1.1.1": subscribers,
		"ff01::1": nil, "239.1.1.2": nil,
	} {
		peers, group, err := view.groupRecipients(a(dst))
		require.NoError(t, err)
		require.True(t, group)
		require.ElementsMatch(t, want, peers, dst)
	}
}

func TestBoundedGroupQueues(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.cfg.EnableBroadcast = true
	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	n := f.nodes[0]
	for _, ip := range f.ips[1:] {
		require.NoError(t, n.ConnectPeer(t.Context(), ip))
	}
	p, err := n.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.True(t, n.limiter.AllowN(time.Now(), MaxIPPacketSize+1))
	write := func(dst netip.Addr) error { return p.WriteIP(PeerID{}, testIPv4(f.ips[0], dst, "bounded")) }
	require.NoError(t, write(f.ips[1]))
	require.Eventually(t, func() bool { return p.Stats().Queued == 0 }, time.Second, time.Millisecond)
	for range 64 {
		require.NoError(t, write(f.ips[1]))
	}
	require.NoError(t, write(limitedBroadcast))
	require.Eventually(t, func() bool { return p.Stats().Queued == 64 }, time.Second, time.Millisecond)
	for range 64 {
		require.NoError(t, write(f.ips[2]))
	}
	require.ErrorIs(t, write(limitedBroadcast), ErrQueueFull)
	require.EqualValues(t, 3, p.Stats().RejectedOutbound)
	f.cfg.EnableBroadcast = false
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool { return p.Stats().RejectedOutbound == 4 }, time.Second, time.Millisecond)
	require.ErrorIs(t, write(limitedBroadcast), ErrPathPolicy)
	for _, peer := range f.nodes[1:] {
		p.ClearPending(peer.ID())
	}
	require.Zero(t, p.Stats().SentPackets)
}

func TestIngressVIPAndGroupAuthority(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	a, b := f.ips[0], f.ips[1]
	vip, group := netip.MustParseAddr("198.51.100.200"), netip.MustParseAddr("239.1.2.3")
	any := netip.MustParsePrefix("0.0.0.0/0")
	// The topology activates the VIP, but neither handshake credential grants it.
	for i, m := range f.cfg.Members {
		f.cfg.Members[i].AnycastIPs = []netip.Addr{vip}
		f.cfg.Members[i].RoutedPrefixes = []netip.Prefix{any}
		f.opts[i].Auth.Certificates = f.issue(m.IPv4, pki.Scope{RoutedPrefixes: []netip.Prefix{any}})
	}
	f.cfg.EnableMulticast = true
	f.cfg.Members[1].MulticastGroups = []netip.Addr{group}
	f.start()
	n, remote := f.nodes[0], f.nodes[1]
	require.NoError(t, n.ConnectPeer(t.Context(), b))
	rx := make(chan []byte, 4)
	sink, err := remote.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, buf []byte) { rx <- buf }})
	require.NoError(t, err)
	out, err := n.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.NoError(t, out.WriteIP(remote.ID(), testIPv4(a, vip, "no service grant")))
	require.Eventually(t, func() bool { return out.Stats().RejectedOutbound == 1 }, time.Second, time.Millisecond)
	// A signed identity carrying a default route still cannot inject an unauthorized VIP.
	stream, err := n.preferredSession(remote.id, false).open(t.Context())
	require.NoError(t, err)
	defer stream.Close()
	_, err = stream.Write([]byte{opIP})
	require.NoError(t, err)
	for _, packet := range [][]byte{testIPv4(vip, b, "source"), testIPv4(a, vip, "destination"), testIPv4(netip.MustParseAddr("10.13.0.255"), b, "broadcast source")} {
		require.NoError(t, writeFrame(stream, packet))
	}
	f.cfg.EnableMulticast = false
	require.NoError(t, remote.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, writeFrame(stream, testIPv4(a, group, "group disabled at receiver")))
	require.Eventually(t, func() bool { return sink.Stats().RejectedInbound == 4 }, time.Second, time.Millisecond)
	require.Empty(t, rx)
}

func TestResolveNextHopWithTopologyChange(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	vip := netip.MustParseAddr("10.13.0.200")
	for i := 1; i < len(f.cfg.Members); i++ {
		f.cfg.Members[i].AnycastIPs = []netip.Addr{vip}
	}
	f.cfg.EnableMulticast = true
	f.start()
	client, first, second := f.nodes[0], f.nodes[1], f.nodes[2]
	write := func(p *IPPort, peer PeerID, dst netip.Addr, body string) error {
		return p.WriteIP(peer, testIPv4(client.Addresses().IPv4, dst, body))
	}
	p, err := client.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.ErrorIs(t, write(p, PeerID{}, vip, ""), ErrNextHopRequired)
	p.Close()

	members := client.AnycastMembers(vip)
	require.ElementsMatch(t, []PeerID{first.id, second.id}, members)
	clear(members)
	require.NotContains(t, client.AnycastMembers(vip), PeerID{})
	_, ok := client.LookupPeer(vip)
	require.False(t, ok)
	for _, ip := range []netip.Addr{first.Addresses().IPv4, first.Addresses().IPv6} {
		id, ok := client.LookupPeer(ip)
		require.True(t, ok)
		require.Equal(t, first.id, id)
	}

	var calls atomic.Int32
	hold, release := make(chan struct{}), make(chan struct{})
	denied := errors.New("service unavailable")
	p, err = client.OpenIPPort(IPPortOptions{
		Deliver: func(PeerID, []byte) {},
		ResolveNextHop: func(dst netip.Addr, packet []byte) (PeerID, error) {
			calls.Add(1)
			p.Stats()
			client.Paths()
			if dst != vip {
				return PeerID{}, denied
			}
			switch string(packet[20:]) {
			case "empty":
				return PeerID{}, nil
			case "hold":
				close(hold)
				select {
				case <-release:
				case <-t.Context().Done():
					return PeerID{}, t.Context().Err()
				}
			}
			return first.id, nil
		},
	})
	require.NoError(t, err)
	require.ErrorIs(t, write(p, PeerID{}, vip, "empty"), ErrNextHopRequired)
	require.ErrorIs(t, write(p, PeerID{}, netip.MustParseAddr("192.0.2.10"), ""), denied)
	require.NoError(t, write(p, PeerID{}, first.Addresses().IPv4, "owned"))
	require.NoError(t, write(p, PeerID{}, netip.MustParseAddr("239.1.1.3"), "empty group"))
	require.ErrorIs(t, write(p, PeerID{}, netip.MustParseAddr("10.13.0.42"), ""), ErrPeerUnavailable)
	require.ErrorIs(t, write(p, second.id, first.Addresses().IPv4, ""), ErrAddressUnauthorized)
	require.EqualValues(t, 2, calls.Load())
	done := make(chan error, 1)
	go func() { done <- write(p, PeerID{}, vip, "hold") }()
	select {
	case <-hold:
	case <-time.After(2 * time.Second):
		t.Fatal("resolver did not run")
	}
	f.cfg.Members[1].AnycastIPs = nil
	require.NoError(t, client.ApplyTopology(t.Context(), f.cfg))
	close(release)
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrAddressUnauthorized)
	case <-time.After(2 * time.Second):
		t.Fatal("write did not finish")
	}
	require.EqualValues(t, 3, calls.Load())
	require.Equal(t, []PeerID{second.id}, client.AnycastMembers(vip))
}

func TestAnycastSubmissionAndWithdrawal(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	vip := netip.MustParseAddr("198.51.100.200")
	for i := 1; i < len(f.opts); i++ {
		m := &f.cfg.Members[i]
		m.AnycastIPs = []netip.Addr{vip}
		f.opts[i].Auth.Certificates = f.issue(m.IPv4, pki.Scope{AnycastIPs: m.AnycastIPs})
	}
	// The client initially has an endpoint only for B.
	endpoints := f.cfg.Members[1].Endpoints
	f.cfg.Members[1].Endpoints = nil
	f.start()
	client, a, b := f.nodes[0], f.nodes[1], f.nodes[2]
	results := make(chan TransmitResult, 8)
	var out *IPPort
	out, err := client.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}, ObserveTransmit: func(r TransmitResult) {
		out.Stats()
		client.Paths()
		results <- r
	}})
	require.NoError(t, err)
	type delivery struct {
		dst, from PeerID
		body      string
	}
	received := make(chan delivery, 8)
	for _, n := range f.nodes[1:] {
		_, err := n.OpenIPPort(IPPortOptions{Deliver: func(from PeerID, packet []byte) {
			received <- delivery{n.id, from, string(packet[20:])}
		}})
		require.NoError(t, err)
	}
	write := func(peer PeerID, body string) {
		t.Helper()
		require.NoError(t, out.WriteIP(peer, testIPv4(client.Addresses().IPv4, vip, body)))
	}
	result := func(peer PeerID) TransmitResult {
		t.Helper()
		select {
		case r := <-results:
			require.Equal(t, peer, r.Peer)
			require.Equal(t, client.Addresses().IPv4, r.Source)
			require.Equal(t, vip, r.Destination)
			return r
		case <-time.After(3 * time.Second):
			t.Fatal("missing submission result")
			return TransmitResult{}
		}
	}
	write(a.id, "cold failure")
	r := result(a.id)
	require.Error(t, r.Err)
	require.Empty(t, r.Transport)
	write(b.id, "selected B")
	r = result(b.id)
	require.NoError(t, r.Err)
	require.Equal(t, "tcp", r.Transport)
	require.True(t, r.Endpoint.IsValid())
	select {
	case d := <-received:
		require.Equal(t, delivery{b.id, client.id, "selected B"}, d)
	case <-time.After(2 * time.Second):
		t.Fatal("B did not receive its packet")
	}

	f.cfg.Members[1].Endpoints = endpoints
	f.cfg.Members[0].BytesPerSecond = 1
	require.NoError(t, client.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, client.ConnectPeer(t.Context(), a.Addresses().IPv4))
	require.True(t, client.limiter.AllowN(time.Now(), MaxIPPacketSize+1))
	write(a.id, "in flight")
	require.Eventually(t, func() bool { return out.Stats().Queued == 0 }, time.Second, time.Millisecond)
	write(a.id, "queued")
	f.cfg.Members[1].AnycastIPs = nil
	require.NoError(t, client.ApplyTopology(t.Context(), f.cfg))
	require.ErrorIs(t, result(a.id).Err, ErrAddressUnauthorized)
	require.EqualValues(t, 3, out.Stats().RejectedOutbound)
	require.EqualValues(t, 1, out.Stats().SentPackets)
	require.Zero(t, out.Stats().Queued)
	require.Equal(t, []PeerID{b.id}, client.AnycastMembers(vip))
	require.Empty(t, received)
}

// Return once the first packet is waiting for bandwidth and the rest are queued.
func queueShapedPackets(t *testing.T, a, b *Node, dst netip.Addr, bodies ...string) (*IPPort, <-chan TransmitResult, <-chan string) {
	t.Helper()
	received := make(chan string, len(bodies))
	_, err := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, pkt []byte) { received <- string(pkt[20:]) }})
	require.NoError(t, err)
	results := make(chan TransmitResult, len(bodies))
	port, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}, ObserveTransmit: func(r TransmitResult) { results <- r }})
	require.NoError(t, err)
	require.True(t, a.limiter.AllowN(time.Now(), MaxIPPacketSize+1))
	for _, body := range bodies {
		require.NoError(t, port.WriteIP(b.id, testIPv4(a.Addresses().IPv4, dst, body)))
	}
	require.Eventually(t, func() bool {
		return a.limiter.Tokens() < 0 && port.Stats().Queued == len(bodies)-1
	}, time.Second, time.Millisecond)
	return port, results, received
}

func TestChaosPathLossWhileShaping(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeerID(t.Context(), b.id))
	port, results, received := queueShapedPackets(t, a, b, b.Addresses().IPv4, "in flight", "queued")
	require.Eventually(t, func() bool { return b.preferredSession(a.id, true) != nil }, time.Second, time.Millisecond)
	b.preferredSession(a.id, true).close()
	require.Eventually(t, func() bool { _, ok := a.PreferredPath(b.id); return !ok }, time.Second, time.Millisecond)
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))

	require.Eventually(t, func() bool { return len(results) == 2 }, 3*time.Second, time.Millisecond)
	require.ErrorIs(t, (<-results).Err, ErrPeerUnavailable)
	recovered := <-results
	require.NoError(t, recovered.Err)
	require.Equal(t, "tcp", recovered.Transport)
	select {
	case got := <-received:
		require.Equal(t, "queued", got)
	case <-time.After(time.Second):
		t.Fatal("missing packet on the replacement connection")
	}
	require.EqualValues(t, 1, port.Stats().RejectedOutbound)
}

func TestReplyViaIngressGateway(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	src := netip.MustParseAddr("192.0.2.7")
	for i := 1; i < len(f.opts); i++ {
		m := &f.cfg.Members[i]
		m.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
		if i == 1 {
			m.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		}
		f.opts[i].Auth.Certificates = f.issue(m.IPv4, pki.Scope{RoutedPrefixes: m.RoutedPrefixes})
	}
	var siteOnly atomic.Bool
	siteID := f.cfg.Members[2].ID
	f.opts[0].InboundPolicy = func(from PeerID, source, dest netip.Addr) bool {
		return !siteOnly.Load() || from == siteID
	}
	f.start()
	service := f.nodes[0]
	type receipt struct {
		from   PeerID
		packet []byte
	}
	requests := make(chan receipt, 2)
	server, err := service.OpenIPPort(IPPortOptions{Deliver: func(from PeerID, b []byte) { requests <- receipt{from, b} }})
	require.NoError(t, err)
	ports := make([]*IPPort, 0, 2)
	for _, gw := range f.nodes[1:] {
		replies := make(chan receipt, 2)
		port, err := gw.OpenIPPort(IPPortOptions{Deliver: func(from PeerID, b []byte) { replies <- receipt{from, b} }})
		require.NoError(t, err)
		ports = append(ports, port)
		body := gw.id.String()
		require.NoError(t, port.WriteIP(PeerID{}, testIPv4(src, service.Addresses().IPv4, body)))
		select {
		case req := <-requests:
			require.Equal(t, gw.id, req.from)
			require.Equal(t, body, string(req.packet[20:]))
			require.NoError(t, server.WriteIP(req.from, testIPv4(service.Addresses().IPv4, src, body)))
		case <-time.After(2 * time.Second):
			t.Fatal("missing request")
		}
		select {
		case reply := <-replies:
			require.Equal(t, service.id, reply.from)
			require.Equal(t, body, string(reply.packet[20:]))
		case <-time.After(2 * time.Second):
			t.Fatal("missing gateway reply")
		}
	}
	siteOnly.Store(true)
	for _, port := range ports {
		require.NoError(t, port.WriteIP(PeerID{}, testIPv4(src, service.Addresses().IPv4, "site only")))
	}
	require.Eventually(t, func() bool { return server.Stats().RejectedInbound == 1 && len(requests) == 1 }, 2*time.Second, time.Millisecond)
	require.Equal(t, siteID, (<-requests).from)
}

// Withdraw one client's default exit while it has both a shaped packet and
// a backlog. The site route and another client's exit decision stay usable.
func TestChaosDefaultExitWithdrawal(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	dst := netip.MustParseAddr("172.30.0.8")
	for i, prefix := range []string{"0.0.0.0/0", "172.30.0.0/24"} {
		m := &f.cfg.Members[i+1]
		m.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix(prefix)}
		f.opts[i+1].Auth.Certificates = f.issue(m.IPv4, pki.Scope{RoutedPrefixes: m.RoutedPrefixes})
	}
	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	a, exit, site, b := f.nodes[0], f.nodes[1], f.nodes[2], f.nodes[3]
	require.NoError(t, a.ConnectPeerID(t.Context(), exit.id))
	out, results, atExit := queueShapedPackets(t, a, exit, dst, "in flight", "queued")
	for _, addr := range []netip.Addr{a.Addresses().IPv4, netip.MustParseAddr("10.13.0.99"), netip.MustParseAddr("198.51.100.200")} {
		require.ErrorIs(t, out.WriteIP(exit.id, testIPv4(a.Addresses().IPv4, addr, "reserved")), ErrAddressUnauthorized)
	}
	f.cfg.Members[1].RoutedPrefixes = nil
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool { return len(results) > 0 }, time.Second, time.Millisecond)
	require.ErrorIs(t, (<-results).Err, ErrAddressUnauthorized)
	require.EqualValues(t, 2, out.Stats().RejectedOutbound)
	require.Zero(t, out.Stats().Queued)
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	atSite := make(chan string, 1)
	_, err := site.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, pkt []byte) { atSite <- string(pkt[20:]) }})
	require.NoError(t, err)
	other, err := b.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.NoError(t, out.WriteIP(site.id, testIPv4(a.Addresses().IPv4, dst, "site")))
	require.NoError(t, other.WriteIP(exit.id, testIPv4(b.Addresses().IPv4, dst, "exit")))
	require.Eventually(t, func() bool { return len(atSite) == 1 && len(atExit) == 1 }, 2*time.Second, time.Millisecond)
	require.Equal(t, "site", <-atSite)
	require.Equal(t, "exit", <-atExit)
}

func BenchmarkPacketAuthorization(b *testing.B) {
	f := newFixture(b, "", "")
	f.cfg.EnableMulticast = true
	group := netip.MustParseAddr("239.1.2.3")
	vip := netip.MustParseAddr("10.13.0.200")
	for i := 3; i <= 128; i++ {
		pair := labAddresses(netip.AddrFrom4([4]byte{10, 13, 0, byte(i)}))
		f.cfg.Members = append(f.cfg.Members, Member{ID: labPeer(pair.IPv4), IPv4: pair.IPv4, IPv6: pair.IPv6})
	}
	for i := range f.cfg.Members {
		f.cfg.Members[i].MulticastGroups = []netip.Addr{group}
	}
	instance := &f.cfg.Members[len(f.cfg.Members)-1]
	instance.AnycastIPs = []netip.Addr{vip}
	instance.RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	cfg, err := f.cfg.compile(f.cluster)
	require.NoError(b, err)
	source := f.cfg.Members[0]
	from := pki.Identity{ID: source.ID, Addresses: source.addresses()}
	to := pki.Identity{
		ID: instance.ID, Addresses: instance.addresses(),
		Scope: pki.Scope{AnycastIPs: instance.AnycastIPs, RoutedPrefixes: instance.RoutedPrefixes},
	}
	for _, tc := range []struct {
		name string
		dst  netip.Addr
	}{
		{"primary", instance.IPv4}, {"vip", vip}, {"downstream", netip.MustParseAddr("192.0.2.1")}, {"group-128", group},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ip := innerPacket{source: from.IPv4, destination: tc.dst}
			for b.Loop() {
				if !ip.authorizedOn(cfg, from, to) {
					b.Fatal("authorized packet rejected")
				}
			}
		})
	}
}

func TestChaosRelayOnlyWhileShaping(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.link(0, 1)
	f.link(1, 2)
	f.cfg.Members[1].Transit = true
	f.cfg.Members[0].BytesPerSecond = 1
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.start()
	a, r, b := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, r.ConnectPeerID(t.Context(), b.id))
	require.NoError(t, a.ConnectPeerID(t.Context(), r.id))
	require.NoError(t, a.ConnectPeerID(t.Context(), b.id))
	direct, ok := a.PreferredPath(b.id)
	require.True(t, ok)
	require.Equal(t, "tcp", direct.Transport)
	out, results, received := queueShapedPackets(t, a, b, b.Addresses().IPv4, "in flight", "second", "third")
	require.NoError(t, a.SetPeerPathPolicy(b.id, RelayOnly))
	select {
	case r := <-results:
		require.ErrorIs(t, r.Err, ErrPathPolicy)
	case <-time.After(time.Second):
		t.Fatal("old path still waiting for bandwidth")
	}
	require.Eventually(t, func() bool {
		path, ok := a.PreferredPath(b.id)
		return ok && path.Transport == "relay" && a.limiter.Tokens() < 0
	}, 2*time.Second, time.Millisecond)
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool { return len(received) == 2 && len(results) == 2 }, 3*time.Second, time.Millisecond)
	for _, want := range []string{"second", "third"} {
		require.Equal(t, want, <-received)
		r := <-results
		require.NoError(t, r.Err)
		require.Equal(t, "relay", r.Transport)
	}
	require.EqualValues(t, 1, out.Stats().RejectedOutbound)
}
