package nebula

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
	"code.d7z.net/d7z-team/nebula/portshare"

	"github.com/stretchr/testify/require"
)

type fixture struct {
	t       testing.TB
	root    pki.Issuer
	ca      *x509.Certificate
	key     ed25519.PrivateKey
	cluster pki.Cluster
	cfg     Topology
	nodes   []*Node
	opts    []Options
	ips     []netip.Addr
	sockets []*meteredSocket
}

type meteredSocket struct {
	*net.UDPConn
	mu    sync.Mutex
	sent  map[netip.AddrPort]int
	drop  atomic.Bool
	limit int
}

func (s *meteredSocket) WriteTo(b []byte, to net.Addr) (int, error) {
	ep := addrPort(to)
	s.mu.Lock()
	s.sent[ep]++
	s.mu.Unlock()
	if s.drop.Load() || s.limit > 0 && len(b) > s.limit {
		return len(b), nil
	}
	return s.UDPConn.WriteTo(b, to)
}

func (s *meteredSocket) count(a netip.AddrPort) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[a]
}

func labAddresses(ipv4 netip.Addr) pki.Addresses {
	return pki.Addresses{IPv4: ipv4, IPv6: netip.MustParseAddr(fmt.Sprintf("fd42::%x", ipv4.As4()[3]))}
}

// Fixed lab keys keep independent fixtures and wire-format tests reproducible.
func labKey(ip netip.Addr) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("fixture:" + ip.String()))
	return ed25519.NewKeyFromSeed(seed[:])
}

func labPeer(ip netip.Addr) PeerID {
	id, err := pki.NewPeerID(labKey(ip).Public())
	if err != nil {
		panic(err)
	}
	return id
}

func grantLeaf(t testing.TB, set LocalCertificates) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(set.Grant[0])
	require.NoError(t, err)
	return c
}

func newFixture(t testing.TB, transports ...string) *fixture {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	now := time.Now()
	_, rootKey, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	anchor, e := pki.CreateRoot(rootKey, pki.CAProfile{Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(2 * time.Hour), MaxPathLen: -1})
	require.NoError(t, e)
	root := pki.Issuer{Chain: []*x509.Certificate{anchor}, Signer: rootKey}
	req, e := pki.CreateCSR(key, pkix.Name{})
	require.NoError(t, e)
	ca, e := root.IssueCA(req, pki.CAProfile{
		Subject: pkix.Name{CommonName: "lab cluster"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Scope: &pki.Scope{
			Network: "lab", Cluster: true,
			RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			AnycastPools:   []netip.Prefix{netip.MustParsePrefix("10.13.0.192/27"), netip.MustParsePrefix("fd42::c0/123"), netip.MustParsePrefix("198.51.100.192/28")},
		},
		PermittedIPs: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd42::/64")},
		MaxPathLen:   -1,
	}, sha256.Sum256(req.RawSubjectPublicKeyInfo))
	require.NoError(t, e)
	f := &fixture{t: t, root: root, ca: ca, key: key, cfg: Topology{Network: "lab"}}
	f.cluster, e = pki.ReadClusterCA(ca)
	require.NoError(t, e)
	for i, kind := range transports {
		a := netip.MustParseAddr(fmt.Sprintf("10.13.0.%d", i+1))
		id := labPeer(a)
		cert := f.issue(a, pki.Scope{})
		o := Options{
			Auth:                AuthOptions{RootCA: anchor, ClusterCA: ca, Certificates: cert},
			MaintenanceInterval: 120 * time.Millisecond,
			DialTimeout:         700 * time.Millisecond,
		}
		m := Member{ID: id, IPv4: a, IPv6: labAddresses(a).IPv6, PublishTopics: []string{"app/test"}}
		const loopback = "127.0.0.1:0"
		var sock *meteredSocket
		if kind == "udp" || kind == "both" {
			var pc *net.UDPConn
			for attempt := 1; ; attempt++ {
				pc, e = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(loopback)))
				require.NoError(t, e)
				if kind == "udp" {
					break
				}
				// An ephemeral port assigned by UDP may already be in use by TCP.
				o.Transport.TCP4, e = net.Listen("tcp4", pc.LocalAddr().String())
				if e == nil {
					break
				}
				pc.Close()
				if attempt == 8 {
					t.Fatal(e)
				}
			}
			sock = &meteredSocket{UDPConn: pc, sent: map[netip.AddrPort]int{}, limit: 1200}
			o.Transport.UDP4 = sock
			m.Endpoints = append(m.Endpoints, Endpoint{Network: "udp", Address: addrPort(pc.LocalAddr())})
			t.Cleanup(func() { pc.Close() })
		}
		if kind == "tcp" {
			o.Transport.TCP4, e = net.Listen("tcp4", loopback)
			require.NoError(t, e)
		}
		if l := o.Transport.TCP4; l != nil {
			m.Endpoints = append(m.Endpoints, Endpoint{Network: "tcp", Address: addrPort(l.Addr())})
			t.Cleanup(func() { l.Close() })
		}
		f.ips = append(f.ips, a)
		f.opts = append(f.opts, o)
		f.sockets = append(f.sockets, sock)
		f.cfg.Members = append(f.cfg.Members, m)
	}
	return f
}

func (f *fixture) issue(keyAddr netip.Addr, scope pki.Scope, override ...pki.Addresses) LocalCertificates {
	f.t.Helper()
	priv := labKey(keyAddr)
	addresses := labAddresses(keyAddr)
	if len(override) > 0 {
		addresses = override[0]
	}
	csr, e := pki.CreateCSR(priv, pkix.Name{})
	require.NoError(f.t, e)
	issuer := pki.Issuer{Chain: []*x509.Certificate{f.ca}, Signer: f.key}
	scope.Network = "lab"
	approved := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	leaf, e := issuer.IssueGrant(csr, pki.Enrollment{Scope: scope, IPv4: addresses.IPv4, IPv6: addresses.IPv6, PublicKeyHash: approved, NotBefore: time.Now().Add(-time.Minute).Truncate(time.Second), NotAfter: time.Now().Add(40 * time.Minute)})
	require.NoError(f.t, e)
	node, e := f.root.IssueNode(csr, approved, leaf.NotBefore, leaf.NotAfter)
	require.NoError(f.t, e)
	return LocalCertificates{Node: tls.Certificate{Certificate: [][]byte{node.Raw}, PrivateKey: priv, Leaf: node}, Grant: [][]byte{leaf.Raw, f.ca.Raw}}
}

func (f *fixture) start() {
	f.t.Helper()
	for _, o := range f.opts {
		if o.Topology.Members == nil {
			o.Topology = f.cfg
		}
		n, e := New(f.t.Context(), o)
		require.NoError(f.t, e)
		f.nodes = append(f.nodes, n)
		f.t.Cleanup(func() { n.Close() })
	}
	for _, n := range f.nodes {
		require.NoError(f.t, n.Start())
	}
}

// Each node starts with its own member only. For each requested adjacency,
// wait until both ends can use it to forward a discovery query.
func (f *fixture) startDiscovery(neighbors ...int) {
	f.t.Helper()
	for i := range f.opts {
		if i < len(neighbors) && neighbors[i] >= 0 {
			f.opts[i].Auth.TrustedEntrypoints = append(f.opts[i].Auth.TrustedEntrypoints, f.cfg.Members[neighbors[i]].ID)
		}
		f.opts[i].Topology = Topology{Network: f.cfg.Network, Members: []Member{f.cfg.Members[i]}}
	}
	f.start()
	for i, neighbor := range neighbors {
		if neighbor >= 0 {
			local, remote := f.nodes[i], f.nodes[neighbor]
			ep := f.cfg.Members[neighbor].Endpoints[0]
			id, err := local.ConnectEndpoint(f.t.Context(), ep)
			require.NoError(f.t, err)
			require.Equal(f.t, remote.ID(), id)
			require.Eventually(f.t, func() bool {
				path, ok := remote.PreferredPath(local.ID())
				return ok && path.Transport == ep.Network
			}, 3*time.Second, time.Millisecond, "%s did not register the %s path from %s", id, ep.Network, local.ID())
		}
	}
}

func (f *fixture) link(i, j int) {
	x, y := &f.cfg.Members[i], &f.cfg.Members[j]
	x.Links = append(x.Links, y.ID)
	y.Links = append(y.Links, x.ID)
}

func testIPv4(src, dst netip.Addr, payload string) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	copy(b[20:], payload)
	return b
}

func testIPv6(src, dst netip.Addr, size int) []byte {
	b := make([]byte, size)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(size-40))
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	return b
}

func TestIPDeliveryAndMemberWithdrawal(t *testing.T) {
	f := newFixture(t, "both", "both")
	a, b := f.ips[0], f.ips[1]
	f.link(0, 1)
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	f.opts[1].Auth.Certificates = f.issue(b, pki.Scope{RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	f.start()
	x, y := f.nodes[0], f.nodes[1]
	require.NoError(t, x.ConnectPeer(t.Context(), b))
	out, e := x.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, e)
	// The gateway's default route covers external destinations. An unassigned
	// overlay address still requires its own member.
	unassigned := netip.MustParseAddr("10.13.0.99")
	require.ErrorIs(t, out.WriteIP(y.ID(), testIPv4(a, unassigned, "gw")), ErrAddressUnauthorized)
	in := make(chan []byte, 8)
	_, e = y.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, b []byte) { in <- b }})
	require.NoError(t, e)
	packets := [][]byte{testIPv4(a, b, "hello"), testIPv6(x.Addresses().IPv6, y.Addresses().IPv6, 1280), testIPv4(a, netip.MustParseAddr("192.0.2.10"), "gw")}
	for _, pkt := range packets {
		require.NoError(t, out.WriteIP(y.ID(), pkt))
		select {
		case got := <-in:
			require.Equal(t, pkt, got)
		case <-time.After(3 * time.Second):
			t.Fatalf("IP delivery stalled: %+v %+v", out.Stats(), x.Paths())
		}
	}
	require.Greater(t, x.RecommendedMTU(y.ID(), false, 1500), 1000)
	require.Less(t, x.RecommendedMTU(y.ID(), false, 1500), 1280)
	require.Equal(t, 1280, x.RecommendedMTU(y.ID(), true, 1500))
	require.ErrorIs(t, out.WriteIP(y.ID(), testIPv4(b, a, "spoof")), ErrAddressUnauthorized)
	paths := x.Paths()
	require.NotEmpty(t, paths)
	require.Equal(t, tls.X25519MLKEM768, paths[0].TLSGroup)
	require.Equal(t, uint16(tls.VersionTLS13), paths[0].TLSVersion)
	require.True(t, slices.ContainsFunc(paths, func(p PathStatus) bool { return p.StreamFallbacks > 0 }))
	f.cfg.Members = slices.Delete(f.cfg.Members, 1, 2)
	f.cfg.Members[0].Links = nil
	require.NoError(t, x.ApplyTopology(t.Context(), f.cfg))
	require.ErrorIs(t, out.WriteIP(y.ID(), packets[2]), ErrAddressUnauthorized)
	require.NoError(t, x.SetPeerPathPolicy(y.ID(), Blocked))
	require.Empty(t, x.Paths())
	require.NoError(t, y.ApplyTopology(t.Context(), f.cfg))
	require.False(t, y.ControlStatus().Ready)
	require.True(t, y.ControlStatus().Started)
}

func TestTCPFallbackOnInitialDial(t *testing.T) {
	f := newFixture(t, "both", "both")
	f.sockets[0].drop.Store(true)
	f.opts[0].DialTimeout = 5 * time.Second
	started, release := make(chan struct{}, 1), make(chan struct{})
	var calls atomic.Int32
	f.opts[0].Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	second := Endpoint{"udp", netip.MustParseAddrPort("127.0.0.1:9")}
	f.cfg.Members[1].Endpoints = append(f.cfg.Members[1].Endpoints, second)
	f.start()
	a, b := f.nodes[0], f.ips[1]
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	waiter, abandon := context.WithCancel(ctx)
	abandon()
	require.ErrorIs(t, a.ConnectPeer(waiter, b), context.Canceled)
	a.mu.Lock()
	coldDials := len(a.attempts)
	a.mu.Unlock()
	require.Zero(t, coldDials)

	// Drop UDP and hold the TCP fallback until the initiating caller goes away.
	waiter, abandon = context.WithCancel(ctx)
	defer abandon()
	first, secondWaiter := make(chan error, 1), make(chan error, 1)
	go func() { first <- a.ConnectPeer(waiter, b) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() { secondWaiter <- a.ConnectPeer(ctx, f.cfg.Members[1].IPv6) }()
	abandon()
	require.ErrorIs(t, <-first, context.Canceled)
	close(release)
	require.NoError(t, <-secondWaiter)
	require.EqualValues(t, 1, calls.Load())
	paths := a.Paths()
	require.Len(t, paths, 1)
	require.Equal(t, "tcp", paths[0].Transport)
	require.Positive(t, f.sockets[0].count(f.cfg.Members[1].Endpoints[0].Address))
	require.Zero(t, f.sockets[0].count(second.Address))
}

func TestConnectPeerAcceptsInboundDuringDial(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	vip := netip.MustParseAddr("10.13.0.200")
	f.cfg.Members[1].AnycastIPs = []netip.Addr{vip}
	f.opts[1].Auth.Certificates = f.issue(f.ips[1], pki.Scope{AnycastIPs: []netip.Addr{vip}})
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.opts[0].DialTimeout = 10 * time.Second
	f.opts[0].Transport.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("outbound route unavailable")
		}
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.SetPeerPathPolicy(b.id, DirectOnly))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	sent := make(chan TransmitResult, 2)
	port, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}, ObserveTransmit: func(r TransmitResult) { sent <- r }})
	require.NoError(t, err)
	packet := testIPv4(f.ips[0], vip, "service")
	require.NoError(t, port.WriteIP(b.id, packet))
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	done := make(chan error, 1)
	go func() { done <- a.ConnectPeer(ctx, b.Addresses().IPv4) }()
	port.ClearPending(b.id)
	select {
	case r := <-sent:
		require.ErrorIs(t, r.Err, context.Canceled)
	case <-ctx.Done():
		t.Fatal("cleared packet still waiting for the outbound dial")
	}
	require.NoError(t, port.WriteIP(b.id, packet))
	waiter, stop := context.WithCancel(ctx)
	stop()
	require.ErrorIs(t, a.ConnectPeer(waiter, b.Addresses().IPv6), context.Canceled)
	require.NoError(t, b.ConnectPeer(ctx, a.Addresses().IPv4))
	require.NoError(t, <-done)
	select {
	case r := <-sent:
		require.NoError(t, r.Err)
		require.Equal(t, "tcp", r.Transport)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.EqualValues(t, 1, calls.Load())
	require.Len(t, a.sharedAddressDialSlots, 1)
	close(release)
	require.Eventually(t, func() bool { return len(a.sharedAddressDialSlots) == 0 }, time.Second, time.Millisecond)
}

func TestMixedRelayOnlyAndTopologyWithdrawal(t *testing.T) {
	f := newFixture(t, "udp", "both", "tcp", "tcp")
	for i := 0; i < 3; i++ {
		f.link(i, i+1)
	}
	for i := range f.cfg.Members {
		m := &f.cfg.Members[i]
		m.Transit = i == 1 || i == 2
		m.Restricted = !m.Transit
	}
	f.start()
	a, b := f.nodes[0], f.nodes[3]
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	// This relay has its own publishing policy while the whole path is authorized.
	local := f.cfg
	local.Members = slices.Clone(f.cfg.Members)
	local.Members[1].PublishTopics = []string{"app/relay"}
	require.NoError(t, f.nodes[1].ApplyTopology(ctx, local))
	require.NoError(t, a.SetPeerPathPolicy(b.id, RelayOnly))
	err := a.ConnectPeer(ctx, b.Addresses().IPv4)
	if err != nil {
		for _, n := range f.nodes {
			t.Log(n.Addresses().IPv4, n.Paths(), n.ControlStatus())
		}
	}
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(a.Paths(), func(p PathStatus) bool {
		return p.Peer == b.id && p.Transport == "relay" && slices.Equal(p.Circuit, []PeerID{a.id, f.cfg.Members[1].ID, f.cfg.Members[2].ID, b.id})
	}))
	received := make(chan []byte, 1)
	_, e := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, v []byte) { received <- v }})
	require.NoError(t, e)
	port, e := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, e)
	pkt := testIPv4(a.Addresses().IPv4, b.Addresses().IPv4, string(bytes.Repeat([]byte("x"), 4096)))
	require.NoError(t, port.WriteIP(b.id, pkt))
	select {
	case got := <-received:
		require.Equal(t, pkt, got)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.cfg.Members[1].Transit = false
	require.NoError(t, f.nodes[1].ApplyTopology(ctx, f.cfg))
	require.Eventually(t, func() bool { return a.preferredSession(b.id, false) == nil }, 2*time.Second, 10*time.Millisecond)
}

func TestRelayOnlyEnforcesUnderlayPolicy(t *testing.T) {
	f := newFixture(t, "both", "both")
	var tcpDials atomic.Int64
	f.opts[0].Transport.DialTCP = func(context.Context, string, string) (net.Conn, error) {
		tcpDials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.SetPeerPathPolicy(b.ID(), RelayOnly))
	require.Error(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	a.punch(b.ID())
	require.Zero(t, tcpDials.Load())
	require.Zero(t, f.sockets[0].count(f.cfg.Members[1].Endpoints[0].Address))
}

func TestHealthSwitchesTransportAndRecovers(t *testing.T) {
	f := newFixture(t, "both", "both")
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	active := func() string {
		for _, p := range a.Paths() {
			if p.Peer == b.id && p.Active {
				return p.Transport
			}
		}
		return ""
	}
	require.Equal(t, "udp", active())
	f.sockets[0].drop.Store(true)
	f.sockets[1].drop.Store(true)
	require.Eventually(t, func() bool { return active() == "tcp" }, 6*time.Second, 20*time.Millisecond)
	f.sockets[0].drop.Store(false)
	f.sockets[1].drop.Store(false)
	require.Eventually(t, func() bool { return active() == "udp" }, 12*time.Second, 20*time.Millisecond)
}

func TestParallelCircuitFailover(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	for _, i := range []int{1, 2} {
		f.link(0, i)
		f.link(i, 3)
		f.cfg.Members[i].Transit = true
	}
	f.opts[0].MaxCircuits = 1
	f.start()
	a, b := f.nodes[0], f.nodes[3]
	require.NoError(t, a.SetPeerPathPolicy(b.id, RelayOnly))
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	s := a.preferredSession(b.id, false)
	require.NotNil(t, s)
	path := slices.Clone(s.path)
	require.ErrorIs(t, a.startCircuit(t.Context(), path), ErrPathPolicy)
	require.NoError(t, a.SetPeerPathPolicy(path[1], Blocked))
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	next := a.preferredSession(b.id, false)
	require.NotNil(t, next)
	require.NotEqual(t, path[1], next.path[1])
	require.Equal(t, 1, a.ControlStatus().Circuits)
}

func BenchmarkMeshIP(b *testing.B) {
	for _, network := range []string{"udp", "udp-shared", "tcp"} {
		b.Run(network, func(b *testing.B) {
			transport := network
			shared := network == "udp-shared"
			if shared {
				transport = "udp"
			}
			f := newFixture(b, transport, transport)
			if shared {
				for i := range f.opts {
					mux := portshare.NewUDP(f.opts[i].Transport.UDP4)
					b.Cleanup(func() { mux.Close() })
					f.opts[i].Transport.UDP4 = mux.Mesh()
				}
			}
			f.start()
			client, server := f.nodes[0], f.nodes[1]
			require.NoError(b, client.ConnectPeer(b.Context(), server.Addresses().IPv4))
			recv := make(chan struct{}, 1)
			port, err := client.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
			require.NoError(b, err)
			_, err = server.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) { recv <- struct{}{} }})
			require.NoError(b, err)
			pkt := testIPv4(client.Addresses().IPv4, server.Addresses().IPv4, string(make([]byte, 1004)))
			durations := make([]time.Duration, 0)
			b.SetBytes(int64(len(pkt)))
			for b.Loop() {
				start := time.Now()
				if err := port.WriteIP(server.id, pkt); err != nil {
					b.Fatal(err)
				}
				select {
				case <-recv:
				case <-time.After(2 * time.Second):
					b.Fatal("delivery timeout")
				}
				durations = append(durations, time.Since(start))
			}
			slices.Sort(durations)
			b.ReportMetric(float64(durations[(len(durations)-1)*95/100].Nanoseconds()), "p95-ns")
			b.ReportMetric(float64(durations[(len(durations)-1)*99/100].Nanoseconds()), "p99-ns")
		})
	}
}

func BenchmarkPathStatus(b *testing.B) {
	for _, count := range []int{16, 128} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			f := newFixture(b, slices.Repeat([]string{"tcp"}, count+1)...)
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
			}
			f.start()
			node := f.nodes[0]
			for _, peer := range f.ips[1:] {
				require.NoError(b, node.ConnectPeer(b.Context(), peer))
			}
			for b.Loop() {
				if got := len(node.Paths()); got != count {
					b.Fatalf("got %d sessions, want %d", got, count)
				}
			}
		})
	}
}

func TestNodeOptionLimits(t *testing.T) {
	f := newFixture(t, "")
	opts := Options{Auth: f.opts[0].Auth, Topology: f.cfg}
	n, err := New(t.Context(), opts)
	require.NoError(t, err)
	t.Cleanup(func() { n.Close() })
	require.Equal(t, 2*time.Second, n.o.MaintenanceInterval)
	require.Equal(t, 4*time.Second, n.o.DialTimeout)
	require.Equal(t, 256, cap(n.handshakeSlots))
	require.Equal(t, 512, n.o.MaxCircuits)
	require.Equal(t, MaxIPPacketSize, n.MaxIPSize())

	for _, tc := range []struct {
		field string
		opts  Options
	}{
		{"MaintenanceInterval", Options{MaintenanceInterval: -time.Second}},
		{"DialTimeout", Options{DialTimeout: -time.Second}},
		{"MaxInboundHandshakes", Options{MaxInboundHandshakes: -1}},
		{"MaxCircuits", Options{MaxCircuits: -1}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			tc.opts.Auth, tc.opts.Topology = opts.Auth, opts.Topology
			_, err := New(t.Context(), tc.opts)
			require.ErrorContains(t, err, tc.field)
		})
	}
}

func TestNodeLifecycle(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	o := f.opts[0]
	o.Topology = f.cfg
	n, err := New(t.Context(), o)
	require.NoError(t, err)
	t.Cleanup(func() { n.Close() })
	peer := f.cfg.Members[1]
	port, err := n.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	sub, err := n.Subscribe("app/test")
	require.NoError(t, err)
	require.NoError(t, n.SetPeerPathPolicy(peer.ID, DirectOnly))
	offlineIP := netip.MustParseAddr("10.13.0.42")
	offline := labPeer(offlineIP)
	_, known := n.LookupPeer(offlineIP)
	require.False(t, known)
	require.NoError(t, n.SetPeerPathPolicy(offline, RelayOnly))
	configured, effective := n.PeerPathPolicy(offline)
	require.Equal(t, RelayOnly, configured)
	require.Equal(t, RelayOnly, effective)
	ip := testIPv4(f.ips[0], peer.IPv4, "data")
	checkOperations := func(want error) {
		t.Helper()
		require.ErrorIs(t, n.ConnectPeer(t.Context(), peer.IPv4), want)
		require.ErrorIs(t, n.ConnectPeerID(t.Context(), peer.ID), want)
		_, err := n.ConnectEndpoint(t.Context(), peer.Endpoints[0])
		require.ErrorIs(t, err, want)
		_, err = n.ResolveIP(t.Context(), peer.IPv4)
		require.ErrorIs(t, err, want)
		_, err = n.Publish(t.Context(), "app/test", nil)
		require.ErrorIs(t, err, want)
		require.ErrorIs(t, port.WriteIP(peer.ID, ip), want)
	}
	checkOperations(ErrNodeNotStarted)
	require.NoError(t, n.Start())
	require.ErrorIs(t, n.Start(), ErrNodeAlreadyStarted)
	port.Close()
	require.ErrorIs(t, port.WriteIP(peer.ID, ip), ErrPortClosed)
	require.NoError(t, n.Close())
	require.ErrorIs(t, n.Start(), ErrNodeClosed)
	checkOperations(ErrNodeClosed)
	_, open := <-sub.Publications()
	require.False(t, open)
}
