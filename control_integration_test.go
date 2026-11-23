package nebula_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/control"
	"github.com/slackhq/nebula/nebulagvisor"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type managedTransport struct {
	nebula.DatagramTransport
	mu      sync.Mutex
	blocked netip.AddrPort
	writes  map[netip.AddrPort]int
}

func (t *managedTransport) WriteTo(b []byte, to netip.AddrPort) error {
	t.mu.Lock()
	t.writes[to]++
	blocked := to == t.blocked
	t.mu.Unlock()
	if blocked {
		return nil
	}
	return t.DatagramTransport.WriteTo(b, to)
}

type managedPeer struct {
	transport *managedTransport
	id        netip.Addr
	crt       cert.Certificate
	key       []byte
	publisher ed25519.PrivateKey
	stack     *stack.Stack
	socket    net.PacketConn
	opts      nebula.Options
	n         *nebula.Node
}

type managedMesh struct {
	ca     cert.Certificate
	signer *ecdsa.PrivateKey
	cfg    control.Config
	peers  []managedPeer
}

type meshOptions struct {
	size             int
	terminalMappings int
	ipv6Overlay      bool
	restricted       bool
	extra            [][2]int
	observedOnly     bool   // derive dynamic candidates from direct neighbor observations
	stockRelay       string // run the middle peer of a three-node mesh as an upstream subprocess
}

func newManagedMesh(t *testing.T, opt meshOptions) *managedMesh {
	t.Helper()
	ca, k, err := cert.CreateCA(cert.CAOptions{Name: "network operator", Curve: cert.Curve_P256})
	require.NoError(t, err)
	signer, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k)
	require.NoError(t, err)
	m := &managedMesh{ca: ca, signer: signer, cfg: control.Config{Format: 1, Network: "integration", Revision: 41, Members: map[netip.Addr]control.Member{}}, peers: make([]managedPeer, opt.size)}
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	subnet := netip.MustParsePrefix("10.90.0.0/24")
	proto := ipv4.ProtocolNumber
	if opt.ipv6Overlay {
		subnet = netip.MustParsePrefix("fd90::/64")
		proto = ipv6.ProtocolNumber
	}
	next := subnet.Addr().Next()
	for i := range m.peers {
		p := &m.peers[i]
		p.id, next = next, next.Next()
		p.crt, p.key, err = cert.IssueCertificate(ca, k, cert.CertificateOptions{Name: p.id.String(), Networks: []netip.Prefix{netip.PrefixFrom(p.id, subnet.Bits())}, NotAfter: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		_, p.publisher, err = ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		p.socket, err = net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.socket.Close() })
	}
	for i := range m.peers {
		p := &m.peers[i]
		fp, err := p.crt.Fingerprint()
		require.NoError(t, err)
		member := control.Member{Certificate: fp, Transit: opt.restricted && i > 0 && i < opt.size-1, Restricted: opt.restricted && (i == 0 || i == opt.size-1), Publisher: p.publisher.Public().(ed25519.PublicKey), Topics: []string{"app/test"}}
		static := map[netip.Addr][]netip.AddrPort{}
		links := []int{i - 1, i + 1}
		for _, edge := range opt.extra {
			switch i {
			case edge[0]:
				links = append(links, edge[1])
			case edge[1]:
				links = append(links, edge[0])
			}
		}
		for _, j := range links {
			if j >= 0 && j < opt.size {
				q := m.peers[j]
				member.Links = append(member.Links, q.id)
				static[q.id] = []netip.AddrPort{q.socket.LocalAddr().(*net.UDPAddr).AddrPort()}
			}
		}
		if member.Transit {
			member.BytesPerSecond = 1 << 20
		}
		m.cfg.Members[p.id] = member
		p.transport = &managedTransport{DatagramTransport: nebula.WrapPacketConn(p.socket), writes: map[netip.AddrPort]int{}}
		p.opts = nebula.Options{
			Identities: []nebula.Identity{{Certificate: p.crt, PrivateKey: p.key}},
			CAPool:     pool, Transport: p.transport,
			Paths: nebula.PathOptions{
				Probes: nebula.PathProbeOptions{
					ActiveInterval: 250 * time.Millisecond, StandbyInterval: 300 * time.Millisecond,
					InitialTimeout: 250 * time.Millisecond, MinTimeout: 100 * time.Millisecond,
					TickInterval: 50 * time.Millisecond,
				},
				Selection: nebula.PathSelectionOptions{FailureThreshold: 2, RetryInterval: 100 * time.Millisecond},
			},
			Relay:     nebula.RelayOptions{Serve: member.Transit},
			Handshake: nebula.HandshakeOptions{TryInterval: 50 * time.Millisecond, Retries: 15},
			Lighthouse: nebula.LighthouseOptions{
				StaticHosts:        static,
				AdvertiseEndpoints: []netip.AddrPort{p.socket.LocalAddr().(*net.UDPAddr).AddrPort()},
			},
			Control: &nebula.ControlOptions{
				Authority: ca, Network: m.cfg.Network, Bootstrap: member.Links, Publisher: p.publisher,
				StateFile: filepath.Join(t.TempDir(), "current.json"), SyncInterval: 200 * time.Millisecond,
			},
		}
		if member.Restricted {
			p.opts.Relay.MaxMappings = opt.terminalMappings
		}
		if opt.observedOnly {
			p.opts.Lighthouse.AdvertiseEndpoints = nil
		}
		if opt.stockRelay != "" {
			if i == 1 {
				nebula.StartTestStockNode(t, opt.stockRelay, pool, p.opts.Identities[0], p.socket.(*net.UDPConn), static, nil, true)
				continue
			}
			other := m.peers[2-i].id
			p.opts.Paths.Peers = map[netip.Addr]nebula.PeerPathPolicy{other: {Mode: nebula.RelayOnly, Relays: []netip.Addr{m.peers[1].id}}}
			member.Links = nil
			m.cfg.Members[p.id] = member
		}
		p.n, err = nebula.New(t.Context(), p.opts)
		require.NoError(t, err)
		p.stack = newStack(t)
		ep, err := nebulagvisor.NewEndpoint(p.n, nebulagvisor.Options{})
		require.NoError(t, err)
		addNIC(t, p.stack, 1, ep, p.id.String())
		p.stack.SetRouteTable([]tcpip.Route{route(subnet.String(), "", 1)})
		socket, err := gonet.DialUDP(p.stack, &tcpip.FullAddress{Addr: addr(p.id.String()), Port: nebula.DefaultControlPort}, nil, proto)
		require.NoError(t, err)
		require.NoError(t, p.n.AttachControl(socket))
		t.Cleanup(func() { require.NoError(t, p.n.Close()); require.NoError(t, p.n.Wait()) })
	}
	if opt.stockRelay != "" {
		delete(m.cfg.Members, m.peers[1].id)
		m.apply(t, 2)
	}
	m.apply(t, 0)
	for _, p := range m.peers {
		if p.n == nil {
			continue
		}
		require.NoError(t, p.n.Start())
	}
	m.synced(t)
	return m
}

func (m *managedMesh) apply(t *testing.T, i int) {
	t.Helper()
	wire, err := control.Sign(m.cfg, m.ca, m.signer)
	require.NoError(t, err)
	require.NoError(t, m.peers[i].n.ApplyNetworkConfig(t.Context(), wire))
}

func (m *managedMesh) synced(t *testing.T) {
	t.Helper()
	for _, p := range m.peers {
		if p.n == nil {
			continue
		}
		require.Eventually(t, func() bool { return p.n.ControlStatus().Revision == m.cfg.Revision }, 12*time.Second, 20*time.Millisecond, "node %s", p.id)
	}
}

func TestManagedDiscoveryAndEvents(t *testing.T) {
	m := newManagedMesh(t, meshOptions{size: 3, observedOnly: true})
	a, b := m.peers[0], m.peers[2]
	sub, err := b.n.Subscribe("app/test/update")
	require.NoError(t, err)
	defer sub.Close()
	id, err := a.n.Publish(t.Context(), "app/test/update", []byte("changed"))
	require.NoError(t, err)
	select {
	case e := <-sub.Events():
		require.Equal(t, id, e.ID)
		require.Equal(t, a.id, e.Origin)
		require.Equal(t, []byte("changed"), e.Payload)
	case <-time.After(6 * time.Second):
		t.Fatal("missing event")
	}
	_, err = a.n.Publish(t.Context(), "app/admin/update", nil)
	require.Error(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	require.NoError(t, a.n.ConnectPeer(ctx, b.id))
	peer, ok := a.n.Peer(b.id)
	require.True(t, ok)
	require.Equal(t, b.socket.LocalAddr().(*net.UDPAddr).AddrPort(), peer.CurrentEndpoint)
	// Rotate the full list forward without replaying intermediate revisions.
	fp, err := b.crt.Fingerprint()
	require.NoError(t, err)
	m.cfg.Revision = 47
	m.cfg.Revoked = []string{fp}
	m.apply(t, 0)
	require.Eventually(t, func() bool { peer, ok := a.n.Peer(b.id); return !ok || peer.Certificate == nil }, time.Second, 10*time.Millisecond)
	// The final neighbor may itself be the revoked identity; install the next
	// signed snapshot through the trusted local administration entry point.
	m.cfg.Revision++
	m.cfg.Revoked = nil
	m.apply(t, 0)
	m.synced(t)
	require.NoError(t, a.n.ConnectPeer(ctx, b.id))
}

func TestManagedMultiHop(t *testing.T) {
	for _, family := range []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
	}{{"IPv4", ipv4.ProtocolNumber}, {"IPv6", ipv6.ProtocolNumber}} {
		t.Run(family.name, func(t *testing.T) {
			m := newManagedMesh(t, meshOptions{size: 5, restricted: true, terminalMappings: 1, ipv6Overlay: family.proto == ipv6.ProtocolNumber})
			a, b := m.peers[0], m.peers[4]
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := a.n.ConnectPeer(ctx, b.id)
			if err != nil {
				for _, p := range m.peers {
					t.Log(p.id, p.n.ControlStatus())
				}
			}
			require.NoError(t, err)
			x, err := a.n.CheckPeerPath(ctx, b.id, nebula.TunnelPath{})
			require.NoError(t, err)
			require.True(t, x.SamePath)
			require.NotEmpty(t, x.Sent.Circuit)
			conn, accepted := tcpPair(t, a.stack, b.stack, b.id.String(), family.proto)
			roundTrip(t, conn, accepted)
			require.Equal(t, 1, a.n.RelayStats().UsedMappings)
			require.Equal(t, 1, b.n.RelayStats().UsedMappings)
			for _, p := range m.peers[1:4] {
				require.Positive(t, p.n.RelayStats().ForwardedDatagrams)
				require.Positive(t, p.n.ControlStatus().Egress.SentBytes)
			}
			_, err = a.n.CheckPeerPath(ctx, b.id, nebula.TunnelPath{Endpoint: b.socket.LocalAddr().(*net.UDPAddr).AddrPort()})
			require.ErrorIs(t, err, nebula.ErrPathPolicy)
		})
	}
}

func TestManagedSameGatewayFailover(t *testing.T) {
	m := newManagedMesh(t, meshOptions{size: 6, restricted: true, extra: [][2]int{{1, 3}, {2, 4}}})
	a, b := m.peers[0], m.peers[5]
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	require.NoError(t, a.n.ConnectPeer(ctx, b.id))
	var active, backup nebula.TunnelPath
	require.Eventually(t, func() bool {
		peer, _ := a.n.Peer(b.id)
		active = peer.PathHealth.Active.Path
		backup = peer.PathHealth.Standby.Path
		return active.Circuit != "" && backup.Circuit != "" && active.Circuit != backup.Circuit
	}, 7*time.Second, 20*time.Millisecond)
	require.Equal(t, active.Relay, backup.Relay)
	var path, alt []netip.Addr
	for _, v := range a.n.ControlStatus().Circuits {
		if v.ID == active.Circuit {
			path = v.Route
		}
		if v.ID == backup.Circuit {
			alt = v.Route
		}
	}
	require.NotEmpty(t, alt)
	require.NotEmpty(t, path)
	var failed bool
	for i := 1; i < len(path)-2; i++ {
		j := slices.Index(alt, path[i])
		if j >= 0 && j+1 < len(alt) && alt[j+1] == path[i+1] {
			continue
		}
		var src *managedTransport
		var dst netip.AddrPort
		for _, p := range m.peers {
			if p.id == path[i] {
				src = p.transport
			}
			if p.id == path[i+1] {
				dst = p.socket.LocalAddr().(*net.UDPAddr).AddrPort()
			}
		}
		src.mu.Lock()
		src.blocked = dst
		src.mu.Unlock()
		failed = true
		break
	}
	require.True(t, failed)
	require.Eventually(t, func() bool { p, _ := a.n.Peer(b.id); return p.PathHealth.Active.Path.Circuit == backup.Circuit }, 6*time.Second, 20*time.Millisecond)
	x, y := tcpPair(t, a.stack, b.stack, b.id.String(), ipv4.ProtocolNumber)
	roundTrip(t, x, y)
	a.transport.mu.Lock()
	actual := len(a.transport.writes)
	a.transport.mu.Unlock()
	require.Equal(t, 1, actual)
}

func TestManagedUpstreamRelay(t *testing.T) {
	binary := os.Getenv("NEBULA_INTEROP_BINARY")
	if binary == "" {
		t.Skip("set NEBULA_INTEROP_BINARY to the upstream executable")
	}
	m := newManagedMesh(t, meshOptions{size: 3, stockRelay: binary})
	a, b := m.peers[0], m.peers[2]
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require.NoError(t, a.n.ConnectPeer(ctx, b.id))
	path, err := a.n.CheckPeerPath(ctx, b.id, nebula.TunnelPath{})
	require.NoError(t, err)
	require.True(t, path.SamePath)
	require.Equal(t, m.peers[1].id, path.Sent.Relay)

	sub, err := b.n.Subscribe("app/test")
	require.NoError(t, err)
	defer sub.Close()
	m.cfg.Revision++
	m.apply(t, 0)
	m.synced(t)
	id, err := a.n.Publish(ctx, "app/test", []byte("through upstream"))
	require.NoError(t, err)
	select {
	case event := <-sub.Events():
		require.Equal(t, id, event.ID)
	case <-ctx.Done():
		t.Fatal("missing application event")
	}
}

func TestManagedPartitionRejoin(t *testing.T) {
	m := newManagedMesh(t, meshOptions{size: 3})
	a, gateway, b := m.peers[0], m.peers[1], m.peers[2]
	sub, err := b.n.Subscribe("app/test")
	require.NoError(t, err)
	defer sub.Close()
	gateway.transport.mu.Lock()
	gateway.transport.blocked = b.socket.LocalAddr().(*net.UDPAddr).AddrPort()
	gateway.transport.mu.Unlock()
	for i := 0; i < 3; i++ {
		m.cfg.Settings = map[string]json.RawMessage{"app/service": json.RawMessage(fmt.Sprintf(`{"generation":%d}`, i))}
		m.cfg.Revision++
		m.apply(t, 0)
		require.Eventually(t, func() bool { return gateway.n.ControlStatus().Revision == m.cfg.Revision }, 5*time.Second, 10*time.Millisecond)
	}
	id, err := a.n.Publish(t.Context(), "app/test", []byte("recover"))
	require.NoError(t, err)
	require.Less(t, b.n.ControlStatus().Revision, m.cfg.Revision)
	gateway.transport.mu.Lock()
	gateway.transport.blocked = netip.AddrPort{}
	gateway.transport.mu.Unlock()
	m.synced(t)
	wire := b.n.SignedNetworkConfig()
	applied, digest, err := control.Verify(wire, m.cfg.Network, m.ca)
	require.NoError(t, err)
	require.Equal(t, b.n.ControlStatus().Digest, digest)
	require.JSONEq(t, `{"generation":2}`, string(applied.Settings["app/service"]))
	wire[0] = 0
	require.NotEqual(t, wire, b.n.SignedNetworkConfig())
	select {
	case e := <-sub.Events():
		require.Equal(t, id, e.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("missing event after reconnection")
	}
	select {
	case <-sub.Events():
		t.Fatal("duplicate delivery across inventories")
	case <-time.After(3 * b.opts.Control.SyncInterval):
	}
}

func TestManagedSharedTransit(t *testing.T) {
	m := newManagedMesh(t, meshOptions{size: 5, restricted: true})
	a, second, trunk, b := m.peers[0], m.peers[1], m.peers[2], m.peers[4]
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	require.NoError(t, second.n.SetPeerPathPolicy(ctx, b.id, &nebula.PeerPathPolicy{Mode: nebula.RelayOnly, Relays: []netip.Addr{trunk.id}}))
	errs := make(chan error, 4)
	for _, src := range []*managedPeer{&a, &second} {
		go func() { errs <- src.n.ConnectPeer(ctx, b.id) }()
		go func() { errs <- b.n.ConnectPeer(ctx, src.id) }()
	}
	for range 4 {
		require.NoError(t, <-errs)
	}

	member := m.cfg.Members[trunk.id]
	member.BytesPerSecond = 32 * 1024
	m.cfg.Members[trunk.id] = member
	m.cfg.Revision++
	m.apply(t, 2)
	m.synced(t)

	receiver, err := gonet.DialUDP(b.stack, &tcpip.FullAddress{Addr: addr(b.id.String()), Port: 7777}, nil, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer receiver.Close()
	sockets := make([]*gonet.UDPConn, 0, 2)
	for _, p := range []*managedPeer{&a, &second} {
		s, err := gonet.DialUDP(p.stack, nil, &tcpip.FullAddress{Addr: addr(b.id.String()), Port: 7777}, ipv4.ProtocolNumber)
		require.NoError(t, err)
		defer s.Close()
		sockets = append(sockets, s)
	}
	bulk := make([]byte, 900)
	for range 200 {
		_, _ = sockets[0].Write(bulk)
		time.Sleep(time.Millisecond)
	}
	stats := trunk.n.ControlStatus().Egress
	require.Positive(t, stats.DroppedBytes)
	require.Greater(t, stats.QueuedBytes, 24*1024)
	require.LessOrEqual(t, stats.QueuedBytes, 256*1024)
	require.Positive(t, stats.ControlBytes)
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = sockets[1].Write([]byte("second source"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	var first bool
	for {
		n, from, err := receiver.ReadFrom(buf)
		require.NoError(t, err)
		source := from.(*net.UDPAddr).AddrPort().Addr()
		if source == a.id && n == len(bulk) {
			first = true
		}
		if source == second.id && string(buf[:n]) == "second source" {
			break
		}
	}
	require.True(t, first)
	require.Positive(t, trunk.n.ControlStatus().Egress.QueuedBytes, "the sparse source should pass the bulk backlog")

	// Config updates on the congested relay still use its reserved control budget.
	m.cfg.Revision++
	m.apply(t, 2)
	m.synced(t)
	require.Eventually(t, func() bool { return trunk.n.ControlStatus().Egress.QueuedBytes == 0 }, 8*time.Second, 20*time.Millisecond)
	require.Greater(t, trunk.n.ControlStatus().Egress.SentBytes, stats.SentBytes)
}

func TestManagedGatewayEndpointRotation(t *testing.T) {
	m := newManagedMesh(t, meshOptions{size: 3, restricted: true})
	leaf, gateway := m.peers[0], m.peers[1]
	ep := gateway.socket.LocalAddr().(*net.UDPAddr).AddrPort()
	require.NoError(t, leaf.n.SetPeerEndpoints(gateway.id, nil))
	peer, ok := leaf.n.Peer(gateway.id)
	require.True(t, ok)
	require.False(t, peer.PathHealth.Active.Path.Endpoint.IsValid())

	// Re-authorize through the signed topology alone; recovery must use it for probes too.
	member := m.cfg.Members[gateway.id]
	member.Endpoints = []netip.AddrPort{ep}
	m.cfg.Members[gateway.id] = member
	m.cfg.Revision++
	m.apply(t, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	check, err := leaf.n.CheckPeerPath(ctx, gateway.id, nebula.TunnelPath{Endpoint: ep})
	require.NoError(t, err)
	require.True(t, check.SamePath)
	m.synced(t)
}
