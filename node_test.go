package nebula

import (
	"context"
	"crypto/fips140"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

type memoryDatagram struct {
	packet []byte
	from   netip.AddrPort
}

type memoryDatagramNetwork struct {
	mu        sync.RWMutex
	endpoints map[netip.AddrPort]*memoryDatagramTransport
	blocked   map[memoryDatagramPath]struct{}
	writes    map[memoryDatagramPath]datagramCounts
}

type memoryDatagramPath struct {
	from netip.AddrPort
	to   netip.AddrPort
}

type memoryDatagramTransport struct {
	network  *memoryDatagramNetwork
	addr     netip.AddrPort
	packets  chan memoryDatagram
	failures chan error
	closed   chan struct{}
	once     sync.Once
	rebinds  atomic.Uint32
}

func newMemoryDatagramNetwork(addrs ...netip.AddrPort) []*memoryDatagramTransport {
	network := &memoryDatagramNetwork{
		endpoints: make(map[netip.AddrPort]*memoryDatagramTransport, len(addrs)),
		blocked:   make(map[memoryDatagramPath]struct{}),
		writes:    make(map[memoryDatagramPath]datagramCounts),
	}
	transports := make([]*memoryDatagramTransport, len(addrs))
	for i, addr := range addrs {
		transport := &memoryDatagramTransport{
			network: network, addr: addr, packets: make(chan memoryDatagram, 64),
			failures: make(chan error, 1), closed: make(chan struct{}),
		}
		transports[i] = transport
		network.endpoints[addr] = transport
	}
	return transports
}

type datagramCounts struct{ total, relayedIP int }

func (n *memoryDatagramNetwork) writesTo(from, to netip.AddrPort) datagramCounts {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.writes[memoryDatagramPath{from: from, to: to}]
}

func (n *memoryDatagramNetwork) blockBoth(a, b netip.AddrPort) {
	n.mu.Lock()
	n.blocked[memoryDatagramPath{from: a, to: b}] = struct{}{}
	n.blocked[memoryDatagramPath{from: b, to: a}] = struct{}{}
	n.mu.Unlock()
}

func (t *memoryDatagramTransport) ReadFrom(buffer []byte) (int, netip.AddrPort, error) {
	select {
	case <-t.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	case err := <-t.failures:
		return 0, netip.AddrPort{}, err
	case packet := <-t.packets:
		if len(buffer) < len(packet.packet) {
			return 0, netip.AddrPort{}, io.ErrShortBuffer
		}
		return copy(buffer, packet.packet), packet.from, nil
	}
}

func (t *memoryDatagramTransport) WriteTo(packet []byte, destination netip.AddrPort) error {
	t.network.mu.Lock()
	key := memoryDatagramPath{from: t.addr, to: destination}
	counts := t.network.writes[key]
	counts.total++
	var outer, inner header.H
	if outer.Parse(packet) == nil && outer.Type == header.Message && outer.Subtype == header.MessageRelay && inner.Parse(packet[header.Len:]) == nil && inner.Type == header.Message && inner.Subtype == header.MessageNone {
		counts.relayedIP++
	}
	t.network.writes[key] = counts
	peer := t.network.endpoints[destination]
	_, blocked := t.network.blocked[memoryDatagramPath{from: t.addr, to: destination}]
	t.network.mu.Unlock()
	if peer == nil {
		return errors.New("unknown in-memory datagram destination")
	}
	if blocked {
		return nil
	}
	datagram := memoryDatagram{packet: append([]byte(nil), packet...), from: t.addr}
	select {
	case <-t.closed:
		return net.ErrClosed
	case <-peer.closed:
		return net.ErrClosed
	case peer.packets <- datagram:
		return nil
	}
}

func (t *memoryDatagramTransport) LocalAddr() (netip.AddrPort, error) { return t.addr, nil }

func (t *memoryDatagramTransport) Rebind() error {
	t.rebinds.Add(1)
	return nil
}

func (t *memoryDatagramTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type nodeTestIdentity struct {
	identity Identity
	addr     netip.Addr
	addr6    netip.Addr
	virtual  netip.Addr
}

func newNodeTestIdentities(t testing.TB) (*cert.CAPool, nodeTestIdentity, nodeTestIdentity) {
	curve := cert.Curve_CURVE25519
	if fips140.Enforced() {
		curve = cert.Curve_P256
	}
	return newNodeTestIdentitiesFor(t, cert.Version2, curve)
}

func newNodeTestIdentitiesFor(t testing.TB, version cert.Version, curve cert.Curve) (*cert.CAPool, nodeTestIdentity, nodeTestIdentity) {
	t.Helper()
	now := time.Now().Add(-time.Minute)
	caNetworks := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")}
	caUnsafe := []netip.Prefix{
		netip.MustParsePrefix("172.30.0.0/24"),
		netip.MustParsePrefix("192.168.55.0/24"),
	}
	if version == cert.Version2 {
		caNetworks = append(caNetworks, netip.MustParsePrefix("fd00:42::/64"))
		caUnsafe = append(caUnsafe, netip.MustParsePrefix("2001:db8:42::/64"))
	}
	ca, caKey, err := cert.CreateCA(cert.CAOptions{
		Version: version, Curve: curve, Name: "test-ca",
		Networks: caNetworks, UnsafeNetworks: caUnsafe,
		NotBefore: now, NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)
	issue := func(name, overlay4, overlay6 string, unsafe []netip.Prefix) nodeTestIdentity {
		networks := []netip.Prefix{netip.MustParsePrefix(overlay4)}
		if version == cert.Version2 {
			networks = append(networks, netip.MustParsePrefix(overlay6))
		}
		crt, key, err := cert.IssueCertificate(ca, caKey, cert.CertificateOptions{
			Version: version, Name: name,
			Networks: networks, UnsafeNetworks: unsafe,
			NotBefore: now, NotAfter: now.Add(30 * time.Minute),
		})
		require.NoError(t, err)
		identity := nodeTestIdentity{
			identity: Identity{Certificate: crt, PrivateKey: key},
			addr:     crt.Networks()[0].Addr(),
		}
		if len(crt.Networks()) > 1 {
			identity.addr6 = crt.Networks()[1].Addr()
		}
		return identity
	}
	aUnsafe := []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	if version == cert.Version2 {
		aUnsafe = append(aUnsafe, netip.MustParsePrefix("2001:db8:42::/64"))
	}
	a := issue("a", "10.42.0.1/24", "fd00:42::1/64", aUnsafe)
	a.virtual = netip.MustParseAddr("172.30.0.10")
	b := issue("b", "10.42.0.2/24", "fd00:42::2/64", []netip.Prefix{netip.MustParsePrefix("192.168.55.0/24")})
	b.virtual = netip.MustParseAddr("192.168.55.10")
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(ca))
	return pool, a, b
}

func newNodeTestPair(t *testing.T) (*Node, *Node, nodeTestIdentity, nodeTestIdentity) {
	curve := cert.Curve_CURVE25519
	if fips140.Enforced() {
		curve = cert.Curve_P256
	}
	return newNodeTestPairFor(t, cert.Version2, curve, "aes")
}

func newNodeTestPairFor(t *testing.T, version cert.Version, curve cert.Curve, cipher string) (*Node, *Node, nodeTestIdentity, nodeTestIdentity) {
	t.Helper()
	pool, a, b := newNodeTestIdentitiesFor(t, version, curve)
	underlayA := netip.MustParseAddrPort("127.0.0.1:21001")
	underlayB := netip.MustParseAddrPort("127.0.0.1:21002")
	transports := newMemoryDatagramNetwork(underlayA, underlayB)
	logger := slog.New(slog.DiscardHandler)
	staticA := map[netip.Addr][]netip.AddrPort{b.addr: {underlayB}}
	staticB := map[netip.Addr][]netip.AddrPort{a.addr: {underlayA}}
	if a.addr6.IsValid() {
		staticA[b.addr6] = []netip.AddrPort{underlayB}
		staticB[a.addr6] = []netip.AddrPort{underlayA}
	}
	nodeA, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: transports[0], Logger: logger,
		InitiatingVersion: version, Cipher: cipher,
		Lighthouse: LighthouseOptions{StaticHosts: staticA},
	})
	require.NoError(t, err)
	nodeB, err := New(t.Context(), Options{
		Identities: []Identity{b.identity}, CAPool: pool, Transport: transports[1], Logger: logger,
		InitiatingVersion: version, Cipher: cipher,
		Lighthouse: LighthouseOptions{StaticHosts: staticB},
	})
	require.NoError(t, err)
	require.NoError(t, nodeA.Start())
	require.NoError(t, nodeB.Start())
	t.Cleanup(func() {
		require.NoError(t, nodeA.Close())
		require.NoError(t, nodeB.Close())
		require.NoError(t, nodeA.Wait())
		require.NoError(t, nodeB.Wait())
	})
	return nodeA, nodeB, a, b
}

func TestNodeLifecycle(t *testing.T) {
	require.Nil(t, WrapPacketConn(nil))
	pool, a, _ := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22001"))[0]
	node, err := New(t.Context(), Options{Identities: []Identity{a.identity}, CAPool: pool, Transport: transport})
	require.NoError(t, err)
	err = node.ConnectPeer(t.Context(), netip.MustParseAddr("10.42.0.2"))
	require.ErrorIs(t, err, ErrNodeNotStarted)
	require.NoError(t, node.Start())
	require.ErrorIs(t, node.Start(), ErrNodeStarted)
	require.NoError(t, node.Close())
	require.NoError(t, node.Close())
	require.NoError(t, node.Wait())
	_, err = node.OpenIPPort(func([]byte) {})
	require.ErrorIs(t, err, ErrNodeClosed)
}

func TestNodeTimerIntervals(t *testing.T) {
	type intervals struct{ check, pendingDeletion, handshakeRetry time.Duration }
	defaults := intervals{5 * time.Second, 10 * time.Second, 100 * time.Millisecond}
	custom := intervals{2 * time.Second, 3 * time.Second, 40 * time.Millisecond}
	pool, local, _ := newNodeTestIdentities(t)
	for _, tc := range []struct {
		name      string
		set, want intervals
	}{
		{"zero", intervals{}, defaults},
		{"negative", intervals{-time.Second, -time.Second, -time.Second}, defaults},
		{"custom", custom, custom},
		{"mixed", intervals{custom.check, 0, custom.handshakeRetry}, intervals{custom.check, defaults.pendingDeletion, custom.handshakeRetry}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22001"))[0]
			node, err := New(t.Context(), Options{
				Identities:  []Identity{local.identity},
				CAPool:      pool,
				Transport:   transport,
				Connections: ConnectionOptions{CheckInterval: tc.set.check, PendingDeletionInterval: tc.set.pendingDeletion},
				Handshake:   HandshakeOptions{TryInterval: tc.set.handshakeRetry},
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, node.Close())
				require.NoError(t, node.Wait())
			})
			require.NoError(t, node.Start())
			require.Equal(t, tc.want.check, node.connections.checkInterval)
			require.Equal(t, tc.want.pendingDeletion, node.connections.pendingDeletionInterval)
			require.Equal(t, tc.want.handshakeRetry, node.handshake.config.TryInterval)
		})
	}
}

func TestNodeRejectsUntrustedIdentity(t *testing.T) {
	_, a, _ := newNodeTestIdentities(t)
	untrustedPool, _, _ := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22003"))[0]
	t.Cleanup(func() { _ = transport.Close() })
	_, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: untrustedPool, Transport: transport,
	})
	require.ErrorContains(t, err, "verify identity certificate")
}

func TestNodeFatalTransportAndRebind(t *testing.T) {
	pool, a, _ := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22002"))[0]
	node, err := New(t.Context(), Options{Identities: []Identity{a.identity}, CAPool: pool, Transport: transport})
	require.NoError(t, err)
	require.NoError(t, node.Start())
	require.NoError(t, node.Rebind())
	require.Equal(t, uint32(1), transport.rebinds.Load())

	fatalErr := errors.New("injected transport failure")
	transport.failures <- fatalErr
	require.ErrorIs(t, node.Wait(), fatalErr)
	require.ErrorIs(t, node.Err(), fatalErr)
	require.ErrorIs(t, node.Context().Err(), context.Canceled)
	require.NoError(t, node.Close())
}

func TestNodeProtocolMatrix(t *testing.T) {
	tests := []struct {
		name    string
		version cert.Version
		curve   cert.Curve
		cipher  string
	}{
		{"v1-curve25519-aes", cert.Version1, cert.Curve_CURVE25519, "aes"},
		{"v2-curve25519-chachapoly", cert.Version2, cert.Curve_CURVE25519, "chachapoly"},
		{"v1-p256-chachapoly", cert.Version1, cert.Curve_P256, "chachapoly"},
		{"v2-p256-aes", cert.Version2, cert.Curve_P256, "aes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if fips140.Enforced() && (tc.curve == cert.Curve_CURVE25519 || tc.cipher == "chachapoly") {
				t.Skip("algorithm is intentionally unavailable in FIPS 140-only mode")
			}
			nodeA, nodeB, a, b := newNodeTestPairFor(t, tc.version, tc.curve, tc.cipher)
			assertIPExchange(t, nodeA, nodeB, a.addr, b.addr)
		})
	}
}

func TestNodeLighthousePunchAndRelay(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	curve := cert.Curve_CURVE25519
	if fips140.Enforced() {
		curve = cert.Curve_P256
	}
	now := time.Now().Add(-time.Minute)
	relayCA, relayCAKey, err := cert.CreateCA(cert.CAOptions{
		Version: cert.Version2, Curve: curve, Name: "relay-ca",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")},
		NotBefore: now, NotAfter: now.Add(time.Hour),
	})
	require.NoError(t, err)
	require.NoError(t, pool.AddCA(relayCA))
	relayCertificate, relayKey, err := cert.IssueCertificate(relayCA, relayCAKey, cert.CertificateOptions{
		Version: cert.Version2, Name: "lighthouse-relay",
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.42.0.3/24")},
		NotBefore: now, NotAfter: now.Add(30 * time.Minute),
	})
	require.NoError(t, err)
	relayIdentity := Identity{Certificate: relayCertificate, PrivateKey: relayKey}
	relayAddr := relayCertificate.Networks()[0].Addr()

	underlayRelay := netip.MustParseAddrPort("127.0.0.1:23001")
	underlayA := netip.MustParseAddrPort("127.0.0.1:23002")
	underlayB := netip.MustParseAddrPort("127.0.0.1:23003")
	transports := newMemoryDatagramNetwork(underlayRelay, underlayA, underlayB)
	logger := slog.New(slog.DiscardHandler)

	relayNode, err := New(t.Context(), Options{
		Identities: []Identity{relayIdentity}, CAPool: pool, Transport: transports[0], Logger: logger,
		Lighthouse: LighthouseOptions{AmLighthouse: true},
		Relay:      RelayOptions{Serve: true},
	})
	require.NoError(t, err)
	peerOptions := func(identity Identity, transport DatagramTransport, advertised netip.AddrPort) Options {
		return Options{
			Identities: []Identity{identity}, CAPool: pool, Transport: transport, Logger: logger,
			Lighthouse: LighthouseOptions{
				Hosts:              []netip.Addr{relayAddr},
				StaticHosts:        map[netip.Addr][]netip.AddrPort{relayAddr: {underlayRelay}},
				AdvertiseEndpoints: []netip.AddrPort{advertised},
				UpdateInterval:     time.Hour,
			},
			Punchy: PunchyOptions{Punch: true, Respond: true, Delay: time.Millisecond, RespondDelay: time.Millisecond},
			Relay:  RelayOptions{AdvertiseVia: []netip.Addr{relayAddr}},
		}
	}
	nodeA, err := New(t.Context(), peerOptions(a.identity, transports[1], underlayA))
	require.NoError(t, err)
	nodeB, err := New(t.Context(), peerOptions(b.identity, transports[2], underlayB))
	require.NoError(t, err)
	for _, node := range []*Node{relayNode, nodeA, nodeB} {
		require.NoError(t, node.Start())
	}
	t.Cleanup(func() {
		for _, node := range []*Node{nodeA, nodeB, relayNode} {
			require.NoError(t, node.Close())
		}
		for _, node := range []*Node{nodeA, nodeB, relayNode} {
			require.NoError(t, node.Wait())
		}
	})

	registered := func(addr netip.Addr, endpoint netip.AddrPort) bool {
		peer, ok := relayNode.PeerDiscovery(addr)
		return ok && slices.Contains(peer.Endpoints, endpoint) && slices.Equal(peer.Relays, []netip.Addr{relayAddr})
	}
	require.Eventually(t, func() bool { return registered(a.addr, underlayA) }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return registered(b.addr, underlayB) }, 5*time.Second, 10*time.Millisecond)

	transports[0].network.blockBoth(underlayA, underlayB)
	assertIPExchange(t, nodeA, nodeB, a.addr, b.addr)

	require.Eventually(t, func() bool {
		snapshot, ok := nodeB.Peer(a.addr)
		return ok && snapshot.LastDataPath == (TunnelPath{Relay: relayAddr, Endpoint: underlayRelay})
	}, time.Second, time.Millisecond)
	peer := nodeB.engine.hostMap.QueryVpnAddr(a.addr)
	require.NotNil(t, peer)
	require.False(t, peer.GetRemote().IsValid(), "the blocked peers must communicate through the relay, not a direct endpoint")
}

func TestNodePacketConnTransport(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	packetA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if errors.Is(err, os.ErrPermission) {
		t.Skip("sandbox does not permit loopback UDP sockets")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = packetA.Close() })
	packetB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = packetB.Close() })
	underlayA := packetA.LocalAddr().(*net.UDPAddr).AddrPort()
	underlayB := packetB.LocalAddr().(*net.UDPAddr).AddrPort()

	nodeA, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: WrapPacketConn(packetA),
		Lighthouse: LighthouseOptions{StaticHosts: map[netip.Addr][]netip.AddrPort{b.addr: {underlayB}}},
	})
	require.NoError(t, err)
	nodeB, err := New(t.Context(), Options{
		Identities: []Identity{b.identity}, CAPool: pool, Transport: WrapPacketConn(packetB),
		Lighthouse: LighthouseOptions{StaticHosts: map[netip.Addr][]netip.AddrPort{a.addr: {underlayA}}},
	})
	require.NoError(t, err)
	require.NoError(t, nodeA.Start())
	require.NoError(t, nodeB.Start())
	t.Cleanup(func() {
		require.NoError(t, nodeA.Close())
		require.NoError(t, nodeB.Close())
		require.NoError(t, nodeA.Wait())
		require.NoError(t, nodeB.Wait())
	})
	require.ErrorContains(t, nodeA.Rebind(), "does not support rebinding")

	assertIPExchange(t, nodeA, nodeB, a.addr, b.addr)
}

// NewTestNICNodes exposes the existing authenticated in-memory pair to the
// external package test that imports the public gVisor adapter.
func NewTestNICNodes(t *testing.T) (client, gateway *Node) {
	g, a, _, _ := newNodeTestPair(t)
	return a, g
}
