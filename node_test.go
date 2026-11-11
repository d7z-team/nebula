package nebula

import (
	"context"
	"crypto/fips140"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
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
	t.network.mu.RLock()
	peer := t.network.endpoints[destination]
	_, blocked := t.network.blocked[memoryDatagramPath{from: t.addr, to: destination}]
	t.network.mu.RUnlock()
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
	virtual6 netip.Addr
}

func newNodeTestIdentities(t *testing.T) (*cert.CAPool, nodeTestIdentity, nodeTestIdentity) {
	curve := cert.Curve_CURVE25519
	if fips140.Enforced() {
		curve = cert.Curve_P256
	}
	return newNodeTestIdentitiesFor(t, cert.Version2, curve)
}

func newNodeTestIdentitiesFor(t *testing.T, version cert.Version, curve cert.Curve) (*cert.CAPool, nodeTestIdentity, nodeTestIdentity) {
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
	if version == cert.Version2 {
		a.virtual6 = netip.MustParseAddr("2001:db8:42::10")
	}
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
	virtual := []netip.Addr{a.virtual}
	unsafeRoutes := []Route{{Prefix: netip.MustParsePrefix("172.30.0.0/24"), Via: a.addr}}
	if a.addr6.IsValid() {
		staticA[b.addr6] = []netip.AddrPort{underlayB}
		staticB[a.addr6] = []netip.AddrPort{underlayA}
		virtual = append(virtual, a.virtual6)
		unsafeRoutes = append(unsafeRoutes, Route{Prefix: netip.MustParsePrefix("2001:db8:42::/64"), Via: a.addr})
	}
	nodeA, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: transports[0], Logger: logger,
		InitiatingVersion: version, Cipher: cipher,
		Lighthouse:       LighthouseOptions{StaticHosts: staticA},
		VirtualAddresses: virtual,
		UnsafeRoutes: []Route{
			{Prefix: netip.MustParsePrefix("192.168.55.0/24"), Via: b.addr},
		},
	})
	require.NoError(t, err)
	nodeB, err := New(t.Context(), Options{
		Identities: []Identity{b.identity}, CAPool: pool, Transport: transports[1], Logger: logger,
		InitiatingVersion: version, Cipher: cipher,
		Lighthouse:       LighthouseOptions{StaticHosts: staticB},
		VirtualAddresses: []netip.Addr{b.virtual},
		UnsafeRoutes:     unsafeRoutes,
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

func TestNodeTCPUDPHTTPAndVirtualAddress(t *testing.T) {
	nodeA, nodeB, a, b := newNodeTestPair(t)

	tcpListener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), "18080"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpListener.Close() })
	go func() {
		conn, err := tcpListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := nodeB.DialContext(ctx, "tcp4", net.JoinHostPort(a.addr.String(), "18080"))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("nebula"))
	require.NoError(t, err)
	reply := make([]byte, 6)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "nebula", string(reply))
	require.NoError(t, conn.Close())

	udpListener, err := nodeA.ListenPacket("udp4", net.JoinHostPort(a.addr.String(), "15353"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = udpListener.Close() })
	udpConn, err := nodeB.Dial("udp4", net.JoinHostPort(a.addr.String(), "15353"))
	require.NoError(t, err)
	require.NoError(t, udpConn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = udpConn.Write([]byte("datagram"))
	require.NoError(t, err)
	packet := make([]byte, 32)
	n, source, err := udpListener.ReadFrom(packet)
	require.NoError(t, err)
	require.Equal(t, "datagram", string(packet[:n]))
	_, err = udpListener.WriteTo([]byte("ok"), source)
	require.NoError(t, err)
	n, err = udpConn.Read(packet)
	require.NoError(t, err)
	require.Equal(t, "ok", string(packet[:n]))
	require.NoError(t, udpConn.Close())

	virtualListener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.virtual.String(), "18081"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = virtualListener.Close() })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "virtual-http") })}
	go server.Serve(virtualListener)
	t.Cleanup(func() { _ = server.Close() })
	client := &http.Client{Transport: &http.Transport{DialContext: nodeB.DialContext}}
	response, err := client.Get("http://" + net.JoinHostPort(a.virtual.String(), "18081"))
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "virtual-http", string(body))

	listenerB, err := nodeB.Listen("tcp4", net.JoinHostPort(b.addr.String(), "18082"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listenerB.Close() })
	remoteAddr := make(chan net.Addr, 1)
	go func() {
		accepted, err := listenerB.Accept()
		if err != nil {
			return
		}
		remoteAddr <- accepted.RemoteAddr()
		_ = accepted.Close()
	}()
	virtualDialer := nodeA.Dialer(DialerOptions{LocalAddr: a.virtual})
	virtualConn, err := virtualDialer.Dial("tcp4", net.JoinHostPort(b.addr.String(), "18082"))
	require.NoError(t, err)
	require.NoError(t, virtualConn.Close())
	select {
	case addr := <-remoteAddr:
		require.Equal(t, a.virtual.String(), addr.(*net.TCPAddr).AddrPort().Addr().String())
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	unsafeListener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.virtual.String(), "18083"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unsafeListener.Close() })
	unsafeSource := make(chan netip.Addr, 1)
	go func() {
		accepted, err := unsafeListener.Accept()
		if err == nil {
			unsafeSource <- accepted.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
			_ = accepted.Close()
		}
	}()
	unsafeConn, err := nodeB.Dialer(DialerOptions{LocalAddr: b.virtual}).DialContext(
		ctx, "tcp4", net.JoinHostPort(a.virtual.String(), "18083"),
	)
	require.NoError(t, err)
	require.NoError(t, unsafeConn.Close())
	select {
	case addr := <-unsafeSource:
		require.Equal(t, b.virtual, addr, "unsafe source must be preserved and routed back through the actual peer")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestNodeLifecycle(t *testing.T) {
	require.Nil(t, WrapPacketConn(nil))
	pool, a, _ := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22001"))[0]
	node, err := New(t.Context(), Options{Identities: []Identity{a.identity}, CAPool: pool, Transport: transport})
	require.NoError(t, err)
	_, err = node.Dial("tcp4", "10.42.0.2:80")
	require.ErrorIs(t, err, ErrNodeNotStarted)
	require.NoError(t, node.Start())
	require.ErrorIs(t, node.Start(), ErrNodeStarted)
	_, err = node.Listen("udp", ":80")
	require.ErrorContains(t, err, "unsupported stream network")
	_, err = node.ListenPacket("tcp", ":80")
	require.ErrorContains(t, err, "unsupported packet network")
	_, err = node.Dial("tcp-invalid", "10.42.0.2:80")
	require.ErrorContains(t, err, "unsupported network")
	require.NoError(t, node.Close())
	require.NoError(t, node.Close())
	require.NoError(t, node.Wait())
	_, err = node.Listen("tcp4", "10.42.0.1:80")
	require.ErrorIs(t, err, ErrNodeClosed)
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

func TestNodeIPv6VirtualAddress(t *testing.T) {
	nodeA, nodeB, a, b := newNodeTestPair(t)
	listener, err := nodeA.Listen("tcp6", net.JoinHostPort(a.virtual6.String(), "18100"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := nodeB.DialContext(ctx, "tcp6", net.JoinHostPort(a.virtual6.String(), "18100"))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("v6"))
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "v6", string(reply))
	require.NoError(t, conn.Close())

	peerListener, err := nodeB.Listen("tcp6", net.JoinHostPort(b.addr6.String(), "18101"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = peerListener.Close() })
	remote := make(chan netip.Addr, 1)
	go func() {
		accepted, err := peerListener.Accept()
		if err == nil {
			remote <- accepted.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
			_ = accepted.Close()
		}
	}()
	conn, err = nodeA.Dialer(DialerOptions{LocalAddr: a.virtual6}).DialContext(ctx, "tcp6", net.JoinHostPort(b.addr6.String(), "18101"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	select {
	case addr := <-remote:
		require.Equal(t, a.virtual6, addr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestNodeListenerSemanticsAndDualUDP(t *testing.T) {
	nodeA, nodeB, a, _ := newNodeTestPair(t)

	exactOverlay, err := nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), "18110"))
	require.NoError(t, err)
	exactVirtual, err := nodeA.Listen("tcp4", net.JoinHostPort(a.virtual.String(), "18110"))
	require.NoError(t, err, "the same port may be bound on distinct exact addresses")
	_, err = nodeA.Listen("tcp4", ":18110")
	require.Error(t, err)
	require.NoError(t, exactOverlay.Close())
	require.NoError(t, exactVirtual.Close())

	exactOverlayPacket, err := nodeA.ListenPacket("udp4", net.JoinHostPort(a.addr.String(), "18111"))
	require.NoError(t, err)
	exactVirtualPacket, err := nodeA.ListenPacket("udp4", net.JoinHostPort(a.virtual.String(), "18111"))
	require.NoError(t, err, "the same UDP port may be bound on distinct exact addresses")
	_, err = nodeA.ListenPacket("udp4", ":18111")
	require.Error(t, err)
	require.NoError(t, exactOverlayPacket.Close())
	require.NoError(t, exactVirtualPacket.Close())

	wildcard, err := nodeA.Listen("tcp", ":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = wildcard.Close() })
	port := wildcard.Addr().(*net.TCPAddr).Port
	require.NotZero(t, port)
	_, err = nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), strconv.Itoa(port)))
	require.Error(t, err)

	accepted := make(chan error, 1)
	go func() {
		for range 3 {
			conn, err := wildcard.Accept()
			if err != nil {
				accepted <- err
				return
			}
			_ = conn.Close()
		}
		accepted <- nil
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, addr := range []netip.Addr{a.addr, a.virtual, a.addr6} {
		network := "tcp4"
		if addr.Is6() {
			network = "tcp6"
		}
		conn, err := nodeB.DialContext(ctx, network, net.JoinHostPort(addr.String(), strconv.Itoa(port)))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	require.NoError(t, <-accepted)

	packetConn, err := nodeA.ListenPacket("udp", ":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = packetConn.Close() })
	udpPort := packetConn.LocalAddr().(*net.UDPAddr).Port
	require.NotZero(t, udpPort)
	_, err = nodeA.ListenPacket("udp4", net.JoinHostPort(a.addr.String(), strconv.Itoa(udpPort)))
	require.Error(t, err, "a dual-stack wildcard endpoint must reserve its IPv4 port")
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(5*time.Second)))
	for _, tc := range []struct {
		network string
		addr    netip.Addr
		body    string
	}{{"udp4", a.addr, "four"}, {"udp6", a.addr6, "six"}} {
		conn, err := nodeB.Dial(tc.network, net.JoinHostPort(tc.addr.String(), strconv.Itoa(udpPort)))
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = conn.Write([]byte(tc.body))
		require.NoError(t, err)
		buffer := make([]byte, 16)
		n, source, err := packetConn.ReadFrom(buffer)
		require.NoError(t, err)
		require.Equal(t, tc.body, string(buffer[:n]))
		_, err = packetConn.WriteTo([]byte("ok"), source)
		require.NoError(t, err)
		n, err = conn.Read(buffer)
		require.NoError(t, err)
		require.Equal(t, "ok", string(buffer[:n]))
		require.NoError(t, conn.Close())
	}

	v6TCP, err := nodeA.Listen("tcp6", ":0")
	require.NoError(t, err)
	v6TCPPort := v6TCP.Addr().(*net.TCPAddr).Port
	v4TCP, err := nodeA.Listen("tcp4", ":"+strconv.Itoa(v6TCPPort))
	require.NoError(t, err, "a tcp6 wildcard endpoint must not reserve the IPv4 port")
	require.NoError(t, v4TCP.Close())
	require.NoError(t, v6TCP.Close())

	v6UDP, err := nodeA.ListenPacket("udp6", ":0")
	require.NoError(t, err)
	v6UDPPort := v6UDP.LocalAddr().(*net.UDPAddr).Port
	v4UDP, err := nodeA.ListenPacket("udp4", ":"+strconv.Itoa(v6UDPPort))
	require.NoError(t, err, "a udp6 wildcard endpoint must not reserve the IPv4 port")
	require.NoError(t, v4UDP.Close())
	require.NoError(t, v6UDP.Close())
}

func TestNodeNativeListenersUnblockOnClose(t *testing.T) {
	nodeA, _, _, _ := newNodeTestPair(t)

	listener, err := nodeA.Listen("tcp", ":0")
	require.NoError(t, err)
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	require.NoError(t, listener.Close())
	select {
	case err := <-accepted:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("closing the native TCP listener did not unblock Accept")
	}

	packetConn, err := nodeA.ListenPacket("udp", ":0")
	require.NoError(t, err)
	read := make(chan error, 1)
	go func() {
		_, _, err := packetConn.ReadFrom(make([]byte, 1))
		read <- err
	}()
	require.NoError(t, packetConn.Close())
	select {
	case err := <-read:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("closing the native UDP endpoint did not unblock ReadFrom")
	}
}

func TestNodeCloseDestroysNativeEndpoints(t *testing.T) {
	nodeA, _, _, _ := newNodeTestPair(t)

	listener, err := nodeA.Listen("tcp", ":0")
	require.NoError(t, err)
	packetConn, err := nodeA.ListenPacket("udp", ":0")
	require.NoError(t, err)

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	read := make(chan error, 1)
	go func() {
		_, _, err := packetConn.ReadFrom(make([]byte, 1))
		read <- err
	}()
	closed := make(chan error, 1)
	go func() { closed <- nodeA.Close() }()

	for name, result := range map[string]<-chan error{
		"Node.Close":   closed,
		"TCP Accept":   accepted,
		"UDP ReadFrom": read,
	} {
		select {
		case err := <-result:
			if name == "Node.Close" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not return after destroying the gVisor stack", name)
		}
	}
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
			nodeA, nodeB, a, _ := newNodeTestPairFor(t, tc.version, tc.curve, tc.cipher)
			listener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), "18120"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					_ = conn.Close()
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, err := nodeB.DialContext(ctx, "tcp4", net.JoinHostPort(a.addr.String(), "18120"))
			require.NoError(t, err)
			require.NoError(t, conn.Close())
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
		Relay:      RelayOptions{AmRelay: true},
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
			Relay:  RelayOptions{UseRelays: true, Relays: []netip.Addr{relayAddr}},
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
		remotes := relayNode.lighthouse.Query(addr)
		if remotes == nil {
			return false
		}
		for _, candidate := range remotes.CopyAddrs(nil) {
			if candidate == endpoint {
				remotes.RLock()
				hasRelay := len(remotes.relays) == 1 && remotes.relays[0] == relayAddr
				remotes.RUnlock()
				return hasRelay
			}
		}
		return false
	}
	require.Eventually(t, func() bool { return registered(a.addr, underlayA) }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return registered(b.addr, underlayB) }, 5*time.Second, 10*time.Millisecond)

	transports[0].network.blockBoth(underlayA, underlayB)
	listener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), "18125"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := nodeB.DialContext(ctx, "tcp4", net.JoinHostPort(a.addr.String(), "18125"))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("relayed"))
	require.NoError(t, err)
	reply := make([]byte, len("relayed"))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "relayed", string(reply))
	require.NoError(t, conn.Close())

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

	listener, err := nodeA.Listen("tcp4", net.JoinHostPort(a.addr.String(), "18130"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := nodeB.DialContext(ctx, "tcp4", net.JoinHostPort(a.addr.String(), "18130"))
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("udp transport"))
	require.NoError(t, err)
	reply := make([]byte, len("udp transport"))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "udp transport", string(reply))
	require.NoError(t, conn.Close())
}
