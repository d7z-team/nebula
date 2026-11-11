package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type gatedWriteTransport struct {
	base        *memoryDatagramTransport
	enabled     atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (t *gatedWriteTransport) ReadFrom(packet []byte) (int, netip.AddrPort, error) {
	return t.base.ReadFrom(packet)
}

func (t *gatedWriteTransport) WriteTo(packet []byte, destination netip.AddrPort) error {
	if t.enabled.Load() {
		t.enteredOnce.Do(func() { close(t.entered) })
		select {
		case <-t.release:
		case <-t.base.closed:
		}
	}
	return t.base.WriteTo(packet, destination)
}

func (t *gatedWriteTransport) LocalAddr() (netip.AddrPort, error) { return t.base.LocalAddr() }
func (t *gatedWriteTransport) Close() error                       { return t.base.Close() }

func (t *gatedWriteTransport) unblock() {
	t.releaseOnce.Do(func() { close(t.release) })
}

func TestNodeSnapshotLifecycleAndCopies(t *testing.T) {
	pool, a, _ := newNodeTestIdentities(t)
	underlay := netip.MustParseAddrPort("127.0.0.1:22001")
	transport := newMemoryDatagramNetwork(underlay)[0]
	node, err := New(t.Context(), Options{
		Identities:       []Identity{a.identity},
		CAPool:           pool,
		Transport:        transport,
		VirtualAddresses: []netip.Addr{a.virtual},
		Logger:           slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})

	ready := node.Snapshot()
	require.Equal(t, NodeStateReady, ready.State)
	require.Equal(t, underlay, ready.TransportAddress)
	require.Contains(t, ready.OverlayAddresses, a.addr)
	require.Equal(t, []netip.Addr{a.virtual}, ready.VirtualAddresses)
	require.Len(t, ready.Certificates, 1)
	require.NotSame(t, a.identity.Certificate, ready.Certificates[0])
	require.Nil(t, node.Err())

	ready.OverlayAddresses[0] = netip.IPv4Unspecified()
	ready.VirtualAddresses[0] = netip.IPv4Unspecified()
	ready.Certificates[0].Networks()[0] = netip.MustParsePrefix("10.99.0.1/24")
	again := node.Snapshot()
	require.Contains(t, again.OverlayAddresses, a.addr)
	require.Equal(t, []netip.Addr{a.virtual}, again.VirtualAddresses)
	require.Equal(t, a.addr, again.Certificates[0].Networks()[0].Addr())

	require.NoError(t, node.Start())
	require.Equal(t, NodeStateRunning, node.Snapshot().State)
	require.NoError(t, node.Close())
	closed := node.Snapshot()
	require.Equal(t, NodeStateClosed, closed.State)
	require.Equal(t, underlay, closed.TransportAddress)
}

func TestNodePeerManagementConnectSnapshotAndDisconnect(t *testing.T) {
	nodeA, nodeB, _, b := newNodeTestPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	connectResults := make(chan error, 2)
	for range 2 {
		go func() { connectResults <- nodeA.ConnectPeer(ctx, b.addr) }()
	}
	require.NoError(t, <-connectResults)
	require.NoError(t, <-connectResults)
	peer, ok := nodeA.Peer(b.addr)
	require.True(t, ok)
	require.Equal(t, PeerStateEstablished, peer.State)
	require.False(t, peer.HandshakePending)
	require.True(t, peer.CurrentEndpoint.IsValid())
	require.NotEmpty(t, peer.KnownEndpoints)
	require.NotNil(t, peer.Certificate)
	require.Equal(t, "b", peer.Certificate.Name())
	require.True(t, peer.Initiator)
	canceled, cancelCanceled := context.WithCancel(t.Context())
	cancelCanceled()
	require.NoError(t, nodeA.ConnectPeer(canceled, b.addr), "an established peer is an idempotent success")
	if b.addr6.IsValid() {
		require.Contains(t, peer.Addresses, b.addr6)
		alternate, found := nodeA.Peer(b.addr6)
		require.True(t, found)
		require.Equal(t, peer.Addresses, alternate.Addresses)
	}

	peer.Addresses[0] = netip.IPv4Unspecified()
	peer.KnownEndpoints[0] = netip.MustParseAddrPort("192.0.2.1:1")
	peer.Certificate.Networks()[0] = netip.MustParsePrefix("10.99.0.2/24")
	again, ok := nodeA.Peer(b.addr)
	require.True(t, ok)
	require.Contains(t, again.Addresses, b.addr)
	require.NotContains(t, again.KnownEndpoints, netip.MustParseAddrPort("192.0.2.1:1"))
	require.Equal(t, b.addr, again.Certificate.Networks()[0].Addr())

	disconnectAddr := b.addr
	if b.addr6.IsValid() {
		disconnectAddr = b.addr6
	}
	result, err := nodeA.DisconnectPeer(disconnectAddr, DisconnectOptions{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, result.TunnelsClosed, 1)
	require.Eventually(t, func() bool {
		_, foundA := nodeA.Peer(b.addr)
		_, foundB := nodeB.Peer(nodeA.engine.myVpnAddrs[0])
		return !foundA && !foundB
	}, time.Second, 10*time.Millisecond)

	result, err = nodeA.DisconnectPeer(b.addr, DisconnectOptions{LocalOnly: true})
	require.NoError(t, err)
	require.Equal(t, DisconnectResult{}, result)
}

func TestNodeConnectPeerContextAndPendingCancellation(t *testing.T) {
	nodeA, nodeB, _, b := newNodeTestPair(t)
	transportA := nodeA.transport.(*memoryDatagramTransport)
	transportB := nodeB.transport.(*memoryDatagramTransport)
	transportA.network.blockBoth(transportA.addr, transportB.addr)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- nodeA.ConnectPeer(ctx, b.addr) }()

	require.Eventually(t, func() bool {
		peer, ok := nodeA.Peer(b.addr)
		return ok && peer.State == PeerStateConnecting && peer.HandshakePending && peer.Certificate == nil
	}, time.Second, 5*time.Millisecond)
	require.ErrorIs(t, <-result, context.DeadlineExceeded)

	disconnected, err := nodeA.DisconnectPeer(b.addr, DisconnectOptions{LocalOnly: true})
	require.NoError(t, err)
	require.Equal(t, 1, disconnected.HandshakesCanceled)
	require.Equal(t, 0, disconnected.TunnelsClosed)
	_, ok := nodeA.Peer(b.addr)
	require.False(t, ok)
}

func TestNodeConnectPeerUnblocksWhenNodeCloses(t *testing.T) {
	nodeA, nodeB, _, b := newNodeTestPair(t)
	transportA := nodeA.transport.(*memoryDatagramTransport)
	transportB := nodeB.transport.(*memoryDatagramTransport)
	transportA.network.blockBoth(transportA.addr, transportB.addr)

	result := make(chan error, 1)
	go func() { result <- nodeA.ConnectPeer(context.Background(), b.addr) }()
	require.Eventually(t, func() bool {
		peer, ok := nodeA.Peer(b.addr)
		return ok && peer.State == PeerStateConnecting
	}, time.Second, 5*time.Millisecond)
	require.NoError(t, nodeA.Close())
	require.ErrorIs(t, <-result, ErrNodeClosed)
}

func TestNodeConnectPeerHandshakeFailure(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	underlayA := netip.MustParseAddrPort("127.0.0.1:22003")
	underlayB := netip.MustParseAddrPort("127.0.0.1:22004")
	transports := newMemoryDatagramNetwork(underlayA, underlayB)
	node, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: transports[0],
		Logger: slog.New(slog.DiscardHandler),
		Lighthouse: LighthouseOptions{StaticHosts: map[netip.Addr][]netip.AddrPort{
			b.addr: {underlayB},
		}},
		Handshake: HandshakeOptions{TryInterval: 5 * time.Millisecond, Retries: 2},
	})
	require.NoError(t, err)
	require.NoError(t, node.Start())
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
		require.NoError(t, transports[1].Close())
	})

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err = node.ConnectPeer(ctx, b.addr)
	require.ErrorIs(t, err, ErrPeerUnavailable)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestNodePeerManagementValidationAndLifecycle(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22002"))[0]
	node, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: transport,
		Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})

	require.ErrorIs(t, node.ConnectPeer(t.Context(), b.addr), ErrNodeNotStarted)
	_, err = node.DisconnectPeer(b.addr, DisconnectOptions{})
	require.ErrorIs(t, err, ErrNodeNotStarted)
	require.NoError(t, node.Start())

	for _, addr := range []netip.Addr{a.addr, a.virtual, netip.Addr{}} {
		require.ErrorIs(t, node.ConnectPeer(t.Context(), addr), ErrPeerUnavailable)
		_, err = node.DisconnectPeer(addr, DisconnectOptions{})
		require.ErrorIs(t, err, ErrPeerUnavailable)
	}

	require.NoError(t, node.Close())
	require.ErrorIs(t, node.ConnectPeer(t.Context(), b.addr), ErrNodeClosed)
	_, err = node.DisconnectAll(DisconnectAllOptions{})
	require.ErrorIs(t, err, ErrNodeClosed)
}

func TestNodeManagementObservesParentCancellation(t *testing.T) {
	pool, local, remote := newNodeTestIdentities(t)
	parent, cancelParent := context.WithCancel(context.Background())
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:22007"))[0]
	node, err := New(parent, Options{
		Identities: []Identity{local.identity}, CAPool: pool, Transport: transport,
		Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	require.NoError(t, node.Start())
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})
	cancelParent()
	<-node.Context().Done()

	require.ErrorIs(t, node.ConnectPeer(t.Context(), remote.addr), ErrNodeClosed)
	_, err = node.DisconnectPeer(remote.addr, DisconnectOptions{})
	require.ErrorIs(t, err, ErrNodeClosed)
	require.ErrorIs(t, node.RefreshPeer(t.Context(), remote.addr), ErrNodeClosed)
	require.ErrorIs(t, node.AdvertiseNow(t.Context()), ErrNodeClosed)
}

func TestNodeDisconnectAllEstablishedAndPending(t *testing.T) {
	nodeA, nodeB, a, b := newNodeTestPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.ConnectPeer(ctx, b.addr))

	// Add a second, unreachable address in the same overlay to exercise pending
	// cancellation independently from the established tunnel.
	pendingAddr := netip.MustParseAddr("10.42.0.200")
	nodeA.handshake.StartHandshake(pendingAddr, nil)
	require.Eventually(t, func() bool {
		peers := nodeA.Peers()
		return slices.ContainsFunc(peers, func(peer PeerSnapshot) bool {
			return slices.Contains(peer.Addresses, pendingAddr) && peer.State == PeerStateConnecting
		})
	}, time.Second, 5*time.Millisecond)

	result, err := nodeA.DisconnectAll(DisconnectAllOptions{LocalOnly: true})
	require.NoError(t, err)
	require.GreaterOrEqual(t, result.TunnelsClosed, 1)
	require.Equal(t, 1, result.HandshakesCanceled)
	require.Empty(t, nodeA.Peers())

	// Local-only teardown deliberately leaves the remote side unchanged.
	_, ok := nodeB.Peer(a.addr)
	require.True(t, ok)
}

func TestNodeDisconnectAllKeepsConfiguredLighthouses(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	underlayA := netip.MustParseAddrPort("127.0.0.1:22003")
	underlayB := netip.MustParseAddrPort("127.0.0.1:22004")
	transports := newMemoryDatagramNetwork(underlayA, underlayB)
	logger := slog.New(slog.DiscardHandler)
	nodeA, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: transports[0], Logger: logger,
		Lighthouse: LighthouseOptions{
			Hosts:       []netip.Addr{b.addr},
			StaticHosts: map[netip.Addr][]netip.AddrPort{b.addr: {underlayB}},
		},
	})
	require.NoError(t, err)
	nodeB, err := New(t.Context(), Options{
		Identities: []Identity{b.identity}, CAPool: pool, Transport: transports[1], Logger: logger,
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

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.ConnectPeer(ctx, b.addr))
	result, err := nodeA.DisconnectAll(DisconnectAllOptions{LocalOnly: true, KeepLighthouses: true})
	require.NoError(t, err)
	require.Equal(t, DisconnectResult{}, result)
	_, ok := nodeA.Peer(b.addr)
	require.True(t, ok)

	result, err = nodeA.DisconnectAll(DisconnectAllOptions{LocalOnly: true})
	require.NoError(t, err)
	require.Equal(t, 1, result.TunnelsClosed)
}

func TestNodeDisconnectPeerClosesEveryTunnelOnce(t *testing.T) {
	nodeA, nodeB, _, b := newNodeTestPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.ConnectPeer(ctx, b.addr))

	original := nodeA.engine.hostMap.QueryVpnAddr(b.addr)
	require.NotNil(t, original)
	localIndex := original.localIndexId + 1
	for nodeA.engine.hostMap.QueryIndex(localIndex) != nil || localIndex == 0 {
		localIndex++
	}
	remote := original.GetRemote()
	older := &hostInfo{
		connectionState: original.connectionState,
		remoteIndexId:   original.remoteIndexId + 1,
		localIndexId:    localIndex,
		remotes:         original.remotes,
		vpnAddrs:        slices.Clone(original.vpnAddrs),
		networks:        original.networks,
		relayState: relayState{
			relayForByAddr: map[netip.Addr]*relay{},
			relayForByIdx:  map[uint32]*relay{},
		},
		HandshakePacket: map[uint8][]byte{},
	}
	older.remote.Store(&remote)
	nodeA.engine.hostMap.Lock()
	nodeA.engine.hostMap.unlockedAddHostInfo(older, nodeA.engine)
	nodeA.engine.hostMap.Unlock()

	// A rehandshake is keyed by the primary address. Disconnecting through a
	// secondary certificate address must still cancel it as part of the same
	// logical identity.
	transportA := nodeA.transport.(*memoryDatagramTransport)
	transportB := nodeB.transport.(*memoryDatagramTransport)
	transportA.network.blockBoth(transportA.addr, transportB.addr)
	nodeA.handshake.StartHandshake(b.addr, nil)
	require.Eventually(t, func() bool {
		peer, ok := nodeA.Peer(b.addr)
		return ok && peer.HandshakePending
	}, time.Second, 5*time.Millisecond)
	disconnectAddr := b.addr
	if b.addr6.IsValid() {
		disconnectAddr = b.addr6
	}
	result, err := nodeA.DisconnectPeer(disconnectAddr, DisconnectOptions{LocalOnly: true})
	require.NoError(t, err)
	require.Equal(t, 2, result.TunnelsClosed)
	require.Equal(t, 1, result.HandshakesCanceled)

	result, err = nodeA.DisconnectPeer(b.addr, DisconnectOptions{LocalOnly: true})
	require.NoError(t, err)
	require.Equal(t, DisconnectResult{}, result)
}

func TestNodeDisconnectRemovesTunnelBeforeNotificationWrite(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	underlayA := netip.MustParseAddrPort("127.0.0.1:22005")
	underlayB := netip.MustParseAddrPort("127.0.0.1:22006")
	transports := newMemoryDatagramNetwork(underlayA, underlayB)
	gated := &gatedWriteTransport{
		base: transports[0], entered: make(chan struct{}), release: make(chan struct{}),
	}
	t.Cleanup(gated.unblock)
	logger := slog.New(slog.DiscardHandler)
	nodeA, err := New(t.Context(), Options{
		Identities: []Identity{a.identity}, CAPool: pool, Transport: gated, Logger: logger,
		Lighthouse: LighthouseOptions{StaticHosts: map[netip.Addr][]netip.AddrPort{b.addr: {underlayB}}},
	})
	require.NoError(t, err)
	nodeB, err := New(t.Context(), Options{
		Identities: []Identity{b.identity}, CAPool: pool, Transport: transports[1], Logger: logger,
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

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.ConnectPeer(ctx, b.addr))
	gated.enabled.Store(true)
	result := make(chan error, 1)
	go func() {
		_, err := nodeA.DisconnectPeer(b.addr, DisconnectOptions{})
		result <- err
	}()
	select {
	case <-gated.entered:
	case <-time.After(time.Second):
		t.Fatal("CloseTunnel notification was not attempted")
	}
	_, ok := nodeA.Peer(b.addr)
	require.False(t, ok, "local tunnel removal must precede a possibly blocking transport write")
	gated.unblock()
	require.NoError(t, <-result)
}

func TestNodeManagementConcurrentSnapshotsDisconnectAndClose(t *testing.T) {
	nodeA, _, _, b := newNodeTestPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, nodeA.ConnectPeer(ctx, b.addr))

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					nodeA.Snapshot()
					nodeA.Peers()
					nodeA.Peer(b.addr)
					nodeA.Discovery()
					nodeA.PeerDiscovery(b.addr)
				}
			}
		})
	}
	disconnectResult := make(chan error, 1)
	closeResult := make(chan error, 1)
	go func() {
		_, err := nodeA.DisconnectPeer(b.addr, DisconnectOptions{LocalOnly: true})
		disconnectResult <- err
	}()
	go func() { closeResult <- nodeA.Close() }()
	require.NoError(t, <-closeResult)
	if err := <-disconnectResult; err != nil {
		require.ErrorIs(t, err, ErrNodeClosed)
	}
	close(stop)
	readers.Wait()
}

func TestSortTunnelsRelayLast(t *testing.T) {
	direct := &hostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.42.0.30")}, localIndexId: 3}
	throughRelay := &hostInfo{
		vpnAddrs: []netip.Addr{netip.MustParseAddr("10.42.0.20")}, localIndexId: 2,
		relayState: relayState{relays: []netip.Addr{netip.MustParseAddr("10.42.0.1")}},
	}
	relayTunnel := &hostInfo{
		vpnAddrs: []netip.Addr{netip.MustParseAddr("10.42.0.1")}, localIndexId: 1,
		relayState: relayState{
			relayForByAddr: map[netip.Addr]*relay{netip.MustParseAddr("10.42.0.20"): {}},
		},
	}
	tunnels := []*hostInfo{relayTunnel, direct, throughRelay}
	sortTunnelsRelayLast(tunnels)
	require.Equal(t, []*hostInfo{throughRelay, direct, relayTunnel}, tunnels)
}
