package nebula

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

type discoveryManagementRecordingWriter struct {
	certificateState *certificateState
	messages         chan []byte
}

func (w *discoveryManagementRecordingWriter) SendVia(*hostInfo, *relay, []byte, []byte, []byte, bool) {
}

func (w *discoveryManagementRecordingWriter) SendMessageToVpnAddr(
	_ header.MessageType,
	_ header.MessageSubType,
	_ netip.Addr,
	payload, _, _ []byte,
) {
	w.messages <- slices.Clone(payload)
}

func (w *discoveryManagementRecordingWriter) SendMessageToHostInfo(
	header.MessageType,
	header.MessageSubType,
	*hostInfo,
	[]byte,
	[]byte,
	[]byte,
) {
}

func (w *discoveryManagementRecordingWriter) Handshake(netip.Addr) {}

func (w *discoveryManagementRecordingWriter) GetHostInfo(netip.Addr) *hostInfo { return nil }

func (w *discoveryManagementRecordingWriter) GetCertState() *certificateState {
	return w.certificateState
}

func newDiscoveryManagementTestNode(
	t *testing.T,
	provider EndpointProvider,
) (*Node, nodeTestIdentity, nodeTestIdentity) {
	t.Helper()
	pool, local, lighthouseIdentity := newNodeTestIdentities(t)
	localEndpoint := netip.MustParseAddrPort("127.0.0.1:24001")
	lighthouseEndpoint := netip.MustParseAddrPort("127.0.0.1:24002")
	transport := newMemoryDatagramNetwork(localEndpoint)[0]
	node, err := New(t.Context(), Options{
		Identities: []Identity{local.identity},
		CAPool:     pool,
		Transport:  transport,
		Lighthouse: LighthouseOptions{
			Hosts:              []netip.Addr{lighthouseIdentity.addr},
			StaticHosts:        map[netip.Addr][]netip.AddrPort{lighthouseIdentity.addr: {lighthouseEndpoint}},
			AdvertiseEndpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:4242")},
			EndpointProvider:   provider,
			UpdateInterval:     -1,
		},
		Relay: RelayOptions{
			UseRelays: true,
			Relays:    []netip.Addr{lighthouseIdentity.addr},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})
	return node, local, lighthouseIdentity
}

// markDiscoveryManagementTestNodeStarted avoids running discovery workers in
// tests that need deterministic control of their queues. Close and Wait still
// exercise the normal ownership cleanup installed by New.
func markDiscoveryManagementTestNodeStarted(node *Node) {
	node.mu.Lock()
	node.state = nodeStarted
	node.mu.Unlock()
}

func TestDiscoverySnapshot(t *testing.T) {
	node, _, lighthouseIdentity := newDiscoveryManagementTestNode(t, func(context.Context) ([]netip.AddrPort, error) {
		t.Fatal("Discovery must not invoke EndpointProvider")
		return nil, nil
	})

	snapshot := node.Discovery()
	require.False(t, snapshot.IsLighthouse)
	require.False(t, snapshot.IsRelay)
	require.True(t, snapshot.UsesRelays)
	require.Equal(t, []netip.Addr{lighthouseIdentity.addr}, snapshot.Lighthouses)
	require.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:4242")}, snapshot.ConfiguredEndpoints)
	require.Equal(t, []netip.Addr{lighthouseIdentity.addr}, snapshot.AdvertisedRelays)

	// Every collection is detached from the node and can be modified by the
	// caller without changing subsequent snapshots.
	snapshot.Lighthouses[0] = netip.MustParseAddr("10.42.0.99")
	snapshot.ConfiguredEndpoints[0] = netip.MustParseAddrPort("203.0.113.9:9")
	snapshot.AdvertisedRelays[0] = netip.MustParseAddr("10.42.0.98")
	require.Equal(t, []netip.Addr{lighthouseIdentity.addr}, node.Discovery().Lighthouses)
	require.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:4242")}, node.Discovery().ConfiguredEndpoints)
	require.Equal(t, []netip.Addr{lighthouseIdentity.addr}, node.Discovery().AdvertisedRelays)
}

func TestPeerDiscoverySnapshot(t *testing.T) {
	node, local, lighthouseIdentity := newDiscoveryManagementTestNode(t, nil)
	remotes := node.lighthouse.addrMap[lighthouseIdentity.addr]
	require.NotNil(t, remotes)
	remotes.Lock()
	remotes.unlockedPrependV6(local.addr, netAddrToProtoV6AddrPort(netip.MustParseAddr("::ffff:192.0.2.44"), 4242))
	remotes.unlockedSetRelay(local.addr, []netip.Addr{
		netip.MustParseAddr("10.42.0.10"),
		netip.MustParseAddr("10.42.0.9"),
	})
	remotes.Unlock()

	snapshot, ok := node.PeerDiscovery(lighthouseIdentity.addr)
	require.True(t, ok)
	require.True(t, snapshot.Static)
	require.Equal(t, []netip.Addr{lighthouseIdentity.addr}, snapshot.Addresses)
	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:24002"),
		netip.MustParseAddrPort("192.0.2.44:4242"),
	}, snapshot.Endpoints)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.42.0.9"),
		netip.MustParseAddr("10.42.0.10"),
	}, snapshot.Relays)

	// The snapshot does not share backing storage with the remote cache.
	snapshot.Addresses[0] = netip.MustParseAddr("10.42.0.77")
	snapshot.Endpoints[0] = netip.MustParseAddrPort("203.0.113.1:1")
	snapshot.Relays[0] = netip.MustParseAddr("10.42.0.78")
	again, ok := node.PeerDiscovery(lighthouseIdentity.addr)
	require.True(t, ok)
	require.Equal(t, lighthouseIdentity.addr, again.Addresses[0])
	require.Equal(t, netip.MustParseAddrPort("127.0.0.1:24002"), again.Endpoints[0])
	require.Equal(t, netip.MustParseAddr("10.42.0.9"), again.Relays[0])

	_, ok = node.PeerDiscovery(netip.Addr{})
	require.False(t, ok)
	_, ok = node.PeerDiscovery(netip.MustParseAddr("192.0.2.1"))
	require.False(t, ok)
	_, ok = node.PeerDiscovery(netip.MustParseAddr("10.42.0.88"))
	require.False(t, ok)
}

func TestRefreshPeerReliableQueueAndCancellation(t *testing.T) {
	node, local, lighthouseIdentity := newDiscoveryManagementTestNode(t, nil)
	target := netip.MustParseAddr("10.42.0.77")

	require.ErrorIs(t, node.RefreshPeer(t.Context(), target), ErrNodeNotStarted)
	markDiscoveryManagementTestNodeStarted(node)
	require.ErrorIs(t, node.RefreshPeer(t.Context(), netip.Addr{}), ErrPeerUnavailable)
	require.ErrorIs(t, node.RefreshPeer(t.Context(), netip.MustParseAddr("192.0.2.1")), ErrPeerUnavailable)
	require.ErrorIs(t, node.RefreshPeer(t.Context(), local.addr), ErrPeerUnavailable)

	// Refreshing the lighthouse itself is an intentional no-op.
	node.lighthouse.queryChan = make(chan netip.Addr, 1)
	node.lighthouse.queryChan <- netip.MustParseAddr("10.42.0.76")
	require.NoError(t, node.RefreshPeer(t.Context(), lighthouseIdentity.addr))

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, node.RefreshPeer(ctx, target), context.DeadlineExceeded)

	require.Equal(t, netip.MustParseAddr("10.42.0.76"), <-node.lighthouse.queryChan)
	require.NoError(t, node.RefreshPeer(t.Context(), target))
	require.Equal(t, target, <-node.lighthouse.queryChan)

	node.lighthouse.queryChan <- netip.MustParseAddr("10.42.0.75")
	result := make(chan error, 1)
	go func() { result <- node.RefreshPeer(context.Background(), target) }()
	require.NoError(t, node.Close())
	require.ErrorIs(t, <-result, ErrNodeClosed)
}

func TestAdvertiseNowProviderErrorsAndCancellation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var calls atomic.Int32
		node, _, _ := newDiscoveryManagementTestNode(t, func(ctx context.Context) ([]netip.AddrPort, error) {
			require.NoError(t, ctx.Err())
			calls.Add(1)
			return []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.2:4242"),
				netip.MustParseAddrPort("10.42.0.99:4242"), // overlay endpoints are never advertised
			}, nil
		})
		markDiscoveryManagementTestNodeStarted(node)
		require.NoError(t, node.AdvertiseNow(nil))
		require.EqualValues(t, 1, calls.Load())
	})

	t.Run("provider error", func(t *testing.T) {
		sentinel := errors.New("provider failed")
		node, _, _ := newDiscoveryManagementTestNode(t, func(context.Context) ([]netip.AddrPort, error) {
			return nil, sentinel
		})
		writer := &discoveryManagementRecordingWriter{
			certificateState: node.engine.pki.getCertState(),
			messages:         make(chan []byte, 1),
		}
		node.lighthouse.ifce = writer
		markDiscoveryManagementTestNodeStarted(node)
		require.ErrorIs(t, node.AdvertiseNow(t.Context()), sentinel)
		var update NebulaMeta
		require.NoError(t, update.Unmarshal(<-writer.messages))
		require.Equal(t, NebulaMeta_HostUpdateNotification, update.Type)
		require.Len(t, update.Details.V4AddrPorts, 1, "fixed endpoints must still be advertised when the provider fails")
		require.Equal(t, netip.MustParseAddrPort("198.51.100.2:4242"), protoV4AddrPortToNetAddrPort(update.Details.V4AddrPorts[0]))
	})

	t.Run("caller context", func(t *testing.T) {
		node, _, _ := newDiscoveryManagementTestNode(t, func(ctx context.Context) ([]netip.AddrPort, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		markDiscoveryManagementTestNodeStarted(node)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, node.AdvertiseNow(ctx), context.DeadlineExceeded)
	})

	t.Run("node close", func(t *testing.T) {
		providerStarted := make(chan struct{})
		node, _, _ := newDiscoveryManagementTestNode(t, func(ctx context.Context) ([]netip.AddrPort, error) {
			close(providerStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		markDiscoveryManagementTestNodeStarted(node)
		result := make(chan error, 1)
		go func() { result <- node.AdvertiseNow(context.Background()) }()
		<-providerStarted
		require.NoError(t, node.Close())
		require.ErrorIs(t, <-result, ErrNodeClosed)
	})
}

func TestAdvertiseNowSerializesProviderCalls(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	node, _, _ := newDiscoveryManagementTestNode(t, func(context.Context) ([]netip.AddrPort, error) {
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return nil, nil
	})
	markDiscoveryManagementTestNodeStarted(node)

	firstResult := make(chan error, 1)
	go func() { firstResult <- node.AdvertiseNow(context.Background()) }()
	<-firstStarted

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, node.AdvertiseNow(ctx), context.DeadlineExceeded)
	require.EqualValues(t, 1, calls.Load(), "a canceled waiter must not invoke the provider concurrently")

	close(releaseFirst)
	require.NoError(t, <-firstResult)
	require.EqualValues(t, 1, calls.Load())
}

func TestDiscoverySnapshotOrdering(t *testing.T) {
	node, _, _ := newDiscoveryManagementTestNode(t, nil)
	node.lighthouse.lighthouses = []netip.Addr{
		netip.MustParseAddr("10.42.0.20"),
		netip.MustParseAddr("10.42.0.3"),
	}
	node.lighthouse.advertiseAddrs = []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.2:2"),
		netip.MustParseAddrPort("192.0.2.1:2"),
		netip.MustParseAddrPort("192.0.2.1:1"),
	}

	snapshot := node.Discovery()
	require.True(t, slices.IsSortedFunc(snapshot.Lighthouses, func(a, b netip.Addr) int { return a.Compare(b) }))
	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("192.0.2.1:2"),
		netip.MustParseAddrPort("203.0.113.2:2"),
	}, snapshot.ConfiguredEndpoints)
}

func TestDiscoveryManagementNoOpWithoutLighthouses(t *testing.T) {
	pool, local, remote := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:24003"))[0]
	var providerCalls atomic.Int32
	node, err := New(t.Context(), Options{
		Identities: []Identity{local.identity}, CAPool: pool, Transport: transport,
		Lighthouse: LighthouseOptions{EndpointProvider: func(context.Context) ([]netip.AddrPort, error) {
			providerCalls.Add(1)
			return nil, errors.New("provider must not run without lighthouses")
		}},
	})
	require.NoError(t, err)
	markDiscoveryManagementTestNodeStarted(node)
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.NoError(t, node.RefreshPeer(ctx, remote.addr))
	require.NoError(t, node.AdvertiseNow(ctx))
	require.Zero(t, providerCalls.Load())
	require.Empty(t, node.lighthouse.queryChan)
}
