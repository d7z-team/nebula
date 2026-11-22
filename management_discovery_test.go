package nebula

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

type discoveryMessage struct {
	server  netip.Addr
	payload []byte
}

type discoveryManagementRecordingWriter struct {
	hosts            map[netip.Addr]*hostInfo
	certificateState *certificateState
	messages         chan discoveryMessage
}

func (w *discoveryManagementRecordingWriter) SendMessageToVpnAddr(
	_ header.MessageType,
	_ header.MessageSubType,
	server netip.Addr,
	payload, _, _ []byte,
) {
	w.messages <- discoveryMessage{server, slices.Clone(payload)}
}

func (w *discoveryManagementRecordingWriter) GetHostInfo(addr netip.Addr) *hostInfo {
	return w.hosts[addr]
}

func (w *discoveryManagementRecordingWriter) GetCertState() *certificateState {
	return w.certificateState
}

func newDiscoveryManagementTestNode(
	t testing.TB,
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
			AdvertiseVia: []netip.Addr{lighthouseIdentity.addr},
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
	node.state = NodeStateRunning
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
	require.Equal(t, Auto, snapshot.DefaultPathPolicy.Mode)
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
	remotes.LearnRemote(local.addr, netip.MustParseAddrPort("[::ffff:192.0.2.44]:4242"))
	node.lighthouse.replaceReport([]netip.Addr{lighthouseIdentity.addr}, local.addr, &NebulaMetaDetails{
		RelayVpnAddrs: []*Addr{netAddrToProtoAddr(netip.MustParseAddr("10.42.0.10")), netAddrToProtoAddr(netip.MustParseAddr("10.42.0.9"))},
	})

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
	for range 1000 {
		node.lighthouse.QueryServer(target)
	}
	require.NoError(t, node.RefreshPeer(t.Context(), target))
	require.Len(t, node.lighthouse.queryChan, 1)
	require.Equal(t, target, <-node.lighthouse.queryChan)

	node.lighthouse.queryChan <- netip.MustParseAddr("10.42.0.75")
	result := make(chan error, 1)
	go func() { result <- node.RefreshPeer(context.Background(), netip.MustParseAddr("10.42.0.78")) }()
	require.NoError(t, node.Close())
	require.ErrorIs(t, <-result, ErrNodeClosed)
}

func TestRefreshPeerConcurrentWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		node, _, _ := newDiscoveryManagementTestNode(t, nil)
		markDiscoveryManagementTestNodeStarted(node)
		lh := node.lighthouse
		lh.queryChan = make(chan netip.Addr, 1)
		wire := make(chan discoveryMessage, 3)
		lh.sender = &discoveryManagementRecordingWriter{certificateState: node.engine.pki.getCertState(), messages: wire}
		first, second := netip.MustParseAddr("10.42.0.76"), netip.MustParseAddr("10.42.0.77")
		require.NoError(t, node.RefreshPeer(t.Context(), first))
		results := make(chan error, 2)
		for range 2 {
			go func() { results <- node.RefreshPeer(t.Context(), second) }()
		}
		synctest.Wait()
		require.Empty(t, results)

		node.workers.Go(lh.runQueryWorker)
		synctest.Wait()
		require.Len(t, results, 2)
		require.NoError(t, <-results)
		require.NoError(t, <-results)
		require.Len(t, wire, 2)
		for _, want := range []netip.Addr{first, second} {
			var query NebulaMeta
			require.NoError(t, query.Unmarshal((<-wire).payload))
			require.Equal(t, NebulaMeta_HostQuery, query.Type)
			addr, _, err := query.Details.GetVpnAddrAndVersion()
			require.NoError(t, err)
			require.Equal(t, want, addr)
		}
	})
}

func TestLighthouseMixedWireVersions(t *testing.T) {
	node, local, peer := newDiscoveryManagementTestNode(t, nil)
	markDiscoveryManagementTestNodeStarted(node)
	_, legacy, _ := newNodeTestIdentitiesFor(t, cert.Version1, local.identity.Certificate.Curve())
	legacyServer := netip.MustParseAddr("10.42.0.3")
	lh := node.lighthouse
	lh.lighthouses = []netip.Addr{peer.addr, legacyServer}
	lh.relaysForMe = []netip.Addr{peer.addr, peer.addr6}
	wire := make(chan discoveryMessage, 4)
	lh.sender = &discoveryManagementRecordingWriter{
		certificateState: node.engine.pki.getCertState(),
		hosts:            map[netip.Addr]*hostInfo{legacyServer: {connectionState: &connectionState{myCert: legacy.identity.Certificate}}},
		messages:         wire,
	}

	read := func(server netip.Addr, kind NebulaMeta_MessageType) *NebulaMetaDetails {
		t.Helper()
		require.NotEmpty(t, wire)
		m := <-wire
		require.Equal(t, server, m.server)
		var msg NebulaMeta
		require.NoError(t, msg.Unmarshal(m.payload))
		require.Equal(t, kind, msg.Type)
		require.NotNil(t, msg.Details)
		return msg.Details
	}

	target := netip.MustParseAddr("10.42.0.77")
	require.NoError(t, lh.sendToLighthouses(t.Context(), NebulaMeta_HostQuery, target, nil, nil, nil))
	v2 := read(peer.addr, NebulaMeta_HostQuery)
	v1 := read(legacyServer, NebulaMeta_HostQuery)
	require.Equal(t, netAddrToProtoAddr(target), v2.VpnAddr)
	require.Zero(t, v2.OldVpnAddr)
	require.Nil(t, v1.VpnAddr)
	addr, version, err := v1.GetVpnAddrAndVersion()
	require.NoError(t, err)
	require.Equal(t, cert.Version1, version)
	require.Equal(t, target, addr)

	require.NoError(t, node.AdvertiseNow(t.Context()))
	v2 = read(peer.addr, NebulaMeta_HostUpdateNotification)
	v1 = read(legacyServer, NebulaMeta_HostUpdateNotification)
	require.Nil(t, v2.VpnAddr)
	require.Zero(t, v2.OldVpnAddr)
	require.Equal(t, lh.relaysForMe, v2.GetRelays())
	addr, version, err = v1.GetVpnAddrAndVersion()
	require.NoError(t, err)
	require.Equal(t, cert.Version1, version)
	require.Equal(t, local.addr, addr)
	require.Equal(t, []netip.Addr{peer.addr}, v1.GetRelays())
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
			messages:         make(chan discoveryMessage, 1),
		}
		node.lighthouse.sender = writer
		markDiscoveryManagementTestNodeStarted(node)
		require.ErrorIs(t, node.AdvertiseNow(t.Context()), sentinel)
		var update NebulaMeta
		require.NoError(t, update.Unmarshal((<-writer.messages).payload))
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
	require.True(t, slices.IsSortedFunc(snapshot.Lighthouses, netip.Addr.Compare))
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

func TestSetPeerEndpoints(t *testing.T) {
	n, _, _, b := newNodeTestPair(t)
	original, ok := n.PeerDiscovery(b.addr)
	require.True(t, ok)
	replacement := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.33:1234")}
	require.NoError(t, n.SetPeerEndpoints(b.addr, replacement))
	require.Error(t, n.SetPeerEndpoints(b.addr, []netip.AddrPort{netip.AddrPortFrom(b.addr, 1234)}))
	snapshot, _ := n.PeerDiscovery(b.addr)
	require.Equal(t, replacement, snapshot.Endpoints)
	replacement[0] = netip.AddrPort{}
	require.NoError(t, n.SetPeerEndpoints(b.addr, nil))
	snapshot, _ = n.PeerDiscovery(b.addr)
	require.False(t, snapshot.Static)
	require.Empty(t, snapshot.Endpoints)
	require.NoError(t, n.SetPeerEndpoints(b.addr, original.Endpoints))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	require.NoError(t, n.ConnectPeer(ctx, b.addr))
}

func TestPeerDiscoveryAfterHandshake(t *testing.T) {
	node, _, peer := newDiscoveryManagementTestNode(t, nil)
	endpoint := netip.MustParseAddrPort("203.0.113.25:4242")
	remotes := node.lighthouse.getOrCreateRemotes([]netip.Addr{peer.addr})
	remotes.LearnRemote(peer.addr, endpoint)
	remotes.BlockRemote(packetSender{UdpAddr: endpoint})
	blocked, ok := node.PeerDiscovery(peer.addr)
	require.True(t, ok)
	require.NotContains(t, blocked.Endpoints, endpoint)

	remotes.RefreshFromHandshake([]netip.Addr{peer.addr, peer.addr6})
	refreshed, ok := node.PeerDiscovery(peer.addr)
	require.True(t, ok)
	require.Contains(t, refreshed.Addresses, peer.addr6)
	require.Contains(t, refreshed.Endpoints, endpoint)
}

func BenchmarkPeerDiscovery(b *testing.B) {
	node, _, peer := newDiscoveryManagementTestNode(b, nil)
	var endpoints []netip.AddrPort
	for i := range 8 {
		port := uint16(4242 + i)
		endpoints = append(endpoints,
			netip.AddrPortFrom(netip.MustParseAddr("192.0.2.8"), port),
			netip.AddrPortFrom(netip.MustParseAddr("2001:db8::8"), port),
		)
	}
	for _, workload := range []string{"cached", "replace"} {
		b.Run(workload, func(b *testing.B) {
			require.NoError(b, node.lighthouse.setStaticEndpoints(peer.addr, endpoints))
			_, _ = node.PeerDiscovery(peer.addr)
			b.ReportAllocs()
			for b.Loop() {
				if workload == "replace" {
					if err := node.lighthouse.setStaticEndpoints(peer.addr, endpoints); err != nil {
						b.Fatal(err)
					}
				}
				got, ok := node.PeerDiscovery(peer.addr)
				if !ok || len(got.Endpoints) != len(endpoints) {
					b.Fatal(got)
				}
			}
		})
	}
}

func TestDiscoveryDialCandidates(t *testing.T) {
	node, local, lighthouse := newDiscoveryManagementTestNode(t, nil)
	target := netip.MustParseAddr("10.42.0.99")
	preferred := netip.MustParseAddrPort("192.168.1.9:9")
	public := netip.MustParseAddrPort("203.0.113.1:9")
	private := netip.MustParseAddrPort("10.1.1.2:9")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:9")
	lh := node.lighthouse
	lh.preferredRanges = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	require.NoError(t, lh.setStaticEndpoints(target, []netip.AddrPort{private, preferred}))
	remotes := lh.getOrCreateRemotes([]netip.Addr{target})
	remotes.LearnRemote(target, v6)
	report := &NebulaMetaDetails{
		V4AddrPorts:   []*V4AddrPort{netAddrToProtoV4AddrPort(public.Addr(), public.Port())},
		V6AddrPorts:   []*V6AddrPort{netAddrToProtoV6AddrPort(v6.Addr(), v6.Port())},
		RelayVpnAddrs: []*Addr{netAddrToProtoAddr(local.addr)},
	}
	lh.replaceReport([]netip.Addr{target}, lighthouse.addr, report)
	lh.replaceReport([]netip.Addr{target}, local.addr, report)
	first := remotes.candidates()
	require.Equal(t, []netip.AddrPort{preferred, v6, public, private}, first.endpoints)
	require.Equal(t, []netip.Addr{local.addr}, first.relays)

	// Replace one source while a worker still holds the first snapshot.
	lh.replaceReport([]netip.Addr{target}, lighthouse.addr, &NebulaMetaDetails{})
	require.Equal(t, first.endpoints, remotes.candidates().endpoints)
	lh.replaceReport([]netip.Addr{target}, local.addr, &NebulaMetaDetails{})
	require.Equal(t, []netip.AddrPort{preferred, v6, private}, remotes.candidates().endpoints)
	require.Equal(t, []netip.AddrPort{preferred, v6, public, private}, first.endpoints)
	require.Empty(t, remotes.candidates().relays)
}

func TestDiscoveryReportFiltersBeforeLimit(t *testing.T) {
	node, local, peer := newDiscoveryManagementTestNode(t, nil)
	report := &NebulaMetaDetails{}
	for i := range maxRemotes + 1 {
		port := uint16(i + 1)
		report.V4AddrPorts = append(report.V4AddrPorts, netAddrToProtoV4AddrPort(local.addr, port))
		report.V6AddrPorts = append(report.V6AddrPorts, netAddrToProtoV6AddrPort(local.addr6, port))
	}
	v4, v6 := netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("2001:db8::8")
	for i := range maxRemotes + 1 {
		port := uint16(i + 1)
		report.V4AddrPorts = append(report.V4AddrPorts, netAddrToProtoV4AddrPort(v4, port))
		report.V6AddrPorts = append(report.V6AddrPorts, netAddrToProtoV6AddrPort(v6, port))
	}
	target := netip.MustParseAddr("10.42.0.99")
	node.lighthouse.replaceReport([]netip.Addr{target}, peer.addr, report)
	got, ok := node.PeerDiscovery(target)
	require.True(t, ok)
	var want []netip.AddrPort
	for _, addr := range []netip.Addr{v4, v6} {
		for i := range maxRemotes {
			want = append(want, netip.AddrPortFrom(addr, uint16(i+1)))
		}
	}
	require.Equal(t, want, got.Endpoints)
}

func BenchmarkPendingLighthouseQuery(b *testing.B) {
	node, _, _ := newDiscoveryManagementTestNode(b, nil)
	peer := netip.MustParseAddr("10.42.0.77")
	node.lighthouse.QueryServer(peer)
	b.ReportAllocs()
	for b.Loop() {
		node.lighthouse.QueryServer(peer)
	}
}
