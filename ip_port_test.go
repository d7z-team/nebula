package nebula

import (
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func testIPv4(src, dst netip.Addr, body string) []byte {
	pkt := make([]byte, 20+len(body))
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 253
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[20:], body)
	return pkt
}

func testIPPort(t *testing.T, n *Node) (*IPPort, <-chan []byte) {
	t.Helper()
	rx := make(chan []byte, 8)
	p, err := n.OpenIPPort(func(packet []byte) { rx <- slices.Clone(packet) })
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p, rx
}

func assertIPExchange(t *testing.T, a, b *Node, src, dst netip.Addr) {
	t.Helper()
	pa, rxA := testIPPort(t, a)
	pb, rxB := testIPPort(t, b)
	for _, tc := range []struct {
		port   *IPPort
		rx     <-chan []byte
		packet []byte
	}{
		{pa, rxB, testIPv4(src, dst, "outbound")}, {pb, rxA, testIPv4(dst, src, "return")},
	} {
		require.NoError(t, tc.port.WriteIP(netip.Addr{}, tc.packet))
		select {
		case got := <-tc.rx:
			require.Equal(t, tc.packet, got)
		case <-time.After(5 * time.Second):
			t.Fatal("tunnel did not deliver IP packet")
		}
	}
}

func TestIPPortAuthorizationAndQueues(t *testing.T) {
	a, b, ai, bi := newNodeTestPair(t)
	port, _ := testIPPort(t, a)
	_, rx := testIPPort(t, b)
	_, err := a.OpenIPPort(func([]byte) {})
	require.ErrorIs(t, err, ErrPortInUse)
	forwarded := testIPv4(ai.virtual, bi.virtual, "routed")
	require.ErrorIs(t, port.WriteIP(netip.Addr{}, forwarded), ErrMissingGateway)
	require.ErrorIs(t, port.WriteIP(ai.addr, forwarded), ErrPeerUnavailable)
	require.ErrorIs(t, port.WriteIP(bi.virtual, forwarded), ErrPeerUnavailable)
	require.ErrorIs(t, port.WriteIP(bi.addr, testIPv4(bi.addr, bi.virtual, "invalid source")), ErrAddressNotCertified)
	require.ErrorIs(t, port.WriteIP(netip.MustParseAddr("10.42.0.255"), forwarded), ErrPeerUnavailable)
	before := port.Stats().RejectedOutbound
	wrong := testIPv4(ai.addr, ai.virtual, "not on b")
	require.NoError(t, port.WriteIP(bi.addr, wrong)) // Pending, the actual certificate is still unknown.
	require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == before+1 }, 3*time.Second, time.Millisecond)
	require.Equal(t, "peer certificate does not authorize destination", port.Stats().LastDrop.Reason)
	require.ErrorIs(t, port.WriteIP(bi.addr, wrong), ErrAddressNotCertified)
	require.Zero(t, port.Stats().SentPackets)
	require.NoError(t, port.WriteIP(bi.addr, forwarded))
	select {
	case got := <-rx:
		require.Equal(t, forwarded, got)
	case <-time.After(time.Second):
		t.Fatal("missing forwarded packet")
	}

	unknown := netip.MustParseAddr("10.42.0.240")
	for range 100 {
		require.NoError(t, port.WriteIP(unknown, forwarded))
	}
	require.ErrorIs(t, port.WriteIP(unknown, forwarded), ErrQueueFull)
	require.Equal(t, 100, port.ClearPending(unknown))
	require.Zero(t, port.Stats().Queued)
	require.Zero(t, port.ClearPending(unknown))
	port.Close()
	require.ErrorIs(t, port.WriteIP(bi.addr, forwarded), ErrPortClosed)
	replacement, _ := testIPPort(t, a)
	require.Equal(t, PortStats{}, replacement.Stats())
	port.Close()
	require.NoError(t, replacement.WriteIP(bi.addr, forwarded))
}

func TestIPPortInboundPolicyAndSource(t *testing.T) {
	pool, a, b := newNodeTestIdentities(t)
	underlay := netip.MustParseAddrPort("127.0.0.1:24001")
	denied := true
	node, err := New(t.Context(), Options{Identities: []Identity{a.identity}, CAPool: pool, Transport: newMemoryDatagramNetwork(underlay)[0], InboundPolicy: func(peer, src, dst netip.Addr) bool {
		require.Equal(t, b.addr, peer)
		require.Equal(t, b.virtual, src)
		require.Equal(t, a.virtual, dst)
		return !denied
	}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close(); _ = node.Wait() })
	port, rx := testIPPort(t, node)
	peer := &hostInfo{vpnAddrs: []netip.Addr{b.addr}}
	peer.buildNetworks(node.engine.myVpnNetworksTable, b.identity.Certificate)
	for _, src := range []netip.Addr{a.addr, netip.MustParseAddr("10.42.0.50"), a.virtual, b.virtual} {
		port.receiveIP(peer, testIPv4(src, a.virtual, "in"), packetSender{})
	}
	require.EqualValues(t, 4, port.Stats().RejectedInbound)
	denied = false
	pkt := testIPv4(b.virtual, a.virtual, "asymmetric")
	port.receiveIP(peer, pkt, packetSender{})
	require.Equal(t, pkt, <-rx)
	stats := port.Stats()
	require.EqualValues(t, 1, stats.ReceivedPackets)
	require.EqualValues(t, len(pkt), stats.ReceivedBytes)
}

func TestRelayedIPPortTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMeshWithOptions(t, 3, Options{
			DatagramMagic: []byte("mesh"), Relay: RelayOptions{Serve: true},
		})
		tr[0].network.blockBoth(tr[0].addr, tr[1].addr)
		policy := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[2].addr}}
		require.NoError(t, nodes[0].SetPeerPathPolicy(t.Context(), ids[1].addr, &policy))
		require.NoError(t, nodes[1].SetPeerPathPolicy(t.Context(), ids[0].addr, &policy))

		portA, rxA := testIPPort(t, nodes[0])
		portB, rxB := testIPPort(t, nodes[1])
		relayPort, _ := testIPPort(t, nodes[2])
		// A full-sized IP packet must fit through the relay with a framing prefix.
		packet := testIPv4(ids[0].addr, ids[1].addr, strings.Repeat("x", MaxIPPacketSize-20))
		require.NoError(t, portA.WriteIP(netip.Addr{}, packet))
		select {
		case got := <-rxB:
			require.Equal(t, packet, got)
		case <-time.After(5 * time.Second):
			t.Fatal("maximum-size IP packet did not reach the peer through the relay")
		}
		synctest.Wait()
		relay := nodes[2].RelayStats()
		require.Equal(t, 2, relay.UsedMappings)
		require.GreaterOrEqual(t, relay.ForwardedDatagrams, uint64(3)) // Handshake in both directions and IP data.

		reply := testIPv4(ids[1].addr, ids[0].addr, "reply")
		require.NoError(t, portB.WriteIP(netip.Addr{}, reply))
		synctest.Wait()
		require.Len(t, rxA, 1)
		require.Equal(t, reply, <-rxA)
		forwarded := nodes[2].RelayStats().ForwardedDatagrams
		require.Equal(t, relay.ForwardedDatagrams+1, forwarded)
		require.Zero(t, nodes[0].RelayStats().ForwardedDatagrams)
		require.Zero(t, nodes[1].RelayStats().ForwardedDatagrams)
		require.Equal(t, PortStats{SentPackets: 1, SentBytes: uint64(len(packet)), ReceivedPackets: 1, ReceivedBytes: uint64(len(reply))}, portA.Stats())
		require.Equal(t, PortStats{SentPackets: 1, SentBytes: uint64(len(reply)), ReceivedPackets: 1, ReceivedBytes: uint64(len(packet))}, portB.Stats())
		require.Equal(t, PortStats{}, relayPort.Stats())

		// B can still submit to R when R's transport loses its destination A.
		network := tr[2].network
		network.mu.Lock()
		delete(network.endpoints, tr[0].addr)
		network.mu.Unlock()
		attempts := network.writesTo(tr[2].addr, tr[0].addr).total
		require.NoError(t, portB.WriteIP(netip.Addr{}, reply))
		synctest.Wait()
		require.Equal(t, attempts+1, network.writesTo(tr[2].addr, tr[0].addr).total)
		require.EqualValues(t, 2, portB.Stats().SentPackets)
		require.Equal(t, forwarded, nodes[2].RelayStats().ForwardedDatagrams)
	})
}

func TestIPPortStatsAcrossPathRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b, local, peer := newNodeTestPair(t)
		require.NoError(t, a.ConnectPeer(t.Context(), peer.addr))
		port, _ := testIPPort(t, a)
		_, rx := testIPPort(t, b)

		// Queue a policy update ahead of the writer's final route check so
		// the route changes after dequeue and before transport submission.
		submit := a.engine.paths.submit
		require.NoError(t, submit.Acquire(t.Context(), math.MaxInt64))
		updated := make(chan error, 1)
		go func() { updated <- a.SetPeerPathPolicy(t.Context(), peer.addr, &PeerPathPolicy{Mode: RelayOnly}) }()
		synctest.Wait()
		packet := testIPv4(local.addr, peer.addr, "retry")
		err := port.WriteIP(peer.addr, packet)
		synctest.Wait()
		inFlight := port.Stats()
		submit.Release(math.MaxInt64)
		require.NoError(t, err)
		require.Equal(t, PortStats{}, inFlight)
		require.NoError(t, <-updated)
		synctest.Wait()
		require.Equal(t, PortStats{Queued: 1}, port.Stats())

		require.NoError(t, a.SetPeerPathPolicy(t.Context(), peer.addr, nil))
		select {
		case got := <-rx:
			require.Equal(t, packet, got)
		case <-time.After(time.Second):
			t.Fatal("queued packet did not reach the peer after restoring its direct route")
		}
		synctest.Wait()
		require.Equal(t, PortStats{SentPackets: 1, SentBytes: uint64(len(packet))}, port.Stats())
	})
}

func TestIPPortFlushDuringHandshake(t *testing.T) {
	a, b, ai, bi := newNodeTestPair(t)
	addrB, err := b.transport.LocalAddr()
	require.NoError(t, err)
	require.NoError(t, a.SetPeerEndpoints(bi.addr, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:29999")}))
	p, _ := testIPPort(t, a)
	_, rx := testIPPort(t, b)
	stale := testIPv4(ai.addr, bi.virtual, "old route")
	require.NoError(t, p.WriteIP(bi.addr, stale))
	require.Eventually(t, func() bool { s, ok := a.Peer(bi.addr); return ok && s.HandshakePending }, time.Second, time.Millisecond)
	require.Equal(t, 1, p.ClearPending(bi.addr))
	require.NoError(t, a.SetPeerEndpoints(bi.addr, []netip.AddrPort{addrB}))
	live := testIPv4(ai.addr, bi.virtual, "new route")
	require.NoError(t, p.WriteIP(bi.addr, live))
	select {
	case got := <-rx:
		require.Equal(t, live, got)
	case <-time.After(4 * time.Second):
		t.Fatal("replacement queue failed to deliver")
	}
	require.Eventually(t, func() bool { s, ok := a.Peer(bi.addr); return ok && s.LastDataPath == (TunnelPath{Endpoint: addrB}) }, time.Second, time.Millisecond)
}

func TestIPPortCloseWithTransportWriteInFlight(t *testing.T) {
	node, transport, a, b := newGatedNodePair(t)
	port, _ := testIPPort(t, node)
	transport.enabled.Store(true)
	pkt := testIPv4(a.addr, b.addr, "in flight")
	require.NoError(t, port.WriteIP(b.addr, pkt))
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("transport did not receive frame")
	}
	require.NoError(t, port.WriteIP(b.addr, pkt))
	require.Equal(t, 1, port.Stats().Queued)
	port.Close()
	require.Zero(t, port.Stats().Queued)
	replacement, _ := testIPPort(t, node)
	require.NoError(t, replacement.WriteIP(b.addr, pkt))
	stopped := make(chan error, 1)
	go func() { _ = node.Close(); stopped <- node.Wait() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("closing the transport did not release IP workers")
	}
}
