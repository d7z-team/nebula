package nebula

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
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
		node.engine.deliverIP(peer, testIPv4(src, a.virtual, "in"))
	}
	require.EqualValues(t, 4, port.Stats().RejectedInbound)
	denied = false
	pkt := testIPv4(b.virtual, a.virtual, "asymmetric")
	node.engine.deliverIP(peer, pkt)
	require.Equal(t, pkt, <-rx)
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
