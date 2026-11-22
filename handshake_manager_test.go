package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOutboundHandshakeTimerDoesNotDriveReplacementGeneration(t *testing.T) {
	pool, local, remote := newNodeTestIdentities(t)
	transport := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:25001"))[0]
	node, err := New(t.Context(), Options{
		Identities: []Identity{local.identity},
		CAPool:     pool,
		Transport:  transport,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, node.Close())
		require.NoError(t, node.Wait())
	})

	oldHostInfo := node.handshake.StartHandshake(remote.addr, nil)
	oldGeneration := node.handshake.queryVpnIp(remote.addr)
	require.NotNil(t, oldGeneration)
	require.Same(t, oldHostInfo, oldGeneration.hostinfo)

	// This is the same lifecycle as DisconnectPeer canceling a pending
	// handshake followed immediately by ConnectPeer for the same address.
	node.handshake.DeleteHostInfo(oldHostInfo)
	newHostInfo := node.handshake.StartHandshake(remote.addr, nil)
	newGeneration := node.handshake.queryVpnIp(remote.addr)
	require.NotNil(t, newGeneration)
	require.Same(t, newHostInfo, newGeneration.hostinfo)
	require.NotSame(t, oldGeneration, newGeneration)

	// Isolate the stale entry that was already resident in the timer wheel
	// when the first generation was canceled.
	interval := node.handshake.config.TryInterval
	timer := newTimerWheel[outboundHandshakeTimerItem](interval, time.Duration(node.handshake.config.Retries)*interval)
	node.handshake.retryTimer = timer
	now := time.Now()
	timer.Advance(now)
	timer.Add(outboundHandshakeTimerItem{vpnAddr: remote.addr, generation: oldGeneration}, interval)
	node.handshake.NextOutboundHandshakeTimerTick(now.Add(2 * interval))

	oldGeneration.Lock()
	oldCounter := oldGeneration.counter
	oldGeneration.Unlock()
	newGeneration.Lock()
	newCounter := newGeneration.counter
	newGeneration.Unlock()
	require.Zero(t, oldCounter, "a detached generation must not be retried")
	require.Zero(t, newCounter, "a stale timer must not advance the replacement generation")
}

func TestLighthouseReportTriggersRelayHandshake(t *testing.T) {
	node, _, relay := newDiscoveryManagementTestNode(t, nil)
	target := netip.MustParseAddr("10.42.0.99")
	hm := node.handshake
	hm.StartHandshake(target, nil)
	hh := hm.queryVpnIp(target)
	for range hm.config.Retries {
		hm.handleOutbound(target, hh, true)
	}

	node.lighthouse.replaceReport([]netip.Addr{target}, relay.addr, &NebulaMetaDetails{
		RelayVpnAddrs: []*Addr{netAddrToProtoAddr(relay.addr)},
	})
	hm.handleOutbound(target, hh, true)
	require.NotNil(t, hm.queryVpnIp(relay.addr), "a relay-only reply should start a tunnel to the relay")
	require.Same(t, hh, hm.queryVpnIp(target))
}
