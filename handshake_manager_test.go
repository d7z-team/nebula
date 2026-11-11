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
	interval := node.handshake.config.tryInterval
	timer := newLockingTimerWheel[outboundHandshakeTimerItem](interval, hsTimeout(node.handshake.config.retries, interval))
	node.handshake.OutboundHandshakeTimer = timer
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
