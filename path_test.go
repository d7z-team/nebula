package nebula

import (
	"context"
	"crypto/fips140"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
)

// Use the existing gateway/client pair so the same topology exercises unsafe routes.
func pathTestIdentities(t *testing.T, version cert.Version, count int) (*cert.CAPool, []nodeTestIdentity) {
	t.Helper()
	curve := cert.Curve_CURVE25519
	if fips140.Enforced() {
		curve = cert.Curve_P256
	}
	pool, a, b := newNodeTestIdentitiesFor(t, version, curve)
	ids := []nodeTestIdentity{a, b}
	now := time.Now().Add(-time.Minute)
	ca, key, err := cert.CreateCA(cert.CAOptions{Version: version, Curve: curve, Name: "relay CA", NotBefore: now, NotAfter: now.Add(time.Hour)})
	require.NoError(t, err)
	require.NoError(t, pool.AddCA(ca))
	for i := 3; i <= count; i++ {
		p := netip.MustParsePrefix(fmt.Sprintf("10.42.0.%d/24", i))
		c, k, err := cert.IssueCertificate(ca, key, cert.CertificateOptions{Version: version, Name: fmt.Sprintf("relay-%d", i), Networks: []netip.Prefix{p}, NotBefore: now, NotAfter: now.Add(30 * time.Minute)})
		require.NoError(t, err)
		ids = append(ids, nodeTestIdentity{addr: p.Addr(), identity: Identity{Certificate: c, PrivateKey: k}})
	}
	return pool, ids
}

func pathTestMesh(t *testing.T, count int) ([]*Node, []nodeTestIdentity, []*memoryDatagramTransport) {
	t.Helper()
	return pathTestMeshWithOptions(t, count, Options{
		Relay: RelayOptions{Serve: true}, Handshake: HandshakeOptions{TryInterval: 30 * time.Millisecond},
		Punchy: PunchyOptions{Punch: true, Respond: true, Delay: time.Millisecond},
	})
}

func pathTestMeshWithOptions(t *testing.T, count int, opts Options) ([]*Node, []nodeTestIdentity, []*memoryDatagramTransport) {
	t.Helper()
	pool, ids := pathTestIdentities(t, cert.Version2, count)
	var endpoints []netip.AddrPort
	for i := range ids {
		endpoints = append(endpoints, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(30001+i)))
	}
	transports := newMemoryDatagramNetwork(endpoints...)
	var nodes []*Node
	for i, id := range ids {
		static := map[netip.Addr][]netip.AddrPort{}
		for j, other := range ids {
			if i != j {
				static[other.addr] = []netip.AddrPort{endpoints[j]}
			}
		}
		opts.Identities, opts.CAPool, opts.Transport = []Identity{id.identity}, pool, transports[i]
		opts.Lighthouse.StaticHosts = static
		nodes = append(nodes, startTestNode(t, opts))
	}
	return nodes, ids, transports
}

func TestPathPolicyAndDualRole(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 4)
		a, b, r, x := nodes[0], nodes[1], nodes[2], nodes[3]
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		direct, err := a.CheckPeerPath(ctx, ids[1].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, TunnelPath{Endpoint: tr[1].addr}, direct.Received)
		policy := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[2].addr}}
		require.NoError(t, a.SetPeerPathPolicy(ctx, ids[1].addr, &policy))
		writes := tr[0].network.writesTo(tr[0].addr, tr[1].addr).total
		a.punchy.Schedule(tr[1].addr, ids[1].addr)
		require.NoError(t, b.SetPeerPathPolicy(ctx, ids[0].addr, &policy))
		reply, err := a.CheckPeerPath(ctx, ids[1].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, ids[2].addr, reply.Sent.Relay)
		require.Equal(t, reply.Sent, reply.Received)
		synctest.Wait()
		before := tr[0].network.writesTo(tr[2].addr, tr[1].addr).relayedIP
		assertIPExchange(t, a, b, ids[0].addr, ids[1].addr)
		synctest.Wait()
		require.Equal(t, before+1, tr[0].network.writesTo(tr[2].addr, tr[1].addr).relayedIP, "one forward per business datagram")
		_, err = a.CheckPeerPath(ctx, ids[1].addr, TunnelPath{Endpoint: tr[1].addr})
		require.ErrorIs(t, err, ErrPathPolicy)
		// A is simultaneously an endpoint using R and the relay for X -> R.
		viaA := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[0].addr}}
		require.NoError(t, x.SetPeerPathPolicy(ctx, ids[2].addr, &viaA))
		reply, err = x.CheckPeerPath(ctx, ids[2].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, ids[0].addr, reply.Received.Relay)
		assertIPExchange(t, x, r, ids[3].addr, ids[2].addr)
		_, err = a.DisconnectPeer(ids[1].addr, DisconnectOptions{})
		require.NoError(t, err)
		require.Equal(t, writes, tr[0].network.writesTo(tr[0].addr, tr[1].addr).total)
	})
}

func TestPathHealthFailover(t *testing.T) {
	nodes, ids, tr := pathTestMesh(t, 3)
	a := nodes[0]
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	policy := PeerPathPolicy{Relays: []netip.Addr{ids[2].addr}}
	require.NoError(t, a.SetPeerPathPolicy(ctx, ids[1].addr, &policy))
	_, err := a.CheckPeerPath(ctx, ids[1].addr, TunnelPath{Relay: ids[2].addr})
	require.NoError(t, err)
	tr[0].network.blockBoth(tr[0].addr, tr[1].addr)
	direct := TunnelPath{Endpoint: tr[1].addr}
	for range 3 {
		_, err = a.CheckPeerPath(ctx, ids[1].addr, direct)
		require.ErrorIs(t, err, ErrPathTimeout)
	}
	s, ok := a.Peer(ids[1].addr)
	require.True(t, ok)
	require.Equal(t, ids[2].addr, s.PathHealth.Active.Path.Relay)
	require.Equal(t, "failover", s.PathHealth.Reason)
	reply, err := a.CheckPeerPath(ctx, ids[1].addr, TunnelPath{})
	require.NoError(t, err)
	require.Equal(t, ids[2].addr, reply.Sent.Relay)
}

func TestPathQualitySelection(t *testing.T) {
	fast := tunnelRoute{TunnelPath: TunnelPath{Endpoint: netip.MustParseAddrPort("127.0.0.1:1")}}
	stable := tunnelRoute{TunnelPath: TunnelPath{Endpoint: netip.MustParseAddrPort("127.0.0.1:2")}}
	// The trace is shared by all three policies. Each step represents one virtual
	// second of user traffic and a sampling opportunity on each eligible route.
	type metrics struct{ probes, switches, earlySwitches, outage, switchAt int }
	var opts PathOptions
	require.NoError(t, opts.normalizeTuning())
	results := map[string]metrics{}
	for _, mode := range []string{"full", "without-canary", "without-hysteresis"} {
		var s sessionPaths
		var m metrics
		now := time.Unix(100, 0)
		s.setHandshakeRoute(fast, now, 10*time.Second)
		for tick := 1; tick <= 90; tick++ {
			now = now.Add(time.Second)
			before := s.active
			// The stable path loses its return direction at second 68.
			if !before.Endpoint.IsValid() || (before == stable && tick >= 68) {
				m.outage++
			}
			for _, r := range []tunnelRoute{fast, stable} {
				if mode == "without-canary" && before.Endpoint.IsValid() && r != before {
					continue
				}
				if q := s.samples[r]; q != nil && now.Before(q.RetryAfter) {
					continue
				}
				delay := 30 * time.Millisecond
				if r == stable {
					delay = 55 * time.Millisecond
				} else if tick == 8 || (tick >= 37 && tick%2 == 1) {
					delay = 140 * time.Millisecond
				}
				result := PathCheckResult{Sent: r.TunnelPath, Received: r.TunnelPath, SamePath: true, RTT: delay, At: now}
				if r == stable && tick >= 68 {
					result.Err = ErrPathTimeout
				}
				s.record(r, result, &opts.Selection)
				m.probes++
			}
			if mode == "without-hysteresis" {
				// Control: same estimator, timeouts and sampling, choose the lowest current cost immediately.
				for _, r := range []tunnelRoute{fast, stable} {
					q, active := s.samples[r], s.samples[s.active]
					if q != nil && q.failures == 0 && (active == nil || q.cost() < active.cost()) {
						s.standby, s.active = s.active, r
					}
				}
			}
			if before != s.active {
				m.switches++
				if tick < 37 {
					m.earlySwitches++
				}
				if tick >= 37 && tick < 68 && m.switchAt == 0 {
					m.switchAt = tick
				}
			}
		}
		results[mode] = m
		t.Logf("%s: probes=%d switches=%d before_degradation=%d quality_switch_second=%d interrupted_seconds=%d", mode, m.probes, m.switches, m.earlySwitches, m.switchAt, m.outage)
	}
	full, noCanary, immediate := results["full"], results["without-canary"], results["without-hysteresis"]
	require.Zero(t, full.earlySwitches)
	require.Greater(t, immediate.earlySwitches, full.earlySwitches)
	require.GreaterOrEqual(t, full.switchAt, 37)
	require.Equal(t, 2, full.switches)
	require.Equal(t, 3, full.outage)
	require.Zero(t, noCanary.switchAt)
	require.Less(t, noCanary.probes, full.probes)
}

// NewTestRelayNICNodes supplies a switchable link for the external gVisor test.
func NewTestRelayNICNodes(t *testing.T) (client, gateway *Node, switchPath func()) {
	nodes, ids, _ := pathTestMesh(t, 3)
	return nodes[1], nodes[0], func() {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		p := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[2].addr}}
		require.NoError(t, nodes[1].SetPeerPathPolicy(ctx, ids[0].addr, &p))
		reply, err := nodes[1].CheckPeerPath(ctx, ids[0].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, ids[2].addr, reply.Received.Relay)
	}
}

func TestPathPolicySubmissionAndCancel(t *testing.T) {
	n, gated, _, b := newGatedNodePair(t)
	gated.enabled.Store(true)
	defer gated.unblock()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := n.CheckPeerPath(ctx, b.addr, TunnelPath{}); result <- err }()
	select {
	case <-gated.entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not reach transport")
	}
	limited, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer stop()
	p := PeerPathPolicy{Mode: RelayOnly}
	require.ErrorIs(t, n.SetPeerPathPolicy(limited, b.addr, &p), context.DeadlineExceeded)
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("probe wait did not cancel")
	}
	_, overridden := n.PeerPathPolicy(b.addr)
	require.False(t, overridden)
	updated := make(chan error, 1)
	go func() { updated <- n.SetPeerPathPolicy(t.Context(), b.addr, &p) }()
	gated.unblock()
	require.NoError(t, <-updated)
	h := n.engine.hostMap.QueryVpnAddr(b.addr)
	require.ErrorIs(t, n.engine.writePath(h, tunnelRoute{TunnelPath: TunnelPath{Endpoint: h.GetRemote()}}, punchPacket, true, nil), ErrPathPolicy)
}

func TestRelayOutageAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 3)
		a, b := nodes[0], nodes[1]
		p := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[2].addr}}
		require.NoError(t, a.SetPeerPathPolicy(t.Context(), ids[1].addr, &p))
		require.NoError(t, b.SetPeerPathPolicy(t.Context(), ids[0].addr, &p))
		out, err := a.CheckPeerPath(t.Context(), ids[1].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, ids[2].addr, out.Sent.Relay)
		tr[0].network.blockBoth(tr[0].addr, tr[2].addr)
		require.Eventually(t, func() bool {
			_, e := a.CheckPeerPath(t.Context(), ids[1].addr, TunnelPath{})
			h := a.engine.hostMap.QueryVpnAddr(ids[1].addr)
			return e != nil && (h == nil || !a.engine.currentRoute(h).Endpoint.IsValid())
		}, 15*time.Second, time.Second)
		require.ErrorIs(t, a.ConnectPeer(t.Context(), ids[1].addr), ErrPeerUnavailable)
		require.Zero(t, tr[0].network.writesTo(tr[0].addr, tr[1].addr).total)
		netw := tr[0].network
		netw.mu.Lock()
		clear(netw.blocked)
		netw.mu.Unlock()
		require.Eventually(t, func() bool {
			check, e := a.CheckPeerPath(t.Context(), ids[1].addr, TunnelPath{})
			return e == nil && check.Sent.Relay == ids[2].addr
		}, 90*time.Second, time.Second)
		assertIPExchange(t, a, b, ids[0].addr, ids[1].addr)
		require.Zero(t, tr[0].network.writesTo(tr[0].addr, tr[1].addr).total)
	})
}

func TestPathCheckRebindAndIdleMonitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 2)
		a := nodes[0]
		require.NoError(t, a.ConnectPeer(t.Context(), ids[1].addr))
		h := a.engine.hostMap.QueryVpnAddr(ids[1].addr)
		r := a.engine.currentRoute(h)
		tr[0].network.blockBoth(tr[0].addr, tr[1].addr)
		pending, err := a.startProbe(h, r, true)
		require.NoError(t, err)
		synctest.Wait()
		require.NoError(t, a.Rebind())
		a.engine.finishReply(h, r, pending.id[:], true)
		<-pending.done
		require.ErrorIs(t, pending.result.Err, ErrPathChanged)
		tr[0].network.mu.Lock()
		clear(tr[0].network.blocked)
		tr[0].network.mu.Unlock()
		// Let both nodes' ordinary activity expire before measuring idle checks.
		time.Sleep(75 * time.Second)
		last, _ := a.Peer(ids[1].addr)
		time.Sleep(40 * time.Second)
		idle, _ := a.Peer(ids[1].addr)
		require.Equal(t, last.PathHealth.LastCheck.At, idle.PathHealth.LastCheck.At)
		require.NoError(t, a.SetPeerPathPolicy(t.Context(), ids[1].addr, &PeerPathPolicy{MonitorInterval: 2 * time.Second}))
		time.Sleep(75 * time.Second)
		before, _ := a.Peer(ids[1].addr)
		time.Sleep(6 * time.Second)
		after, _ := a.Peer(ids[1].addr)
		require.True(t, after.PathHealth.LastCheck.At.After(before.PathHealth.LastCheck.At))
		h.paths.mu.Lock()
		idleFor := time.Since(h.paths.demand)
		h.paths.mu.Unlock()
		require.Greater(t, idleFor, time.Minute)
	})
}

func TestPathRebindAtScale(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 2)
		a, b := nodes[0], nodes[1]
		require.NoError(t, a.ConnectPeer(t.Context(), ids[1].addr))
		aSession := a.engine.hostMap.QueryVpnAddr(ids[1].addr)
		bSession := b.engine.hostMap.QueryVpnAddr(ids[0].addr)
		// Model 1,000 already authenticated sessions over one transport pair.
		// Distinct indices route the encrypted Test messages and replies to the
		// correct per-peer state. The fixture shares only the two Noise key sets.
		const count = 1000
		peers := make([]*hostInfo, 0, count)
		addr := netip.MustParseAddr("fd00:42::1000")
		target := netip.MustParseAddr("10.42.0.150")
		for i := range count {
			addr = addr.Next()
			h := &hostInfo{vpnAddrs: []netip.Addr{addr}, remotes: aSession.remotes, connectionState: aSession.connectionState, localIndexId: uint32(i + 1), remoteIndexId: uint32(i + 1)}
			reply := &hostInfo{vpnAddrs: bSession.vpnAddrs, remotes: bSession.remotes, connectionState: bSession.connectionState, localIndexId: h.remoteIndexId, remoteIndexId: h.localIndexId}
			h.remote.Store(&tr[1].addr)
			reply.remote.Store(&tr[0].addr)
			h.paths.setHandshakeRoute(tunnelRoute{TunnelPath: TunnelPath{Endpoint: tr[1].addr}}, time.Now(), a.engine.paths.probes.ActiveInterval)
			a.engine.hostMap.Lock()
			a.engine.hostMap.Hosts[addr] = h
			a.engine.hostMap.Indexes[h.localIndexId] = h
			a.engine.hostMap.Unlock()
			b.engine.hostMap.Lock()
			b.engine.hostMap.Indexes[reply.localIndexId] = reply
			b.engine.hostMap.Unlock()
			a.engine.paths.checks.Add(h, a.engine.paths.probes.TickInterval)
			peers = append(peers, h)
			// Repeated requests from every dependent peer share one pending direct adjacency.
			for range 3 {
				_, ready := a.engine.ensureRelay(h, target)
				require.False(t, ready)
			}
		}
		a.handshake.RLock()
		pending := len(a.handshake.vpnIps)
		adjacency := a.handshake.vpnIps[target]
		a.handshake.RUnlock()
		require.Equal(t, 1, pending)
		require.NotNil(t, adjacency)
		require.True(t, adjacency.directOnly.Load())
		require.NoError(t, a.Rebind())
		start := time.Now()
		base := tr[0].network.writesTo(tr[0].addr, tr[1].addr).total
		// NAT keepalives from the two real peers are included in the transport
		// counter, so count completed per-session authenticated probes separately.
		serviced := 0
		for tick := 1; tick <= 58; tick++ {
			time.Sleep(time.Second)
			synctest.Wait()
			serviced = 0
			for _, h := range peers {
				h.paths.mu.Lock()
				if h.paths.last.SamePath && h.paths.last.Err == nil {
					serviced++
				}
				h.paths.mu.Unlock()
			}
			writes := tr[0].network.writesTo(tr[0].addr, tr[1].addr).total - base
			require.LessOrEqual(t, serviced, 10+20*tick)
			require.LessOrEqual(t, writes, 10+20*tick+2*tick, "aggregate probe budget plus real-peer maintenance")
			if serviced == count {
				break
			}
		}
		require.Equal(t, count, serviced)
		t.Logf("%d logical peers received authenticated checks in %v after Rebind", serviced, time.Since(start))
	})
}

func TestRelayCycleAndPendingExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 4)
		a, r, other := nodes[0], nodes[2], nodes[3]
		target := ids[1].addr
		for _, tc := range []struct {
			n     *Node
			relay netip.Addr
		}{{a, ids[2].addr}, {r, ids[3].addr}, {other, ids[2].addr}} {
			require.NoError(t, tc.n.SetPeerPathPolicy(t.Context(), target, &PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{tc.relay}}))
		}
		require.ErrorIs(t, a.ConnectPeer(t.Context(), target), ErrPeerUnavailable)
		require.Zero(t, tr[2].network.writesTo(tr[2].addr, tr[3].addr).total)
		require.Zero(t, tr[3].network.writesTo(tr[3].addr, tr[2].addr).total)
		require.Zero(t, tr[0].network.writesTo(tr[0].addr, tr[1].addr).total)
		leg := a.engine.hostMap.QueryVpnAddr(ids[2].addr)
		mapping, ok := leg.relayState.mappingByAddr(target)
		require.True(t, ok)
		require.Equal(t, relayRequested, mapping.State)
		time.Sleep(75 * time.Second)
		require.Nil(t, a.engine.hostMap.QueryRelayIndex(mapping.LocalIndex))
		_, ok = leg.relayState.mappingByAddr(target)
		require.False(t, ok)
	})
}

func TestPeerPathPolicyBeforeStart(t *testing.T) {
	pool, local, remote := newNodeTestIdentities(t)
	relay := remote.addr.Next()
	override := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{relay}}
	n, err := New(t.Context(), Options{
		Identities: []Identity{local.identity}, CAPool: pool,
		Transport: newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:30001"))[0],
		Paths: PathOptions{Default: PeerPathPolicy{Mode: DirectOnly}, Peers: map[netip.Addr]PeerPathPolicy{
			remote.addr: override,
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, n.Close()); require.NoError(t, n.Wait()) })

	p, ok := n.PeerPathPolicy(netip.AddrFrom16(remote.addr.As16()))
	require.True(t, ok)
	require.Equal(t, override, p)
	p.Relays[0] = local.addr
	p, ok = n.PeerPathPolicy(remote.addr)
	require.True(t, ok)
	require.Equal(t, []netip.Addr{relay}, p.Relays)

	require.NoError(t, n.SetPeerPathPolicy(t.Context(), remote.addr, &PeerPathPolicy{Mode: Auto}))
	p, ok = n.PeerPathPolicy(remote.addr)
	require.True(t, ok)
	require.Equal(t, PeerPathPolicy{Mode: Auto}, p)
	require.NoError(t, n.SetPeerPathPolicy(t.Context(), remote.addr, nil))
	_, ok = n.PeerPathPolicy(remote.addr)
	require.False(t, ok)
	require.Equal(t, DirectOnly, n.Discovery().DefaultPathPolicy.Mode)
}

func TestPathPolicyCertificateAliases(t *testing.T) {
	nodes, ids, tr := pathTestMesh(t, 3)
	a, b := nodes[0], ids[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.addr))
	direct := PeerPathPolicy{Mode: DirectOnly}
	require.NoError(t, a.SetPeerPathPolicy(t.Context(), b.addr, &direct))
	relay := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{ids[2].addr}}
	require.NoError(t, a.SetPeerPathPolicy(t.Context(), b.addr6, &relay))
	snapshot, ok := a.Peer(b.addr)
	require.True(t, ok)
	require.Equal(t, PathBlocked, snapshot.PathHealth.Policy.Mode)
	require.False(t, snapshot.PathHealth.Active.Path.Endpoint.IsValid())
	for _, path := range []TunnelPath{{Endpoint: tr[1].addr}, {Relay: ids[2].addr}} {
		_, err := a.CheckPeerPath(t.Context(), b.addr, path)
		require.ErrorIs(t, err, ErrPathPolicy)
	}
	require.NoError(t, a.SetPeerPathPolicy(t.Context(), b.addr6, nil))
	check, err := a.CheckPeerPath(t.Context(), b.addr6, TunnelPath{Endpoint: tr[1].addr})
	require.NoError(t, err)
	require.True(t, check.SamePath)
}

func TestPathControlBudgetAndDuplicatePunches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMeshWithOptions(t, 2, Options{
			Punchy: PunchyOptions{Delay: time.Millisecond},
			Paths: PathOptions{Probes: PathProbeOptions{
				ControlBudget: PacketBudget{Burst: 4, Every: 50 * time.Millisecond},
			}},
		})
		a := nodes[0]
		target := ids[1].addr
		ep := tr[1].addr
		for range 1000 {
			a.punchy.Schedule(ep, target)
		}
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		require.Equal(t, 1, tr[0].network.writesTo(tr[0].addr, ep).total)
		h := &hostInfo{vpnAddrs: []netip.Addr{target}}
		route := tunnelRoute{TunnelPath: TunnelPath{Endpoint: ep}}
		for range 1000 {
			a.engine.writePath(h, route, punchPacket, true, nil)
		}
		require.Equal(t, 4, tr[0].network.writesTo(tr[0].addr, ep).total)
		for range 10 {
			time.Sleep(100 * time.Millisecond)
			for range 100 {
				a.engine.writePath(h, route, punchPacket, true, nil)
			}
		}
		require.Equal(t, 24, tr[0].network.writesTo(tr[0].addr, ep).total)
	})
}

func TestSharedRelayFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMesh(t, 4)
		a, relayID := nodes[0], ids[2].addr
		policy := PeerPathPolicy{Mode: RelayOnly, Relays: []netip.Addr{relayID}}
		endpoints := []netip.Addr{ids[1].addr, ids[3].addr}
		for _, peer := range endpoints {
			require.NoError(t, a.SetPeerPathPolicy(t.Context(), peer, &policy))
			check, err := a.CheckPeerPath(t.Context(), peer, TunnelPath{})
			require.NoError(t, err)
			require.Equal(t, relayID, check.Received.Relay)
		}
		h := a.engine.hostMap.QueryVpnAddr(relayID)
		tr[0].network.blockBoth(tr[0].addr, tr[2].addr)
		// Both endpoints have a real established mapping. Time out their probes
		// together, then inspect the single shared direct-adjacency state.
		for round := range 3 {
			var requests []*pathProbe
			for _, peer := range endpoints {
				target := a.engine.hostMap.QueryVpnAddr(peer)
				route, err := a.resolveProbeRoute(target, TunnelPath{Relay: relayID})
				if err != nil {
					continue
				}
				p, err := a.startProbe(target, route, true)
				require.NoError(t, err)
				requests = append(requests, p)
			}
			for _, p := range requests {
				<-p.done
			}
			if round == 0 {
				require.NotEmpty(t, requests)
			}
		}
		require.Eventually(t, func() bool { return h.paths.failedDirect(tr[2].addr, a.engine.paths.selection.FailureThreshold) }, 6*time.Second, 100*time.Millisecond)
		for _, peer := range endpoints {
			require.Nil(t, a.handshake.queryVpnIp(peer))
			require.False(t, a.engine.currentRoute(a.engine.hostMap.QueryVpnAddr(peer)).Endpoint.IsValid())
		}
		tr[0].network.mu.Lock()
		clear(tr[0].network.blocked)
		tr[0].network.mu.Unlock()
		for _, peer := range endpoints {
			require.Eventually(t, func() bool {
				check, err := a.CheckPeerPath(t.Context(), peer, TunnelPath{})
				return err == nil && check.Received.Relay == relayID
			}, 90*time.Second, time.Second)
		}
	})
}

func TestConfiguredPathSelection(t *testing.T) {
	opts := PathOptions{Selection: PathSelectionOptions{
		SwitchThreshold: 2, FailureThreshold: 2, SampleWindow: 2,
		HoldTime: time.Second, Freshness: 2 * time.Second,
		MinBackoff: 2 * time.Second, MaxBackoff: 5 * time.Second,
	}}
	require.NoError(t, opts.normalizeTuning())
	direct := tunnelRoute{TunnelPath: TunnelPath{Endpoint: netip.MustParseAddrPort("192.0.2.1:1")}}
	backup := tunnelRoute{TunnelPath: TunnelPath{Endpoint: netip.MustParseAddrPort("192.0.2.2:2")}}
	now := time.Unix(100, 0)
	var paths sessionPaths
	paths.setHandshakeRoute(direct, now, time.Second)
	observe := func(r tunnelRoute, delay time.Duration, err error) {
		paths.record(r, PathCheckResult{At: now, SamePath: true, RTT: delay, Err: err}, &opts.Selection)
	}
	observe(direct, 200*time.Millisecond, nil)
	for i := range 2 {
		now = now.Add(time.Second)
		observe(backup, 20*time.Millisecond, nil)
		if i == 0 {
			require.Equal(t, direct, paths.active)
		}
	}
	require.Equal(t, backup, paths.active)
	// Refresh the standby immediately before failing the primary twice.
	observe(direct, 200*time.Millisecond, nil)
	observe(backup, 0, ErrPathTimeout)
	require.Equal(t, backup, paths.active)
	observe(backup, 0, ErrPathTimeout)
	require.Equal(t, direct, paths.active)
	q := paths.samples[backup]
	require.Equal(t, 2, q.Samples)
	require.Equal(t, 2, q.Timeouts)
	for _, backoff := range []time.Duration{2 * time.Second, 4 * time.Second, 5 * time.Second} {
		require.Equal(t, now.Add(backoff), q.RetryAfter)
		observe(backup, 0, ErrPathTimeout)
	}
	observe(backup, time.Millisecond, nil)
	require.Equal(t, 1, q.Timeouts)
	require.True(t, q.RetryAfter.IsZero())
}

func TestInvalidPathTuning(t *testing.T) {
	pool, id, _ := newNodeTestIdentities(t)
	for _, paths := range []PathOptions{
		{Probes: PathProbeOptions{MinTimeout: 2 * time.Second, MaxTimeout: time.Second}},
		{Selection: PathSelectionOptions{MinBackoff: time.Minute, MaxBackoff: time.Second}},
		{Selection: PathSelectionOptions{SampleWindow: 65}},
		{Selection: PathSelectionOptions{ImprovementPercent: 101}},
		{Probes: PathProbeOptions{ControlBudget: PacketBudget{Every: time.Duration(math.MaxInt64), Burst: 2}}},
	} {
		tr := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:34001"))[0]
		_, err := New(t.Context(), Options{Identities: []Identity{id.identity}, CAPool: pool, Transport: tr, Paths: paths})
		require.Error(t, err)
		require.NoError(t, tr.Close())
	}
}

func TestManualPathProbeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, _ := pathTestMeshWithOptions(t, 2, Options{Paths: PathOptions{
			Probes: PathProbeOptions{ProbeBudget: PacketBudget{Burst: 1, Every: 200 * time.Millisecond}},
		}})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		first, err := nodes[0].CheckPeerPath(ctx, ids[1].addr, TunnelPath{})
		require.NoError(t, err)
		second, err := nodes[0].CheckPeerPath(ctx, ids[1].addr, TunnelPath{})
		require.NoError(t, err)
		require.Equal(t, 200*time.Millisecond, second.At.Sub(first.At))
	})
}

func TestConfiguredPathChecksAndRelayExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nodes, ids, tr := pathTestMeshWithOptions(t, 2, Options{
			Paths: PathOptions{Probes: PathProbeOptions{
				TickInterval: 5 * time.Millisecond, SweepInterval: 50 * time.Millisecond,
				ActiveInterval: 200 * time.Millisecond, MinTimeout: 50 * time.Millisecond, MaxTimeout: 50 * time.Millisecond,
			}},
			Relay: RelayOptions{MaxMappings: 1, PendingTimeout: 100 * time.Millisecond},
		})
		n := nodes[0]
		require.NoError(t, n.ConnectPeer(t.Context(), ids[1].addr))
		require.Eventually(t, func() bool {
			p, ok := n.Peer(ids[1].addr)
			return ok && p.PathHealth.Active.Samples > 0
		}, 400*time.Millisecond, 10*time.Millisecond)

		hm := n.engine.hostMap
		h := hm.QueryVpnAddr(ids[1].addr)
		target := ids[1].addr.Next()
		_, err := hm.getOrAddRelay(h, target, 0, relayTypeTerminal, relayRequested)
		require.NoError(t, err)
		require.Equal(t, RelayStats{UsedMappings: 1, MaxMappings: 1}, n.RelayStats())
		_, err = hm.getOrAddRelay(h, target.Next(), 0, relayTypeTerminal, relayRequested)
		require.ErrorContains(t, err, "relay capacity reached")
		time.Sleep(160 * time.Millisecond)
		synctest.Wait()
		require.Equal(t, RelayStats{MaxMappings: 1}, n.RelayStats())
		_, err = hm.getOrAddRelay(h, target.Next(), 0, relayTypeTerminal, relayRequested)
		require.NoError(t, err)

		tr[0].network.blockBoth(tr[0].addr, tr[1].addr)
		start := time.Now()
		_, err = n.CheckPeerPath(t.Context(), ids[1].addr, TunnelPath{})
		require.ErrorIs(t, err, ErrPathTimeout)
		require.Less(t, time.Since(start), 100*time.Millisecond)
	})
}
