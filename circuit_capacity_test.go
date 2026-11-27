package nebula

import (
	"context"
	"crypto/x509"
	"flag"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var fullRelayCapacity = flag.Bool("full-relay-capacity", false, "exercise 512 authenticated circuits across one physical adjacency")

func TestCircuitWithdrawalWhileOpening(t *testing.T) {
	f := newFixture(t, "", "tcp", "tcp")
	f.link(0, 1)
	f.link(1, 2)
	f.cfg.Members[1].Transit = true
	// The target listens on TCP but never completes the downstream handshake.
	f.opts = f.opts[:2]
	for i := range f.opts {
		f.opts[i].DialTimeout = 5 * time.Second
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.start()
	src, relay, target := f.nodes[0], f.nodes[1], f.cfg.Members[2].ID
	require.NoError(t, src.SetPeerPathPolicy(target, RelayOnly))
	done := make(chan error, 1)
	go func() { done <- src.ConnectPeerID(t.Context(), target) }()
	require.Eventually(t, func() bool { return relay.RelayStatus().TransitCircuits == 1 }, 2*time.Second, time.Millisecond)
	neighbor := src.preferredSession(relay.id, true)
	require.NotNil(t, neighbor)
	require.NoError(t, src.SetPeerPathPolicy(target, Blocked))
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrPathPolicy)
	case <-time.After(time.Second):
		t.Fatal("withdrawn circuit still waiting for the relay's ready reply")
	}
	require.Zero(t, src.ControlStatus().Circuits)
	reply, err := neighbor.request(t.Context(), opPing, []byte("ping"), 4)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), reply)
}

// startBackbone builds one or two distinct first hops into a shared hub.
// Source nodes follow the relays in the fixture; service nodes come last.
func startBackbone(t *testing.T, f *fixture, trunks, sources int) {
	t.Helper()
	f.start()
	link := func(a, b int) {
		_, err := f.nodes[a].ConnectEndpoint(t.Context(), f.cfg.Members[b].Endpoints[0])
		require.NoError(t, err)
		f.link(a, b)
	}
	for i := range trunks {
		link(i, trunks)
		for j := range sources {
			link(i, trunks+1+j)
		}
	}
	for j := trunks + 1 + sources; j < len(f.nodes); j++ {
		link(trunks, j)
	}
	for i := range f.cfg.Members {
		f.cfg.Members[i].Restricted = true
		f.cfg.Members[i].Transit = i <= trunks
	}
	for _, n := range f.nodes {
		require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	}
}

func TestRelayCapacity(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			sources, targets := 8, 9 // Cross the 64 inbound request slots in ordinary CI.
			if *fullRelayCapacity {
				sources, targets = 16, 32
			}
			f := newFixture(t, slices.Repeat([]string{network}, 2+sources+targets)...)
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
				f.opts[i].DialTimeout = 4 * time.Second
			}
			startBackbone(t, f, 1, sources)
			left, right := f.nodes[0], f.nodes[1]
			for i, source := range f.nodes[2 : 2+sources] {
				for j, target := range f.nodes[2+sources:] {
					require.NoError(t, source.ConnectPeerID(t.Context(), target.id), "circuit %d of %d", i*targets+j+1, sources*targets)
				}
			}
			require.Equal(t, sources*targets, left.ControlStatus().Circuits)
			require.Equal(t, sources*targets, right.ControlStatus().Circuits)
			paths := slices.DeleteFunc(left.Paths(), func(p PathStatus) bool { return p.Peer != right.id })
			require.Len(t, paths, 1)
			require.Equal(t, network, paths[0].Transport)
			if *fullRelayCapacity {
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				t.Logf("all %d nodes at capacity: %.1f MiB live Go heap", len(f.nodes), float64(m.HeapAlloc)/(1<<20))
			}
			s := left.preferredSession(right.id, true)
			at := time.Now()
			reply, err := s.request(t.Context(), opPing, []byte("ping"), 4)
			require.NoError(t, err)
			require.Equal(t, []byte("ping"), reply)
			t.Log("backbone ping", time.Since(at))
			// Ask across the backbone for a target outside the left relay's cache.
			a, b := f.nodes[2], f.nodes[len(f.nodes)-1]
			require.Empty(t, left.ipMatches(b.Addresses().IPv4, nil))
			at = time.Now()
			hits, err := left.ResolveIP(t.Context(), b.Addresses().IPv4)
			require.NoError(t, err)
			require.Len(t, hits, 1)
			require.Equal(t, b.id, hits[0].Peer)
			t.Log("uncached lookup", time.Since(at))
			ends := [2]*Node{a, b}
			in := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
			var ports [2]*IPPort
			for i, n := range ends {
				ports[i], err = n.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, packet []byte) { in[i] <- packet }})
				require.NoError(t, err)
			}
			for i, src := range ends {
				dst := ends[1-i]
				packet := testIPv4(src.Addresses().IPv4, dst.Addresses().IPv4, "round trip")
				require.NoError(t, ports[i].WriteIP(dst.id, packet))
				select {
				case got := <-in[1-i]:
					require.Equal(t, packet, got)
				case <-time.After(4 * time.Second):
					t.Fatal("IP delivery timed out")
				}
			}
			f.cfg.Members[1].Transit = false
			require.NoError(t, right.ApplyTopology(t.Context(), f.cfg))
			require.Eventually(t, func() bool {
				for _, n := range f.nodes {
					if n.ControlStatus().Circuits != 0 {
						return false
					}
				}
				return true
			}, 5*time.Second, 10*time.Millisecond)
			require.True(t, left.usable(s))
		})
	}
}

func TestInboundCircuitLimits(t *testing.T) {
	f := newFixture(t, slices.Repeat([]string{"tcp"}, 6)...)
	// A and B share a hub with two service peers across one backbone.
	aID := f.cfg.Members[2].ID
	overrides := map[PeerID]int{aID: 1}
	f.opts[0].MaxCircuits = 3
	f.opts[0].InboundCircuitLimits = InboundCircuitLimits{Default: 2, ByPeer: overrides}
	f.opts[1].InboundCircuitLimits = InboundCircuitLimits{Default: 1, ByPeer: map[PeerID]int{f.cfg.Members[0].ID: 0}}
	f.opts[5].InboundCircuitLimits.Default = 1
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	startBackbone(t, f, 1, 2)
	overrides[aID] = 2
	left, a, b, x, y := f.nodes[0], f.nodes[2], f.nodes[3], f.nodes[4], f.nodes[5]
	require.NoError(t, a.ConnectPeerID(t.Context(), x.id))
	require.Error(t, a.ConnectPeerID(t.Context(), y.id))
	require.Positive(t, left.RelayStatus().RejectedPeerLimit)
	require.NoError(t, b.ConnectPeerID(t.Context(), x.id))
	require.NoError(t, b.ConnectPeerID(t.Context(), y.id))
	status := left.RelayStatus()
	require.Equal(t, 3, status.TransitCircuits)
	require.Equal(t, map[PeerID]int{a.id: 1, b.id: 2}, status.InboundCircuits)
	require.Error(t, a.ConnectPeerID(t.Context(), y.id))
	require.Positive(t, left.RelayStatus().RejectedCapacity)
	require.NoError(t, a.SetPeerPathPolicy(x.id, Blocked))
	require.Eventually(t, func() bool { return left.RelayStatus().InboundCircuits[a.id] == 0 }, time.Second, time.Millisecond)
	require.Error(t, a.ConnectPeerID(t.Context(), y.id)) // The destination enforces the common hub's ceiling.
	require.Positive(t, y.RelayStatus().RejectedPeerLimit)
	require.NoError(t, b.SetPeerPathPolicy(y.id, Blocked))
	require.Eventually(t, func() bool { return y.ControlStatus().Circuits == 0 }, time.Second, time.Millisecond)
	require.NoError(t, a.ConnectPeerID(t.Context(), y.id))
}

func TestTransitDraining(t *testing.T) {
	f := newFixture(t, slices.Repeat([]string{"tcp"}, 6)...)
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
		f.opts[i].DialTimeout = 4 * time.Second
	}
	checking, resume := make(chan struct{}), make(chan struct{})
	started := sync.OnceFunc(func() { close(checking) })
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	sourceID := f.cfg.Members[3].ID
	f.opts[4].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
		if c.Member == sourceID && c.Purpose == NodeIdentity && c.Usage == x509.ExtKeyUsageClientAuth {
			started()
			select {
			case <-resume:
			case <-ctx.Done():
				return time.Time{}, ctx.Err()
			}
		}
		return time.Time{}, nil
	}
	startBackbone(t, f, 2, 1)
	src, x, y := f.nodes[3], f.nodes[4], f.nodes[5]
	connected := make(chan error, 1)
	go func() { connected <- src.ConnectPeerID(t.Context(), x.id) }()
	select {
	case <-checking:
	case <-time.After(4 * time.Second):
		t.Fatal("endpoint did not receive the reserved circuit")
	}
	primary, backup := f.nodes[0], f.nodes[1]
	if backup.RelayStatus().TransitCircuits > 0 {
		primary, backup = backup, primary
	}
	require.NoError(t, primary.SetTransitDraining(true))
	require.NoError(t, backup.SetTransitDraining(true))
	release()
	require.NoError(t, <-connected)
	old := src.preferredSession(x.id, false)
	require.Equal(t, primary.id, old.path[1])
	require.Error(t, src.ConnectPeerID(t.Context(), y.id))
	require.Positive(t, primary.RelayStatus().RejectedDraining)
	require.Positive(t, backup.RelayStatus().RejectedDraining)
	require.NoError(t, backup.SetTransitDraining(false))
	require.NoError(t, src.ConnectPeerID(t.Context(), y.id))
	require.Equal(t, backup.id, src.preferredSession(y.id, false).path[1])
	_, err := old.request(t.Context(), opPing, []byte("old"), 3)
	require.NoError(t, err)
	// The draining relay continues to accept circuits ending at itself.
	require.NoError(t, x.ConnectPeerID(t.Context(), primary.id))
	require.Equal(t, 1, primary.RelayStatus().TransitCircuits)
	for i := range f.cfg.Members {
		if f.cfg.Members[i].ID == primary.id {
			f.cfg.Members[i].Transit = false
		}
	}
	require.NoError(t, primary.ApplyTopology(t.Context(), f.cfg))
	require.Zero(t, primary.RelayStatus().TransitCircuits)
	require.Eventually(t, func() bool { return old.closed.Load() }, time.Second, time.Millisecond)
}

// Compare the chosen first hop after reversing adjacency order, and exhaust
// the cursor one edge at a time to check resumption and equal-hop rotation.
func TestRelayRouteRotation(t *testing.T) {
	src, left, right := PeerID{1}, PeerID{2}, PeerID{3}
	x, y, dst := PeerID{4}, PeerID{5}, PeerID{6}
	p := topologyView{members: map[PeerID]Member{
		src:   {Links: []PeerID{left, right}},
		left:  {Transit: true, Links: []PeerID{src, x, y}},
		right: {Transit: true, Links: []PeerID{src, x, y}},
		x:     {Transit: true, Links: []PeerID{left, right, dst}},
		y:     {Transit: true, Links: []PeerID{left, right, dst}},
		dst:   {Links: []PeerID{x, y}},
	}}
	distance := p.relayDistances(src, dst)
	var first PeerID
	for pass := range 2 {
		var cursor routeCursor
		var routes [][]PeerID
		for i := 0; i < 100 && len(routes) < 4; i++ {
			work := 1
			if path := cursor.next(&p, src, dst, distance, &work); path != nil {
				routes = append(routes, path)
			}
		}
		require.Len(t, routes, 4)
		require.NotEqual(t, routes[0][1], routes[1][1])
		require.Equal(t, routes[0][1], routes[2][1])
		require.ElementsMatch(t, [][]PeerID{{src, left, x, dst}, {src, right, x, dst}, {src, left, y, dst}, {src, right, y, dst}}, routes)
		if pass == 0 {
			first = routes[0][1]
		} else {
			require.Equal(t, first, routes[0][1])
		}
		for _, m := range p.members {
			slices.Reverse(m.Links)
		}
	}
}

func TestRelaySessionSurvivesRequestTimeout(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	for i := range f.opts {
		f.opts[i].DialTimeout = 400 * time.Millisecond
		f.opts[i].MaintenanceInterval = time.Hour
	}
	startBackbone(t, f, 1, 1)
	src, dst := f.nodes[2], f.nodes[3]
	require.NoError(t, src.ConnectPeerID(t.Context(), dst.id))
	s := src.preferredSession(dst.id, false)
	r := f.nodes[0]
	f.cfg.Members[0].BytesPerSecond = 1
	require.NoError(t, r.ApplyTopology(t.Context(), f.cfg))
	// Spend the initial burst before opening a new end-to-end stream.
	r.shaper.mu.Lock()
	burst := r.shaper.limiter.ReserveN(time.Now(), r.shaper.limiter.Burst())
	r.shaper.mu.Unlock()
	require.True(t, burst.OK())
	_, err := s.request(t.Context(), opPing, []byte("slow"), 4)
	require.Error(t, err)
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, r.ApplyTopology(t.Context(), f.cfg))
	reply, err := s.request(t.Context(), opPing, []byte("live"), 4)
	require.NoError(t, err)
	require.Equal(t, []byte("live"), reply)
}
