package nebula

import (
	"context"
	"flag"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	relayScale     = flag.Bool("relay-scale", false, "exercise normal maintenance and traffic with 208 access nodes")
	backboneWeight = flag.Uint("backbone-weight", 8, "ingress service weight for the return trunk at each scale-test access relay")
	relayFlight    = flag.Int("relay-flight", 1, "outstanding 8 KiB packets per source in the relay scale test")
)

// A bounded delivery window keeps the producers busy without including
// IPPort queue overflow or an unbounded test sender in the measurement.
type trafficFlow struct {
	source, target *Node
	inflight       chan struct{}
	received       atomic.Uint64
	start, stop    <-chan struct{}
}

func startRelayTraffic(t *testing.T, flows []*trafficFlow, outstanding int) {
	t.Helper()
	byPair := make(map[[2]PeerID]*trafficFlow)
	ports := make(map[*Node]*IPPort)
	for _, flow := range flows {
		flow.inflight = make(chan struct{}, outstanding)
		byPair[[2]PeerID{flow.source.id, flow.target.id}] = flow
	}
	for _, flow := range flows {
		for _, n := range []*Node{flow.source, flow.target} {
			if ports[n] != nil {
				continue
			}
			p, err := n.OpenIPPort(IPPortOptions{Deliver: func(from PeerID, b []byte) {
				flow := byPair[[2]PeerID{from, n.id}]
				flow.received.Add(uint64(len(b)))
				<-flow.inflight
			}})
			require.NoError(t, err)
			ports[n] = p
		}
	}
	ctx := t.Context()
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	for _, flow := range flows {
		wg.Go(func() {
			if flow.start != nil {
				select {
				case <-flow.start:
				case <-ctx.Done():
					return
				}
			}
			packet := testIPv4(flow.source.Addresses().IPv4, flow.target.Addresses().IPv4, strings.Repeat("t", 8192-20))
			for {
				select {
				case <-ctx.Done():
					return
				case <-flow.stop:
					return
				case flow.inflight <- struct{}{}:
				}
				if err := ports[flow.source].WriteIP(flow.target.id, packet); err != nil {
					<-flow.inflight
					if ctx.Err() == nil {
						t.Errorf("send to %v: %v", flow.target.id, err)
					}
					return
				}
			}
		})
	}
}

func TestRelayFairness(t *testing.T) {
	for _, tc := range []struct {
		name, network string
		weightA       uint16
	}{
		{"tcp", "tcp", 1}, {"quic", "udp", 1}, {"weighted", "tcp", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const rate = 1 << 20
			f := newFixture(t, slices.Repeat([]string{tc.network}, 12)...)
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
				f.opts[i].DialTimeout = 4 * time.Second
			}
			f.cfg.Members[0].BytesPerSecond = rate
			if tc.weightA != 1 {
				f.opts[0].RelayWeights = map[PeerID]uint16{f.cfg.Members[2].ID: tc.weightA}
			}
			startBackbone(t, f, 1, 2)
			a, b := f.nodes[2], f.nodes[3]
			var heavyFlows []*trafficFlow
			for _, dst := range f.nodes[4:] {
				require.NoError(t, a.ConnectPeerID(t.Context(), dst.id))
				heavyFlows = append(heavyFlows, &trafficFlow{source: a, target: dst})
			}
			dst := f.nodes[4]
			require.NoError(t, b.ConnectPeerID(t.Context(), dst.id))
			startB, stopB := make(chan struct{}), make(chan struct{})
			lightFlow := &trafficFlow{source: b, target: dst, start: startB, stop: stopB}
			startRelayTraffic(t, append(heavyFlows, lightFlow), 8)
			totals := func() (a, b uint64) {
				for _, flow := range heavyFlows {
					a += flow.received.Load()
				}
				return a, lightFlow.received.Load()
			}
			require.Eventually(t, func() bool { a, _ := totals(); return a > 256<<10 }, 4*time.Second, 10*time.Millisecond)
			first, _ := totals()
			baselineStart := time.Now()
			time.Sleep(time.Second)
			last, _ := totals()
			baseline := float64(last-first) / time.Since(baselineStart).Seconds()
			close(startB)
			require.Eventually(t, func() bool { return lightFlow.received.Load() > 128<<10 }, 5*time.Second, 10*time.Millisecond)
			a0, b0 := totals()
			ping := b.preferredSession(dst.id, false)
			var samples []time.Duration
			for range 20 {
				at := time.Now()
				reply, err := ping.request(t.Context(), opPing, []byte("ping"), 4)
				require.NoError(t, err)
				require.Equal(t, []byte("ping"), reply)
				samples = append(samples, time.Since(at))
				time.Sleep(35 * time.Millisecond)
			}
			a1, b1 := totals()
			large, small := a1-a0, b1-b0
			share := float64(small) / float64(small+large)
			slices.Sort(samples)
			t.Logf("delivered A/B %d/%d bytes, B share %.2f, short-request p95 %v", large, small, share, samples[18])
			require.InDelta(t, 1/(1+float64(tc.weightA)), share, 0.10)
			close(stopB)
			require.Eventually(t, func() bool { return len(lightFlow.inflight) == 0 }, 3*time.Second, 10*time.Millisecond)
			a0, _ = totals()
			at := time.Now()
			time.Sleep(1500 * time.Millisecond)
			a1, _ = totals()
			utilization := float64(a1-a0) / time.Since(at).Seconds() / rate
			t.Logf("single remaining source %.1f%% of configured rate", 100*utilization)
			// Buffered deliveries may straddle the baseline window. Sustained
			// throughput is also capped by the configured token rate.
			require.Greater(t, utilization*rate, 0.80*min(baseline, float64(rate)))
			require.Greater(t, baseline, 0.70*rate)
		})
	}
}

func TestRelaySlowExit(t *testing.T) {
	f := newFixture(t, "", "", "", "", "")
	for _, i := range []int{0, 2, 3, 4} {
		f.link(1, i)
	}
	f.cfg.Members[1].Transit = true
	f.start()
	n := f.nodes[1]
	// Fill the full write window through one exit without reading from it.
	forward := func(from, to int) (net.Conn, net.Conn) {
		l := &circuitLease{n: n, path: []PeerID{f.nodes[from].id, n.id, f.nodes[to].id}, inbound: f.nodes[from].id, transit: true}
		in, src := net.Pipe()
		dst, out := net.Pipe()
		l.ends = []net.Conn{src, dst}
		require.True(t, l.reserve())
		direction := relayDirection{l.inbound, f.nodes[to].id}
		n.wg.Go(func() { l.forward(dst, src, direction) })
		t.Cleanup(func() { _ = in.Close(); _ = out.Close(); l.close() })
		return in, out
	}
	for range peerWriteBlocks + 1 {
		in, _ := forward(0, 2)
		_, err := in.Write([]byte("slow"))
		require.NoError(t, err)
	}
	d := relayDirection{f.nodes[0].id, f.nodes[2].id}
	require.Eventually(t, func() bool {
		n.shaper.mu.Lock()
		defer n.shaper.mu.Unlock()
		w := n.shaper.windows[d]
		return w != nil && len(w.slots) == peerWriteBlocks
	}, time.Second, time.Millisecond)
	// Both another ingress on the same exit and another exit on the same ingress progress.
	for _, pair := range [][2]int{{3, 2}, {0, 4}} {
		in, out := forward(pair[0], pair[1])
		_, err := in.Write([]byte("x"))
		require.NoError(t, err)
		require.NoError(t, out.SetReadDeadline(time.Now().Add(time.Second)))
		var b [1]byte
		_, err = out.Read(b[:])
		require.NoError(t, err)
		require.Equal(t, byte('x'), b[0])
	}
	f.cfg.Members[1].Transit = false
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool {
		n.shaper.mu.Lock()
		defer n.shaper.mu.Unlock()
		return len(n.shaper.windows) == 0 && len(n.shaper.peers) == 0
	}, time.Second, time.Millisecond)
}

func TestRelayScale(t *testing.T) {
	if !*relayScale {
		t.Skip("enable with -relay-scale")
	}
	require.LessOrEqual(t, *backboneWeight, uint(65535))
	require.Positive(t, *relayFlight)
	const sources, targets = 208, 4
	for _, network := range []string{"tcp", "udp"} {
		for _, trunks := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d", network, trunks), func(t *testing.T) {
				f := newFixture(t, slices.Repeat([]string{network}, trunks+1+sources+targets)...)
				for i := range f.opts {
					f.opts[i].MaintenanceInterval = 0
					f.opts[i].DialTimeout = 0
					if i < trunks {
						f.opts[i].RelayWeights = map[PeerID]uint16{f.cfg.Members[trunks].ID: uint16(*backboneWeight)}
					}
					if i <= trunks {
						f.opts[i].MaxCircuits = 1024
						f.cfg.Members[i].BytesPerSecond = 8 << 20
					}
				}
				startBackbone(t, f, trunks, sources)
				base := trunks + 1
				var sessions []*session
				var flows []*trafficFlow
				for i, src := range f.nodes[base : base+sources] {
					for j, dst := range f.nodes[base+sources:] {
						require.NoError(t, src.ConnectPeerID(t.Context(), dst.id))
						s := src.preferredSession(dst.id, false)
						require.NotNil(t, s)
						sessions = append(sessions, s)
						if j == i%targets {
							flows = append(flows, &trafficFlow{source: src, target: dst})
						}
					}
				}
				for _, n := range f.nodes[:trunks] {
					used := n.RelayStatus().TransitCircuits
					require.Positive(t, used)
					t.Log("trunk circuits", used)
				}
				require.Equal(t, sources*targets, f.nodes[trunks].RelayStatus().TransitCircuits)
				startRelayTraffic(t, flows, *relayFlight)
				measureRelayLoad(t, sessions, flows)
			})
		}
	}
}

// Sample live end-to-end sessions throughout eight seconds of sustained load.
// Each request owns its sample slot until the wait group completes.
func measureRelayLoad(t *testing.T, sessions []*session, flows []*trafficFlow) {
	t.Helper()
	var heapPeak uint64
	var longestProbeGap time.Duration
	lastProbe := make([]time.Time, len(sessions))
	pings := make([]time.Duration, 64)
	var missed atomic.Int32
	var probes sync.WaitGroup
	at := time.Now()
	for i := range pings {
		s := sessions[(i*53)%len(sessions)]
		probes.Go(func() {
			begin := time.Now()
			budget := s.n.o.DialTimeout
			ctx, cancel := context.WithDeadline(t.Context(), begin.Add(budget))
			defer cancel()
			reply, err := s.request(ctx, opPing, []byte("ping"), 4)
			pings[i] = time.Since(begin)
			if err != nil || string(reply) != "ping" || pings[i] > budget {
				missed.Add(1)
			}
		})
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		heapPeak = max(heapPeak, m.HeapAlloc)
		for j, s := range sessions {
			s.n.mu.Lock()
			when := s.lastProbe
			s.n.mu.Unlock()
			if !lastProbe[j].IsZero() {
				longestProbeGap = max(longestProbeGap, when.Sub(lastProbe[j]))
			}
			longestProbeGap = max(longestProbeGap, time.Since(when))
			lastProbe[j] = when
		}
		time.Sleep(125 * time.Millisecond)
	}
	probes.Wait()
	t.Logf("short requests completed %d/%d within deadline", len(pings)-int(missed.Load()), len(pings))
	elapsed := time.Since(at)
	closed := 0
	for _, s := range sessions {
		if s.closed.Load() {
			s.healthMu.Lock()
			t.Logf("closed circuit %s -> %s failures %d rtt %s", s.n.id, s.peer, s.failures, s.rtt)
			s.healthMu.Unlock()
			closed++
		}
	}
	var bytes []uint64
	var total uint64
	for _, flow := range flows {
		n := flow.received.Load()
		bytes = append(bytes, n)
		total += n
	}
	slices.Sort(bytes)
	slices.Sort(pings)
	t.Logf("%d sources, delivery %.2f MiB/s, source bytes min/median/max %d/%d/%d, ping p95 %v, max observed probe gap/age %v, sampled process heap peak %.1f MiB, unexpected circuit closes %d", len(flows), float64(total)/(1<<20)/elapsed.Seconds(), bytes[0], bytes[len(bytes)/2], bytes[len(bytes)-1], pings[(len(pings)*95+99)/100-1], longestProbeGap, float64(heapPeak)/(1<<20), closed)
	require.Zero(t, closed)
	require.Positive(t, bytes[0])
	if *relayFlight == 1 && *backboneWeight == 8 {
		require.Zero(t, missed.Load())
	} else {
		require.Less(t, int(missed.Load()), len(pings))
	}
}
