package nebula

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
	"code.d7z.net/d7z-team/nebula/portshare"

	"github.com/stretchr/testify/require"
)

func TestSessionReceiveLimit(t *testing.T) {
	for _, kind := range []string{"tcp", "udp", "relay"} {
		t.Run(kind, func(t *testing.T) {
			var f *fixture
			if kind == "relay" {
				f = newFixture(t, "tcp", "both", "udp")
				f.link(0, 1)
				f.link(1, 2)
				f.cfg.Members[1].Transit = true
				f.cfg.Members[0].Restricted = true
			} else {
				f = newFixture(t, kind, kind)
			}
			last := len(f.opts) - 1
			f.opts[0].MaxIPSize, f.opts[last].MaxIPSize = 1500, 1280
			f.start()
			a, b := f.nodes[0], f.nodes[last]
			received := make(chan []byte, 2)
			_, err := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, p []byte) { received <- p }})
			require.NoError(t, err)
			results := make(chan TransmitResult, 2)
			out, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}, ObserveTransmit: func(r TransmitResult) { results <- r }})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, a.ConnectPeer(ctx, b.id.IPv4()))
			require.Equal(t, 1280, a.RecommendedMTU(b.id, true, 1500))
			require.True(t, slices.ContainsFunc(a.Paths(), func(s PathStatus) bool { return s.Peer == b.id && s.Transport == kind && s.RemoteIPLimit == 1280 }))
			small := testIPv6(a.id.IPv6(), b.id.IPv6(), 1280)
			require.NoError(t, out.WriteIP(b.id, testIPv6(a.id.IPv6(), b.id.IPv6(), 1500)))
			require.NoError(t, out.WriteIP(b.id, small))
			select {
			case p := <-received:
				require.Equal(t, small, p)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.Eventually(t, func() bool { return len(results) == 2 }, time.Second, time.Millisecond)
			oversized := <-results
			require.ErrorIs(t, oversized.Err, ErrPacketTooLarge)
			require.Equal(t, kind, oversized.Transport)
			require.NoError(t, (<-results).Err)
			require.EqualValues(t, 1, out.Stats().RejectedOutbound)
		})
	}
}

func TestRelaySearchContinuesAcrossDials(t *testing.T) {
	f := newFixture(t, slices.Repeat([]string{"tcp"}, 12)...)
	last := len(f.opts) - 1
	f.link(0, 1)
	for i := 2; i < last; i++ {
		f.link(1, i)
		f.link(i, last)
	}
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
		f.cfg.Members[i].Restricted = true
		f.cfg.Members[i].Transit = i > 0 && i < last
	}
	f.start()
	a, r, b := f.nodes[0], f.nodes[1], f.nodes[last]
	for i := 2; i < last-1; i++ {
		require.NoError(t, r.SetPeerPathPolicy(f.ips[i], Blocked))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.ErrorIs(t, a.ConnectPeer(ctx, b.id.IPv4()), ErrPeerUnavailable)
	require.NoError(t, a.ConnectPeer(ctx, b.id.IPv4()))
	want := []PeerID{a.id, r.id, f.nodes[last-1].id, b.id}
	require.True(t, slices.ContainsFunc(a.Paths(), func(s PathStatus) bool { return s.Peer == b.id && slices.Equal(s.Circuit, want) }))
}

func TestIntroductionLookupAndAuthorization(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp", "tcp", "tcp")
	until := time.Now().Add(20 * time.Second)
	var cutoff atomic.Int64
	cutoff.Store(until.UnixNano())
	f.opts[0].CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if c.Usage == x509.ExtKeyUsageCodeSigning && !c.Local {
			return time.Unix(0, cutoff.Load()), nil
		}
		return time.Time{}, nil
	}
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
	}
	f.start()
	hub := f.nodes[0]
	for _, n := range f.nodes[1:] {
		require.NoError(t, hub.ConnectPeer(t.Context(), n.id.IPv4()))
	}
	for _, peer := range f.nodes[1:] {
		require.True(t, hub.lookup(t.Context(), peer.id))
		hub.mu.Lock()
		learned := hub.discovered[peer.id]
		hub.mu.Unlock()
		require.True(t, learned.authorizedUntil.Equal(until))
		require.True(t, learned.Expires.After(until))
		seen := hub.advert(&session{peer: peer.id}).Seen
		s := &session{peer: hub.id}
		s.acknowledgedIntro.Store(seen)
		require.Empty(t, peer.advert(s).Record)
	}
	peer := f.nodes[1]
	cutoff.Store(time.Now().Add(150 * time.Millisecond).UnixNano())
	_, ok := hub.learn(peer.signedIntroduction(peer.policy.Load(), 0))
	require.True(t, ok)
	require.Eventually(t, func() bool {
		hub.prunePaths()
		hub.mu.Lock()
		defer hub.mu.Unlock()
		_, known := hub.discovered[peer.id]
		_, indexed := hub.introduced[f.cfg.Members[1].Endpoints[0]][peer.id]
		return !known && !indexed
	}, time.Second, 10*time.Millisecond)
}

func TestCanaryAndTransmitHysteresis(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	backup, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { backup.Close() })
	vip := netip.MustParseAddr("10.13.0.200")
	f.cfg.Members[1].AnycastIPs = []netip.Addr{vip}
	ep := Endpoint{"tcp", addrPort(backup.Addr())}
	f.cfg.Members[1].Endpoints = append(f.cfg.Members[1].Endpoints, ep)
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
	renewed := f.issue(b.id, pki.Scope{AnycastIPs: []netip.Addr{vip}})
	require.NoError(t, b.ReloadCertificates(t.Context(), LocalCertificates{Client: renewed}))
	// A second physical listener forwards authenticated connections to the same node.
	go func() {
		c, err := backup.Accept()
		if err == nil {
			b.attachTLS(b.ctx, c, PeerID{}, nil, false, nil)
		}
	}()
	primary := a.preferredSession(b.id, false)
	a.mu.Lock()
	a.peers[b.id].lastCanary = time.Time{}
	a.mu.Unlock()
	a.probeAlternatePaths(primary, 0)
	a.mu.Lock()
	sessions := slices.Clone(a.peers[b.id].sessions)
	a.mu.Unlock()
	require.Len(t, sessions, 2)
	require.Equal(t, ep.Address, sessions[1].endpoint)

	sent := make(chan TransmitResult, 1)
	port, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}, ObserveTransmit: func(r TransmitResult) { sent <- r }})
	require.NoError(t, err)
	setRTTs := func(primary, backup time.Duration) {
		for i, rtt := range []time.Duration{primary, backup} {
			s := sessions[i]
			s.healthMu.Lock()
			s.rtt = rtt * time.Millisecond
			s.jitter = 0
			s.healthMu.Unlock()
		}
	}
	send := func(dst netip.Addr) netip.AddrPort {
		t.Helper()
		require.NoError(t, port.WriteIP(b.id, testIPv4(a.id.IPv4(), dst, "data")))
		select {
		case r := <-sent:
			require.NoError(t, r.Err)
			return r.Endpoint
		case <-time.After(time.Second):
			t.Fatal("no transmit result")
			return netip.AddrPort{}
		}
	}
	setRTTs(10, 11)
	require.Equal(t, primary.endpoint, send(b.id.IPv4()))
	require.Equal(t, ep.Address, send(vip))

	// The backup temporarily scores best while the application checks connectivity.
	setRTTs(100, 10)
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
	status := a.Paths()
	require.Len(t, status, 2)
	require.True(t, status[0].Active)
	require.Equal(t, ep.Address, status[0].Endpoint)
	require.Equal(t, 1280, a.RecommendedMTU(b.id, true, 1280))
	setRTTs(11, 10)
	require.Equal(t, primary.endpoint, send(b.id.IPv4()))
	setRTTs(100, 10)
	require.Equal(t, ep.Address, send(b.id.IPv4()))
}

func TestMaintenanceReachesLaterNeighbors(t *testing.T) {
	f := newFixture(t, slices.Repeat([]string{"tcp"}, 19)...)
	last := len(f.opts) - 1
	first, late := f.opts[1].TCP4.Addr().String(), f.opts[last].TCP4.Addr().String()
	f.opts[0].DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == first || address == late {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var live []*Node
	for _, i := range []int{0, 1, last} {
		o := f.opts[i]
		o.Topology = f.cfg
		o.Interval = 25 * time.Millisecond
		o.DialTimeout = 150 * time.Millisecond
		n, err := New(t.Context(), o)
		require.NoError(t, err)
		t.Cleanup(func() { n.Close() })
		require.NoError(t, n.Start())
		live = append(live, n)
	}
	a := live[0]
	require.NoError(t, a.ConnectPeer(t.Context(), live[1].id.IPv4()))
	for i := 1; i <= last; i++ {
		f.link(0, i)
	}
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool {
		var healthy, joined bool
		for _, p := range a.Paths() {
			healthy = healthy || p.Peer == live[1].id && p.RTT > 0
			joined = joined || p.Peer == live[2].id && p.RTT > 0
		}
		return healthy && joined
	}, 4*time.Second, 10*time.Millisecond)
}

type interruptedListener struct {
	net.Listener
	calls int
	stop  chan struct{}
	fatal error
}

func (l *interruptedListener) Accept() (net.Conn, error) {
	l.calls++
	switch l.calls {
	case 1:
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.ErrDeadlineExceeded}
	case 2:
		return l.Listener.Accept()
	default:
		<-l.stop
		return nil, l.fatal
	}
}

func TestTCPListenerRecoveryAndFailure(t *testing.T) {
	for _, kind := range []string{"dedicated", "shared"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, "tcp", "tcp")
			l := &interruptedListener{Listener: f.opts[1].TCP4, stop: make(chan struct{}), fatal: errors.New("listener unavailable")}
			stop := sync.OnceFunc(func() { close(l.stop) })
			defer stop()
			f.opts[1].TCP4 = l
			var shared *portshare.TCP
			if kind == "shared" {
				shared = portshare.NewTCP(l)
				t.Cleanup(func() { shared.Close() })
				f.opts[1].TCP4 = shared.Mesh()
			}
			f.start()
			a, b := f.nodes[0], f.nodes[1]
			require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
			stop()
			require.Eventually(t, func() bool { return b.ControlStatus().ListenerErrors["tcp4"] == l.fatal.Error() }, time.Second, time.Millisecond)
			require.True(t, b.ControlStatus().Ready)
			if shared != nil {
				_, err := shared.Other().Accept()
				require.ErrorIs(t, err, l.fatal)
			}
		})
	}
}

func TestCloseDuringReceiveLimitExchange(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.opts[1].DialTimeout = time.Minute
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	d := tls.Dialer{Config: a.tlsConfig(b.id, false)}
	c, err := d.DialContext(t.Context(), "tcp", f.opts[1].TCP4.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	// Send only the first byte of the two-byte client preface.
	_, err = c.Write([]byte{5})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- b.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("closing node waited for the receive limit deadline")
	}
}
