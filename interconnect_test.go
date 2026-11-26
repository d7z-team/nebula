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
			require.NoError(t, a.ConnectPeer(ctx, b.Addresses().IPv4))
			require.Equal(t, 1280, a.RecommendedMTU(b.id, true, 1500))
			require.True(t, slices.ContainsFunc(a.Paths(), func(s PathStatus) bool { return s.Peer == b.id && s.Transport == kind && s.RemoteIPLimit == 1280 }))
			small := testIPv6(a.Addresses().IPv6, b.Addresses().IPv6, 1280)
			require.NoError(t, out.WriteIP(b.id, testIPv6(a.Addresses().IPv6, b.Addresses().IPv6, 1500)))
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

func TestRelaySearchSkipsUnreachableTargets(t *testing.T) {
	f := newFixture(t, "", "", "", "")
	f.link(0, 1)
	f.link(2, 3)
	f.cfg.Members[1].Transit = true
	f.cfg.Members[2].Transit = true
	f.start()
	a := f.nodes[0]
	// Neither a member outside the view nor a disconnected component can
	// yield a relay route. Both identities remain eligible for direct discovery.
	unknown := labPeer(netip.MustParseAddr("10.13.0.20"))
	for _, peer := range []PeerID{unknown, f.nodes[3].ID()} {
		require.ErrorIs(t, a.ConnectPeerID(t.Context(), peer), ErrPeerUnavailable)
		a.mu.Lock()
		_, retained := a.routeCursors[peer]
		a.mu.Unlock()
		require.False(t, retained)
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
		f.opts[i].MaintenanceInterval = time.Hour
		f.cfg.Members[i].Restricted = true
		f.cfg.Members[i].Transit = i > 0 && i < last
	}
	f.start()
	a, r, b := f.nodes[0], f.nodes[1], f.nodes[last]
	configured, effective := a.PeerPathPolicy(b.id)
	require.Equal(t, Auto, configured)
	require.Equal(t, RelayOnly, effective)
	for i := 2; i < last-1; i++ {
		require.NoError(t, r.SetPeerPathPolicy(f.nodes[i].id, Blocked))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.ErrorIs(t, a.ConnectPeer(ctx, b.Addresses().IPv4), ErrPeerUnavailable)
	require.NoError(t, a.ConnectPeer(ctx, b.Addresses().IPv4))
	want := []PeerID{a.id, r.id, f.nodes[last-1].id, b.id}
	require.True(t, slices.ContainsFunc(a.Paths(), func(s PathStatus) bool { return s.Peer == b.id && slices.Equal(s.Circuit, want) }))
}

func TestRelaySearchAfterLastCandidate(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.link(0, 1)
	f.link(1, 2)
	f.cfg.Members[1].Transit = true
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	// The only transit node initially declines the canary's one candidate.
	view := f.cfg
	view.Members = slices.Clone(view.Members)
	view.Members[1].Transit = false
	f.opts[1].Topology = view
	f.start()
	a, relay, b := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, a.SetPeerPathPolicy(b.id, RelayOnly))
	require.Error(t, a.dialRelay(t.Context(), b.id, 1))
	require.NoError(t, relay.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, a.ConnectPeerID(t.Context(), b.id))
	path, ok := a.PreferredPath(b.id)
	require.True(t, ok)
	require.Equal(t, []PeerID{a.id, relay.id, b.id}, path.Circuit)
}

func TestIntroductionLookupAndAuthorization(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp", "tcp", "tcp")
	until := time.Now().Add(20 * time.Second)
	var cutoff atomic.Int64
	cutoff.Store(until.UnixNano())
	f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if c.Usage == x509.ExtKeyUsageCodeSigning && !c.Local {
			return time.Unix(0, cutoff.Load()), nil
		}
		return time.Time{}, nil
	}
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.start()
	hub := f.nodes[0]
	for _, n := range f.nodes[1:] {
		require.NoError(t, hub.ConnectPeer(t.Context(), n.Addresses().IPv4))
	}
	for _, peer := range f.nodes[1:] {
		require.True(t, hub.rendezvous(t.Context(), peer.id))
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
	_, ok := hub.learnIntroduction(t.Context(), peer.localIntroduction(peer.policy.Load()).record, nil)
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
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	renewed := f.issue(b.Addresses().IPv4, pki.Scope{AnycastIPs: []netip.Addr{vip}})
	require.NoError(t, b.ReloadCertificates(t.Context(), renewed))
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
		require.NoError(t, port.WriteIP(b.id, testIPv4(a.Addresses().IPv4, dst, "data")))
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
	require.Equal(t, primary.endpoint, send(b.Addresses().IPv4))
	require.Equal(t, ep.Address, send(vip))

	// The backup temporarily scores best while the application checks connectivity.
	setRTTs(100, 10)
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	status := a.Paths()
	require.Len(t, status, 2)
	require.True(t, status[0].Active)
	require.Equal(t, ep.Address, status[0].Endpoint)
	path, ok := a.PreferredPath(b.id)
	require.True(t, ok)
	require.Equal(t, status[0], path)
	require.Equal(t, 1280, a.RecommendedMTU(b.id, true, 1280))
	setRTTs(11, 10)
	require.Equal(t, primary.endpoint, send(b.Addresses().IPv4))
	setRTTs(100, 10)
	require.Equal(t, ep.Address, send(b.Addresses().IPv4))
}

func TestMaintenanceReachesLaterNeighbors(t *testing.T) {
	f := newFixture(t, slices.Repeat([]string{"tcp"}, 19)...)
	last := len(f.opts) - 1
	first, late := f.opts[1].Transport.TCP4.Addr().String(), f.opts[last].Transport.TCP4.Addr().String()
	f.opts[0].Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
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
		o.MaintenanceInterval = 25 * time.Millisecond
		o.DialTimeout = 150 * time.Millisecond
		n, err := New(t.Context(), o)
		require.NoError(t, err)
		t.Cleanup(func() { n.Close() })
		require.NoError(t, n.Start())
		live = append(live, n)
	}
	a := live[0]
	require.NoError(t, a.ConnectPeer(t.Context(), live[1].Addresses().IPv4))
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
			l := &interruptedListener{Listener: f.opts[1].Transport.TCP4, stop: make(chan struct{}), fatal: errors.New("listener unavailable")}
			stop := sync.OnceFunc(func() { close(l.stop) })
			defer stop()
			f.opts[1].Transport.TCP4 = l
			var shared *portshare.TCP
			if kind == "shared" {
				shared = portshare.NewTCP(l)
				t.Cleanup(func() { shared.Close() })
				f.opts[1].Transport.TCP4 = shared.Mesh()
			}
			f.start()
			a, b := f.nodes[0], f.nodes[1]
			require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
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
	d := tls.Dialer{Config: a.tlsConfig(b.id, true, a.cred.Load())}
	c, err := d.DialContext(t.Context(), "tcp", f.opts[1].Transport.TCP4.Addr().String())
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

func TestColdCircuitAcrossSlowHops(t *testing.T) {
	f := newFixture(t, "udp", "both", "tcp", "tcp")
	for i := 0; i < 3; i++ {
		f.link(i, i+1)
	}
	f.cfg.Members[1].Transit = true
	f.cfg.Members[2].Transit = true
	for i, opts := range f.opts {
		opts.Topology = f.cfg
		opts.MaintenanceInterval = time.Hour
		opts.DialTimeout = 600 * time.Millisecond
		if i == 1 || i == 2 {
			opts.Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
				select {
				case <-time.After(375 * time.Millisecond):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
		}
		n, err := New(t.Context(), opts)
		require.NoError(t, err)
		// Keep the two downstream legs cold until the foreground circuit reaches them.
		for range cap(n.neighborDialSlots) {
			n.neighborDialSlots <- struct{}{}
		}
		t.Cleanup(func() { n.Close() })
		require.NoError(t, n.Start())
		f.nodes = append(f.nodes, n)
	}
	a, b := f.nodes[0], f.nodes[3]
	_, err := a.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
	require.NoError(t, err)
	require.NoError(t, a.SetPeerPathPolicy(b.id, RelayOnly))
	require.NoError(t, a.ConnectPeerID(t.Context(), b.id))
	path, ok := a.PreferredPath(b.id)
	require.True(t, ok)
	require.Equal(t, []PeerID{a.id, f.nodes[1].id, f.nodes[2].id, b.id}, path.Circuit)
	received := make(chan []byte, 1)
	_, err = b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, data []byte) { received <- data }})
	require.NoError(t, err)
	out, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	packet := testIPv4(a.Addresses().IPv4, b.Addresses().IPv4, "first circuit")
	require.NoError(t, out.WriteIP(b.id, packet))
	select {
	case data := <-received:
		require.Equal(t, packet, data)
	case <-time.After(2 * time.Second):
		t.Fatal("first circuit did not deliver the packet")
	}
}

func TestNeighborDialWhilePublicationsArePaced(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	f.opts[0].MaintenanceInterval = 40 * time.Millisecond
	f.start()
	a, b, c := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, a.ConnectPeerID(t.Context(), b.id))
	require.True(t, a.limiter.AllowN(time.Now(), MaxIPPacketSize+1))
	for i := range cap(a.backgroundSlots) + 2 {
		_, err := a.Publish(t.Context(), "app/test", []byte{byte(i)})
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return len(a.backgroundSlots) == cap(a.backgroundSlots) }, time.Second, time.Millisecond)
	f.link(0, 2)
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool {
		path, ok := a.PreferredPath(c.id)
		return ok && path.Transport == "tcp"
	}, 2*time.Second, 5*time.Millisecond)
}

type failingUDPReader struct {
	net.PacketConn
	err error
}

func (s failingUDPReader) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := s.PacketConn.ReadFrom(b)
	if err == nil {
		return 0, nil, s.err
	}
	return n, from, err
}

func TestUDPListenerFailure(t *testing.T) {
	for _, kind := range []string{"dedicated", "shared"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, "udp")
			socket := failingUDPReader{f.opts[0].Transport.UDP4, errors.New("physical UDP reader failed")}
			f.opts[0].Transport.UDP4 = socket
			var other net.PacketConn
			if kind == "shared" {
				shared := portshare.NewUDP(socket)
				t.Cleanup(func() { shared.Close() })
				f.opts[0].Transport.UDP4 = shared.Mesh()
				other = shared.Other()
			}
			f.start()
			n := f.nodes[0]
			_, err := socket.WriteTo([]byte{1}, socket.LocalAddr())
			require.NoError(t, err)
			require.Eventually(t, func() bool { return n.ControlStatus().ListenerErrors["udp4"] != "" }, time.Second, time.Millisecond)
			require.Contains(t, n.ControlStatus().ListenerErrors["udp4"], socket.err.Error())
			if other != nil {
				_, _, err := other.ReadFrom(make([]byte, 1))
				require.ErrorIs(t, err, socket.err)
			}
			require.True(t, n.ControlStatus().Ready)
		})
	}
	f := newFixture(t, "udp")
	f.start()
	require.NoError(t, f.nodes[0].Close())
	require.Empty(t, f.nodes[0].ControlStatus().ListenerErrors)
}
