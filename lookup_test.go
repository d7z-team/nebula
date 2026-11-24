package nebula

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestConnectEndpointAndIPDiscovery(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			f := newFixture(t, network, network, network, network)
			route := netip.MustParsePrefix("172.30.0.0/24")
			gateway := labPeer(f.ips[3])
			f.cfg.Members[3].RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}
			f.opts[3].Certificates.Client = f.issue(gateway, pki.Scope{RoutedPrefixes: []netip.Prefix{route}})
			f.startDiscovery(1, -1, 1, 2)
			a, n := f.nodes[0], f.nodes[3]
			_, ok := a.LookupPeer(gateway.IPv4())
			require.False(t, ok)
			dst := netip.MustParseAddr("172.30.0.42")
			for _, addr := range []netip.Addr{gateway.IPv4(), gateway.IPv6(), dst} {
				got, err := a.ResolveIP(t.Context(), addr)
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, gateway, got[0].Peer)
				expected := netip.PrefixFrom(addr, addr.BitLen())
				if addr == dst {
					expected = route
				}
				require.Equal(t, expected, got[0].Prefix)
				require.True(t, time.Now().Before(got[0].ValidUntil))
				require.NotEmpty(t, got[0].Endpoints)
				got[0].Endpoints[0] = Endpoint{}
			}
			require.Len(t, a.Paths(), 1)
			if network == "udp" {
				require.Zero(t, f.sockets[0].count(f.cfg.Members[3].Endpoints[0].Address))
				require.Zero(t, f.sockets[3].count(f.cfg.Members[0].Endpoints[0].Address))
				// Live rendezvous must still reach the target despite cached answers.
				require.True(t, a.rendezvous(t.Context(), gateway))
				require.Positive(t, f.sockets[0].count(f.cfg.Members[3].Endpoints[0].Address))
				require.Positive(t, f.sockets[3].count(f.cfg.Members[0].Endpoints[0].Address))
			}
			port, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
			require.NoError(t, err)
			require.ErrorIs(t, port.WriteIP(gateway, testIPv4(a.id.IPv4(), dst, "downstream")), ErrAddressUnauthorized)
			require.NoError(t, a.ConnectPeerID(t.Context(), gateway))
			rx := make(chan string, 1)
			_, err = n.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, b []byte) { rx <- string(b[20:]) }})
			require.NoError(t, err)
			require.NoError(t, port.WriteIP(PeerID{}, testIPv4(a.id.IPv4(), gateway.IPv4(), "primary")))
			select {
			case msg := <-rx:
				require.Equal(t, "primary", msg)
			case <-time.After(time.Second):
				t.Fatal("missing primary packet")
			}
		})
	}
}

func TestHiddenIntroduction(t *testing.T) {
	f := newFixture(t, "both", "both", "both")
	target := labPeer(f.ips[0])
	prefix := netip.MustParsePrefix("172.30.9.0/24")
	f.cfg.Members[0].RoutedPrefixes = []netip.Prefix{prefix}
	f.opts[0].Certificates.Client = f.issue(target, pki.Scope{RoutedPrefixes: []netip.Prefix{prefix}})
	f.opts[0].HideEndpoints = true
	f.opts[0].AdvertiseEndpoints = []Endpoint{{"udp", netip.MustParseAddrPort("203.0.113.7:4444")}}
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
	}
	f.startDiscovery()
	h, relay, visitor := f.nodes[0], f.nodes[1], f.nodes[2]
	_, ok := visitor.PreferredPath(target)
	require.False(t, ok)
	_, err := h.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		p, ok := relay.PreferredPath(target)
		return ok && p.Transport == "udp" && p.Endpoint.IsValid()
	}, time.Second, time.Millisecond)
	// Report a NAT mapping on the actual QUIC adjacency and inspect H's signed reply.
	s := relay.preferredSession(target, true)
	raw, err := s.request(t.Context(), opHello, []byte(`{"observed":"198.51.100.8:45001"}`), maxControlFrame)
	require.NoError(t, err)
	var hello advert
	require.NoError(t, json.Unmarshal(raw, &hello))
	h.mu.Lock()
	observations := len(h.observations)
	h.mu.Unlock()
	require.Zero(t, observations)

	_, body, _, err := relay.verifyStatement(t.Context(), "introduction", hello.Record, relay.policy.Load())
	require.NoError(t, err)
	var intro introduction
	require.NoError(t, json.Unmarshal(body, &intro))
	require.Empty(t, intro.Endpoints)
	require.Equal(t, []netip.Prefix{prefix}, intro.RoutedPrefixes)
	require.True(t, h.rendezvous(t.Context(), relay.id))
	relay.mu.Lock()
	origin := relay.discovered[target].record
	relay.mu.Unlock()
	require.Equal(t, hello.Record, origin)
	_, err = visitor.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[1])
	require.NoError(t, err)
	// The live query reaches H via the relay. Its signed reply must not be
	// accompanied by a packet that reveals H's source address to the visitor.
	require.True(t, visitor.rendezvous(t.Context(), target))
	require.Zero(t, f.sockets[0].count(f.cfg.Members[2].Endpoints[0].Address))
	visitor.mu.Lock()
	answer := visitor.discovered[target].record
	visitor.mu.Unlock()
	require.Equal(t, hello.Record, answer)

	// An older, still-valid public introduction may arrive after H restarts
	// with private endpoints. The relay must keep the newer signed record.
	intro.Endpoints = f.cfg.Members[0].Endpoints
	intro.Expires = intro.Expires.Add(-time.Second)
	older, err := h.signStatement("introduction", intro, h.cred.Load().Object)
	require.NoError(t, err)
	_, accepted := relay.learnIntroduction(t.Context(), older, nil)
	require.True(t, accepted)

	// An offline H can only be discovered from the relay's cached signature.
	require.NoError(t, h.Close())
	require.NoError(t, visitor.Revalidate(t.Context()))
	for _, ip := range []netip.Addr{target.IPv4(), target.IPv6(), prefix.Addr().Next()} {
		matches, err := visitor.ResolveIP(t.Context(), ip)
		require.NoError(t, err)
		require.Len(t, matches, 1)
		require.Equal(t, target, matches[0].Peer)
		require.Empty(t, matches[0].Endpoints)
		want := netip.PrefixFrom(ip, ip.BitLen())
		if prefix.Contains(ip) {
			want = prefix
		}
		require.Equal(t, want, matches[0].Prefix)
	}
}

func TestDownstreamDiscoveryAcrossBranches(t *testing.T) {
	// The visitor can only reach the six gateways through the same neighbor.
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp")
	dst := netip.MustParseAddr("172.30.0.42")
	for i := 2; i < len(f.opts); i++ {
		prefix := netip.PrefixFrom(dst, 22+i-2).Masked()
		f.cfg.Members[i].RoutedPrefixes = []netip.Prefix{prefix}
		f.opts[i].Certificates.Client = f.issue(labPeer(f.ips[i]), pki.Scope{RoutedPrefixes: []netip.Prefix{prefix}})
	}
	f.startDiscovery(1, -1, 1, 1, 1, 1, 1, 1)
	a, hub := f.nodes[0], f.nodes[1]
	got, err := a.ResolveIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, got, 6)
	for _, leaf := range f.nodes[2:] {
		leaf.mu.Lock()
		queries := len(leaf.queries)
		leaf.mu.Unlock()
		require.Positive(t, queries, "search skipped branch %v", leaf.id)
	}
	for i, m := range got {
		require.Equal(t, 27-i, m.Prefix.Bits())
		require.Equal(t, f.nodes[7-i].id, m.Peer)
	}
	require.Len(t, a.Paths(), 1)
	g := f.nodes[7]
	self := f.cfg.Members[7].Clone()
	self.RoutedPrefixes = nil
	require.NoError(t, g.ApplyTopology(t.Context(), Topology{Network: "lab", Members: []Member{self}}))
	require.Eventually(t, func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		i := hub.discovered[g.id]
		return len(i.record) > 0 && len(i.RoutedPrefixes) == 0
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, a.Revalidate(t.Context()))
	got, err = a.ResolveIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, got, 5)
}

func TestLookupReplyUsesObjectCertificate(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	wide := netip.MustParsePrefix("172.30.0.0/16")
	narrow := netip.MustParsePrefix("172.30.9.0/24")
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{wide}
	id := labPeer(f.ips[1])
	f.opts[1].Certificates.Client = f.issue(id, pki.Scope{RoutedPrefixes: []netip.Prefix{wide}})
	f.opts[1].Certificates.Object = f.issue(id, pki.Scope{RoutedPrefixes: []netip.Prefix{narrow}})
	f.start()
	a, g := f.nodes[0], f.nodes[1]
	intro := g.localIntroduction(g.policy.Load()).introduction
	require.Equal(t, []netip.Prefix{narrow}, intro.RoutedPrefixes)
	intro.RoutedPrefixes = []netip.Prefix{wide}
	validSignature, err := g.signStatement("introduction", intro, g.cred.Load().Object)
	require.NoError(t, err)
	_, accepted := a.learnIntroduction(t.Context(), validSignature, &query{IP: netip.MustParseAddr("172.30.8.1")})
	require.False(t, accepted)
	require.NoError(t, a.ConnectPeer(t.Context(), id.IPv4()))
	got, err := a.ResolveIP(t.Context(), netip.MustParseAddr("172.30.9.1"))
	require.NoError(t, err)
	require.Equal(t, narrow, got[0].Prefix)
}

func TestConcurrentResolveCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "tcp", "tcp", "tcp")
			waiting, release := make(chan struct{}, 1), make(chan struct{})

			var armed atomic.Bool
			f.opts[1].CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
				if armed.Load() && c.Member == labPeer(f.ips[0]) && c.Usage == x509.ExtKeyUsageCodeSigning {
					select {
					case waiting <- struct{}{}:
					default:
					}
					select {
					case <-release:
					case <-ctx.Done():
						return time.Time{}, ctx.Err()
					}
				}
				return time.Time{}, nil
			}
			for i := range f.opts {
				f.opts[i].DialTimeout = 3 * time.Second
				f.opts[i].Interval = time.Hour
			}
			f.startDiscovery(1, -1, 1)
			a, g := f.nodes[0], f.nodes[2]
			armed.Store(true)
			addr := g.id.IPv4()
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(t.Context(), 350*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			first, second := make(chan error, 1), make(chan error, 1)
			go func() { _, err := a.ResolveIP(ctx, addr); first <- err }()
			select {
			case <-waiting:
			case <-time.After(time.Second):
				t.Fatal("query did not reach hub")
			}
			go func() { _, err := a.ResolveIP(t.Context(), addr); second <- err }()
			require.Eventually(t, func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				r := a.resolutions[addr]
				return r != nil && r.waiters == 2
			}, time.Second, 5*time.Millisecond)
			if mode == "cancel" {
				cancel()
				require.ErrorIs(t, <-first, context.Canceled)
			} else {
				require.ErrorIs(t, <-first, context.DeadlineExceeded)
			}
			close(release)
			require.NoError(t, <-second)
			require.Len(t, a.Paths(), 1)
		})
	}
}
