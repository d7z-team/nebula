package nebula

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestLookupReplyAfterRequesterWithdrawal(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	requester := f.cfg.Members[0].ID
	var denied atomic.Bool
	f.opts[1].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if denied.Load() && c.Member == requester {
			return time.Time{}, ErrPathPolicy
		}
		return time.Time{}, nil
	}
	// The owner reviews the query origin before producing its signed reply.
	// Commit the forwarder's new policy at that point.
	f.opts[2].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
		if c.Member == requester && denied.CompareAndSwap(false, true) {
			return time.Time{}, f.nodes[1].Revalidate(ctx)
		}
		return time.Time{}, ctx.Err()
	}
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
		f.opts[i].DialTimeout = 4 * time.Second
	}
	f.start()
	x, forwarder, owner := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, forwarder.ConnectPeerID(t.Context(), requester))
	require.NoError(t, forwarder.ConnectPeerID(t.Context(), owner.ID()))
	s := forwarder.preferredSession(requester, false)
	require.NotNil(t, s)
	q := query{
		ID: "0123456789abcdef0123456789abcdef", Target: &owner.id,
		Origin: x.localIntroduction(x.policy.Load()).record, Visited: []PeerID{requester}, Budget: forwarder.o.DialTimeout,
	}
	body, err := json.Marshal(q)
	require.NoError(t, err)
	var reply bytes.Buffer
	forwarder.handleLookup(s, &reply, body)
	require.False(t, forwarder.usable(s))
	require.Zero(t, reply.Len())
	// The owner's valid reply reached the forwarder under its new policy.
	matches := forwarder.ipMatches(owner.Addresses().IPv4, nil)
	require.Len(t, matches, 1)
	require.Equal(t, owner.ID(), matches[0].Peer)
}

func TestConnectEndpointAndIPDiscovery(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			f := newFixture(t, network, network, network, network)
			route := netip.MustParsePrefix("172.30.0.0/24")
			gateway := f.cfg.Members[3].ID
			f.cfg.Members[3].RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}
			f.opts[3].Auth.Certificates = f.issue(f.ips[3], pki.Scope{RoutedPrefixes: []netip.Prefix{route}})
			f.startDiscovery(1, -1, 1, 2)
			a, n := f.nodes[0], f.nodes[3]
			_, ok := a.LookupPeer(n.Addresses().IPv4)
			require.False(t, ok)
			dst := netip.MustParseAddr("172.30.0.42")
			for _, addr := range []netip.Addr{n.Addresses().IPv4, n.Addresses().IPv6, dst} {
				got, err := a.ResolveIP(t.Context(), addr)
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, gateway, got[0].Peer)
				require.Equal(t, n.Addresses(), got[0].Addresses)
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
			require.ErrorIs(t, port.WriteIP(gateway, testIPv4(a.Addresses().IPv4, dst, "downstream")), ErrAddressUnauthorized)
			require.NoError(t, a.ConnectPeerID(t.Context(), gateway))
			rx := make(chan string, 1)
			_, err = n.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, b []byte) { rx <- string(b[20:]) }})
			require.NoError(t, err)
			require.NoError(t, port.WriteIP(PeerID{}, testIPv4(a.Addresses().IPv4, n.Addresses().IPv4, "primary")))
			select {
			case msg := <-rx:
				require.Equal(t, "primary", msg)
			case <-time.After(time.Second):
				t.Fatal("missing primary packet")
			}
		})
	}
}

func TestRendezvousEndpointOrder(t *testing.T) {
	f := newFixture(t, "udp", "both", "udp")
	static := f.cfg.Members[1].Endpoints
	f.cfg.Members[1].Endpoints = []Endpoint{static[1], static[0], static[1]}
	additional := f.cfg.Members[2].Endpoints[0]
	f.opts[1].Transport.AdvertiseEndpoints = []Endpoint{additional, static[0]}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	_, ok := a.learnIntroduction(t.Context(), b.localIntroduction(b.policy.Load()).record, nil)
	require.True(t, ok)
	a.mu.Lock()
	eps := a.endpointsLocked(b.id)
	a.mu.Unlock()
	require.Equal(t, []Endpoint{static[1], static[0], additional}, eps)
	a.punch(b.id)
	for _, ep := range []Endpoint{static[0], additional} {
		require.Equal(t, 1, f.sockets[0].count(ep.Address))
	}
}

func TestHiddenIntroduction(t *testing.T) {
	f := newFixture(t, "both", "both", "both")
	target := f.cfg.Members[0].ID
	prefix := netip.MustParsePrefix("172.30.9.0/24")
	f.cfg.Members[0].RoutedPrefixes = []netip.Prefix{prefix}
	f.opts[0].Auth.Certificates = f.issue(f.ips[0], pki.Scope{RoutedPrefixes: []netip.Prefix{prefix}})
	f.opts[0].Transport.HideEndpoints = true
	f.opts[0].Transport.AdvertiseEndpoints = []Endpoint{{"udp", netip.MustParseAddrPort("203.0.113.7:4444")}}
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	for _, i := range []int{0, 2} {
		f.opts[i].Auth.TrustedEntrypoints = []PeerID{f.cfg.Members[1].ID}
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
	older, err := h.signStatement("introduction", intro, h.cred.Load().cmsSigner)
	require.NoError(t, err)
	_, accepted := relay.learnIntroduction(t.Context(), older, nil)
	require.True(t, accepted)

	// An offline H can only be discovered from the relay's cached signature.
	require.NoError(t, h.Close())
	require.NoError(t, visitor.Revalidate(t.Context()))
	for _, ip := range []netip.Addr{h.Addresses().IPv4, h.Addresses().IPv6, prefix.Addr().Next()} {
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

func TestAdvertRetainsUsableNATMapping(t *testing.T) {
	f := newFixture(t, "udp", "udp")
	mapping := Endpoint{"udp", netip.MustParseAddrPort("[2001:db8::1]:45001")}
	route := netip.MustParsePrefix("172.30.0.0/24")
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{route}
	f.opts[1].Auth.Certificates = f.issue(f.ips[1], pki.Scope{RoutedPrefixes: []netip.Prefix{route}})
	reporter := f.cfg.Members[0].ID
	configured := f.cfg.Members[1].Endpoints[0]
	// Denied entries must not consume the introduction's fixed endpoint budget.
	for port := 1; port <= maxIntroductionEndpoints; port++ {
		f.opts[1].Transport.AdvertiseEndpoints = append(f.opts[1].Transport.AdvertiseEndpoints,
			Endpoint{"tcp", netip.AddrPortFrom(configured.Address.Addr(), uint16(port))})
	}
	f.opts[1].Transport.AdvertiseEndpoints = append(f.opts[1].Transport.AdvertiseEndpoints, configured)
	var publishMapping atomic.Bool
	publishMapping.Store(true)
	f.opts[1].Transport.AllowAdvertiseEndpoint = func(c EndpointCandidate) bool {
		switch c.Source {
		case EndpointFromListener:
			return c.Endpoint == configured && c.Observer == (PeerID{})
		case EndpointFromObservation:
			return c.Endpoint == mapping && c.Observer == reporter && publishMapping.Load()
		default:
			return false
		}
	}
	f.opts[0].MaintenanceInterval = time.Hour
	f.opts[1].MaintenanceInterval = time.Hour
	f.startDiscovery(1, -1)
	observer, target := f.nodes[0], f.nodes[1]
	s := observer.preferredSession(target.ID(), true)
	require.NotNil(t, s)
	for _, port := range []uint16{mapping.Address.Port(), mapping.Address.Port() + 1, 0} {
		report, err := json.Marshal(advert{Observed: netip.AddrPortFrom(mapping.Address.Addr(), port)})
		require.NoError(t, err)
		_, err = s.request(t.Context(), opHello, report, maxControlFrame)
		require.NoError(t, err)
	}
	matches, err := observer.RefreshIP(t.Context(), route.Addr().Next())
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, []Endpoint{configured, mapping}, matches[0].Endpoints)
	publishMapping.Store(false)
	matches, err = observer.RefreshIP(t.Context(), route.Addr().Next())
	require.NoError(t, err)
	require.Equal(t, []Endpoint{configured}, matches[0].Endpoints)
}

func TestDownstreamDiscoveryAcrossBranches(t *testing.T) {
	// The visitor can only reach the six gateways through the same neighbor.
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp")
	dst := netip.MustParseAddr("172.30.0.42")
	for i := 2; i < len(f.opts); i++ {
		prefix := netip.PrefixFrom(dst, 22+i-2).Masked()
		f.cfg.Members[i].RoutedPrefixes = []netip.Prefix{prefix}
		f.opts[i].Auth.Certificates = f.issue(f.ips[i], pki.Scope{RoutedPrefixes: []netip.Prefix{prefix}})
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
	got, err = a.RefreshIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, got, 5)
}

func TestRefreshIPWithCachedDefault(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	dst := netip.MustParseAddr("172.30.0.42")
	site := netip.PrefixFrom(dst, 24).Masked()
	for i, prefix := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), site} {
		routes := []netip.Prefix{prefix}
		f.cfg.Members[i+2].RoutedPrefixes = routes
		f.opts[i+2].Auth.Certificates = f.issue(f.ips[i+2], pki.Scope{RoutedPrefixes: routes})
	}
	f.opts[1].Auth.TrustedEntrypoints = []PeerID{f.cfg.Members[3].ID}
	f.startDiscovery(1, -1, 1, -1)
	visitor, hub, gateway := f.nodes[0], f.nodes[1], f.nodes[3]
	initial, err := visitor.ResolveIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, initial, 1)
	require.Zero(t, initial[0].Prefix.Bits())
	_, err = hub.ConnectEndpoint(t.Context(), f.cfg.Members[3].Endpoints[0])
	require.NoError(t, err)
	cached, err := visitor.ResolveIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, cached, 1)
	require.Equal(t, initial[0].Peer, cached[0].Peer)
	matches, err := visitor.RefreshIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, matches, 2)
	require.Equal(t, gateway.ID(), matches[0].Peer)
	require.Equal(t, site, matches[0].Prefix)
	require.Equal(t, initial[0].Peer, matches[1].Peer)
	require.Len(t, visitor.Paths(), 1)

	// The visitor still has the site's valid record after the hub stops returning it.
	require.NoError(t, hub.SetPeerPathPolicy(gateway.ID(), Blocked))
	refreshed, err := visitor.RefreshIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, refreshed, 1)
	require.Equal(t, initial[0].Peer, refreshed[0].Peer)
	cached, err = visitor.ResolveIP(t.Context(), dst)
	require.NoError(t, err)
	require.Len(t, cached, 2)
	require.Equal(t, gateway.ID(), cached[0].Peer)
	_, err = visitor.RefreshIP(t.Context(), gateway.Addresses().IPv4)
	require.ErrorIs(t, err, ErrInvalidPacketAddress)
}

func TestLookupReplyUsesObjectCertificate(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	wide := netip.MustParsePrefix("172.30.0.0/16")
	narrow := netip.MustParsePrefix("172.30.9.0/24")
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{wide}
	f.opts[1].Auth.Certificates = f.issue(f.ips[1], pki.Scope{RoutedPrefixes: []netip.Prefix{narrow}})
	f.start()
	a, g := f.nodes[0], f.nodes[1]
	intro := g.localIntroduction(g.policy.Load()).introduction
	require.Equal(t, []netip.Prefix{narrow}, intro.RoutedPrefixes)
	intro.RoutedPrefixes = []netip.Prefix{wide}
	validSignature, err := g.signStatement("introduction", intro, g.cred.Load().cmsSigner)
	require.NoError(t, err)
	_, accepted := a.learnIntroduction(t.Context(), validSignature, &query{IP: netip.MustParseAddr("172.30.8.1")})
	require.False(t, accepted)
	require.NoError(t, a.ConnectPeer(t.Context(), f.ips[1]))
	got, err := a.ResolveIP(t.Context(), netip.MustParseAddr("172.30.9.1"))
	require.NoError(t, err)
	require.Equal(t, narrow, got[0].Prefix)
}

func TestConcurrentResolveCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, "tcp", "tcp", "tcp")
			addr := netip.MustParseAddr("172.30.0.42")
			routes := []netip.Prefix{netip.PrefixFrom(addr, 24).Masked()}
			f.cfg.Members[2].RoutedPrefixes = routes
			f.opts[2].Auth.Certificates = f.issue(f.ips[2], pki.Scope{RoutedPrefixes: routes})
			waiting, release := make(chan struct{}, 1), make(chan struct{})

			var armed atomic.Bool
			f.opts[1].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
				if armed.Load() && c.Member == f.cfg.Members[0].ID && c.Usage == x509.ExtKeyUsageCodeSigning {
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
				f.opts[i].MaintenanceInterval = time.Hour
			}
			f.startDiscovery(1, -1, 1)
			a := f.nodes[0]
			armed.Store(true)
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
			go func() { _, err := a.RefreshIP(t.Context(), addr); second <- err }()
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

func TestGatewayIntroductionBudget(t *testing.T) {
	f := newFixture(t, "tcp")
	member := &f.cfg.Members[0]
	grant := netip.MustParsePrefix("172.16.0.0/16")
	wide := f.issue(member.IPv4, pki.Scope{RoutedPrefixes: []netip.Prefix{grant}})
	routes := make([]netip.Prefix, 4096)
	for i := range routes {
		routes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, byte(i >> 4), byte(i << 4)}), 32)
	}
	member.RoutedPrefixes = routes
	opts := f.opts[0]
	opts.Auth.Certificates = wide
	opts.Topology = f.cfg
	_, err := New(t.Context(), opts)
	require.ErrorIs(t, err, pki.ErrDocumentTooLarge)

	// The same topology fits while the object signer authorizes a single route.
	narrow := f.issue(member.IPv4, pki.Scope{RoutedPrefixes: routes[:1]})
	f.opts[0].Auth.Certificates = narrow
	f.start()
	n := f.nodes[0]
	require.ErrorIs(t, n.ReloadCertificates(t.Context(), wide), pki.ErrDocumentTooLarge)
	first, err := n.ResolveIP(t.Context(), routes[0].Addr())
	require.NoError(t, err)
	require.Equal(t, routes[0], first[0].Prefix)
	require.Equal(t, grantLeaf(t, narrow).SerialNumber.String(), n.ControlStatus().GrantSerial)

	member.RoutedPrefixes = routes[:1]
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, n.ReloadCertificates(t.Context(), wide))
	member.RoutedPrefixes = routes
	require.ErrorIs(t, n.ApplyTopology(t.Context(), f.cfg), pki.ErrDocumentTooLarge)
	require.Equal(t, routes[:1], n.localIntroduction(n.policy.Load()).RoutedPrefixes)

	// Fill the record up to the last host route that fits, leaving room for
	// several observations. The exact count depends on the actual certificate.
	base := n.localIntroduction(n.policy.Load()).introduction
	base.Expires = time.Unix(base.Expires.Unix(), 999999999).UTC()
	end := sort.Search(len(routes), func(i int) bool {
		base.RoutedPrefixes = routes[:i+1]
		return errors.Is(n.checkIntroductionSize(n.policy.Load(), n.cred.Load().cmsSigner, base), pki.ErrDocumentTooLarge)
	})
	require.Greater(t, end, 10)
	member.RoutedPrefixes = routes[:end-4]
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	n.mu.Lock()
	for i := range 15 {
		n.observations[observer{peer: labPeer(netip.AddrFrom4([4]byte{10, 13, 0, byte(i + 2)}))}] = observation{
			endpoint: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(12000+i)),
			expires:  time.Now().Add(time.Minute),
		}
	}
	n.mu.Unlock()
	local := n.localIntroduction(n.policy.Load())
	var intro introduction
	_, body, _, err := n.verifyStatement(t.Context(), "introduction", local.record, n.policy.Load())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &intro))
	require.Greater(t, len(intro.Endpoints), len(member.Endpoints))
	require.Less(t, len(intro.Endpoints), len(local.candidates))
	require.Equal(t, member.Endpoints[0], intro.Endpoints[0])
	require.Equal(t, local.candidates[:len(intro.Endpoints)], intro.Endpoints)
	require.Equal(t, member.RoutedPrefixes, intro.RoutedPrefixes)
	intro.Endpoints = local.candidates[:len(intro.Endpoints)+1]
	_, err = n.signStatement("introduction", intro, n.cred.Load().cmsSigner)
	require.ErrorIs(t, err, pki.ErrDocumentTooLarge)
	for _, dst := range []netip.Addr{member.IPv6, member.RoutedPrefixes[len(member.RoutedPrefixes)-1].Addr()} {
		matches, err := n.ResolveIP(t.Context(), dst)
		require.NoError(t, err)
		require.Equal(t, member.ID, matches[0].Peer)
	}
}
