package nebula

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

type deadlineFailConn struct {
	net.Conn
	onClear bool
}

func (c deadlineFailConn) SetDeadline(t time.Time) error {
	if t.IsZero() == c.onClear {
		return errors.ErrUnsupported
	}
	return c.Conn.SetDeadline(t)
}

func TestConnectEndpointRequiresTCPDeadlines(t *testing.T) {
	for name, onClear := range map[string]bool{"set": false, "clear": true} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "", "tcp")
			f.opts[0].Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return deadlineFailConn{c, onClear}, nil
			}
			f.start()
			n := f.nodes[0]
			_, err := n.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
			require.ErrorIs(t, err, errors.ErrUnsupported)
			require.Empty(t, n.Paths())
		})
	}
}

func TestConnectPeerAfterSuccessfulPathIsWithdrawn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, "", "")
		f.cfg.Members[1].Endpoints = []Endpoint{{Network: "tcp", Address: netip.MustParseAddrPort("127.0.0.1:4242")}}
		refused := errors.New("replacement dial refused")
		release := make(chan struct{})
		var dials atomic.Int32
		f.opts[0].Transport.DialTCP = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			<-release
			return nil, refused
		}
		f.start()
		a, peer := f.nodes[0], f.cfg.Members[1]

		// The registered path has been withdrawn, but its dial has yet to
		// report completion. Both address families join that same attempt.
		old := &peerAttempt{changed: make(chan struct{})}
		a.mu.Lock()
		a.attempts[peer.ID] = old
		a.mu.Unlock()
		done := make(chan error, 2)
		for _, addr := range []netip.Addr{peer.IPv4, peer.IPv6} {
			go func() { done <- a.ConnectPeer(t.Context(), addr) }()
		}
		synctest.Wait()
		a.mu.Lock()
		delete(a.attempts, peer.ID)
		close(old.changed)
		old.changed = nil
		a.mu.Unlock()

		synctest.Wait()
		close(release)
		for range 2 {
			require.ErrorIs(t, <-done, refused)
		}
		require.EqualValues(t, 1, dials.Load())
	})
}

func TestGroupSendUsesInboundPathWhileWaitingForDialSlot(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.EnableBroadcast = true
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	for range cap(a.sharedAddressDialSlots) {
		a.sharedAddressDialSlots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	received := make(chan []byte, 1)
	_, err := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, pkt []byte) { received <- pkt }})
	require.NoError(t, err)
	out, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	pkt := testIPv4(a.Addresses().IPv4, limitedBroadcast, "inbound path")
	require.NoError(t, out.WriteIP(PeerID{}, pkt))
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.pathRegistered != nil
	}, time.Second, time.Millisecond)
	require.NoError(t, b.ConnectPeerID(ctx, a.id))
	select {
	case got := <-received:
		require.Equal(t, pkt, got)
	case <-ctx.Done():
		t.Fatal("queued broadcast missed the inbound connection")
	}
	require.Len(t, a.sharedAddressDialSlots, cap(a.sharedAddressDialSlots))
}

func TestPeerPolicyChangeDuringDirectDial(t *testing.T) {
	for name, mode := range map[string]PathMode{"allow relay": Auto, "block peer": Blocked} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "tcp", "tcp", "tcp")
			f.link(0, 1)
			f.link(1, 2)
			f.cfg.Members[1].Transit = true
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
			}
			f.opts[0].DialTimeout = 4 * time.Second
			target := f.cfg.Members[2].Endpoints[0].Address.String()
			entered, release := make(chan struct{}), make(chan struct{})
			f.opts[0].Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != target {
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				close(entered)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return nil, errors.New("direct route unavailable")
				}
			}
			f.start()
			a, r, b := f.nodes[0], f.nodes[1], f.nodes[2]
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			require.NoError(t, a.ConnectPeerID(ctx, r.id))
			require.NoError(t, r.ConnectPeerID(ctx, b.id))
			require.NoError(t, a.SetPeerPathPolicy(b.id, DirectOnly))
			result := make(chan error, 1)
			go func() { result <- a.ConnectPeerID(ctx, b.id) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.NoError(t, a.SetPeerPathPolicy(b.id, mode))
			close(release)
			err := <-result
			path, ok := a.PreferredPath(b.id)
			if mode == Blocked {
				require.ErrorIs(t, err, ErrPathPolicy)
				require.False(t, ok)
			} else {
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, []PeerID{a.id, r.id, b.id}, path.Circuit)
			}
		})
	}
}

func TestConnectEndpointTrustAndRestrictions(t *testing.T) {
	for _, policy := range []string{"trust", "restricted"} {
		t.Run(policy, func(t *testing.T) {
			f := newFixture(t, "", "tcp")
			if policy == "trust" {
				f.opts[0] = newFixture(t, "").opts[0]
			} else {
				f.cfg.Members[1].Restricted = true
			}
			f.opts[0].Auth.TrustedEntrypoints = []PeerID{f.cfg.Members[1].ID}
			f.startDiscovery()
			_, err := f.nodes[0].ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
			require.Error(t, err)
			require.Empty(t, f.nodes[1].Paths())
		})
	}
}

func TestOutboundEndpointPolicyWithRelay(t *testing.T) {
	f := newFixture(t, "both", "tcp", "both")
	f.link(0, 1)
	f.link(1, 2)
	f.cfg.Members[1].Transit = true
	target := f.cfg.Members[2]
	denied := target.Endpoints[0].Address // TCP and QUIC share the port.
	relayAddr := f.cfg.Members[1].Endpoints[0].Address
	var allowTCP atomic.Bool
	var deniedTCP atomic.Int32
	f.opts[0].Transport.DialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == denied.String() && !allowTCP.Load() {
			deniedTCP.Add(1)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = time.Hour
	}
	f.opts[0].Transport.AllowOutboundEndpoint = func(e Endpoint) bool {
		return e.Address != denied || e.Network == "tcp" && allowTCP.Load()
	}
	f.opts[2].Transport.AllowOutboundEndpoint = func(e Endpoint) bool { return e.Address == relayAddr }
	f.start()
	a, relay, b := f.nodes[0], f.nodes[1], f.nodes[2]
	for _, ep := range target.Endpoints {
		_, err := a.ConnectEndpoint(t.Context(), ep)
		require.ErrorIs(t, err, ErrPathPolicy)
	}
	for _, n := range []*Node{a, b} {
		require.NoError(t, n.ConnectPeerID(t.Context(), relay.ID()))
	}
	require.Eventually(t, func() bool {
		_, left := relay.PreferredPath(a.ID())
		_, right := relay.PreferredPath(b.ID())
		return left && right
	}, 3*time.Second, time.Millisecond)
	matches, err := a.ResolveIP(t.Context(), b.Addresses().IPv4)
	require.NoError(t, err)
	require.Contains(t, matches[0].Endpoints, target.Endpoints[0])
	require.NoError(t, a.ConnectPeerID(t.Context(), b.ID()))
	path, ok := a.PreferredPath(b.ID())
	require.True(t, ok)
	require.Equal(t, "relay", path.Transport)

	// In one canary round, skip the denied UDP endpoint and dial the newly allowed TCP endpoint.
	b.mu.Lock()
	before := len(b.queries)
	b.mu.Unlock()
	allowTCP.Store(true)
	a.mu.Lock()
	a.peers[b.ID()].lastCanary = time.Time{}
	a.mu.Unlock()
	a.probeAlternatePaths(a.preferredSession(b.ID(), false), 0)
	b.mu.Lock()
	after := len(b.queries)
	b.mu.Unlock()
	require.Equal(t, before, after)
	require.True(t, slices.ContainsFunc(a.Paths(), func(p PathStatus) bool { return p.Peer == b.ID() && p.Transport == "tcp" }))
	require.Zero(t, deniedTCP.Load())
	require.Zero(t, f.sockets[0].count(denied))
	require.Zero(t, a.ControlStatus().DialFailures)
}

func TestConnectEndpointRecoveryAfterUDPBlackout(t *testing.T) {
	f := newFixture(t, "udp", "udp")
	for i := range f.opts {
		f.opts[i].MaintenanceInterval = 40 * time.Millisecond
		f.opts[i].DialTimeout = 180 * time.Millisecond
	}
	f.startDiscovery(1, -1)
	a, b := f.nodes[0], f.nodes[1]
	ep := f.cfg.Members[1].Endpoints[0]
	f.sockets[0].drop.Store(true)
	require.Eventually(t, func() bool { return len(a.Paths()) == 0 && len(b.Paths()) == 0 }, 4*time.Second, 10*time.Millisecond)
	_, err := a.ConnectEndpoint(t.Context(), ep)
	require.ErrorContains(t, err, ep.Address.String())
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	f.sockets[0].drop.Store(false)
	id, err := a.ConnectEndpoint(t.Context(), ep)
	require.NoError(t, err)
	require.Equal(t, b.ID(), id)
	got, err := a.ResolveIP(t.Context(), b.Addresses().IPv6)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, id, got[0].Peer)

	reply := make(chan string, 1)
	_, err = a.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, pkt []byte) { reply <- string(pkt[20:]) }})
	require.NoError(t, err)
	port, err := b.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	// ConnectEndpoint returns when A registers its path. B registers independently.
	require.Eventually(t, func() bool {
		path, ok := b.PreferredPath(a.ID())
		return ok && path.Transport == "udp"
	}, 3*time.Second, time.Millisecond, "B did not register the recovered UDP path to A")
	require.NoError(t, port.WriteIP(a.ID(), testIPv4(b.Addresses().IPv4, a.Addresses().IPv4, "after recovery")))
	select {
	case msg := <-reply:
		require.Equal(t, "after recovery", msg)
	case <-time.After(time.Second):
		t.Fatal("missing packet on recovered path")
	}
}

func TestConnectEndpointSharesDial(t *testing.T) {
	for _, action := range []string{"complete", "close"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t, "", "tcp")
			entered, release := make(chan struct{}, 1), make(chan struct{})
			var dials atomic.Int32
			f.opts[0].DialTimeout = 3 * time.Second
			f.opts[0].Transport.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
			}
			f.opts[0].Auth.TrustedEntrypoints = []PeerID{f.cfg.Members[1].ID}
			f.startDiscovery()
			a, b := f.nodes[0], f.nodes[1]
			ep := f.cfg.Members[1].Endpoints[0]
			waiter, cancel := context.WithCancel(t.Context())
			defer cancel()
			canceled, stop := context.WithCancel(t.Context())
			stop()
			_, err := a.ConnectEndpoint(canceled, ep)
			require.ErrorIs(t, err, context.Canceled)
			require.Zero(t, dials.Load())

			first := make(chan error, 1)
			go func() { _, err := a.ConnectEndpoint(waiter, ep); first <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			result := make(chan error, 8)
			for range cap(result) {
				go func() {
					id, err := a.ConnectEndpoint(t.Context(), ep)
					if err == nil && id != b.ID() {
						err = errors.New("unexpected endpoint identity")
					}
					result <- err
				}()
			}
			cancel()
			require.ErrorIs(t, <-first, context.Canceled)
			if action == "close" {
				require.NoError(t, a.Close())
			} else {
				close(release)
			}
			for range cap(result) {
				if action == "close" {
					require.ErrorIs(t, <-result, ErrNodeClosed)
				} else {
					require.NoError(t, <-result)
				}
			}
			require.EqualValues(t, 1, dials.Load())
			if action == "complete" {
				id, err := a.ConnectEndpoint(t.Context(), ep)
				require.NoError(t, err)
				require.Equal(t, b.ID(), id)
				require.Len(t, a.Paths(), 1)
				require.EqualValues(t, 1, dials.Load())
				require.NoError(t, a.SetPeerPathPolicy(id, Blocked))
				_, err = a.ConnectEndpoint(t.Context(), ep)
				require.Error(t, err)
				require.Empty(t, a.Paths())
			}
		})
	}
}

func TestConnectEndpointOutboundTCP(t *testing.T) {
	f := newFixture(t, "", "tcp")
	f.start()
	client := f.nodes[0]
	ep := f.cfg.Members[1].Endpoints[0]
	_, err := client.ConnectEndpoint(t.Context(), Endpoint{})
	require.ErrorContains(t, err, "invalid physical endpoint")
	_, err = client.ConnectEndpoint(t.Context(), Endpoint{"udp", netip.MustParseAddrPort("[::1]:443")})
	require.ErrorIs(t, err, ErrPeerUnavailable)
	require.Contains(t, client.ControlStatus().LastError, "[::1]:443")
	id, err := client.ConnectEndpoint(t.Context(), ep)
	require.NoError(t, err)
	require.Equal(t, f.nodes[1].ID(), id)
}

func TestConnectEndpointRequiresServerAuthorization(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			f := newFixture(t, transport, transport)
			bID := f.cfg.Members[1].ID
			denied := errors.New("server use denied")
			f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
				if c.Member == bID && c.Usage == x509.ExtKeyUsageServerAuth {
					return time.Time{}, denied
				}
				return time.Time{}, nil
			}
			f.startDiscovery(-1, 0)
			a := f.nodes[0]
			require.NoError(t, a.ConnectPeerID(t.Context(), bID))
			_, err := a.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
			require.ErrorIs(t, err, denied)
		})
	}
}

func TestConfiguredPhysicalEndpoints(t *testing.T) {
	f := newFixture(t, "", "")
	f.start()
	for _, tc := range []struct {
		address  string
		physical bool
	}{
		{"10.13.0.2:443", false},
		{"[fd42::c8]:443", false},
		{"[fd42::2%eth0]:443", false},
		{"255.255.255.255:443", false},
		{"127.0.0.1:443", true},
		{"192.168.1.2:443", true},
		{"[fe80::2%eth0]:443", true},
	} {
		t.Run(tc.address, func(t *testing.T) {
			ep := Endpoint{"tcp", netip.MustParseAddrPort(tc.address)}
			opts := f.opts[0]
			opts.Topology = f.cfg
			opts.Transport.AdvertiseEndpoints = []Endpoint{ep}
			n, advertiseErr := New(t.Context(), opts)
			if n != nil {
				t.Cleanup(func() { n.Close() })
			}
			cfg := f.cfg
			cfg.Members = slices.Clone(cfg.Members)
			cfg.Members[1].Endpoints = []Endpoint{ep}
			topologyErr := f.nodes[0].ApplyTopology(t.Context(), cfg)
			if tc.physical {
				require.NoError(t, advertiseErr)
				require.NoError(t, topologyErr)
				return
			}
			require.ErrorContains(t, advertiseErr, tc.address)
			require.ErrorContains(t, topologyErr, tc.address)
			_, err := f.nodes[0].ConnectEndpoint(t.Context(), ep)
			require.ErrorContains(t, err, "invalid physical endpoint")
		})
	}
}
