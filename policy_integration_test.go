package nebula

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.d7z.net/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestQueueRevokedDuringShaping(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	var denied atomic.Bool
	f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if denied.Load() && !c.Local {
			return time.Time{}, errors.New("peer withdrawn")
		}
		return time.Time{}, nil
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	port, _, in := queueShapedPackets(t, a, b, b.Addresses().IPv4, "shaping", "queued", "queued again")
	denied.Store(true)
	require.NoError(t, a.Revalidate(t.Context()))
	require.Zero(t, port.Stats().Queued)
	require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == 3 }, time.Second, time.Millisecond)
	require.Empty(t, in)
}

func TestClearPendingByPeer(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	port, _, received := queueShapedPackets(t, a, b, b.Addresses().IPv4, "in flight", "queued")
	require.Equal(t, 1, port.ClearPending(b.id))

	fresh := testIPv4(a.Addresses().IPv4, b.Addresses().IPv4, "fresh")
	require.NoError(t, port.WriteIP(b.id, fresh))
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	select {
	case got := <-received:
		require.Equal(t, "fresh", got)
	case <-time.After(time.Second):
		t.Fatal("replacement queue did not deliver")
	}
	require.Eventually(t, func() bool {
		s := port.Stats()
		return s.SentPackets == 1 && s.RejectedOutbound == 1 && s.Queued == 0
	}, time.Second, time.Millisecond)
}

func TestLiveCertificateExpiry(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	o := &f.opts[1]
	existing, err := x509.ParseCertificate(o.Auth.Certificates.Grant[0])
	require.NoError(t, err)
	existing.ExtraExtensions = existing.Extensions
	existing.NotAfter = time.Now().Truncate(time.Second).Add(2 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, existing, f.ca, existing.PublicKey, f.key)
	require.NoError(t, err)
	o.Auth.Certificates.Grant[0] = der
	f.start()
	require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
	fresh := f.issue(f.ips[1], pki.Scope{})
	require.NoError(t, f.nodes[1].ReloadCertificates(t.Context(), fresh))
	require.Eventually(t, func() bool { return len(f.nodes[0].Paths()) == 0 && len(f.nodes[1].Paths()) == 0 }, 4*time.Second, 20*time.Millisecond)
	require.True(t, f.nodes[1].ControlStatus().Ready)
	require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
	require.Equal(t, grantLeaf(t, fresh).SerialNumber.String(), f.nodes[0].Paths()[0].GrantSerial)
}

func TestRoleCredentialsAndObjectAuthorization(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	a, b := f.ips[0], f.ips[1]
	creds := f.opts[0].Auth.Certificates
	var deny atomic.Bool
	var node atomic.Pointer[Node]
	f.opts[1].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if n := node.Load(); n != nil {
			_ = n.Paths()
		} // host callbacks may query live state
		if deny.Load() && c.Usage == x509.ExtKeyUsageCodeSigning && c.Member == f.cfg.Members[0].ID {
			return time.Time{}, errors.New("publisher suspended")
		}
		return time.Time{}, nil
	}
	f.start()
	x, y := f.nodes[0], f.nodes[1]
	node.Store(y)
	require.NoError(t, y.ConnectPeer(t.Context(), a))
	require.NoError(t, x.ConnectPeer(t.Context(), b))
	s := y.preferredSession(x.ID(), false)
	require.Equal(t, creds.Node.Certificate[0], s.state.PeerCertificates[0].Raw)
	sub, err := y.Subscribe("app/test/control")
	require.NoError(t, err)
	defer sub.Close()
	id, err := x.Publish(t.Context(), "app/test/control", []byte("host decision"))
	require.NoError(t, err)
	select {
	case got := <-sub.Publications():
		require.Equal(t, id, got.ID)
	case <-time.After(time.Second):
		t.Fatal("missing signed publication")
	}
	deny.Store(true)
	require.NoError(t, y.Revalidate(t.Context()))
	require.Nil(t, y.preferredSession(x.ID(), false))
	y.mu.Lock()
	_, cached := y.publications[id]
	y.mu.Unlock()
	require.False(t, cached)
	wrong := creds
	wrong.Grant = f.opts[1].Auth.Certificates.Grant
	require.Error(t, x.ReloadCertificates(t.Context(), wrong))
	untrusted := newFixture(t, "tcp", "tcp")
	require.Error(t, y.ReloadCertificates(t.Context(), untrusted.opts[1].Auth.Certificates))
}

func TestRevalidateConcurrentPublication(t *testing.T) {
	for _, outcome := range []string{"commit", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			f := newFixture(t, "")
			entered, release := make(chan struct{}), make(chan struct{})
			limit := time.Now().Add(time.Minute)
			var pause, shorten atomic.Bool
			f.opts[0].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
				if pause.CompareAndSwap(true, false) {
					close(entered)
					select {
					case <-ctx.Done():
						return time.Time{}, ctx.Err()
					case <-release:
					}
				}
				if shorten.Load() && c.Purpose == ClusterGrant {
					return limit, nil
				}
				return time.Time{}, nil
			}
			f.start()
			n := f.nodes[0]
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			pause.Store(true)
			done := make(chan error, 1)
			go func() { done <- n.Revalidate(ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// The publication was absent from the review's initial snapshot.
			id, err := n.Publish(ctx, "app/test", []byte("during review"))
			require.NoError(t, err)
			shorten.Store(true)
			if outcome == "cancel" {
				cancel()
				require.ErrorIs(t, <-done, context.Canceled)
			} else {
				close(release)
				require.NoError(t, <-done)
			}
			n.mu.Lock()
			publication, ok := n.publications[id]
			n.mu.Unlock()
			require.True(t, ok)
			if outcome == "commit" {
				require.Equal(t, limit, publication.expires)
				require.Equal(t, limit, n.ControlStatus().AuthorizedUntil)
			} else {
				require.True(t, publication.expires.After(limit))
				require.True(t, n.ControlStatus().AuthorizedUntil.After(limit))
			}
		})
	}
}

func TestConcurrentTopologyAndCredentialUpdates(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.start()
	n, remote := f.nodes[0], f.nodes[1]
	require.NoError(t, n.ConnectPeer(t.Context(), remote.Addresses().IPv4))
	s := n.preferredSession(remote.id, false)
	seed := f.cfg
	seed.Members = slices.Clone(f.cfg.Members)
	seed.Members = slices.Delete(seed.Members, 2, 3)
	updates := []func() error{
		func() error { return n.ApplyTopology(t.Context(), seed) },
		func() error { return n.ReloadCertificates(t.Context(), f.opts[0].Auth.Certificates) },
		func() error { return n.Revalidate(t.Context()) },
	}
	errs := make(chan error, len(updates))
	for _, update := range updates {
		go func() {
			var err error
			for range 8 {
				if err = update(); err != nil {
					break
				}
			}
			errs <- err
		}()
	}
	for range updates {
		require.NoError(t, <-errs)
	}
	require.Same(t, s, n.preferredSession(remote.id, false))
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, n.ConnectPeer(t.Context(), f.ips[2]))
}

func TestChainDeadlineAndTopologyAdmission(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	b, third := f.ips[1], f.ips[2]
	// Each endpoint receives only the two members it currently needs.
	local := f.cfg
	local.Members = slices.Clone(f.cfg.Members)
	local.Members = slices.Delete(local.Members, 2, 3)
	require.NoError(t, local.Validate(f.cluster))
	deadline := time.Now().Add(15 * time.Minute)
	var limit atomic.Pointer[time.Time]
	limit.Store(&deadline)
	f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if c.Local && c.Usage == x509.ExtKeyUsageCodeSigning {
			return deadline, nil
		}
		if !c.Local && c.Usage != x509.ExtKeyUsageCodeSigning {
			return *limit.Load(), nil
		}
		return time.Time{}, nil
	}
	for i := range f.opts {
		o := f.opts[i]
		o.Topology = f.cfg
		if i == 0 {
			o.Topology = local
		}
		n, err := New(t.Context(), o)
		require.NoError(t, err)
		f.nodes = append(f.nodes, n)
		t.Cleanup(func() { n.Close() })
		status := n.ControlStatus()
		require.True(t, status.Ready)
		require.False(t, status.Started)
		if i == 0 {
			require.Equal(t, deadline, status.AuthorizedUntil)
			require.True(t, status.GrantExpires.After(status.AuthorizedUntil))
		}
		require.NoError(t, n.Start())
	}
	n := f.nodes[0]
	require.NoError(t, n.ConnectPeer(t.Context(), b))
	require.ErrorIs(t, n.ConnectPeer(t.Context(), third), ErrPeerUnavailable)
	// Caller-owned maps and slices may be reused after ApplyTopology.
	m := local.Members[0]
	m.PublishTopics[0] = "app/changed"
	require.Equal(t, "app/test", n.policy.Load().members[n.ID()].PublishTopics[0])
	// Preflight and installation report the same conflicting address. The
	// installed view still admits the peer after the failed update.
	conflict := f.cfg.Members[2].ID
	m.ID, m.IPv4, m.IPv6 = conflict, b, f.cfg.Members[2].IPv6
	local.Members = append(local.Members, m)
	want := fmt.Sprintf("duplicate primary address %s: %s and %s", b, f.cfg.Members[1].ID, conflict)
	require.EqualError(t, local.Validate(f.cluster), want)
	require.EqualError(t, n.ApplyTopology(t.Context(), local), want)
	require.NoError(t, n.ConnectPeer(t.Context(), b))
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, n.ConnectPeer(t.Context(), third))
	shortened := time.Now().Add(350 * time.Millisecond)
	limit.Store(&shortened)
	require.NoError(t, n.Revalidate(t.Context()))
	for _, p := range n.Paths() {
		require.Equal(t, shortened, p.AuthorizedUntil)
	}
	require.Eventually(t, func() bool {
		return n.preferredSession(f.cfg.Members[1].ID, false) == nil && n.preferredSession(f.cfg.Members[2].ID, false) == nil
	}, 2*time.Second, 5*time.Millisecond)
	require.True(t, n.ControlStatus().Ready)
}

func TestRestrictedEndpointUpdates(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.link(0, 1)
	f.cfg.Members[0].Restricted = true
	o := f.opts[0]
	o.Topology = f.cfg
	n, err := New(t.Context(), o)
	require.NoError(t, err)
	t.Cleanup(func() { n.Close() })

	m := &f.cfg.Members[1]
	// A TCP client can use any source port on its configured host.
	first := netip.AddrPortFrom(m.Endpoints[0].Address.Addr(), 50123)
	next := netip.MustParseAddrPort("192.0.2.9:50123")
	m.Endpoints[0].Address = netip.AddrPortFrom(next.Addr(), 4242)
	require.NoError(t, n.Revalidate(t.Context()))
	require.True(t, n.endpointAllowed("tcp", first, true))
	require.False(t, n.endpointAllowed("tcp", next, true))
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.False(t, n.endpointAllowed("tcp", first, true))
	require.True(t, n.endpointAllowed("tcp", next, true))
}

func TestTLSAdmissionAndPeerIdentity(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	f.opts[1].Transport.CurvePreferences = []tls.CurveID{tls.CurveP256}
	f.opts[2].Transport.ALPN = "other-app"
	f.opts[3].Transport.CurvePreferences = []tls.CurveID{tls.X25519}
	f.start()
	// New owns its copy even when the caller reuses the options.
	f.opts[1].Transport.CurvePreferences[0] = tls.X25519
	a, b := f.nodes[0], f.nodes[1]
	t.Run("alpn", func(t *testing.T) {
		_, err := f.nodes[2].ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
		require.ErrorContains(t, err, "application protocol")
	})
	t.Run("group", func(t *testing.T) {
		_, err := f.nodes[3].ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
		require.ErrorContains(t, err, "handshake failure")
	})
	// A trusted node at a different endpoint cannot take the intended peer's place.
	f.cfg.Members[2].Endpoints = f.cfg.Members[1].Endpoints
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Error(t, a.ConnectPeer(t.Context(), f.ips[2]))
	require.Empty(t, a.Paths())
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4))
	path, ok := a.PreferredPath(b.id)
	require.True(t, ok)
	require.Equal(t, tls.CurveP256, path.TLSGroup)
}

func TestAddressPairPolicyAndReassignment(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")

	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	done := make(chan error, 2)
	for _, addr := range []netip.Addr{b.Addresses().IPv4, b.Addresses().IPv6} {
		go func() { done <- a.ConnectPeer(t.Context(), addr) }()
	}
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Len(t, a.Paths(), 1)
	require.Equal(t, b.id, a.Paths()[0].Peer)
	require.NoError(t, a.SetPeerPathPolicy(b.id, Blocked))
	require.ErrorIs(t, a.ConnectPeer(t.Context(), b.Addresses().IPv4), ErrPathPolicy)
	require.NoError(t, a.SetPeerPathPolicy(b.id, Auto))
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv6))
	keyAddr := netip.MustParseAddr("10.13.0.99")
	next := labPeer(keyAddr)
	m := f.cfg.Members[1]
	m.ID, m.IPv6 = next, netip.MustParseAddr("fd42::99")
	wrong := f.issue(keyAddr, pki.Scope{}, m.addresses())
	require.Error(t, b.ReloadCertificates(t.Context(), wrong))
	f.cfg.Members = append(f.cfg.Members, m)
	require.Error(t, f.cfg.Validate(f.cluster))
	f.cfg.Members = slices.Delete(f.cfg.Members, 1, 2)
	port, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.True(t, a.shaper.limiter.AllowN(time.Now(), 65536))
	require.NoError(t, port.WriteIP(b.id, testIPv4(a.Addresses().IPv4, b.Addresses().IPv4, "held for previous owner")))
	require.Eventually(t, func() bool { return port.Stats().Queued == 0 }, time.Second, time.Millisecond)
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == 1 }, time.Second, time.Millisecond)
	require.Empty(t, a.Paths())
	owner, ok := a.LookupPeer(b.Addresses().IPv4)
	require.True(t, ok)
	require.Equal(t, next, owner)
	// Both identities share an IPv4 address. Editing the old binding must
	// leave the replacement's configuration independent.
	require.NoError(t, a.SetPeerPathPolicy(b.id, DirectOnly))
	configured, effective := a.PeerPathPolicy(b.id)
	require.Equal(t, DirectOnly, configured)
	require.Equal(t, DirectOnly, effective)
	configured, effective = a.PeerPathPolicy(next)
	require.Equal(t, Auto, configured)
	require.Equal(t, Auto, effective)
	require.NoError(t, a.SetPeerPathPolicy(b.id, Auto))
	require.Error(t, a.ConnectPeerID(t.Context(), b.id))
	require.ErrorIs(t, port.WriteIP(b.id, testIPv4(a.Addresses().IPv4, m.IPv4, "stale binding")), ErrPeerUnavailable)
	require.Error(t, a.ConnectPeer(t.Context(), m.IPv4))
	require.Error(t, port.WriteIP(b.id, testIPv6(a.Addresses().IPv6, b.Addresses().IPv6, 1280)))
}

func TestGatewaySessionCertificateCeiling(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	aIP, bIP := f.ips[0], f.ips[1]
	id := f.cfg.Members[1].ID
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.0.0/16")}
	f.opts[1].Auth.Certificates = f.issue(bIP, pki.Scope{RoutedPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv6))
	received := make(chan []byte, 2)
	sink, err := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, pkt []byte) { received <- pkt }})
	require.NoError(t, err)
	out, err := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	denied := testIPv4(aIP, netip.MustParseAddr("192.0.3.1"), "outside certificate")
	good := testIPv4(aIP, netip.MustParseAddr("192.0.2.1"), "within certificate")
	wide := f.issue(bIP, pki.Scope{RoutedPrefixes: f.cfg.Members[1].RoutedPrefixes})
	require.NoError(t, b.ReloadCertificates(t.Context(), wide))
	require.NoError(t, out.WriteIP(id, denied))
	require.NoError(t, out.WriteIP(id, good))
	select {
	case pkt := <-received:
		require.Equal(t, good, pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("authorized packet did not arrive")
	}
	require.Equal(t, uint64(1), out.Stats().RejectedOutbound)
	// Use the authenticated stream directly to independently exercise ingress authorization.
	stream, err := a.preferredSession(id, false).open(t.Context())
	require.NoError(t, err)
	defer stream.Close()
	_, err = stream.Write([]byte{opIP})
	require.NoError(t, err)
	require.NoError(t, writeFrame(stream, denied))
	require.Eventually(t, func() bool { return sink.Stats().RejectedInbound == 1 }, time.Second, time.Millisecond)
	require.NoError(t, a.SetPeerPathPolicy(id, Blocked))
	require.NoError(t, a.SetPeerPathPolicy(id, Auto))
	require.NoError(t, a.ConnectPeer(t.Context(), b.Addresses().IPv6))
	require.NoError(t, out.WriteIP(id, denied))
	select {
	case pkt := <-received:
		require.Equal(t, denied, pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("new session did not acquire wider authority")
	}
}
