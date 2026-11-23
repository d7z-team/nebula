package nebula

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
	"github.com/stretchr/testify/require"
)

func TestQueueRevokedDuringShaping(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	var denied atomic.Bool
	f.opts[0].CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if denied.Load() && !c.Local {
			return time.Time{}, errors.New("peer withdrawn")
		}
		return time.Time{}, nil
	}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
	in := make(chan []byte, 1)
	_, err := b.OpenIPPort(func(pkt []byte) { in <- pkt })
	require.NoError(t, err)
	port, err := a.OpenIPPort(func([]byte) {})
	require.NoError(t, err)
	require.True(t, a.limiter.AllowN(time.Now(), 65536))
	require.NoError(t, port.WriteIP(b.id.IPv4(), testIPv4(a.id.IPv4(), b.id.IPv4(), "pending")))
	require.Eventually(t, func() bool { return port.Stats().Queued == 0 }, time.Second, time.Millisecond)
	denied.Store(true)
	require.NoError(t, a.Revalidate(t.Context()))
	require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == 1 }, time.Second, time.Millisecond)
	require.Empty(t, in)
}

func TestClearPendingByEitherAddress(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
	received := make(chan []byte, 3)
	_, err := b.OpenIPPort(func(pkt []byte) { received <- pkt })
	require.NoError(t, err)
	port, err := a.OpenIPPort(func([]byte) {})
	require.NoError(t, err)
	require.True(t, a.limiter.AllowN(time.Now(), 65536))
	held := testIPv4(a.id.IPv4(), b.id.IPv4(), "held")
	require.NoError(t, port.WriteIP(b.id.IPv4(), held))
	require.Eventually(t, func() bool { return port.Stats().Queued == 0 }, time.Second, time.Millisecond)
	require.NoError(t, port.WriteIP(b.id.IPv4(), held))
	require.Equal(t, 1, port.ClearPending(b.id.IPv6()))

	fresh := testIPv4(a.id.IPv4(), b.id.IPv4(), "fresh")
	require.NoError(t, port.WriteIP(b.id.IPv4(), fresh))
	f.cfg.Members[0].BytesPerSecond = 0
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	select {
	case got := <-received:
		require.Equal(t, fresh, got)
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
	existing, err := x509.ParseCertificate(o.Certificates.Client.Certificate[0])
	require.NoError(t, err)
	existing.ExtraExtensions = existing.Extensions
	existing.NotAfter = time.Now().Truncate(time.Second).Add(2 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, existing, f.ca, existing.PublicKey, f.key)
	require.NoError(t, err)
	o.Certificates.Client = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: o.Certificates.Client.PrivateKey}
	f.start()
	require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
	fresh, key := f.issue(labPeer(f.ips[1]))
	require.NoError(t, f.nodes[1].ReloadCertificates(t.Context(), LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{fresh.Raw}, PrivateKey: key}}))
	require.Eventually(t, func() bool { return len(f.nodes[0].Peers()) == 0 && len(f.nodes[1].Peers()) == 0 }, 4*time.Second, 20*time.Millisecond)
	require.True(t, f.nodes[1].ControlStatus().Ready)
	require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
	require.Equal(t, fresh.SerialNumber.String(), f.nodes[0].Peers()[0].Serial)
}

func TestEventRepairAndPolicyWithdrawal(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	// The first delivery uses push. Only the late joiner polls for inventory.
	f.opts[0].Interval, f.opts[1].Interval = time.Hour, time.Hour
	f.start()
	a, mid, b := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, a.ConnectPeer(t.Context(), mid.id.IPv4()))
	sub, err := b.Subscribe("app/test/update")
	require.NoError(t, err)
	defer sub.Close()
	id, err := a.Publish(t.Context(), "app/test/update", []byte("revision"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		mid.mu.Lock()
		defer mid.mu.Unlock()
		_, ok := mid.events[id]
		return ok
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, b.ConnectPeer(t.Context(), mid.id.IPv4()))
	select {
	case event := <-sub.Events():
		require.Equal(t, id, event.ID)
		require.Equal(t, a.id, event.Origin)
	case <-time.After(3 * time.Second):
		t.Fatal("inventory did not repair missed event")
	}
	mid.mu.Lock()
	cached := mid.events[id].record
	mid.mu.Unlock()
	duplicate, err := b.acceptEvent(t.Context(), nil, cached)
	require.NoError(t, err)
	require.Equal(t, id, duplicate)
	require.Empty(t, sub.Events())
	f.cfg.Members[0].Topics = []string{"app/metrics"}
	require.NoError(t, b.ApplyTopology(t.Context(), f.cfg))
	_, err = b.acceptEvent(t.Context(), nil, cached)
	require.ErrorIs(t, err, ErrPathPolicy)
	b.mu.Lock()
	_, ok := b.events[id]
	b.mu.Unlock()
	require.False(t, ok)
}

func TestRoleCredentialsAndObjectAuthorization(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	a, b := f.ips[0], f.ips[1]
	issue := func(usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		csr, err := pki.CreateCSR(key, pkix.Name{})
		require.NoError(t, err)
		ca := pki.Issuer{Chain: []*x509.Certificate{f.ca}, Signer: f.key}
		leaf, err := ca.IssueLeaf(csr, pki.Enrollment{Name: "enterprise", Scope: pki.Scope{Network: "lab"}, IPv4: a, IPv6: labPeer(a).IPv6(), Usages: []x509.ExtKeyUsage{usage}, PublicKeyHash: sha256.Sum256(csr.RawSubjectPublicKeyInfo), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(20 * time.Minute)})
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	}
	creds := LocalCertificates{Client: issue(x509.ExtKeyUsageClientAuth), Server: issue(x509.ExtKeyUsageServerAuth), Object: issue(x509.ExtKeyUsageCodeSigning)}
	f.opts[0].Certificates = creds
	var deny atomic.Bool
	var node atomic.Pointer[Node]
	f.opts[1].CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if n := node.Load(); n != nil {
			_ = n.Peers()
		} // host callbacks may query live state
		if deny.Load() && c.Object && c.Member == labPeer(a) {
			return time.Time{}, errors.New("publisher suspended")
		}
		return time.Time{}, nil
	}
	f.start()
	x, y := f.nodes[0], f.nodes[1]
	node.Store(y)
	require.NoError(t, y.ConnectPeer(t.Context(), a))
	require.NoError(t, x.ConnectPeer(t.Context(), b))
	s := y.selectSession(labPeer(a), false)
	require.Equal(t, creds.Server.Certificate[0], s.state.PeerCertificates[0].Raw)
	sub, err := y.Subscribe("app/test/control")
	require.NoError(t, err)
	defer sub.Close()
	id, err := x.Publish(t.Context(), "app/test/control", []byte("host decision"))
	require.NoError(t, err)
	select {
	case got := <-sub.Events():
		require.Equal(t, id, got.ID)
	case <-time.After(time.Second):
		t.Fatal("missing signed event")
	}
	deny.Store(true)
	require.NoError(t, y.Revalidate(t.Context()))
	require.Same(t, s, y.selectSession(labPeer(a), false))
	y.mu.Lock()
	_, cached := y.events[id]
	y.mu.Unlock()
	require.False(t, cached)
	// A peer's TLS key cannot stand in for this member's delegated object key.
	wrong := creds
	wrong.Object = creds.Client
	require.Error(t, x.ReloadCertificates(t.Context(), wrong))
	untrusted := newFixture(t, "tcp", "tcp")
	f.opts[0].Roots.AddCert(untrusted.ca)
	require.Error(t, y.ReloadCertificates(t.Context(), untrusted.opts[1].Certificates))
	require.Error(t, x.ReloadCertificates(t.Context(), LocalCertificates{Client: creds.Server, Server: creds.Server, Object: creds.Object}))
}

func TestConcurrentTopologyAndCredentialUpdates(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.start()
	n, remote := f.nodes[0], f.nodes[1]
	require.NoError(t, n.ConnectPeer(t.Context(), remote.id.IPv4()))
	s := n.selectSession(remote.id, false)
	seed := f.cfg
	seed.Members = slices.Clone(f.cfg.Members)
	seed.Members = slices.Delete(seed.Members, 2, 3)
	errs := make(chan error, 3)
	go func() {
		for range 8 {
			if err := n.ApplyTopology(t.Context(), seed); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	go func() {
		for range 8 {
			if err := n.ReloadCertificates(t.Context(), f.opts[0].Certificates); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	go func() {
		for range 8 {
			if err := n.Revalidate(t.Context()); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()
	for range 3 {
		require.NoError(t, <-errs)
	}
	require.Same(t, s, n.selectSession(remote.id, false))
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, n.ConnectPeer(t.Context(), f.ips[2]))
}

func TestChainDeadlineAndTopologyAdmission(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	a, b, third := f.ips[0], f.ips[1], f.ips[2]
	// Each endpoint receives only the two members it currently needs.
	local := f.cfg
	local.Members = slices.Clone(f.cfg.Members)
	local.Members = slices.Delete(local.Members, 2, 3)
	require.NoError(t, local.Validate())
	deadline := time.Now().Add(time.Hour)
	var limit atomic.Pointer[time.Time]
	limit.Store(&deadline)
	f.opts[0].CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if !c.Local && !c.Object {
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
		require.NoError(t, n.Start())
	}
	n := f.nodes[0]
	require.NoError(t, n.ConnectPeer(t.Context(), b))
	require.ErrorIs(t, n.ConnectPeer(t.Context(), third), ErrPeerUnavailable)
	// Caller-owned maps and slices may be reused after ApplyTopology.
	m := local.Members[0]
	m.Topics[0] = "app/changed"
	require.Equal(t, "app/test", n.policy.Load().members[labPeer(a)].Topics[0])
	// Preflight and installation report the same conflicting address. The
	// installed view still admits the peer after the failed update.
	conflict, err := pki.NewPeerID(b, labPeer(a).IPv6())
	require.NoError(t, err)
	m.IPv4 = conflict.IPv4()
	m.IPv6 = conflict.IPv6()
	local.Members = append(local.Members, m)
	err = local.Validate()
	require.Error(t, err)
	require.EqualError(t, n.ApplyTopology(t.Context(), local), err.Error())
	require.NoError(t, n.ConnectPeer(t.Context(), b))
	require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
	require.NoError(t, n.ConnectPeer(t.Context(), third))
	shortened := time.Now().Add(350 * time.Millisecond)
	limit.Store(&shortened)
	require.NoError(t, n.Revalidate(t.Context()))
	for _, p := range n.Peers() {
		require.Equal(t, shortened, p.AuthorizedUntil)
	}
	require.Eventually(t, func() bool {
		return n.selectSession(labPeer(b), false) == nil && n.selectSession(labPeer(third), false) == nil
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

func TestPeerNameAndTLSAdmission(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	for name, change := range map[string]func(*tls.Config){
		"expected peer": func(c *tls.Config) { c.ServerName = f.ips[2].String() },
		"alpn":          func(c *tls.Config) { c.NextProtos = []string{"other-app"} },
		"group":         func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} },
		"trust":         func(c *tls.Config) { c.RootCAs = x509.NewCertPool() },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := a.tlsConfig(b.id, false)
			change(cfg)
			d := tls.Dialer{Config: cfg}
			c, err := d.DialContext(t.Context(), "tcp", b.o.TCP4.Addr().String())
			if c != nil {
				c.Close()
			}
			require.Error(t, err)
		})
	}
	// A trusted node at a different endpoint cannot take the intended peer's place.
	f.cfg.Members[2].Endpoints = f.cfg.Members[1].Endpoints
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Error(t, a.ConnectPeer(t.Context(), f.ips[2]))
	require.Empty(t, a.Peers())
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv4()))
}

func TestAddressPairPolicyAndReassignment(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")

	f.cfg.Members[0].BytesPerSecond = 1
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	done := make(chan error, 2)
	for _, addr := range []netip.Addr{b.id.IPv4(), b.id.IPv6()} {
		go func() { done <- a.ConnectPeer(t.Context(), addr) }()
	}
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Len(t, a.Peers(), 1)
	require.Equal(t, b.id, a.Peers()[0].Peer)
	require.NoError(t, a.SetPeerPathPolicy(b.id.IPv6(), Blocked))
	require.ErrorIs(t, a.ConnectPeer(t.Context(), b.id.IPv4()), ErrPathPolicy)
	require.NoError(t, a.SetPeerPathPolicy(b.id.IPv4(), Auto))
	require.NoError(t, a.ConnectPeer(t.Context(), b.id.IPv6()))
	next, err := pki.NewPeerID(b.id.IPv4(), netip.MustParseAddr("fd42::99"))
	require.NoError(t, err)
	wrong, key := f.issue(next)
	require.Error(t, b.ReloadCertificates(t.Context(), LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{wrong.Raw}, PrivateKey: key}}))
	m := f.cfg.Members[1]
	m.IPv4, m.IPv6 = next.IPv4(), next.IPv6()
	f.cfg.Members = append(f.cfg.Members, m)
	require.Error(t, f.cfg.Validate())
	f.cfg.Members = slices.Delete(f.cfg.Members, 1, 2)
	port, err := a.OpenIPPort(func([]byte) {})
	require.NoError(t, err)
	require.True(t, a.limiter.AllowN(time.Now(), 65536))
	require.NoError(t, port.WriteIP(b.id.IPv4(), testIPv4(a.id.IPv4(), b.id.IPv4(), "held for previous owner")))
	require.Eventually(t, func() bool { return port.Stats().Queued == 0 }, time.Second, time.Millisecond)
	require.NoError(t, a.ApplyTopology(t.Context(), f.cfg))
	require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == 1 }, time.Second, time.Millisecond)
	require.Empty(t, a.Peers())
	require.Error(t, a.ConnectPeer(t.Context(), next.IPv4()))
	require.Error(t, port.WriteIP(b.id.IPv6(), testIPv6(a.id.IPv6(), b.id.IPv6(), 1280)))
}

func TestGatewaySessionCertificateCeiling(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	aIP, bIP := f.ips[0], f.ips[1]
	id := labPeer(bIP)
	f.cfg.Members[1].RoutedPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.0.0/16")}
	narrow, key := f.issue(id, netip.MustParsePrefix("192.0.2.0/24"))
	f.opts[1].Certificates.Client = tls.Certificate{Certificate: [][]byte{narrow.Raw}, PrivateKey: key}
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	require.NoError(t, a.ConnectPeer(t.Context(), id.IPv6()))
	received := make(chan []byte, 2)
	sink, err := b.OpenIPPort(func(pkt []byte) { received <- pkt })
	require.NoError(t, err)
	out, err := a.OpenIPPort(func([]byte) {})
	require.NoError(t, err)
	denied := testIPv4(aIP, netip.MustParseAddr("192.0.3.1"), "outside certificate")
	good := testIPv4(aIP, netip.MustParseAddr("192.0.2.1"), "within certificate")
	wide, k := f.issue(id, f.cfg.Members[1].RoutedPrefixes...)
	require.NoError(t, b.ReloadCertificates(t.Context(), LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{wide.Raw}, PrivateKey: k}}))
	require.NoError(t, out.WriteIP(id.IPv6(), denied))
	require.NoError(t, out.WriteIP(bIP, good))
	select {
	case pkt := <-received:
		require.Equal(t, good, pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("authorized packet did not arrive")
	}
	require.Equal(t, uint64(1), out.Stats().RejectedOutbound)
	// Use the authenticated stream directly to independently exercise ingress authorization.
	require.NoError(t, a.selectSession(id, false).sendIP(denied))
	require.Eventually(t, func() bool { return sink.Stats().RejectedInbound == 1 }, time.Second, time.Millisecond)
	require.NoError(t, a.SetPeerPathPolicy(bIP, Blocked))
	require.NoError(t, a.SetPeerPathPolicy(id.IPv6(), Auto))
	require.NoError(t, a.ConnectPeer(t.Context(), id.IPv6()))
	require.NoError(t, out.WriteIP(bIP, denied))
	select {
	case pkt := <-received:
		require.Equal(t, denied, pkt)
	case <-time.After(2 * time.Second):
		t.Fatal("new session did not acquire wider authority")
	}
}
