package nebula

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestInstanceConflictRecovery(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "administrator selects instance"
		if revoke {
			name = "withdraw one credential"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "tcp", "tcp", "tcp")
			id := labPeer(f.ips[1])
			f.cfg.Members[0].BytesPerSecond = 1
			var withdrawn atomic.Bool
			firstCert := f.opts[1].Auth.Certificates.Client.Leaf
			f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
				if withdrawn.Load() && c.Chain[0].Equal(firstCert) {
					return time.Time{}, errors.New("withdrawn")
				}
				return time.Time{}, nil
			}
			if revoke {
				f.opts[2].Auth.Certificates.Client = f.issue(id, pki.Scope{})
			} else {
				f.opts[2].Auth.Certificates = f.opts[1].Auth.Certificates
			}
			f.start()
			client, a, b := f.nodes[0], f.nodes[1], f.nodes[2]
			ep := f.cfg.Members[2].Endpoints[0]
			require.NoError(t, client.ConnectPeerID(t.Context(), id))
			_, err := client.ConnectEndpoint(t.Context(), ep)
			require.ErrorIs(t, err, ErrInstanceConflict)
			require.Eventually(t, func() bool {
				return len(client.InstanceConflicts()) == 1
			}, 2*time.Second, time.Millisecond)
			port, _, received := queueShapedPackets(t, client, b, id.IPv4(), "in flight", "queued")
			require.NoError(t, a.Close())
			require.Eventually(t, func() bool { return port.Stats().RejectedOutbound == 2 }, 2*time.Second, time.Millisecond)
			require.ErrorIs(t, port.WriteIP(id, testIPv4(client.id.IPv4(), id.IPv4(), "held")), ErrInstanceConflict)
			require.Empty(t, client.Paths())
			holds := client.InstanceConflicts()
			require.Len(t, holds, 1)
			require.Equal(t, id, holds[0].Peer)
			require.Equal(t, a.instance, holds[0].Retained)
			require.NotZero(t, holds[0].ConfirmedAt)
			require.False(t, holds[0].Selected)
			require.False(t, holds[0].EvidenceTruncated)
			_, err = client.ConnectEndpoint(t.Context(), ep)
			require.ErrorIs(t, err, ErrInstanceConflict)
			if revoke {
				withdrawn.Store(true)
				require.NoError(t, client.Revalidate(t.Context()))
			} else {
				require.ErrorIs(t, client.ResolveInstanceConflict(id, client.instance), ErrInstanceConflict)
				require.NoError(t, client.ResolveInstanceConflict(id, b.instance))
			}
			holds = client.InstanceConflicts()
			require.Len(t, holds, 1)
			require.True(t, holds[0].Selected)
			require.Equal(t, b.instance, holds[0].Retained)
			_, err = client.ConnectEndpoint(t.Context(), ep)
			require.NoError(t, err)
			require.Empty(t, client.InstanceConflicts())
			f.cfg.Members[0].BytesPerSecond = 0
			require.NoError(t, client.ApplyTopology(t.Context(), f.cfg))
			fresh := testIPv4(client.id.IPv4(), id.IPv4(), "new delivery")
			require.NoError(t, port.WriteIP(id, fresh))
			select {
			case got := <-received:
				require.Equal(t, "new delivery", got)
			case <-time.After(time.Second):
				t.Fatal("missing post-recovery packet")
			}
			require.Equal(t, b.instance, client.Paths()[0].Instance)
		})
	}
}

func TestInstanceConflictEvidenceLimit(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	id := labPeer(f.ips[1])
	f.opts[2].Auth.Certificates = f.opts[1].Auth.Certificates
	f.start()
	client, duplicate := f.nodes[0], f.nodes[2]
	require.NoError(t, client.ConnectPeerID(t.Context(), id))
	for range 16 {
		require.NoError(t, duplicate.ReloadCertificates(t.Context(), LocalCertificates{Client: f.issue(id, pki.Scope{})}))
		_, err := client.ConnectEndpoint(t.Context(), f.cfg.Members[2].Endpoints[0])
		require.ErrorIs(t, err, ErrInstanceConflict)
	}
	require.Eventually(t, func() bool {
		holds := client.InstanceConflicts()
		return len(holds) == 1 && holds[0].EvidenceTruncated
	}, 2*time.Second, time.Millisecond)
	require.NoError(t, client.Revalidate(t.Context()))
	require.NoError(t, client.ResolveInstanceConflict(id, f.nodes[1].instance))
	require.Empty(t, client.InstanceConflicts())
}

func TestInstanceRestartAndSignedIntroductions(t *testing.T) {
	f := newFixture(t, "both", "both", "tcp")
	f.opts[2].Auth.Certificates = f.opts[1].Auth.Certificates
	f.start()
	client, a, b := f.nodes[0], f.nodes[1], f.nodes[2]
	record := a.localIntroduction(a.policy.Load()).record
	discovered := func() IPObservation {
		rows := slices.DeleteFunc(client.InspectIP(a.id.IPv4()), func(o IPObservation) bool { return o.Source != "introduction" })
		require.Len(t, rows, 1)
		return rows[0]
	}
	_, ok := client.learnIntroduction(t.Context(), record, nil)
	require.True(t, ok)
	first := discovered()
	require.NotEmpty(t, first.Advertised)
	endpoint := first.Advertised[0]
	first.Advertised[0] = Endpoint{}
	require.Equal(t, endpoint, discovered().Advertised[0])
	_, ok = client.learnIntroduction(t.Context(), record, nil)
	require.True(t, ok)
	require.Equal(t, first.LastSeen, discovered().LastSeen)
	require.NoError(t, client.ConnectPeerID(t.Context(), a.id))
	_, ok = client.learnIntroduction(t.Context(), b.localIntroduction(b.policy.Load()).record, nil)
	require.False(t, ok)
	require.True(t, slices.ContainsFunc(client.InspectIP(a.id.IPv4()), func(o IPObservation) bool {
		return o.Source == "introduction" && o.Instance == b.instance && o.Decision == "instance mismatch"
	}))
	before := a.ControlStatus().Instance
	require.NoError(t, a.ReloadCertificates(t.Context(), LocalCertificates{Client: f.issue(a.id, pki.Scope{})}))
	require.Equal(t, before, a.ControlStatus().Instance)
	require.NoError(t, a.Close())
	require.Eventually(t, func() bool { _, ok := client.PreferredPath(a.id); return !ok }, time.Second, time.Millisecond)
	_, err := client.ConnectEndpoint(t.Context(), f.cfg.Members[2].Endpoints[0])
	require.NoError(t, err)
	_, ok = client.learnIntroduction(t.Context(), b.localIntroduction(b.policy.Load()).record, nil)
	require.True(t, ok)
	_, ok = client.learnIntroduction(t.Context(), record, nil)
	require.False(t, ok)
	require.Equal(t, b.instance, client.Paths()[0].Instance)
}

func TestInstanceConflictRetainsBothHandshakeRoles(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	id := labPeer(f.ips[1])
	f.opts[2].Auth.Certificates.Client = f.issue(id, pki.Scope{})
	incumbentCert := f.opts[1].Auth.Certificates.Client.Leaf
	var withdrawn atomic.Int32
	f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if c.Chain[0].Equal(incumbentCert) && int32(c.Usage) == withdrawn.Load() {
			return time.Time{}, ErrPathPolicy
		}
		return time.Time{}, nil
	}
	f.start()
	client, incumbent := f.nodes[0], f.nodes[1]
	_, err := client.ConnectEndpoint(t.Context(), f.cfg.Members[1].Endpoints[0])
	require.NoError(t, err)
	_, err = incumbent.ConnectEndpoint(t.Context(), f.cfg.Members[0].Endpoints[0])
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(client.Paths()) == 2 }, time.Second, time.Millisecond)
	ep := f.cfg.Members[2].Endpoints[0]
	_, err = client.ConnectEndpoint(t.Context(), ep)
	require.ErrorIs(t, err, ErrInstanceConflict)
	var role x509.ExtKeyUsage
	require.Eventually(t, func() bool {
		for _, row := range client.InspectIP(id.IPv4()) {
			if row.Source == "conflict" && row.Decision == "retained" {
				role = row.Usage
				return true
			}
		}
		return false
	}, 2*time.Second, time.Millisecond)
	require.NoError(t, incumbent.Close())
	require.Eventually(t, func() bool { return len(client.Paths()) == 0 }, time.Second, time.Millisecond)
	withdrawn.Store(int32(role))
	require.NoError(t, client.Revalidate(t.Context()))
	// The other handshake role still authorizes the incumbent.
	_, err = client.ConnectEndpoint(t.Context(), ep)
	require.ErrorIs(t, err, ErrInstanceConflict)
}

func TestInspectAddressClaims(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	duplicate, err := pki.NewPeerID(f.ips[1], labPeer(f.ips[2]).IPv6())
	require.NoError(t, err)
	f.opts[2].Auth.Certificates.Client = f.issue(duplicate, pki.Scope{})
	f.opts[2].Topology = Topology{Network: "lab", Members: []Member{{IPv4: duplicate.IPv4(), IPv6: duplicate.IPv6()}}}
	prefix := netip.MustParsePrefix("172.30.0.0/24")
	vip := netip.MustParseAddr("10.13.0.200")
	for i := range 2 {
		f.cfg.Members[i].AnycastIPs = []netip.Addr{vip}
		f.cfg.Members[i].RoutedPrefixes = []netip.Prefix{prefix}
	}
	f.start()
	client, b := f.nodes[0], f.nodes[2]
	_, err = client.ConnectEndpoint(t.Context(), f.cfg.Members[2].Endpoints[0])
	require.Error(t, err)
	_, ok := client.learnIntroduction(t.Context(), b.localIntroduction(b.policy.Load()).record, nil)
	require.False(t, ok)
	for _, ip := range []netip.Addr{duplicate.IPv4(), duplicate.IPv6()} {
		obs := client.InspectIP(ip)
		require.True(t, slices.ContainsFunc(obs, func(o IPObservation) bool {
			return o.Peer == duplicate && o.Source == "certificate" && o.Decision == "address conflict" && o.Instance == (InstanceID{}) && o.CertificateSHA256 != "" && o.Usage == x509.ExtKeyUsageServerAuth
		}))
		require.True(t, slices.ContainsFunc(obs, func(o IPObservation) bool {
			return o.Peer == duplicate && o.Source == "introduction" && o.Decision == "address conflict" && o.Instance == b.instance
		}))
	}
	for _, q := range []struct {
		ip    netip.Addr
		match string
	}{{vip, "anycast"}, {prefix.Addr().Next(), "routed"}} {
		rows := client.InspectIP(q.ip)
		require.Len(t, rows, 2)
		for _, r := range rows {
			require.Equal(t, q.match, r.Match)
			require.Equal(t, "configured", r.Decision)
		}
	}
}

func TestConcurrentInstanceAdmission(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp", "tcp")
	id := labPeer(f.ips[1])
	for i := 2; i < len(f.opts); i++ {
		f.opts[i].Auth.Certificates.Client = f.issue(id, pki.Scope{})
	}
	f.opts[0].Topology = Topology{Network: f.cfg.Network, Members: f.cfg.Members[:1]}
	var withdrawn atomic.Pointer[x509.Certificate]
	f.opts[0].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
		if leaf := withdrawn.Load(); leaf != nil && c.Chain[0].Equal(leaf) {
			return time.Time{}, ErrPathPolicy
		}
		return time.Time{}, nil
	}
	f.start()
	client := f.nodes[0]
	type dialResult struct {
		index int
		err   error
	}
	results := make(chan dialResult, 3)
	for i := 1; i < len(f.opts); i++ {
		go func() {
			_, err := client.ConnectEndpoint(t.Context(), f.cfg.Members[i].Endpoints[0])
			results <- dialResult{i, err}
		}()
	}
	var winner int
	var refused []int
	for range 3 {
		r := <-results
		if r.err == nil {
			require.Zero(t, winner)
			winner = r.index
		} else {
			require.ErrorIs(t, r.err, ErrInstanceConflict)
			refused = append(refused, r.index)
		}
	}
	require.NotZero(t, winner)
	require.Len(t, refused, 2)
	require.Eventually(t, func() bool {
		var held int
		for _, row := range client.InspectIP(id.IPv4()) {
			if row.Source == "conflict" && row.Decision == "held out" {
				held++
			}
		}
		return held == 2
	}, 2*time.Second, time.Millisecond)
	require.NoError(t, f.nodes[winner].Close())
	require.Eventually(t, func() bool { return len(client.Paths()) == 0 }, time.Second, time.Millisecond)
	require.NoError(t, client.ResolveInstanceConflict(id, f.nodes[winner].instance))
	withdrawn.Store(f.opts[winner].Auth.Certificates.Client.Leaf)
	require.NoError(t, client.Revalidate(t.Context()))
	port, err := client.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, err)
	require.ErrorIs(t, port.WriteIP(id, testIPv4(client.id.IPv4(), id.IPv4(), "await selection")), ErrInstanceConflict)
	owner, ok := client.LookupPeer(id.IPv4())
	require.True(t, ok)
	require.Equal(t, id, owner)
	for _, i := range refused {
		_, err := client.ConnectEndpoint(t.Context(), f.cfg.Members[i].Endpoints[0])
		require.ErrorIs(t, err, ErrInstanceConflict)
	}
	keep := f.nodes[refused[1]]
	require.NoError(t, client.ResolveInstanceConflict(id, keep.instance))
	_, err = client.ConnectEndpoint(t.Context(), f.cfg.Members[refused[1]].Endpoints[0])
	require.NoError(t, err)
	require.Equal(t, keep.instance, client.Paths()[0].Instance)
}
