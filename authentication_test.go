package nebula

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gopkg.d7z.net/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestIntroductionAfterSignerReload(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.start()
	sender, receiver := f.nodes[0], f.nodes[1]
	to := &session{peer: receiver.id}
	ad, _ := sender.advert(to)
	_, ok := receiver.learnIntroduction(t.Context(), ad.Record, nil)
	require.True(t, ok)
	set := f.opts[0].Auth.Certificates
	renewed := f.issue(sender.Addresses().IPv4, pki.Scope{})
	for _, next := range []LocalCertificates{{Node: renewed.Node, Grant: set.Grant}, renewed} {
		ack, _ := receiver.advert(&session{peer: sender.id})
		to.acknowledgedIntro.Store(ack.Seen)
		ad, _ = sender.advert(to)
		require.Empty(t, ad.Record)
		require.NoError(t, sender.ReloadCertificates(t.Context(), next))
		ad, _ = sender.advert(to)
		record := ad.Record
		_, chain, err := pki.VerifyObjectSignature(record, sender.Cluster().Network(), "introduction")
		require.NoError(t, err)
		require.True(t, grantLeaf(t, next).Equal(chain[0]))
		require.True(t, slices.ContainsFunc(chain[1:], next.Node.Leaf.Equal))
		peer, ok := receiver.learnIntroduction(t.Context(), record, nil)
		require.True(t, ok)
		require.Equal(t, sender.id, peer)
	}
}

// Model an outgoing handshake after TLS has authenticated the remote node.
func startGrantWrite(local, remote *Node, w io.Writer) <-chan error {
	s := session{n: local, peer: remote.ID(), outgoing: true, state: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{remote.cred.Load().Node.Leaf},
	}}
	done := make(chan error, 1)
	go func() { done <- s.writeGrant(local.ctx, w, local.cred.Load()) }()
	return done
}

func TestGrantWriteRechecksPolicy(t *testing.T) {
	f := newFixture(t, "", "")
	peer := f.cfg.Members[1].ID
	entered := make(chan struct{})
	pause, resume := context.WithCancel(t.Context())
	defer resume()
	var denied atomic.Bool
	f.opts[0].Auth.CheckChain = func(ctx context.Context, check ChainCheck) (time.Time, error) {
		if check.Member == peer {
			if denied.Load() {
				return time.Time{}, ErrPathPolicy
			}
			close(entered)
			<-pause.Done()
		}
		return time.Time{}, ctx.Err()
	}
	f.start()
	n := f.nodes[0]
	var sent bytes.Buffer
	write := startGrantWrite(n, f.nodes[1], &sent)
	select {
	case <-entered:
	case err := <-write:
		t.Fatalf("grant write finished before the host check: %v", err)
	}
	denied.Store(true)
	require.NoError(t, n.Revalidate(t.Context()))
	resume()
	require.ErrorIs(t, <-write, ErrPathPolicy)
	require.Zero(t, sent.Len())
}

func TestRevalidateDuringGrantWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t, "", "")
		f.start()
		n, peer := f.nodes[0], f.nodes[1]
		w, r := net.Pipe()
		defer w.Close()
		defer r.Close()
		first := startGrantWrite(n, peer, w)
		synctest.Wait()

		// Both reviews commit while the first grant is blocked.
		reviews := make(chan error, 2)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { reviews <- n.Revalidate(ctx) }()
		synctest.Wait()
		cancel()
		go func() { reviews <- n.ApplyTopology(t.Context(), f.cfg) }()
		synctest.Wait()
		require.Empty(t, reviews)

		// A later handshake to the same peer belongs to neither snapshot.
		later, reader := net.Pipe()
		defer later.Close()
		defer reader.Close()
		require.NoError(t, later.SetWriteDeadline(time.Now().Add(time.Second)))
		second := startGrantWrite(n, peer, later)
		synctest.Wait()
		body, err := readFrame(r, grantHeaderBytes+maxCredentialBytes)
		require.NoError(t, err)
		require.Equal(t, bytes.Join(n.cred.Load().Grant, nil), body[grantHeaderBytes:])
		require.NoError(t, <-first)
		synctest.Wait()
		require.Len(t, reviews, 2)
		for range 2 {
			require.NoError(t, <-reviews)
		}

		go func() { reviews <- n.Revalidate(t.Context()) }()
		synctest.Wait()
		require.Empty(t, reviews)
		time.Sleep(time.Second)
		require.ErrorIs(t, <-second, os.ErrDeadlineExceeded)
		require.NoError(t, <-reviews)
	})
}

func TestReloadDuringTLSHandshake(t *testing.T) {
	for _, kind := range []string{"udp", "tcp", "relay"} {
		t.Run(kind, func(t *testing.T) {
			var f *fixture
			if kind == "relay" {
				f = newFixture(t, "tcp", "tcp", "tcp")
				f.link(0, 1)
				f.link(1, 2)
				f.cfg.Members[1].Transit = true
			} else {
				f = newFixture(t, kind, kind)
			}
			last := len(f.opts) - 1
			addr := f.ips[last]
			id := f.cfg.Members[last].ID
			old := f.opts[last].Auth.Certificates.Node.Leaf
			// Pause the dialer after it receives the target's old TLS leaf.
			// Neighbor introductions use the same signing key as TLS.
			entered := make(chan struct{})
			paused, resume := context.WithCancel(t.Context())
			defer resume()
			pause := sync.OnceFunc(func() {
				close(entered)
				<-paused.Done()
			})
			f.opts[0].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
				if c.Usage == x509.ExtKeyUsageServerAuth && c.Chain[0].Equal(old) {
					pause()
				}
				return time.Time{}, ctx.Err()
			}
			var denied atomic.Bool
			f.opts[last].Auth.CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
				if denied.Load() && c.Local && c.Chain[0].Equal(old) {
					return time.Time{}, errors.New("withdrawn local leaf")
				}
				return time.Time{}, nil
			}
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
				f.opts[i].DialTimeout = 4 * time.Second
			}
			f.start()
			a, b := f.nodes[0], f.nodes[last]
			if kind == "relay" {
				require.NoError(t, a.SetPeerPathPolicy(id, RelayOnly))
			}
			dial := make(chan error, 1)
			go func() { dial <- a.ConnectPeer(t.Context(), addr) }()
			select {
			case <-entered:
			case err := <-dial:
				t.Fatalf("dial completed before checking the target's TLS certificate: %v", err)
			case <-time.After(4 * time.Second):
				t.Fatal("dialer did not receive the target's TLS certificate")
			}
			replacement := f.issue(addr, pki.Scope{})
			replacement.Grant = f.opts[last].Auth.Certificates.Grant
			wrong := replacement
			wrong.Node.PrivateKey = f.key
			require.Error(t, b.ReloadCertificates(t.Context(), wrong))
			require.NoError(t, b.ReloadCertificates(t.Context(), replacement))
			resume()
			require.NoError(t, <-dial)
			s := a.preferredSession(id, false)
			require.NotNil(t, s)
			require.Equal(t, kind, s.kind)
			require.True(t, s.state.PeerCertificates[0].Equal(old))
			response, err := s.request(t.Context(), opPing, []byte("old session"), 16)
			require.NoError(t, err)
			require.Equal(t, "old session", string(response))
			path, ok := b.PreferredPath(a.id)
			require.True(t, ok)
			require.Equal(t, old.SerialNumber.String(), path.LocalNodeSerial)
			denied.Store(true)
			require.NoError(t, b.Revalidate(t.Context()))
			require.True(t, b.ControlStatus().Ready)
			// Withdrawal also closes the relay's physical connection to the target.
			// Each observer sees its own connection close before it can redial.
			for _, observer := range f.nodes[:last] {
				require.Eventually(t, func() bool {
					return !slices.ContainsFunc(observer.Paths(), func(p PathStatus) bool {
						return p.Peer == id && p.NodeSerial == old.SerialNumber.String()
					})
				}, 2*time.Second, 5*time.Millisecond, "old path at %s", observer.ID())
			}
			require.NoError(t, a.ConnectPeer(t.Context(), addr))
			require.True(t, a.preferredSession(id, false).state.PeerCertificates[0].Equal(replacement.Node.Leaf))
		})
	}
}

func TestReloadRejectsExpiredHostDecision(t *testing.T) {
	f := newFixture(t, "tcp")
	var cut time.Time
	var renew atomic.Bool
	f.opts[0].Auth.CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
		if !renew.Load() {
			return time.Time{}, nil
		}
		if c.Usage == x509.ExtKeyUsageClientAuth {
			cut = time.Now().Add(25 * time.Millisecond)
			return cut, nil
		}
		if c.Usage == x509.ExtKeyUsageServerAuth {
			select {
			case <-time.After(time.Until(cut)):
			case <-ctx.Done():
				return time.Time{}, ctx.Err()
			}
		}
		return time.Time{}, nil
	}
	f.start()
	n := f.nodes[0]
	before := n.ControlStatus()
	cert := f.issue(n.Addresses().IPv4, pki.Scope{})
	renew.Store(true)
	err := n.ReloadCertificates(t.Context(), cert)
	require.ErrorIs(t, err, ErrPathPolicy)
	require.Equal(t, before.GrantSerial, n.ControlStatus().GrantSerial)
	require.True(t, n.ControlStatus().Ready)
	require.NoError(t, n.Revalidate(t.Context()))
	require.False(t, n.ControlStatus().Ready)
}

// Retain the decrypted writes on the reserved stream so disclosure is checked
// at the wire boundary, including when the remote side aborts admission.
func TestGrantDisclosure(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			f := newFixture(t, transport, transport)
			f.start()
			a, b := f.nodes[0], f.nodes[1]
			require.NoError(t, a.ConnectPeerID(t.Context(), b.ID()))
			require.Eventually(t, func() bool { return b.preferredSession(a.ID(), false) != nil }, time.Second, time.Millisecond)
			clientState := a.preferredSession(b.ID(), false).state
			serverState := b.preferredSession(a.ID(), false).state
			for _, st := range []tls.ConnectionState{clientState, serverState} {
				require.Len(t, st.PeerCertificates, 1)
				leaf := st.PeerCertificates[0]
				require.Empty(t, leaf.IPAddresses)
				_, scoped, err := pki.CertificateScope(leaf)
				require.NoError(t, err)
				require.False(t, scoped)
			}

			// Give a second cluster the same ordinary root and node key. Only
			// its grant and pinned issuing CA differ from the original server.
			_, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			req, err := pki.CreateCSR(key, pkix.Name{})
			require.NoError(t, err)
			scope, _, err := pki.CertificateScope(f.ca)
			require.NoError(t, err)
			v4, v6 := f.cluster.MemberPrefixes()
			otherCA, err := f.root.IssueCA(req, pki.CAProfile{
				Subject: f.ca.Subject, NotBefore: f.ca.NotBefore, NotAfter: f.ca.NotAfter,
				Scope: &scope, PermittedIPs: []netip.Prefix{v4, v6},
			}, sha256.Sum256(req.RawSubjectPublicKeyInfo))
			require.NoError(t, err)
			second := *f
			second.ca, second.key = otherCA, key
			opts := f.opts[1]
			opts.Auth.ClusterCA = otherCA
			addresses := pki.Addresses{IPv4: netip.MustParseAddr("10.13.0.89"), IPv6: netip.MustParseAddr("fd42::89")}
			opts.Auth.Certificates.Grant = second.issue(b.Addresses().IPv4, pki.Scope{}, addresses).Grant
			opts.Transport = TransportOptions{}
			opts.Topology = Topology{Network: "lab", Members: []Member{{ID: b.ID(), IPv4: addresses.IPv4, IPv6: addresses.IPv6}}}
			other, err := New(t.Context(), opts)
			require.NoError(t, err)
			defer other.Close()
			require.NoError(t, other.Start())

			for _, tc := range []struct {
				name                   string
				server                 *Node
				trust                  bool
				clientGrant            [][]byte
				wantClient, wantServer bool
			}{
				{"known member", b, true, nil, true, true},
				{"same key at other cluster", other, true, nil, false, false},
				{"unknown entry", b, false, nil, false, false},
				{"another member's grant", b, true, b.cred.Load().Grant, true, false},
				{"same key with foreign grant", b, true, second.issue(a.Addresses().IPv4, pki.Scope{}).Grant, true, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					view := f.cfg
					if !tc.trust {
						view.Members = view.Members[:1]
					}
					// A detached test node has no previously learned introductions.
					o := f.opts[0]
					o.Topology = view
					o.Transport = TransportOptions{}
					local, err := New(t.Context(), o)
					require.NoError(t, err)
					defer local.Close()
					require.NoError(t, local.Start())
					left, right := net.Pipe()
					defer left.Close()
					defer right.Close()
					deadline := time.Now().Add(2 * time.Second)
					require.NoError(t, left.SetDeadline(deadline))
					require.NoError(t, right.SetDeadline(deadline))
					var sent, replied bytes.Buffer
					type stream struct {
						io.Reader
						io.Writer
					}
					out := &session{n: local, state: clientState, outgoing: true}
					in := &session{n: tc.server, state: serverState}
					done := make(chan error, 1)
					go func() {
						defer right.Close()
						done <- in.exchangeGrants(t.Context(), stream{right, io.MultiWriter(&replied, right)}, tc.server.cred.Load())
					}()
					creds := *local.cred.Load()
					if tc.clientGrant != nil {
						creds.Grant = tc.clientGrant
					}
					clientErr := out.exchangeGrants(t.Context(), stream{left, io.MultiWriter(&sent, left)}, &creds)
					left.Close()
					serverErr := <-done
					require.Equal(t, tc.wantClient, bytes.Contains(sent.Bytes(), creds.Grant[0]))
					require.Equal(t, tc.wantServer, bytes.Contains(replied.Bytes(), tc.server.cred.Load().Grant[0]))
					if tc.wantServer {
						require.NoError(t, clientErr)
						require.NoError(t, serverErr)
					} else {
						require.Error(t, clientErr)
						require.Error(t, serverErr)
					}
				})
			}
		})
	}
}
