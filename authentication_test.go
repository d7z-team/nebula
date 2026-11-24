package nebula

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestMaximumEventAndInventoryFrames(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	pair := &f.opts[0].Certificates.Client
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	leaf.ExtraExtensions = append(leaf.Extensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}, Value: make([]byte, (24<<10)-len(leaf.Raw)-len(leaf.RawIssuer)-128)})
	pair.Certificate[0], err = x509.CreateCertificate(rand.Reader, leaf, f.ca, leaf.PublicKey, f.key)
	require.NoError(t, err)
	for i := range f.opts {
		f.opts[i].Interval = time.Hour
	}
	f.start()
	// All three default roles must own their certificate data after New.
	clear(pair.Certificate[0])
	pair.Certificate[0] = nil
	n, other := f.nodes[0], f.nodes[1]
	id, err := n.Publish(t.Context(), "app/test", make([]byte, 4096))
	require.NoError(t, err)
	n.mu.Lock()
	event := n.events[id]
	for i := 1; i < maxEvents; i++ {
		n.events[fmt.Sprintf("%064x", i)] = cachedEvent{expires: event.expires}
	}
	n.mu.Unlock()
	s, back := &session{peer: other.id}, &session{peer: n.id}
	first := n.advert(s)
	firstBytes, err := json.Marshal(first)
	require.NoError(t, err)
	require.LessOrEqual(t, len(firstBytes), 64<<10)
	require.NotEmpty(t, first.Inventory)
	require.Less(t, len(first.Inventory), maxEvents)

	ids := map[string]bool{}
	for _, page := range []advert{first, n.advert(s)} {
		for _, id := range page.Inventory {
			ids[id] = true
		}
	}
	require.Len(t, ids, maxEvents)
	_, ok := other.learn(first.Record)
	require.True(t, ok)
	s.acknowledgedIntro.Store(other.advert(back).Seen)
	steady := n.advert(s)
	require.Empty(t, steady.Record)
	require.Len(t, steady.Inventory, maxEvents)
	steadyBytes, err := json.Marshal(steady)
	require.NoError(t, err)
	require.LessOrEqual(t, len(steadyBytes), 64<<10)
	sub, err := other.Subscribe("app/test")
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, n.ConnectPeer(t.Context(), other.id.IPv4()))
	// Pull the signed maximum-payload event over the real control stream.
	require.Eventually(t, func() bool { return other.preferredSession(n.id, false) != nil }, time.Second, time.Millisecond)
	wire, err := other.preferredSession(n.id, false).request(t.Context(), opGetEvent, []byte(id), pki.MaxDocument)
	require.NoError(t, err)
	require.Equal(t, []byte(event.record), wire)
	_, chain, err := pki.VerifyObjectSignature(wire, n.Cluster().Network(), "event")
	require.NoError(t, err)
	require.True(t, chain[0].Equal(n.cred.Load().Object.Leaf))
	// Push the same DER over the opposite stream and observe local delivery.
	_, err = n.preferredSession(other.id, false).request(t.Context(), opEvent, wire, 0)
	require.NoError(t, err)
	select {
	case received := <-sub.Events():
		require.Equal(t, id, received.ID)
		require.Len(t, received.Payload, maxEventPayload)
	case <-time.After(time.Second):
		t.Fatal("signed event was not delivered")
	}
}

func TestIntroductionAfterSignerReload(t *testing.T) {
	f := newFixture(t, "tcp", "tcp")
	f.start()
	sender, receiver := f.nodes[0], f.nodes[1]
	to := &session{peer: receiver.id}
	_, ok := receiver.learn(sender.advert(to).Record)
	require.True(t, ok)
	to.acknowledgedIntro.Store(receiver.advert(&session{peer: sender.id}).Seen)
	require.Empty(t, sender.advert(to).Record)

	set := f.opts[0].Certificates
	set.Object = f.issue(sender.id, pki.Scope{})
	require.NoError(t, sender.ReloadCertificates(t.Context(), set))
	record := sender.advert(to).Record
	_, chain, err := pki.VerifyObjectSignature(record, sender.Cluster().Network(), "introduction")
	require.NoError(t, err)
	require.True(t, set.Object.Leaf.Equal(chain[0]))
	peer, ok := receiver.learn(record)
	require.True(t, ok)
	require.Equal(t, sender.id, peer)
}

// pausingSigner lets a real TLS handshake select its certificate before renewal.
type pausingSigner struct {
	crypto.Signer
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (s *pausingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.once.Do(func() { close(s.entered); <-s.resume })
	return s.Signer.Sign(r, digest, opts)
}

func TestReloadDuringTLSHandshake(t *testing.T) {
	for _, kind := range []string{"udp", "tcp", "relay"} {
		t.Run(kind, func(t *testing.T) {
			var f *fixture
			if kind == "relay" {
				f = newFixture(t, "tcp", "tcp", "tcp")
				f.link(0, 1)
				f.link(1, 2)
				m := f.cfg.Members[1]
				m.Transit = true
				f.cfg.Members[1] = m
			} else {
				f = newFixture(t, kind, kind)
			}
			last := len(f.opts) - 1
			addr := f.ips[last]
			id := labPeer(addr)
			cert := f.opts[last].Certificates.Client
			old, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)
			var denied atomic.Bool
			f.opts[last].CheckChain = func(_ context.Context, c ChainCheck) (time.Time, error) {
				if denied.Load() && c.Local && c.Chain[0].Equal(old) {
					return time.Time{}, errors.New("withdrawn local leaf")
				}
				return time.Time{}, nil
			}
			for i := range f.opts {
				f.opts[i].Interval = time.Hour
				f.opts[i].DialTimeout = 4 * time.Second
			}
			signer := &pausingSigner{Signer: cert.PrivateKey.(crypto.Signer), entered: make(chan struct{}), resume: make(chan struct{})}
			var resume sync.Once
			release := func() { resume.Do(func() { close(signer.resume) }) }
			// For relay, first establish outer legs with the original credential, so
			// the paused signature belongs to the end-to-end TLS handshake.
			if kind != "relay" {
				cert.PrivateKey = signer
				f.opts[last].Certificates.Server = cert
			}
			f.start()
			a, b := f.nodes[0], f.nodes[last]
			defer release()
			if kind == "relay" {
				require.NoError(t, a.ConnectPeer(t.Context(), f.ips[1]))
				require.NoError(t, f.nodes[1].ConnectPeer(t.Context(), addr))
				require.NoError(t, a.SetPeerPathPolicy(addr, RelayOnly))
				cert.PrivateKey = signer
				creds := f.opts[last].Certificates
				creds.Server = cert
				require.NoError(t, b.ReloadCertificates(t.Context(), creds))
			}
			dial := make(chan error, 1)
			go func() { dial <- a.ConnectPeer(t.Context(), addr) }()
			select {
			case <-signer.entered:
			case <-time.After(4 * time.Second):
				t.Fatal("TLS signer was not selected")
			}
			interKey, err := pki.GenerateKey("p256")
			require.NoError(t, err)
			req, err := pki.CreateCSR(interKey, pkix.Name{CommonName: "renewal CA"})
			require.NoError(t, err)
			root := pki.Issuer{Chain: []*x509.Certificate{f.ca}, Signer: f.key}
			now := time.Now().Truncate(time.Second)
			inter, err := root.IssueCA(req, pki.CAProfile{Subject: req.Subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour / 2)}, sha256.Sum256(req.RawSubjectPublicKeyInfo))
			require.NoError(t, err)
			key, err := pki.GenerateKey("ed25519")
			require.NoError(t, err)
			req, err = pki.CreateCSR(key, pkix.Name{CommonName: id.String()})
			require.NoError(t, err)
			issuer := pki.Issuer{Chain: []*x509.Certificate{inter, f.ca}, Signer: interKey}
			leaf, err := issuer.IssueLeaf(req, pki.Enrollment{Scope: pki.Scope{Network: "lab"}, IPv4: addr, IPv6: id.IPv6(), Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning}, PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute)})
			require.NoError(t, err)
			replacement := LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}
			require.Error(t, b.ReloadCertificates(t.Context(), replacement))
			replacement.Client.Certificate = append(replacement.Client.Certificate, inter.Raw)
			wrong := replacement
			wrong.Client.PrivateKey = f.key
			require.Error(t, b.ReloadCertificates(t.Context(), wrong))
			require.Equal(t, old.SerialNumber.String(), b.ControlStatus().Serial)
			require.NoError(t, b.ReloadCertificates(t.Context(), replacement))
			release()
			require.NoError(t, <-dial)
			require.Eventually(t, func() bool { return b.preferredSession(a.id, false) != nil }, time.Second, 5*time.Millisecond)
			s := a.preferredSession(labPeer(addr), false)
			require.NotNil(t, s)
			require.Equal(t, kind, s.kind)
			require.True(t, s.state.PeerCertificates[0].Equal(old))
			response, err := s.request(t.Context(), opPing, []byte("old session"), 16)
			require.NoError(t, err)
			require.Equal(t, "old session", string(response))
			denied.Store(true)
			require.NoError(t, b.Revalidate(t.Context()))
			require.True(t, b.ControlStatus().Ready)
			require.Eventually(t, func() bool { return a.preferredSession(labPeer(addr), false) == nil }, 2*time.Second, 5*time.Millisecond)
			require.NoError(t, a.ConnectPeer(t.Context(), addr))
			require.True(t, a.preferredSession(labPeer(addr), false).state.PeerCertificates[0].Equal(leaf))
		})
	}
}

func TestReloadRejectsExpiredHostDecision(t *testing.T) {
	f := newFixture(t, "tcp")
	var cut time.Time
	var renew atomic.Bool
	f.opts[0].CheckChain = func(ctx context.Context, c ChainCheck) (time.Time, error) {
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
	cert := f.issue(n.id, pki.Scope{})
	renew.Store(true)
	err := n.ReloadCertificates(t.Context(), LocalCertificates{Client: cert})
	require.ErrorIs(t, err, ErrPathPolicy)
	require.Equal(t, before.Serial, n.ControlStatus().Serial)
	require.True(t, n.ControlStatus().Ready)
	require.NoError(t, n.Revalidate(t.Context()))
	require.False(t, n.ControlStatus().Ready)
}
