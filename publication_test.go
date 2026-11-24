package nebula

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/stretchr/testify/require"
)

func TestMaximumPublicationAndInventoryFrames(t *testing.T) {
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
	publication := n.publications[id]
	for i := 1; i < maxPublications; i++ {
		n.publications[fmt.Sprintf("%064x", i)] = cachedPublication{expires: publication.expires}
	}
	n.mu.Unlock()
	s, back := &session{peer: other.id}, &session{peer: n.id}
	first := n.advert(s)
	firstBytes, err := json.Marshal(first)
	require.NoError(t, err)
	require.LessOrEqual(t, len(firstBytes), 64<<10)
	require.NotEmpty(t, first.Inventory)
	require.Less(t, len(first.Inventory), maxPublications)

	ids := map[string]bool{}
	for _, page := range []advert{first, n.advert(s)} {
		for _, id := range page.Inventory {
			ids[id] = true
		}
	}
	require.Len(t, ids, maxPublications)
	_, ok := other.learnIntroduction(t.Context(), first.Record, nil)
	require.True(t, ok)
	s.acknowledgedIntro.Store(other.advert(back).Seen)
	steady := n.advert(s)
	require.Empty(t, steady.Record)
	require.Len(t, steady.Inventory, maxPublications)
	steadyBytes, err := json.Marshal(steady)
	require.NoError(t, err)
	require.LessOrEqual(t, len(steadyBytes), 64<<10)
	sub, err := other.Subscribe("app/test")
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, n.ConnectPeer(t.Context(), other.id.IPv4()))
	// Pull the signed maximum-payload publication over the real control stream.
	require.Eventually(t, func() bool { return other.preferredSession(n.id, false) != nil }, time.Second, time.Millisecond)
	wire, err := other.preferredSession(n.id, false).request(t.Context(), 0x07, []byte(id), pki.MaxDocument)
	require.NoError(t, err)
	require.Equal(t, []byte(publication.record), wire)
	body, chain, err := pki.VerifyObjectSignature(wire, n.Cluster().Network(), "publication")
	require.NoError(t, err)
	require.True(t, chain[0].Equal(n.cred.Load().Object.Leaf))
	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &envelope))
	require.Equal(t, id, fmt.Sprintf("%x", sha256.Sum256(envelope["value"])))
	// Push the same DER over the opposite stream and observe local delivery.
	c, err := n.preferredSession(other.id, false).openRequest(t.Context(), 0x06, wire)
	require.NoError(t, err)
	defer c.Close()
	ack, err := io.ReadAll(c)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0, 0, 0}, ack)
	select {
	case received := <-sub.Publications():
		require.Equal(t, id, received.ID)
		require.Len(t, received.Payload, maxPublicationPayload)
	case <-time.After(time.Second):
		t.Fatal("signed publication was not delivered")
	}
}

func TestPublicationRepairAndPolicyWithdrawal(t *testing.T) {
	f := newFixture(t, "tcp", "tcp", "tcp")
	// The first delivery uses push. Only the late joiner polls for inventory.
	f.opts[0].Interval, f.opts[1].Interval = time.Hour, time.Hour
	f.start()
	a, mid, b := f.nodes[0], f.nodes[1], f.nodes[2]
	require.NoError(t, a.ConnectPeer(t.Context(), mid.id.IPv4()))
	_, err := mid.ConnectEndpoint(t.Context(), f.cfg.Members[0].Endpoints[0])
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return len(a.Paths()) == 2 && len(mid.Paths()) == 2
	}, time.Second, time.Millisecond)
	sub, err := b.Subscribe("app/test/update")
	require.NoError(t, err)
	defer sub.Close()
	id, err := a.Publish(t.Context(), "app/test/update", []byte("revision"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		mid.mu.Lock()
		defer mid.mu.Unlock()
		_, ok := mid.publications[id]
		return ok && len(a.backgroundSlots) == 0 && len(mid.backgroundSlots) == 0
	}, 2*time.Second, 10*time.Millisecond)
	mid.mu.Lock()
	cached := mid.publications[id].record
	mid.mu.Unlock()
	// Both direct sessions reach the same neighbor. One push delivers the
	// publication and the receiver has no other neighbor to forward it to.
	require.Equal(t, uint64(len(cached)), a.ControlStatus().BytesScheduled)
	require.Zero(t, mid.ControlStatus().BytesScheduled)
	_, err = b.acceptPublication(t.Context(), nil, cached, strings.Repeat("0", 64))
	require.ErrorContains(t, err, "requested ID")
	require.Empty(t, sub.Publications())
	require.NoError(t, b.ConnectPeer(t.Context(), mid.id.IPv4()))
	select {
	case publication := <-sub.Publications():
		require.Equal(t, id, publication.ID)
		require.Equal(t, a.id, publication.Origin)
	case <-time.After(3 * time.Second):
		t.Fatal("inventory did not repair missed publication")
	}
	duplicate, err := b.acceptPublication(t.Context(), nil, cached, id)
	require.NoError(t, err)
	require.Equal(t, id, duplicate)
	require.Empty(t, sub.Publications())
	f.cfg.Members[0].Topics = []string{"app/metrics"}
	require.NoError(t, b.ApplyTopology(t.Context(), f.cfg))
	_, err = b.acceptPublication(t.Context(), nil, cached, "")
	require.ErrorIs(t, err, ErrPathPolicy)
	b.mu.Lock()
	_, ok := b.publications[id]
	b.mu.Unlock()
	require.False(t, ok)
}
