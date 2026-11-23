package nebula

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/control"
	"github.com/stretchr/testify/require"
)

func TestManagedRevocationAtHandshakeCompletion(t *testing.T) {
	pool, local, remote := newNodeTestIdentitiesFor(t, cert.Version2, cert.Curve_P256)
	ca, key, err := cert.CreateCA(cert.CAOptions{Name: "configuration authority", Curve: cert.Curve_P256})
	require.NoError(t, err)
	signer, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
	require.NoError(t, err)
	transports := newMemoryDatagramNetwork(netip.MustParseAddrPort("192.0.2.1:4242"), netip.MustParseAddrPort("192.0.2.2:4242"))
	opts := Options{CAPool: pool, Identities: []Identity{local.identity}}
	nodes := make([]*Node, len(transports))
	for i, tr := range transports {
		opts.Transport = tr
		opts.Control = &ControlOptions{Network: "test", Authority: ca, StateFile: filepath.Join(t.TempDir(), "config")}
		n, err := New(t.Context(), opts)
		require.NoError(t, err)
		nodes[i] = n
		t.Cleanup(func() { require.NoError(t, n.Close()); require.NoError(t, n.Wait()) })
	}
	n := nodes[0]
	cc, err := n.handshake.certVerifier()(remote.identity.Certificate)
	require.NoError(t, err)
	fp, err := cert.CalculateAlternateFingerprint(remote.identity.Certificate)
	require.NoError(t, err)
	require.NotEqual(t, cc.Fingerprint, fp)
	cfg := control.Config{Format: 1, Network: "test", Revision: 1, Revoked: []string{fp}}
	wire, err := control.Sign(cfg, ca, signer)
	require.NoError(t, err)
	require.NoError(t, n.ApplyNetworkConfig(t.Context(), wire))
	// The credential passed verification before the new snapshot was installed.
	pending := &hostInfo{vpnAddrs: []netip.Addr{remote.addr}, localIndexId: 41, connectionState: &connectionState{peerCert: cc}}
	_, err = n.handshake.CheckAndComplete(pending, handshakePacketStage0, n.engine)
	require.ErrorIs(t, err, cert.ErrBlockListed)
	require.False(t, n.handshake.completeOutbound(pending, pending.vpnAddrs))
	require.Nil(t, n.engine.hostMap.QueryIndex(pending.localIndexId))
	_, err = nodes[1].handshake.certVerifier()(remote.identity.Certificate)
	require.NoError(t, err)
}

func TestManagedConfigurationPersistence(t *testing.T) {
	ca, key, err := cert.CreateCA(cert.CAOptions{Name: "operator", Curve: cert.Curve_P256})
	require.NoError(t, err)
	signer, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
	require.NoError(t, err)
	pool, local, _ := newNodeTestIdentities(t)
	stateFile := filepath.Join(t.TempDir(), "config")
	openNode := func() *Node {
		t.Helper()
		tr := newMemoryDatagramNetwork(netip.MustParseAddrPort("192.0.2.1:4242"))[0]
		n, err := New(t.Context(), Options{
			CAPool: pool, Identities: []Identity{local.identity}, Transport: tr,
			Control: &ControlOptions{Network: "test", Authority: ca, StateFile: stateFile},
		})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, n.Close()) })
		return n
	}
	n := openNode()
	var docs [][]byte
	for i := range 12 {
		wire, err := control.Sign(control.Config{Format: 1, Network: "test", Revision: uint64(i + 1)}, ca, signer)
		require.NoError(t, err)
		docs = append(docs, wire)
	}
	require.NoError(t, n.ApplyNetworkConfig(t.Context(), docs[0]))
	// An unchanged snapshot can be acknowledged while a datagram is being written.
	permit := n.engine.paths.submit
	require.NoError(t, permit.Acquire(t.Context(), 1))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	err = n.ApplyNetworkConfig(ctx, docs[0])
	cancel()
	permit.Release(1)
	require.NoError(t, err)
	fp, err := local.identity.Certificate.Fingerprint()
	require.NoError(t, err)
	conflict, err := control.Sign(control.Config{Format: 1, Network: "test", Revision: 1, Revoked: []string{fp}}, ca, signer)
	require.NoError(t, err)
	require.ErrorContains(t, n.ApplyNetworkConfig(t.Context(), conflict), "conflicting")

	done := make(chan error, len(docs))
	start := make(chan struct{})
	for _, doc := range docs {
		go func() {
			<-start
			done <- n.ApplyNetworkConfig(t.Context(), doc)
		}()
	}
	close(start)
	for range docs {
		if err := <-done; err != nil {
			require.ErrorContains(t, err, "stale")
		}
	}
	require.EqualValues(t, len(docs), n.ControlStatus().Revision)
	_, digest, err := control.Verify(docs[len(docs)-1], "test", ca)
	require.NoError(t, err)
	require.Equal(t, digest, n.ControlStatus().Digest)
	require.ErrorContains(t, n.ApplyNetworkConfig(t.Context(), docs[0]), "stale")

	sub, err := n.Subscribe("app/test")
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, n.ApplyNetworkConfig(cancelled, docs[0]), context.Canceled)
	require.NoError(t, n.Close())
	_, open := <-sub.Events()
	require.False(t, open)
	require.ErrorIs(t, n.ApplyNetworkConfig(t.Context(), docs[0]), ErrNodeClosed)

	restored := openNode()
	require.Equal(t, digest, restored.ControlStatus().Digest)
	require.Equal(t, docs[len(docs)-1], restored.SignedNetworkConfig())
	require.NoError(t, os.Remove(stateFile))
	require.NoError(t, os.Mkdir(stateFile, 0700))
	later, err := control.Sign(control.Config{Format: 1, Network: "test", Revision: uint64(len(docs) + 1)}, ca, signer)
	require.NoError(t, err)
	require.Error(t, restored.ApplyNetworkConfig(t.Context(), later))
	require.Equal(t, digest, restored.ControlStatus().Digest)
}
