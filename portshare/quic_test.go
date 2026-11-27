package portshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.d7z.net/nebula/meshwire"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/stretchr/testify/require"
)

func credentials() (*tls.Config, *tls.Config) {
	s := httptest.NewTLSServer(nil)
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return &tls.Config{Certificates: s.TLS.Certificates, NextProtos: []string{meshwire.ALPN}, MinVersion: tls.VersionTLS13}, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{meshwire.ALPN}, MinVersion: tls.VersionTLS13}
}

func testQUICConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1200}
}

type observedSocket struct {
	net.PacketConn
	mute    atomic.Bool
	retries atomic.Uint32
	mu      sync.Mutex
	used    map[string]map[string]bool
}

func (c *observedSocket) WriteTo(b []byte, to net.Addr) (int, error) {
	if c.mute.Load() {
		return len(b), nil
	}
	if len(b) > 0 && b[0]&0xf0 == 0xf0 {
		c.retries.Add(1)
	}
	return c.PacketConn.WriteTo(b, to)
}

func (c *observedSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := c.PacketConn.ReadFrom(b)
	if c.used != nil && e == nil && n >= 21 && b[0]&0xc0 == 0x40 {
		c.mu.Lock()
		m := c.used[a.String()]
		if m == nil {
			m = map[string]bool{}
			c.used[a.String()] = m
		}
		m[string(b[1:21])] = true
		c.mu.Unlock()
	}
	return n, a, e
}

func TestRetryCIDMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	raw := &observedSocket{PacketConn: listenUDP(t), used: map[string]map[string]bool{}}
	u := NewUDP(raw)
	defer u.Close()
	st := &quic.Transport{Conn: u.Mesh(), VerifySourceAddress: func(net.Addr) bool { return true }}
	cfg := testQUICConfig()
	u.Mesh().ConfigureMeshQUIC(st, cfg)
	defer st.Close()
	s, c := credentials()
	l, e := st.Listen(s, cfg)
	require.NoError(t, e)
	defer l.Close()
	old, newPath := &quic.Transport{Conn: listenUDP(t)}, &quic.Transport{Conn: listenUDP(t)}
	defer old.Close()
	defer newPath.Close()
	client, e := old.Dial(ctx, raw.LocalAddr(), c, testQUICConfig())
	require.NoError(t, e)
	defer client.CloseWithError(0, "done")
	server, e := l.Accept(ctx)
	require.NoError(t, e)
	require.Positive(t, raw.retries.Load())
	exchange := func(s string) {
		t.Helper()
		require.NoError(t, client.SendDatagram([]byte(s)))
		b, e := server.ReceiveDatagram(ctx)
		require.NoError(t, e)
		require.Equal(t, s, string(b))
		require.NoError(t, server.SendDatagram(b))
		b, e = client.ReceiveDatagram(ctx)
		require.NoError(t, e)
		require.Equal(t, s, string(b))
	}
	exchange("before")
	path, e := client.AddPath(newPath)
	require.NoError(t, e)
	require.NoError(t, path.Probe(ctx))
	require.NoError(t, path.Switch())
	// Wait for the server to finish validating the new reverse path as well.
	for server.RemoteAddr().String() != newPath.Conn.LocalAddr().String() {
		exchange("migrating")
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	exchange("after")
	raw.mu.Lock()
	defer raw.mu.Unlock()
	first, last := raw.used[old.Conn.LocalAddr().String()], raw.used[newPath.Conn.LocalAddr().String()]
	require.NotEmpty(t, first)
	require.NotEmpty(t, last)
	var distinct bool
	for id := range last {
		if !first[id] {
			distinct = true
		}
	}
	require.True(t, distinct, "fresh destination CID on the new path")
	t.Logf("real Retry, changed UDP source and distinct destination CID, application data echoed from the new path")
}

func TestResetAfterPeerRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	remote := &observedSocket{PacketConn: listenUDP(t)}
	var key quic.StatelessResetKey
	rand.Read(key[:])
	s, c := credentials()
	old := &quic.Transport{Conn: remote, StatelessResetKey: &key}
	defer old.Close()
	l, e := old.Listen(s, testQUICConfig())
	require.NoError(t, e)
	u := NewUDP(listenUDP(t))
	defer u.Close()
	ct := &quic.Transport{Conn: u.Mesh()}
	cfg := testQUICConfig()
	u.Mesh().ConfigureMeshQUIC(ct, cfg)
	defer ct.Close()
	conn, e := ct.Dial(ctx, remote.LocalAddr(), c, cfg)
	require.NoError(t, e)
	srv, e := l.Accept(ctx)
	require.NoError(t, e)
	require.NoError(t, conn.SendDatagram([]byte("warm")))
	_, e = srv.ReceiveDatagram(ctx)
	require.NoError(t, e)
	remote.mute.Store(true)
	require.NoError(t, old.Close())
	remote.mute.Store(false)
	fresh := &quic.Transport{Conn: remote, StatelessResetKey: &key}
	defer fresh.Close()
	_, e = fresh.Listen(s, testQUICConfig())
	require.NoError(t, e)
	require.NoError(t, conn.SendDatagram(make([]byte, 512)))
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("mesh missed authentic reset")
	}
	var reset *quic.StatelessResetError
	require.True(t, errors.As(context.Cause(conn.Context()), &reset))
	require.NoError(t, u.Other().SetReadDeadline(time.Now().Add(40*time.Millisecond)))
	_, _, e = u.Other().ReadFrom(make([]byte, 100))
	require.Error(t, e)
	t.Log("shared client received authenticated stateless reset from restarted peer")
}

func TestResetTokenLifetime(t *testing.T) {
	var registry resetRegistry
	rec := registry.AddProducer()
	first, next := [16]byte{1}, [16]byte{2}
	firstID, newID := quic.ConnectionIDFromBytes([]byte("first")), quic.ConnectionIDFromBytes([]byte("next"))
	rec.RecordEvent(qlog.ParametersSet{
		Initiator:        qlog.InitiatorRemote,
		PreferredAddress: &qlog.PreferredAddress{ConnectionID: firstID, StatelessResetToken: first},
	})
	rec.RecordEvent(qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, DestConnectionID: firstID}})
	rec.RecordEvent(qlog.PacketReceived{
		Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT},
		Frames: []qlog.Frame{{Frame: &qlog.NewConnectionIDFrame{
			SequenceNumber: 2, RetirePriorTo: 2, ConnectionID: newID, StatelessResetToken: next,
		}}},
	})
	require.True(t, registry.owns(first))
	require.False(t, registry.owns(next))
	rec.RecordEvent(qlog.PacketSent{
		Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, DestConnectionID: newID},
		Frames: []qlog.Frame{{Frame: &qlog.RetireConnectionIDFrame{SequenceNumber: 1}}},
	})
	require.False(t, registry.owns(first))
	require.True(t, registry.owns(next))
	require.NoError(t, rec.Close())
	require.False(t, registry.owns(next))
}

func TestCIDRotationOnStableEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	raw := &observedSocket{PacketConn: listenUDP(t), used: map[string]map[string]bool{}}
	u := NewUDP(raw)
	defer u.Close()
	st := &quic.Transport{Conn: u.Mesh()}
	cfg := testQUICConfig()
	u.Mesh().ConfigureMeshQUIC(st, cfg)
	defer st.Close()
	serverTLS, clientTLS := credentials()
	ln, e := st.Listen(serverTLS, cfg)
	require.NoError(t, e)
	defer ln.Close()
	ct := &quic.Transport{Conn: listenUDP(t)}
	defer ct.Close()
	client, e := ct.Dial(ctx, raw.LocalAddr(), clientTLS, testQUICConfig())
	require.NoError(t, e)
	defer client.CloseWithError(0, "done")
	server, e := ln.Accept(ctx)
	require.NoError(t, e)
	stream, e := client.OpenUniStreamSync(ctx)
	require.NoError(t, e)
	chunk := bytes.Repeat([]byte("CID rotation "), 2521)
	type result struct {
		sum   []byte
		count int64
		err   error
	}
	ack := make(chan result, 1)
	go func() {
		stream, err := server.AcceptUniStream(ctx)
		if err != nil {
			ack <- result{err: err}
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, stream)
		ack <- result{h.Sum(nil), n, err}
	}()
	h := sha256.New()
	for range 1536 {
		_, e = stream.Write(chunk)
		require.NoError(t, e)
		h.Write(chunk)
	}
	require.NoError(t, stream.Close())
	select {
	case got := <-ack:
		require.NoError(t, got.err)
		require.Equal(t, int64(len(chunk)*1536), got.count)
		require.Equal(t, h.Sum(nil), got.sum)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	raw.mu.Lock()
	defer raw.mu.Unlock()
	count := len(raw.used[ct.Conn.LocalAddr().String()])
	require.GreaterOrEqual(t, count, 3)
	t.Logf("stable UDP endpoint, %d distinct destination CIDs, %d verified bytes", count, len(chunk)*1536)
}
