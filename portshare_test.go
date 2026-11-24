package nebula

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"
	"code.d7z.net/d7z-team/nebula/portshare"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type countingMeshSocket struct {
	meshwire.SharedSocket
	writes atomic.Uint64
}

func (s *countingMeshSocket) WriteTo(b []byte, to net.Addr) (int, error) {
	s.writes.Add(1)
	return s.SharedSocket.WriteTo(b, to)
}

func TestShareSitesAndPolicy(t *testing.T) {
	f := newFixture(t, "both", "both")
	socks := make([]*portshare.UDP, 2)
	tcp := make([]*portshare.TCP, 2)
	for i := range f.opts {
		f.sockets[i].limit = 0
		socks[i] = portshare.NewUDP(f.opts[i].UDP4)
		tcp[i] = portshare.NewTCP(f.opts[i].TCP4)
		t.Cleanup(func() { socks[i].Close(); tcp[i].Close() })
		f.opts[i].UDP4 = socks[i].Mesh()
		f.opts[i].TCP4 = tcp[i].Mesh()
	}
	meter := &countingMeshSocket{SharedSocket: socks[1].Mesh()}
	f.opts[1].UDP4 = meter
	f.start()
	a, b := f.nodes[0], f.nodes[1]
	names := []string{"one.example.test", "two.example.test", "third.example.test"}
	roots := x509.NewCertPool()
	certs := make(map[string]*tls.Certificate)
	for i, name := range names {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, e)
		ca := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
		require.NoError(t, e)
		leaf, e := x509.ParseCertificate(der)
		require.NoError(t, e)
		roots.AddCert(leaf)
		certs[name] = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := certs[hello.ServerName]; c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("unknown site")
	}}
	streamEnd := make(chan struct{})
	webHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			io.WriteString(w, "before\n")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-streamEnd:
			}
			io.WriteString(w, "after\n")
			return
		}
		fmt.Fprintf(w, "%s|%s|%s|%s", r.Host, r.Proto, r.TLS.ServerName, r.RemoteAddr)
	})
	h2 := &http.Server{TLSConfig: cfg.Clone(), Handler: webHandler}
	h3 := &http3.Server{TLSConfig: cfg.Clone(), Handler: webHandler}
	go h2.ServeTLS(tcp[1].Other(), "", "")
	go h3.Serve(socks[1].Other())
	t.Cleanup(func() { h2.Close(); h3.Close() })
	remote := f.sockets[1].LocalAddr().String()
	siteTr := &quic.Transport{Conn: socks[0].Other()}
	t.Cleanup(func() { siteTr.Close() })
	mkH3 := func(versions ...quic.Version) *http3.Transport {
		if len(versions) == 0 {
			versions = []quic.Version{quic.Version1}
		}
		tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, QUICConfig: &quic.Config{Versions: versions}, Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			return siteTr.Dial(ctx, f.sockets[1].LocalAddr(), tlsCfg, qcfg)
		}}
		t.Cleanup(func() { tr.Close() })
		return tr
	}
	web3 := mkH3()
	get := func(tr http.RoundTripper, name, proto string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		req, e := http.NewRequestWithContext(ctx, "GET", "https://"+name+"/", nil)
		require.NoError(t, e)
		resp, e := tr.RoundTrip(req)
		require.NoError(t, e)
		defer resp.Body.Close()
		data, e := io.ReadAll(resp.Body)
		require.NoError(t, e)
		require.Equal(t, proto, resp.Proto)
		require.Equal(t, certs[name].Leaf.SerialNumber, resp.TLS.PeerCertificates[0].SerialNumber)
		prefix := name + "|" + proto + "|" + name + "|"
		require.True(t, strings.HasPrefix(string(data), prefix), string(data))
		if proto == "HTTP/3.0" {
			require.Equal(t, f.sockets[0].LocalAddr().String(), strings.TrimPrefix(string(data), prefix))
		}
	}
	ht := func(v2 bool) *http.Transport {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Protocols: new(http.Protocols), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", remote)
		}}
		if v2 {
			tr.Protocols.SetHTTP2(true)
		} else {
			tr.Protocols.SetHTTP1(true)
		}
		t.Cleanup(tr.CloseIdleConnections)
		return tr
	}
	web2, web1 := ht(true), ht(false)
	in := make(chan []byte, 4)
	_, e := b.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, p []byte) { in <- bytes.Clone(p) }})
	require.NoError(t, e)
	out, e := a.OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
	require.NoError(t, e)
	deliver := func() {
		t.Helper()
		p := testIPv4(f.ips[0], f.ips[1], "mesh delivery")
		require.NoError(t, out.WriteIP(labPeer(f.ips[1]), p))
		select {
		case r := <-in:
			require.Equal(t, p, r)
		case <-time.After(3 * time.Second):
			t.Fatal("inner IP delivery timeout")
		}
	}
	require.NoError(t, a.ConnectPeer(t.Context(), f.ips[1]))
	deliver()
	for _, name := range names {
		get(web3, name, "HTTP/3.0")
		get(web2, name, "HTTP/2.0")
		get(web1, name, "HTTP/1.1")
	}
	get(mkH3(quic.Version2), names[0], "HTTP/3.0")
	bad := &tls.Config{NextProtos: []string{meshwire.ALPN}, MinVersion: tls.VersionTLS13, RootCAs: f.opts[0].Roots, ServerName: f.ips[1].String()}
	badCtx, stopBad := context.WithTimeout(t.Context(), 2*time.Second)
	badConn, badErr := siteTr.Dial(badCtx, f.sockets[1].LocalAddr(), bad, &quic.Config{Versions: []quic.Version{quic.Version1}})
	if badErr == nil {
		select {
		case <-badConn.Context().Done():
			badErr = context.Cause(badConn.Context())
		case <-badCtx.Done():
			t.Fatal("missing TLS rejection")
		}
	}
	stopBad()
	require.ErrorContains(t, badErr, "certificate")
	deliver()
	p, e := a.dialEndpoint(t.Context(), labPeer(f.ips[1]), Endpoint{"tcp", netip.MustParseAddrPort(remote)})
	require.NoError(t, e)
	require.Equal(t, "tcp", p.kind)
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(b.Paths(), func(p PathStatus) bool {
			return p.Transport == "udp" && p.Endpoint == addrPort(f.sockets[0].LocalAddr())
		})
	}, time.Second, time.Millisecond)
	t.Logf("two transports, three SNI certificates, H1/H2/H3 and mesh; H3 and mesh UDP share %s -> %s", f.sockets[0].LocalAddr(), remote)
	attempt := func() {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		q, err := a.transports[false].Dial(ctx, f.sockets[1].LocalAddr(), a.tlsConfig(b.id, false), a.transports[false].config)
		if q != nil {
			q.CloseWithError(0, "test")
		}
		require.Error(t, err)
	}
	streamCtx, stopStream := context.WithTimeout(t.Context(), 8*time.Second)
	defer stopStream()
	request, e := http.NewRequestWithContext(streamCtx, "GET", "https://"+names[0]+"/stream", nil)
	require.NoError(t, e)
	ongoing, e := web3.RoundTrip(request)
	require.NoError(t, e)
	defer ongoing.Body.Close()
	first := make([]byte, 7)
	_, e = io.ReadFull(ongoing.Body, first)
	require.NoError(t, e)
	require.Equal(t, "before\n", string(first))
	deliver()
	for _, mode := range []PathMode{RelayOnly, Blocked} {
		require.NoError(t, b.SetPeerPathPolicy(f.ips[0], mode))
		before := meter.writes.Load()
		attempt()
		b.punch(a.id)
		get(web3, names[0], "HTTP/3.0")
		get(mkH3(), names[1], "HTTP/3.0")
		require.Equal(t, before, meter.writes.Load())
		t.Logf("policy %d: zero mesh socket writes to sole direct peer, existing and new H3 requests passed", mode)
	}
	close(streamEnd)
	end, e := io.ReadAll(ongoing.Body)
	require.NoError(t, e)
	require.Equal(t, "after\n", string(end))
	require.NoError(t, b.SetPeerPathPolicy(f.ips[0], Auto))
	// Apply a restrictive topology with no authorized neighbors at this listener.
	top := f.cfg
	top.Members = slices.Clone(top.Members)
	top.Members[1].Restricted = true
	require.NoError(t, b.ApplyTopology(t.Context(), top))
	before := meter.writes.Load()
	attempt()
	b.punch(a.id)
	get(mkH3(), names[2], "HTTP/3.0")
	require.Equal(t, before, meter.writes.Load())
	b.Close()
	get(mkH3(), names[2], "HTTP/3.0")
	get(ht(true), names[0], "HTTP/2.0")
}

func TestShareCloseOther(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			f := newFixture(t, network, network)
			var closeOther func() error
			if network == "udp" {
				u := portshare.NewUDP(f.opts[1].UDP4)
				t.Cleanup(func() { u.Close() })
				f.opts[1].UDP4 = u.Mesh()
				closeOther = u.Other().Close
			} else {
				u := portshare.NewTCP(f.opts[1].TCP4)
				t.Cleanup(func() { u.Close() })
				f.opts[1].TCP4 = u.Mesh()
				closeOther = u.Other().Close
			}
			f.start()
			require.NoError(t, closeOther())
			require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
			out, e := f.nodes[0].OpenIPPort(IPPortOptions{Deliver: func(PeerID, []byte) {}})
			require.NoError(t, e)
			c := make(chan []byte, 1)
			_, e = f.nodes[1].OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, p []byte) { c <- bytes.Clone(p) }})
			require.NoError(t, e)
			pkt := testIPv4(f.ips[0], f.ips[1], "other closed")
			require.NoError(t, out.WriteIP(labPeer(f.ips[1]), pkt))
			select {
			case got := <-c:
				require.Equal(t, pkt, got)
			case <-time.After(time.Second):
				t.Fatal("missing receipt")
			}
		})
	}
}

type stalledSiteSocket struct {
	net.PacketConn
	started chan struct{}
	resume  chan struct{}
}

func (c *stalledSiteSocket) WriteTo(b []byte, to net.Addr) (int, error) {
	if bytes.Equal(b, []byte("site write")) {
		close(c.started)
		<-c.resume
	}
	return c.PacketConn.WriteTo(b, to)
}

func TestShareShutdownDuringWebsiteWrite(t *testing.T) {
	f := newFixture(t, "udp", "udp")
	raw := &stalledSiteSocket{f.opts[1].UDP4, make(chan struct{}), make(chan struct{})}
	share := portshare.NewUDP(raw)
	t.Cleanup(func() { share.Close() })
	f.opts[1].UDP4 = share.Mesh()
	f.start()
	resume := sync.OnceFunc(func() { close(raw.resume) })
	t.Cleanup(resume)
	require.NoError(t, f.nodes[0].ConnectPeer(t.Context(), f.ips[1]))
	require.Eventually(t, func() bool { return len(f.nodes[1].Paths()) != 0 }, time.Second, time.Millisecond)
	site := make(chan error, 1)
	go func() {
		_, err := share.Other().WriteTo([]byte("site write"), f.opts[0].UDP4.LocalAddr())
		site <- err
	}()
	<-raw.started
	stopped := make(chan error, 1)
	go func() { stopped <- f.nodes[1].Close() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("node shutdown is waiting for the website")
	}
	resume()
	require.NoError(t, <-site)
}
