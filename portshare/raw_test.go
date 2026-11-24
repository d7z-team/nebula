package portshare

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, e)
	t.Cleanup(func() { p.Close() })
	return p
}

func readDatagram(t *testing.T, c net.PacketConn) ([]byte, net.Addr) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
	b := make([]byte, 65535)
	n, a, e := c.ReadFrom(b)
	require.NoError(t, e)
	return b[:n], a
}

func fragmentedClientHello(t *testing.T, protos []string) []byte {
	l, r := net.Pipe()
	defer r.Close()
	defer l.Close()
	go tls.Client(l, &tls.Config{ServerName: "example.test", NextProtos: protos}).Handshake()
	var h [5]byte
	_, e := io.ReadFull(r, h[:])
	require.NoError(t, e)
	buf := make([]byte, binary.BigEndian.Uint16(h[3:]))
	_, e = io.ReadFull(r, buf)
	require.NoError(t, e)
	var out []byte
	for len(buf) > 0 {
		n := min(len(buf), 97)
		binary.BigEndian.PutUint16(h[3:], uint16(n))
		out = append(out, h[:]...)
		out = append(out, buf[:n]...)
		buf = buf[n:]
	}
	return out
}

func TestTCPByteReplay(t *testing.T) {
	raw, e := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, e)
	p := NewTCP(raw)
	defer p.Close()
	for _, protos := range [][]string{nil, {"acme-tls/1"}, {"custom"}, {"h2", meshwire.ALPN}, {meshwire.ALPN}} {
		b := fragmentedClientHello(t, protos)
		c, e := net.Dial("tcp4", raw.Addr().String())
		require.NoError(t, e)
		for chunk := range slices.Chunk(b, 23) {
			_, e = c.Write(chunk)
			require.NoError(t, e)
		}
		l := p.Other()
		if slices.Equal(protos, []string{meshwire.ALPN}) {
			l = p.Mesh()
		}
		peer, e := l.Accept()
		require.NoError(t, e)
		require.Equal(t, c.LocalAddr().String(), peer.RemoteAddr().String())
		require.Equal(t, c.RemoteAddr().String(), peer.LocalAddr().String())
		got := make([]byte, len(b))
		peer.SetReadDeadline(time.Now().Add(time.Second))
		_, e = io.ReadFull(peer, got)
		require.NoError(t, e)
		require.Equal(t, b, got)
		peer.Close()
		c.Close()
	}
	for _, b := range [][]byte{{}, []byte("GET /plain HTTP/1.0\r\n\r\n"), {22, 255, 255, 0, 1, 0xff}, {22, 3}, {22, 3, 1, 0, 4, 42}} {
		c, e := net.Dial("tcp4", raw.Addr().String())
		require.NoError(t, e)
		defer c.Close()

		_, e = c.Write(b)
		require.NoError(t, e)
		require.NoError(t, c.(*net.TCPConn).CloseWrite())
		peer, e := p.Other().Accept()
		require.NoError(t, e)
		defer peer.Close()
		got := make([]byte, len(b))
		_, e = io.ReadFull(peer, got)
		require.NoError(t, e)
		require.Equal(t, b, got)
	}
}

// RFC 9001, appendix A.1-A.2, gives the client IV and the first header mask.
func TestInitialKeys(t *testing.T) {
	dcid, err := hex.DecodeString("8394c8f03e515708")
	require.NoError(t, err)
	keys, err := clientInitialKeys(dcid)
	require.NoError(t, err)
	require.Equal(t, "fa044b2f42a3fd3b46fb255c", hex.EncodeToString(keys.iv))
	sample, err := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	require.NoError(t, err)
	var mask [16]byte
	keys.header.Encrypt(mask[:], sample)
	require.Equal(t, "437b9aec36", hex.EncodeToString(mask[:5]))
}

func TestInitialCryptoRanges(t *testing.T) {
	var f flight
	require.NoError(t, f.addCrypto(3, []byte("lo")))
	require.Zero(t, f.contiguous)
	require.NoError(t, f.addCrypto(0, []byte("hell")))
	require.Equal(t, "hello", string(f.data[:f.contiguous]))
	require.NoError(t, f.addCrypto(0, []byte("hello")))
	require.ErrorIs(t, f.addCrypto(3, []byte("XX")), errAssembly)
	require.ErrorIs(t, f.addCrypto(helloLimit-1, []byte("ab")), errAssembly)
}

func TestUDPInitialExpiryAndRetransmission(t *testing.T) {
	packets := captureInitialFlight(t, []string{meshwire.ALPN})
	raw, src := listenUDP(t), listenUDP(t)
	p := NewUDP(raw)
	defer p.Close()
	send := func(b []byte) { _, err := src.WriteTo(b, raw.LocalAddr()); require.NoError(t, err) }
	send(packets[0])
	// Wait until the incomplete flight expires at the classifier.
	p.Mesh().SetReadDeadline(time.Now().Add(classifyTimeout + 100*time.Millisecond))
	_, _, err := p.Mesh().ReadFrom(make([]byte, 2048))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	for _, pkt := range packets[1:] {
		send(pkt)
	}
	p.Mesh().SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, err = p.Mesh().ReadFrom(make([]byte, 2048))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	// Preserve the complete datagram, including trailing coalesced bytes.
	retry := append(slices.Clone(packets[0]), 0xc0, 1)
	send(retry)
	for _, want := range append(slices.Clone(packets[1:]), retry) {
		got, from := readDatagram(t, p.Mesh())
		require.Equal(t, want, got)
		require.Equal(t, src.LocalAddr(), from)
	}
}

type blockingSocket struct {
	net.PacketConn
	write   net.Conn
	started chan struct{}
}

func (s *blockingSocket) WriteTo(b []byte, _ net.Addr) (int, error) {
	s.started <- struct{}{}
	return s.write.Write(b)
}

func (s *blockingSocket) SetWriteDeadline(t time.Time) error { return s.write.SetWriteDeadline(t) }

func TestUDPBranchDeadlines(t *testing.T) {
	w, r := net.Pipe()
	defer r.Close()
	defer w.Close()
	s := &blockingSocket{PacketConn: listenUDP(t), write: w, started: make(chan struct{}, 1)}
	p := NewUDP(s)
	defer p.Close()
	write := func(pc net.PacketConn) <-chan error {
		done := make(chan error, 1)
		go func() { _, err := pc.WriteTo([]byte{42}, s.LocalAddr()); done <- err }()
		return done
	}
	wait := func(done <-chan error) error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(time.Second):
			t.Fatal("write remained blocked")
			return nil
		}
	}
	mesh := write(p.Mesh())
	<-s.started
	other := write(p.Other())
	require.NoError(t, p.Other().SetWriteDeadline(time.Now()))
	require.ErrorIs(t, wait(other), os.ErrDeadlineExceeded)
	require.NoError(t, p.Other().SetWriteDeadline(time.Time{}))
	other = write(p.Other())
	require.NoError(t, p.Mesh().Close())
	require.ErrorIs(t, wait(mesh), net.ErrClosed)
	buf := make([]byte, 1)
	require.NoError(t, r.SetReadDeadline(time.Now().Add(time.Second)))
	_, err := io.ReadFull(r, buf)
	require.NoError(t, err)
	require.Equal(t, []byte{42}, buf)
	require.NoError(t, wait(other))
	read := make(chan error, 1)
	go func() { _, _, err := p.Other().ReadFrom(buf); read <- err }()
	require.NoError(t, p.Other().SetReadDeadline(time.Now()))
	require.ErrorIs(t, wait(read), os.ErrDeadlineExceeded)
}

func TestUDPByteReplay(t *testing.T) {
	raw, src := listenUDP(t), listenUDP(t)
	p := NewUDP(raw)
	defer p.Close()
	for _, b := range [][]byte{nil, {0, 1}, {1}, {0xff, 2}, {0x40, 2, 3}, bytes.Repeat([]byte{0x88}, 1300)} {
		_, e := src.WriteTo(b, raw.LocalAddr())
		require.NoError(t, e)
		got, from := readDatagram(t, p.Other())
		require.True(t, bytes.Equal(b, got))
		require.Equal(t, src.LocalAddr().String(), from.String())
		require.Equal(t, raw.LocalAddr(), p.Other().LocalAddr())
	}
	_, e := src.WriteTo([]byte{0}, raw.LocalAddr())
	require.NoError(t, e)
	p.Other().SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, e = p.Other().ReadFrom(make([]byte, 100))
	require.Error(t, e)
}

func captureInitialFlight(t *testing.T, protos []string) [][]byte {
	t.Helper()
	server, client := listenUDP(t), listenUDP(t)
	tr := &quic.Transport{Conn: client}
	defer tr.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go tr.Dial(ctx, server.LocalAddr(), &tls.Config{ServerName: "test.example", NextProtos: protos, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, &quic.Config{InitialPacketSize: 1200, Versions: []quic.Version{quic.Version1}})
	var ds [][]byte
	present := make([]bool, helloLimit)
	first := make([]byte, 4)
	for len(ds) < 20 {
		pkt, _ := readDatagram(t, server)
		ds = append(ds, pkt)
		dcid := pkt[6 : 6+int(pkt[5])]
		keys, err := clientInitialKeys(dcid)
		require.NoError(t, err)
		e := keys.readInitial(pkt, dcid, func(offset uint64, b []byte) error {
			o := int(offset)
			for i := range b {
				present[o+i] = true
				if o+i < 4 {
					first[o+i] = b[i]
				}
			}
			return nil
		})
		require.NoError(t, e)
		n := int(binary.BigEndian.Uint32(first)&0xffffff) + 4
		if n <= len(present) && !slices.Contains(present[:n], false) {
			require.GreaterOrEqual(t, len(ds), 2)
			return ds
		}
	}
	t.Fatal("incomplete flight")
	return nil
}

func TestUDPReorderedInitialReplay(t *testing.T) {
	for _, tt := range []struct {
		name string
		p    []string
	}{{"mesh", []string{meshwire.ALPN}}, {"h3", []string{"h3"}}, {"mixed", []string{"h3", meshwire.ALPN}}, {"custom", []string{"acme-quic"}}} {
		t.Run(tt.name, func(t *testing.T) {
			flight := captureInitialFlight(t, tt.p)
			slices.Reverse(flight)
			raw, source := listenUDP(t), listenUDP(t)
			u := NewUDP(raw)
			defer u.Close()
			target := u.Other()
			if tt.name == "mesh" {
				target = u.Mesh()
			}
			_, e := source.WriteTo(flight[0], raw.LocalAddr())
			require.NoError(t, e)
			for _, p := range []net.PacketConn{u.Mesh(), u.Other()} {
				p.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				_, _, e = p.ReadFrom(make([]byte, 2048))
				require.Error(t, e)
			}
			for _, b := range flight[1:] {
				_, e = source.WriteTo(b, raw.LocalAddr())
				require.NoError(t, e)
			}
			for _, b := range flight {
				got, from := readDatagram(t, target)
				require.Equal(t, b, got)
				require.Equal(t, source.LocalAddr(), from)
			}
		})
	}
}
