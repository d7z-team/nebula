package nebula

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"

	"github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
)

const (
	opPing byte = iota + 1
	opHello
	opEvent
	opCircuit
	opIP
	opLookup
	opGetEvent
)

const (
	maxSessionStreams = 64
	maxControlFrame   = 64 << 10
)

type qStream struct {
	*quic.Stream
	q *quic.Conn
}

func (s qStream) LocalAddr() net.Addr  { return s.q.LocalAddr() }
func (s qStream) RemoteAddr() net.Addr { return s.q.RemoteAddr() }

// A request owns both directions of a stream; closing also releases an unread response.
func (s qStream) Close() error { s.CancelRead(0); return s.Stream.Close() }

type session struct {
	acknowledgedIntro             atomic.Int64
	inventoryOffset               atomic.Uint64
	localChain                    []*x509.Certificate
	until                         time.Time // protected by n.mu
	probing                       atomic.Bool
	n                             *Node
	lease                         *circuitLease
	peer                          PeerID
	localIdentity, remoteIdentity pki.Identity
	kind                          string
	endpoint                      netip.AddrPort
	path                          []PeerID
	state                         tls.ConnectionState
	outgoing                      bool
	q                             *quic.Conn
	mux                           *yamux.Session
	closed                        atomic.Bool
	healthMu                      sync.Mutex
	rtt, jitter                   time.Duration
	failures                      int
	loss                          float64
	sent, lost                    uint64
	lastProbe                     time.Time
	dataMu                        sync.Mutex
	data                          net.Conn
	budget                        atomic.Int64
	overflow                      atomic.Uint64
}

func (s *session) matchesTransport(network string, endpoint netip.AddrPort) bool {
	return s.kind == network && s.endpoint.Addr().BitLen() == endpoint.Addr().BitLen()
}

func (s *session) open(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.q != nil {
		st, err := s.q.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return qStream{st, s.q}, nil
	}
	return s.mux.OpenStream()
}

func (s *session) close() {
	if s.closed.Swap(true) {
		return
	}
	if s.q != nil {
		s.q.CloseWithError(0, "session closed")
	} else {
		s.mux.Close()
	}
	if s.lease != nil {
		s.lease.close()
	}
}

func (n *Node) attachQUIC(q *quic.Conn, peer PeerID) (*session, error) {
	st := q.ConnectionState()
	if !st.SupportsDatagrams.Local || !st.SupportsDatagrams.Remote {
		q.CloseWithError(1, "datagrams required")
		return nil, ErrPathPolicy
	}
	s := &session{n: n, q: q, kind: "udp", endpoint: addrPort(q.RemoteAddr()), state: st.TLS, outgoing: peer != (PeerID{}), peer: peer}
	return n.register(s)
}

func (n *Node) attachTLS(ctx context.Context, raw net.Conn, peer PeerID, path []PeerID, out bool, lease *circuitLease) (*session, error) {
	_ = raw.SetDeadline(time.Now().Add(n.o.DialTimeout))
	cfg := n.tlsConfig(peer, !out)
	var t *tls.Conn
	if out {
		t = tls.Client(raw, cfg)
	} else {
		t = tls.Server(raw, cfg)
	}
	if err := t.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	s := &session{n: n, kind: "tcp", state: t.ConnectionState(), endpoint: addrPort(raw.RemoteAddr()), path: path, peer: peer, outgoing: out, lease: lease}
	raw.SetDeadline(time.Time{})
	cfgMux := yamux.DefaultConfig()
	cfgMux.LogOutput = io.Discard
	cfgMux.EnableKeepAlive = false
	cfgMux.AcceptBacklog = maxSessionStreams
	cfgMux.StreamOpenTimeout = n.o.DialTimeout
	cfgMux.ConnectionWriteTimeout = n.o.DialTimeout
	var err error
	if out {
		s.mux, err = yamux.Client(t, cfgMux)
	} else {
		s.mux, err = yamux.Server(t, cfgMux)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	if len(path) > 0 {
		s.kind = "relay"
		s.endpoint = netip.AddrPort{}
	}
	return n.register(s)
}

// authorizationDeadline uses only the two certificate chains presented during this handshake.
func (s *session) authorizationDeadline(ctx context.Context, p *topologyView) (time.Time, error) {
	n := s.n
	local, remote := x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth
	if s.outgoing {
		local, remote = remote, local
	}
	end, err := n.authorizeChain(ctx, p, n.id, s.localChain, local)
	if err != nil {
		return time.Time{}, err
	}
	other, err := n.authorizeChain(ctx, p, s.peer, s.state.PeerCertificates, remote)
	if other.Before(end) {
		end = other
	}
	return end, err
}

func (n *Node) register(s *session) (*session, error) {
	var err error
	s.localChain, err = pki.ParseChain(s.state.LocalCertificate)
	if err != nil {
		s.close()
		return nil, err
	}
	s.localIdentity, err = pki.ReadIdentity(s.localChain[0])
	if err != nil {
		s.close()
		return nil, err
	}
	s.remoteIdentity, err = pki.ReadIdentity(s.state.PeerCertificates[0])
	a := s.remoteIdentity.ID
	if err != nil || a == n.id || s.peer != (PeerID{}) && a != s.peer || len(s.path) > 0 && (s.path[0] != n.id || s.path[len(s.path)-1] != a) {
		s.close()
		return nil, ErrPathPolicy
	}
	s.peer = a

	s.refreshBudget()
	ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout)
	defer cancel()
	for {
		p := n.policy.Load()
		end, err := s.authorizationDeadline(ctx, p)
		if err != nil {
			s.close()
			return nil, err
		}
		n.mu.Lock()
		if n.policy.Load() == p {
			s.until = end
			break
		}
		n.mu.Unlock()
	}
	if n.state != running || !n.sessionAllowedLocked(s) {
		n.mu.Unlock()
		s.close()
		return nil, ErrPathPolicy
	}
	paths := n.peers[s.peer]
	if paths == nil {
		paths = &peerPaths{lastCanary: time.Now()}
		n.peers[s.peer] = paths
	}
	var replaced *session
	for _, old := range paths.sessions {
		if !old.matchesTransport(s.kind, s.endpoint) || old.outgoing != s.outgoing || !slices.Equal(old.path, s.path) || old.closed.Load() || !n.sessionAllowedLocked(old) {
			continue
		}
		if !s.outgoing && len(s.path) == 0 {
			// A reconnecting peer may have lost its old path silently. Once
			// authenticated, its new direct connection supersedes that path.
			replaced = old
			break
		}
		n.mu.Unlock()
		s.close()
		return old, nil
	}
	paths.sessions = append(paths.sessions, s)
	if replaced != nil {
		n.removeSessionLocked(replaced)
	}
	n.admissions++
	// Publish the session and register its readers before Close can wait for them.
	n.wg.Go(func() { n.serveSession(s) })
	if s.q != nil {
		n.wg.Go(func() {
			for {
				packet, err := s.q.ReceiveDatagram(n.ctx)
				if err != nil {
					return
				}
				n.receiveIP(s, packet)
			}
		})
	}
	n.mu.Unlock()
	if replaced != nil {
		replaced.close()
	}
	return s, nil
}

func (n *Node) serveSession(s *session) {
	slots := make(chan struct{}, maxSessionStreams)
	defer func() {
		s.close()
		n.mu.Lock()
		n.removeSessionLocked(s)
		n.mu.Unlock()
	}()
	for {
		var c net.Conn
		var err error
		if s.q != nil {
			var st *quic.Stream
			st, err = s.q.AcceptStream(n.ctx)
			if err == nil {
				c = qStream{st, s.q}
			}
		} else {
			c, err = s.mux.AcceptStreamWithContext(n.ctx)
		}
		if err != nil {
			return
		}
		if !n.tryTask(slots, func() { n.handleStream(s, c) }) {
			c.Close()
		}
	}
}

func writeFrame(w io.Writer, b []byte) error {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if uint64(n) > uint64(limit) {
		return nil, errors.New("frame too large")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func (s *session) request(ctx context.Context, op byte, body []byte, limit int) ([]byte, error) {
	c, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(s.n.o.DialTimeout)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	c.SetDeadline(deadline)
	if _, err = c.Write([]byte{op}); err != nil {
		return nil, err
	}
	if err = writeFrame(c, body); err != nil {
		return nil, err
	}
	return readFrame(c, limit)
}

func (n *Node) handleStream(s *session, c net.Conn) {
	owned := true
	defer func() {
		if owned {
			c.Close()
		}
	}()
	c.SetDeadline(time.Now().Add(n.o.DialTimeout))
	var op [1]byte
	if _, err := io.ReadFull(c, op[:]); err != nil {
		return
	}
	if !n.usable(s) {
		return
	}
	if op[0] == opIP {
		c.SetDeadline(time.Time{})
		for {
			b, err := readFrame(c, n.o.MaxIPSize)
			if err != nil {
				return
			}
			n.receiveIP(s, b)
		}
	}
	b, err := readFrame(c, maxControlFrame)
	if err != nil {
		return
	}
	if !n.usable(s) {
		return
	}
	switch op[0] {
	case opHello:
		var a advert
		if json.Unmarshal(b, &a) != nil {
			return
		}
		n.observe(s, a)
		out, _ := json.Marshal(n.advert(s))
		writeFrame(c, out)
	case opPing:
		if len(b) <= 32 {
			writeFrame(c, b)
		}
	case opEvent:
		if _, err := n.acceptEvent(n.ctx, s, b); err == nil {
			writeFrame(c, nil)
		}
	case opLookup:
		n.handleLookup(s, c, b)
	case opGetEvent:
		n.mu.Lock()
		e, ok := n.events[string(b)]
		n.mu.Unlock()
		if ok && time.Now().Before(e.expires) && n.allowEventSend(s, string(b), e.record) {
			writeFrame(c, e.record)
		}
	case opCircuit:
		if len(s.path) == 0 {
			owned = !n.forwardCircuit(s, c, b)
		}
	}
}

// quic-go exposes its current directional limit on an oversize send. 64 KiB
// exceeds the UDP payload limit, so this local query never emits a packet.
func (s *session) refreshBudget() {
	if s.q != nil {
		var limit *quic.DatagramTooLargeError
		if errors.As(s.q.SendDatagram(s.n.sizeQuery), &limit) {
			s.budget.Store(limit.MaxDatagramPayloadSize)
		}
	}
}

func (s *session) sendIP(b []byte) error {
	if s.q != nil {
		err := s.q.SendDatagram(b)
		var size *quic.DatagramTooLargeError
		if err == nil {
			return nil
		}
		if !errors.As(err, &size) {
			return err
		}
		s.budget.Store(size.MaxDatagramPayloadSize)
		s.overflow.Add(1)
	}
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if s.data == nil {
		c, err := s.open(s.n.ctx)
		if err != nil {
			return err
		}
		c.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout))
		if _, err = c.Write([]byte{opIP}); err != nil {
			c.Close()
			return err
		}
		s.data = c
	}
	s.data.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout))
	if err := writeFrame(s.data, b); err != nil {
		s.data.Close()
		s.data = nil
		return err
	}
	return nil
}
