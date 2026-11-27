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

	"gopkg.d7z.net/nebula/pki"

	"github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
)

// The first byte on each application stream selects its wire format.
const (
	opPing    byte = 0x01
	opHello   byte = 0x02
	opLookup  byte = 0x03
	opCircuit byte = 0x04
	opIP      byte = 0x05
)

const (
	maxDirectPerFamily = 2 // per peer, transport and direction
	maxSessionStreams  = 64
	maxControlFrame    = 64 << 10
)

type qStream struct {
	*quic.Stream
	q       *quic.Conn
	mu      sync.Mutex
	writers int
	closed  bool
}

func (s *qStream) LocalAddr() net.Addr  { return s.q.LocalAddr() }
func (s *qStream) RemoteAddr() net.Addr { return s.q.RemoteAddr() }

func (s *qStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	s.writers++
	s.mu.Unlock()

	n, err := s.Stream.Write(p)
	s.mu.Lock()
	s.writers--
	s.mu.Unlock()
	return n, err
}

func (s *qStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	writing := s.writers > 0
	s.mu.Unlock()

	s.CancelRead(0)
	// QUIC FIN preserves completed writes. A concurrent Write needs a reset
	// to unblock locally, even when the peer has stopped reading.
	if writing {
		s.CancelWrite(0)
		return nil
	}
	return s.Stream.Close()
}

type session struct {
	acknowledgedIntro             atomic.Int64
	localGrant, remoteGrant       []*x509.Certificate
	localNode                     *x509.Certificate
	until                         time.Time // protected by n.mu
	n                             *Node
	ctx                           context.Context
	cancel                        context.CancelFunc
	lease                         *circuitLease
	peer                          PeerID
	instance                      InstanceID
	registeredAt, lastAlive       time.Time
	localIdentity, remoteIdentity pki.Identity
	remoteIPLimit                 int
	localEndpoint                 netip.AddrPort
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
	probing                       bool      // protected by n.mu
	confirmProbe                  bool      // a collision requires a fresh ping; protected by n.mu
	lastProbe                     time.Time // protected by n.mu
	nextHello                     time.Time // local introduction refresh or retry; protected by n.mu
	dataMu                        sync.Mutex
	data                          net.Conn
	budget                        atomic.Int64
	overflow                      atomic.Uint64
}

func (s *session) remoteEndpoint() netip.AddrPort {
	if s.q != nil {
		return addrPort(s.q.RemoteAddr())
	}
	return s.endpoint
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
		return &qStream{Stream: st, q: s.q}, nil
	}
	return s.mux.OpenStream()
}

func (s *session) close() {
	if s.closed.Swap(true) {
		return
	}
	if s.cancel != nil {
		s.cancel()
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

func (n *Node) attachQUIC(parent context.Context, q *quic.Conn, peer PeerID, outgoing bool, snapshot *credentials) (*session, error) {
	st := q.ConnectionState()
	if !st.SupportsDatagrams.Local || !st.SupportsDatagrams.Remote {
		q.CloseWithError(1, "datagrams required")
		return nil, ErrPathPolicy
	}
	s := &session{n: n, q: q, kind: "udp", endpoint: addrPort(q.RemoteAddr()), state: st.TLS, outgoing: outgoing, peer: peer}
	ctx, cancel := context.WithTimeout(parent, n.o.DialTimeout)
	defer cancel()
	var stream *quic.Stream
	var err error
	if s.outgoing {
		stream, err = q.OpenStreamSync(ctx)
	} else {
		stream, err = q.AcceptStream(ctx)
	}
	if err == nil {
		c := &qStream{Stream: stream, q: q}
		deadline, _ := ctx.Deadline()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		if err = c.SetDeadline(deadline); err == nil {
			err = s.exchangeGrants(ctx, c, snapshot)
		}
		stop()
		c.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
	}
	if err != nil {
		s.close()
		return nil, err
	}
	s.localEndpoint = addrPort(q.LocalAddr())
	return n.register(s)
}

// exchangeDeadline caps a single exchange by both the caller and the node.
func (n *Node) exchangeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(n.o.DialTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		return end
	}
	return deadline
}

func (n *Node) attachTLS(ctx context.Context, raw net.Conn, peer PeerID, path []PeerID, out bool, lease *circuitLease) (*session, error) {
	if err := raw.SetDeadline(n.exchangeDeadline(ctx)); err != nil {
		raw.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	snapshot := n.cred.Load()
	cfg := n.tlsConfig(peer, out, snapshot)
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
	s.localEndpoint = addrPort(raw.LocalAddr())
	err := s.exchangeGrants(ctx, t, snapshot)
	if err == nil {
		err = raw.SetDeadline(time.Time{})
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfgMux := yamux.DefaultConfig()
	cfgMux.LogOutput = io.Discard
	cfgMux.EnableKeepAlive = false
	cfgMux.AcceptBacklog = maxSessionStreams
	// An unacknowledged yamux SYN closes the entire multiplexed session.
	// On a relay, individual requests can time out while other streams progress.
	if len(path) == 0 {
		cfgMux.StreamOpenTimeout = n.o.DialTimeout
	} else {
		cfgMux.StreamOpenTimeout = max(cfgMux.StreamOpenTimeout, n.o.DialTimeout)
	}
	cfgMux.ConnectionWriteTimeout = n.o.DialTimeout
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
	// The registered session owns the connection once dialing ends.
	if !stop() {
		s.close()
		return nil, ctx.Err()
	}
	return n.register(s)
}

func (n *Node) register(s *session) (*session, error) {
	if len(s.path) > 0 && (s.path[0] != n.id || s.path[len(s.path)-1] != s.peer) {
		s.close()
		return nil, ErrPathPolicy
	}
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
	if err := n.admitSessionLocked(s); err != nil {
		n.mu.Unlock()
		s.close()
		return nil, err
	}
	s.registeredAt = time.Now()
	s.lastAlive = s.registeredAt
	s.lastProbe = s.registeredAt
	paths := n.peers[s.peer]
	firstPath := paths == nil
	if firstPath {
		paths = &peerPaths{lastCanary: s.registeredAt}
		n.peers[s.peer] = paths
	}
	var replaced, standby *session
	sameFamily := 0
	remote := s.remoteEndpoint()
	for _, old := range paths.sessions {
		if old.kind != s.kind || old.outgoing != s.outgoing || !slices.Equal(old.path, s.path) || old.closed.Load() || !n.sessionAllowedLocked(old) {
			continue
		}
		previous := old.remoteEndpoint()
		if s.kind == "relay" || s.outgoing && previous == remote {
			n.mu.Unlock()
			s.close()
			return old, nil
		}
		if previous.Addr().BitLen() != remote.Addr().BitLen() {
			continue
		}
		// Distinct source ports on one listener can represent different NAT paths.
		if !s.outgoing && previous == remote && old.localEndpoint == s.localEndpoint {
			replaced = old
			break
		}
		sameFamily++
		if standby == nil || standby == paths.active {
			standby = old
		}
	}
	if replaced == nil && sameFamily >= maxDirectPerFamily {
		replaced = standby
	}
	s.ctx, s.cancel = context.WithCancel(n.ctx)
	paths.sessions = append(paths.sessions, s)
	if n.pathRegistered != nil {
		close(n.pathRegistered)
		n.pathRegistered = nil
	}
	if a := n.attempts[s.peer]; a != nil {
		close(a.changed)
		a.changed = make(chan struct{})
	}
	if replaced != nil {
		n.removeSessionLocked(replaced)
	}
	n.admissions++
	// Publish the session and register its readers before Close can wait for them.
	n.wg.Go(func() { n.serveSession(s) })
	if s.q != nil {
		n.wg.Go(func() {
			for {
				packet, err := s.q.ReceiveDatagram(s.ctx)
				if err != nil {
					return
				}
				n.receiveIP(s, packet)
			}
		})
	}
	n.requestProbeLocked(s)
	port := n.port
	n.mu.Unlock()
	if firstPath && port != nil {
		port.syncInstanceQueue(s.peer)
	}
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
		_, held := n.conflicts[s.peer]
		port := n.port
		n.mu.Unlock()
		if held && port != nil {
			port.syncInstanceQueue(s.peer)
		}
	}()
	for {
		var c net.Conn
		var err error
		if s.q != nil {
			var st *quic.Stream
			st, err = s.q.AcceptStream(s.ctx)
			if err == nil {
				c = &qStream{Stream: st, q: s.q}
			}
		} else {
			c, err = s.mux.AcceptStreamWithContext(s.ctx)
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

var errFrameTooLarge = errors.New("frame too large")

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if uint64(n) > uint64(limit) {
		return nil, errFrameTooLarge
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func (s *session) request(ctx context.Context, op byte, body []byte, limit int) ([]byte, error) {
	c, err := s.openRequest(ctx, op, body)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return readFrame(c, limit)
}

func (s *session) openRequest(ctx context.Context, op byte, body []byte) (net.Conn, error) {
	c, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	// Opening a stream may block while a policy update withdraws the session.
	if !s.n.usable(s) {
		err = ErrPathPolicy
	} else if err = c.SetDeadline(s.n.exchangeDeadline(ctx)); err == nil {
		if _, err = c.Write([]byte{op}); err == nil {
			err = writeFrame(c, body)
		}
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (n *Node) handleStream(s *session, c net.Conn) {
	owned := true
	defer func() {
		if owned {
			c.Close()
		}
	}()
	if err := c.SetDeadline(time.Now().Add(n.o.DialTimeout)); err != nil {
		return
	}
	var op [1]byte
	if _, err := io.ReadFull(c, op[:]); err != nil {
		return
	}
	if !n.usable(s) {
		return
	}
	if op[0] == opIP {
		if err := c.SetDeadline(time.Time{}); err != nil {
			return
		}
		for {
			b, err := readFrame(c, n.o.MaxIPSize)
			if err != nil {
				if err == errFrameTooLarge {
					n.mu.Lock()
					port := n.port
					n.mu.Unlock()
					if port != nil {
						port.recordInbound(0, ErrPacketTooLarge)
					}
				}
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
		n.receiveAdvert(s, a)
		reply, _ := n.advert(s)
		out, _ := json.Marshal(reply)
		if n.usable(s) {
			_ = writeFrame(c, out)
		}
	case opPing:
		if len(b) <= 32 {
			_ = writeFrame(c, b)
		}
	case opLookup:
		n.handleLookup(s, c, b)
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
