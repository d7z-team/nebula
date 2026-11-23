// Package nebula carries IP packets between authenticated peers over QUIC or TLS over TCP.
package nebula

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
)

var (
	ErrNodeNotStarted      = errors.New("node not running")
	ErrNodeClosed          = errors.New("node closed")
	ErrPeerUnavailable     = errors.New("peer unavailable")
	ErrPathPolicy          = errors.New("path denied")
	ErrQueueFull           = errors.New("queue full")
	ErrPortClosed          = errors.New("IP port closed")
	ErrAddressUnauthorized = errors.New("address unauthorized")
	ErrMissingGateway      = errors.New("next hop required")
)

// Options configures a node's transports, credentials and initial topology.
type Options struct {
	Roots                 *x509.CertPool
	Certificates          LocalCertificates
	Topology              Topology
	CheckChain            func(context.Context, ChainCheck) (time.Time, error)
	UDP4, UDP6            net.PacketConn
	TCP4, TCP6            net.Listener
	DialTCP               func(context.Context, string, string) (net.Conn, error)
	AdvertiseEndpoints    []Endpoint
	Interval, DialTimeout time.Duration
	MaxCircuits           int
	MaxIPSize             int
	InboundPolicy         func(peer PeerID, source, destination netip.Addr) bool
}

// Node manages the transports and peer sessions for one mesh identity.
type Node struct {
	o               Options
	id              PeerID
	network         string
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	udpWrites       sync.RWMutex
	state           lifecycle
	wg              sync.WaitGroup
	done            chan struct{}
	cred            atomic.Pointer[credentials]
	policy          atomic.Pointer[topologyView]
	admissions      uint64 // increments when a session or event joins the live set
	introMu         sync.Mutex
	introCache      cachedIntroduction
	transports      map[bool]*quic.Transport
	listeners       []*quic.Listener
	peers           map[PeerID]*peerPaths
	modes           map[PeerID]PathMode
	discovered      map[PeerID]introduction
	attempts        map[PeerID]*attempt
	directDials     map[directDial]*attempt
	observations    map[observer]observation
	introduced      map[Endpoint]map[PeerID]time.Time
	deniedUDP       map[netip.AddrPort]deniedEndpoint
	queries         map[string]time.Time
	backgroundSlots chan struct{}
	port            *IPPort
	handshakeSlots  chan struct{}
	sizeQuery       []byte
	circuits        map[*circuitLease]struct{}
	limiter         *rate.Limiter
	rateCtx         context.Context
	rateCancel      context.CancelFunc
	shaped          atomic.Uint64
	retries         atomic.Uint64
	events          map[string]cachedEvent
	subscriptions   map[*Subscription]struct{}
	lastError       string
}

type lifecycle uint8

const (
	created lifecycle = iota
	running
	closed
)

// New creates a node with the supplied credentials and topology. On success,
// the node owns the UDP socket and TCP listener. Close releases them even before Start.
func New(parent context.Context, o Options) (*Node, error) {
	if parent == nil || (o.UDP4 == nil && o.UDP6 == nil && o.TCP4 == nil && o.TCP6 == nil && o.DialTCP == nil) {
		return nil, errors.New("context and transport required")
	}
	if o.Roots == nil {
		return nil, errors.New("explicit trust roots required")
	}
	o.Roots = o.Roots.Clone()
	view, err := o.Topology.compile()
	if err != nil {
		return nil, err
	}
	o.Topology = Topology{}
	c, err := prepareCertificates(o.Certificates)
	if err != nil {
		return nil, err
	}
	identity, err := pki.ReadIdentity(c.Client.Leaf)
	if err != nil {
		return nil, err
	}
	o.Certificates = LocalCertificates{}
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 4 * time.Second
	}
	if o.MaxCircuits <= 0 {
		o.MaxCircuits = 128
	}
	if o.MaxIPSize == 0 {
		o.MaxIPSize = MaxIPPacketSize
	}
	if o.MaxIPSize < 1280 || o.MaxIPSize > MaxIPPacketSize {
		return nil, errors.New("invalid IP size")
	}
	if o.DialTCP == nil {
		o.DialTCP = (&net.Dialer{}).DialContext
	}
	for _, ep := range o.AdvertiseEndpoints {
		if !ep.Valid() {
			return nil, errors.New("invalid advertised endpoint")
		}
	}
	o.AdvertiseEndpoints = slices.Clone(o.AdvertiseEndpoints)
	ctx, cancel := context.WithCancel(parent)
	n := &Node{
		o:               o,
		network:         view.Network,
		id:              identity.ID,
		ctx:             ctx,
		cancel:          cancel,
		done:            make(chan struct{}),
		peers:           make(map[PeerID]*peerPaths),
		modes:           make(map[PeerID]PathMode),
		attempts:        make(map[PeerID]*attempt),
		directDials:     make(map[directDial]*attempt),
		deniedUDP:       make(map[netip.AddrPort]deniedEndpoint),
		circuits:        make(map[*circuitLease]struct{}),
		discovered:      make(map[PeerID]introduction),
		introduced:      make(map[Endpoint]map[PeerID]time.Time),
		observations:    make(map[observer]observation),
		queries:         make(map[string]time.Time),
		events:          make(map[string]cachedEvent),
		subscriptions:   make(map[*Subscription]struct{}),
		handshakeSlots:  make(chan struct{}, 128),
		backgroundSlots: make(chan struct{}, 16),
	}
	c.until, err = n.credentialDeadline(ctx, view, c)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, err
	}
	if !time.Now().Before(c.until) {
		cancel()
		return nil, ErrPathPolicy
	}
	n.cred.Store(c)
	n.policy.Store(view)
	n.setShapingRate(view.members[n.id].BytesPerSecond)
	return n, nil
}

func (n *Node) task(fn func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state != running {
		return false
	}
	n.wg.Go(fn)
	return true
}

// tryTask reserves capacity before scheduling work, and releases it on shutdown.
func (n *Node) tryTask(slots chan struct{}, fn func()) bool {
	select {
	case slots <- struct{}{}:
		if n.task(func() {
			defer func() { <-slots }()
			fn()
		}) {
			return true
		}
		<-slots
	default:
	}
	return false
}

// Start begins accepting peer connections and maintaining authorized paths.
func (n *Node) Start() error {
	n.mu.Lock()
	if n.state != created || n.ctx.Err() != nil {
		n.mu.Unlock()
		return ErrNodeNotStarted
	}
	n.state = running
	if n.o.UDP4 != nil || n.o.UDP6 != nil {
		n.sizeQuery = make([]byte, MaxIPPacketSize+1)
	}
	n.transports = make(map[bool]*quic.Transport, 2)
	for ipv6, udp := range map[bool]net.PacketConn{false: n.o.UDP4, true: n.o.UDP6} {
		if udp == nil {
			continue
		}
		socket := &policySocket{PacketConn: udp, n: n}
		var pc net.PacketConn = socket
		type bufferedSocket interface {
			syscall.Conn
			SetReadBuffer(int) error
			SetWriteBuffer(int) error
		}
		if raw, ok := udp.(bufferedSocket); ok {
			pc = &struct {
				*policySocket
				bufferedSocket
			}{socket, raw}
		} else if raw, ok := udp.(syscall.Conn); ok {
			pc = &struct {
				*policySocket
				syscall.Conn
			}{socket, raw}
		}
		transport := &quic.Transport{Conn: pc}
		n.transports[ipv6] = transport
		listener, err := transport.Listen(n.tlsConfig(PeerID{}, true), n.quicConfig())
		if err != nil {
			n.mu.Unlock()
			n.Close()
			return err
		}
		n.listeners = append(n.listeners, listener)
	}
	n.mu.Unlock()
	for _, listener := range n.listeners {
		n.task(func() {
			for {
				q, err := listener.Accept(n.ctx)
				if err != nil {
					return
				}
				if !n.tryTask(n.handshakeSlots, func() { n.attachQUIC(q, PeerID{}) }) {
					q.CloseWithError(0, "closing")
				}
			}
		})
	}
	for _, listener := range []net.Listener{n.o.TCP4, n.o.TCP6} {
		if listener == nil {
			continue
		}
		n.task(func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				ep := addrPort(c.RemoteAddr())
				if !n.endpointAllowed("tcp", ep, true) {
					c.Close()
					continue
				}
				if !n.tryTask(n.handshakeSlots, func() { n.attachTLS(n.ctx, c, PeerID{}, nil, false, nil) }) {
					c.Close()
				}
			}
		})
	}
	n.task(n.maintain)
	go func() { <-n.ctx.Done(); n.Close() }()
	return nil
}

// Close shuts down the node and waits for its background tasks to finish.
// Call Close outside the IP receive callback, which runs on one of those tasks.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.state == closed {
		n.mu.Unlock()
		<-n.done
		return nil
	}
	n.state = closed
	n.cancel()
	sessions := n.sessionListLocked()
	clear(n.peers)
	p := n.port
	for sub := range n.subscriptions {
		close(sub.events)
		delete(n.subscriptions, sub)
	}
	n.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	for _, l := range []net.Listener{n.o.TCP4, n.o.TCP6} {
		if l != nil {
			l.Close()
		}
	}
	for _, l := range n.listeners {
		l.Close()
	}
	for _, t := range n.transports {
		t.Close()
	}
	for _, pc := range []net.PacketConn{n.o.UDP4, n.o.UDP6} {
		if pc != nil {
			pc.Close()
		}
	}
	if p != nil {
		p.Close()
	}
	n.wg.Wait()
	close(n.done)
	return nil
}

func (n *Node) quicConfig() *quic.Config {
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, InitialPacketSize: 1200,
		HandshakeIdleTimeout: n.o.DialTimeout, MaxIncomingStreams: maxSessionStreams, MaxIncomingUniStreams: -1,
	}
}

func (n *Node) ID() PeerID     { return n.id }
func (n *Node) MaxIPSize() int { return n.o.MaxIPSize }
func (n *Node) sessionListLocked() []*session {
	ss := make([]*session, 0, len(n.peers))
	for _, peer := range n.peers {
		ss = append(ss, peer.sessions...)
	}
	return ss
}

func addrPort(a net.Addr) netip.AddrPort {
	if v, ok := a.(interface{ AddrPort() netip.AddrPort }); ok {
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
