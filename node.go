// Package nebula carries IP packets between authenticated peers over QUIC or TLS over TCP.
package nebula

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"
	"code.d7z.net/d7z-team/nebula/pki"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
)

var (
	ErrNodeNotStarted      = errors.New("node not started")
	ErrNodeAlreadyStarted  = errors.New("node already started")
	ErrNodeClosed          = errors.New("node closed")
	ErrPeerUnavailable     = errors.New("peer unavailable")
	ErrPathPolicy          = errors.New("path denied")
	ErrPacketTooLarge      = errors.New("packet exceeds receive limit")
	ErrQueueFull           = errors.New("queue full")
	ErrPortClosed          = errors.New("IP port closed")
	ErrAddressUnauthorized = errors.New("address unauthorized")
	ErrNextHopRequired     = errors.New("next hop required")
)

// Options configures a node's transports, credentials and initial topology.
type Options struct {
	// Roots is the explicit trust store. New takes a private copy.
	Roots *x509.CertPool
	// ClusterCA pins the certificate defining this mesh within Roots.
	ClusterCA    *x509.Certificate
	Certificates LocalCertificates
	Topology     Topology
	// CheckChain may deny a verified chain or shorten its lifetime. A zero deadline
	// accepts the chain until expiry. Calls may run concurrently.
	CheckChain func(context.Context, ChainCheck) (time.Time, error)
	// UDP sockets carry QUIC and hole punches for their respective address families.
	// Sockets implementing meshwire.SharedSocket configure the node's QUIC transport at startup.
	UDP4, UDP6 net.PacketConn
	// TCP listeners accept inbound TLS connections, including from portshare.TCP.Mesh.
	TCP4, TCP6 net.Listener
	// DialTCP opens outbound TCP connections. The default is net.Dialer.DialContext.
	DialTCP func(context.Context, string, string) (net.Conn, error)
	// AdvertiseEndpoints adds reachable physical addresses outside the certified
	// member subnets and anycast pools to signed introductions.
	AdvertiseEndpoints []Endpoint
	// HideEndpoints omits all physical endpoints from this node's signed introductions,
	// including AdvertiseEndpoints, local topology entries, listeners and NAT mappings.
	// Incoming rendezvous requests receive the signed record without a UDP punch.
	// Direct neighbors still see the connection address. Use Member.Restricted
	// and Member.Links to limit which members may connect directly.
	HideEndpoints bool
	// Interval is the path maintenance interval. The default is two seconds.
	Interval time.Duration
	// DialTimeout bounds individual dial and control exchanges. The default is four seconds.
	DialTimeout time.Duration
	// MaxCircuits limits concurrent circuits at this node. The default is 128.
	MaxCircuits int
	// MaxIPSize bounds a complete inner packet in bytes and is advertised to authenticated peers.
	// The range is 1280 through 65535. Zero selects 65535.
	MaxIPSize int
	// InboundPolicy optionally filters authenticated, address-authorized IP packets.
	// Calls run on receive tasks and may overlap.
	InboundPolicy func(peer PeerID, source, destination netip.Addr) bool
}

// Node manages the transports and peer sessions for one mesh identity.
type Node struct {
	o                      Options
	id                     PeerID
	ctx                    context.Context
	cancel                 context.CancelFunc
	mu                     sync.Mutex
	udpWrites              sync.RWMutex
	state                  lifecycle
	wg                     sync.WaitGroup
	done                   chan struct{}
	cred                   atomic.Pointer[credentials]
	policy                 atomic.Pointer[topologyView]
	admissions             uint64 // increments when a session or publication joins the live set
	introMu                sync.Mutex
	introCache             cachedIntroduction
	transports             map[bool]*udpTransport
	peers                  map[PeerID]*peerPaths
	modes                  map[PeerID]PathMode
	discovered             map[PeerID]learnedIntroduction
	discoveredOwners       map[netip.Addr]PeerID
	attempts               map[PeerID]*peerAttempt
	directDials            map[endpointDialKey]*endpointAttempt
	observations           map[observer]observation
	introduced             map[Endpoint]map[PeerID]time.Time
	deniedUDP              map[netip.AddrPort]deniedEndpoint
	resolutions            map[netip.Addr]*ipResolution
	queries                map[string]time.Time
	backgroundSlots        chan struct{}
	neighborDialSlots      chan struct{}
	sharedAddressDialSlots chan struct{}
	pathRegistered         chan struct{} // lazy notification for callers waiting for a cold-dial slot
	port                   *IPPort
	handshakeSlots         chan struct{}
	sizeQuery              []byte
	routeCursors           map[PeerID]*routeCursor
	probeSlots             chan struct{}
	circuits               map[*circuitLease]struct{}
	limiter                *rate.Limiter
	rateCtx                context.Context
	rateCancel             context.CancelFunc
	bytesScheduled         atomic.Uint64
	dialFailures           atomic.Uint64
	publications           map[string]cachedPublication
	subscriptions          map[*Subscription]struct{}
	lastConnectError       string
	listenerErrors         map[string]string
}

type lifecycle uint8

const (
	created lifecycle = iota
	running
	closed
)

func (s lifecycle) runningError() error {
	switch s {
	case created:
		return ErrNodeNotStarted
	case closed:
		return ErrNodeClosed
	default:
		return nil
	}
}

// New creates a node with the supplied credentials and topology. On success,
// the node owns the supplied sockets and listeners. Close releases them even before Start.
// With no sockets or listeners the node can still dial outbound TCP.
// Canceling parent shuts down a started node.
func New(parent context.Context, o Options) (*Node, error) {
	if parent == nil {
		return nil, errors.New("parent context required")
	}
	if o.Roots == nil {
		return nil, errors.New("explicit trust roots required")
	}
	o.Roots = o.Roots.Clone()
	cluster, err := pki.ReadClusterCA(o.ClusterCA)
	if err != nil {
		return nil, err
	}
	o.ClusterCA = nil
	view, err := o.Topology.compile(cluster)
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
		if !view.physicalEndpoint(ep) {
			return nil, fmt.Errorf("invalid advertised physical endpoint %v", ep)
		}
	}
	o.AdvertiseEndpoints = slices.Clone(o.AdvertiseEndpoints)
	ctx, cancel := context.WithCancel(parent)
	n := &Node{
		o:                      o,
		id:                     identity.ID,
		ctx:                    ctx,
		cancel:                 cancel,
		done:                   make(chan struct{}),
		peers:                  make(map[PeerID]*peerPaths),
		modes:                  make(map[PeerID]PathMode),
		attempts:               make(map[PeerID]*peerAttempt),
		directDials:            make(map[endpointDialKey]*endpointAttempt),
		deniedUDP:              make(map[netip.AddrPort]deniedEndpoint),
		routeCursors:           make(map[PeerID]*routeCursor),
		probeSlots:             make(chan struct{}, 4),
		circuits:               make(map[*circuitLease]struct{}),
		discovered:             make(map[PeerID]learnedIntroduction),
		discoveredOwners:       make(map[netip.Addr]PeerID),
		introduced:             make(map[Endpoint]map[PeerID]time.Time),
		observations:           make(map[observer]observation),
		resolutions:            make(map[netip.Addr]*ipResolution),
		queries:                make(map[string]time.Time),
		publications:           make(map[string]cachedPublication),
		subscriptions:          make(map[*Subscription]struct{}),
		handshakeSlots:         make(chan struct{}, 128),
		backgroundSlots:        make(chan struct{}, 8),
		neighborDialSlots:      make(chan struct{}, 4),
		sharedAddressDialSlots: make(chan struct{}, 8),
	}
	c.until, err = n.credentialDeadline(ctx, view, c)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := n.validateIntroduction(view, c.Object); err != nil {
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

// tryTask reserves capacity before scheduling work, and releases it on shutdown.
func (n *Node) tryTask(slots chan struct{}, fn func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.tryTaskLocked(slots, fn)
}

func (n *Node) tryTaskLocked(slots chan struct{}, fn func()) bool {
	if n.state != running {
		return false
	}
	select {
	case slots <- struct{}{}:
		n.wg.Go(func() { defer func() { <-slots }(); fn() })
		return true
	default:
		return false
	}
}

// Start begins accepting peer connections and maintaining authorized paths.
// A second call on a running node returns ErrNodeAlreadyStarted.
func (n *Node) Start() error {
	n.mu.Lock()
	if n.state == closed {
		n.mu.Unlock()
		return ErrNodeClosed
	}
	if err := n.ctx.Err(); err != nil {
		n.mu.Unlock()
		return err
	}
	if n.state == running {
		n.mu.Unlock()
		return ErrNodeAlreadyStarted
	}
	n.state = running
	if n.o.UDP4 != nil || n.o.UDP6 != nil {
		n.sizeQuery = make([]byte, MaxIPPacketSize+1)
	}
	n.transports = make(map[bool]*udpTransport, 2)
	listeners := make(map[string]*quic.Listener, 2)
	for family, udp := range map[string]net.PacketConn{"udp4": n.o.UDP4, "udp6": n.o.UDP6} {
		if udp == nil {
			continue
		}
		transport := n.newUDPTransport(udp)
		n.transports[family == "udp6"] = transport
		listener, err := transport.Listen(n.tlsConfig(PeerID{}, true), transport.config)
		if err != nil {
			n.mu.Unlock()
			n.Close()
			return err
		}
		listeners[family] = listener
	}
	for family, listener := range listeners {
		n.wg.Go(func() {
			for {
				q, err := listener.Accept(n.ctx)
				if err != nil {
					n.recordListenerError(family, err)
					return
				}
				if !n.tryTask(n.handshakeSlots, func() { n.attachQUIC(n.ctx, q, PeerID{}, false) }) {
					q.CloseWithError(0, "closing")
				}
			}
		})
	}
	for family, listener := range map[string]net.Listener{"tcp4": n.o.TCP4, "tcp6": n.o.TCP6} {
		if listener == nil {
			continue
		}
		n.wg.Go(func() {
			for {
				c, err := meshwire.AcceptTCP(listener, n.ctx.Done())
				if err != nil {
					n.recordListenerError(family, err)
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
	n.wg.Go(n.maintain)
	n.mu.Unlock()
	go func() { <-n.ctx.Done(); n.Close() }()
	return nil
}

func (n *Node) recordListenerError(family string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == running && n.ctx.Err() == nil {
		if n.listenerErrors == nil {
			n.listenerErrors = make(map[string]string)
		}
		n.listenerErrors[family] = err.Error()
	}
}

// Close shuts down the node and waits for its background tasks to finish.
// From a callback running on a node task, signal the owner to close the node
// after the callback returns.
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
		close(sub.publications)
		delete(n.subscriptions, sub)
	}
	n.mu.Unlock()
	// Let QUIC flush its close frame, even when another service has the
	// physical writer. A stalled write must not hold up shutdown indefinitely.
	sockets := [...]net.PacketConn{n.o.UDP4, n.o.UDP6}
	deadline := time.Now().Add(n.o.DialTimeout)
	for _, pc := range sockets {
		if pc != nil {
			pc.SetWriteDeadline(deadline)
		}
	}
	for _, s := range sessions {
		s.close()
	}
	for _, l := range []net.Listener{n.o.TCP4, n.o.TCP6} {
		if l != nil {
			l.Close()
		}
	}
	for _, t := range n.transports {
		// Closing a QUIC transport also releases its listener.
		t.Close()
	}
	for _, pc := range sockets {
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

type udpTransport struct {
	*quic.Transport
	config *quic.Config
}

func (n *Node) newUDPTransport(udp net.PacketConn) *udpTransport {
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
	t := &udpTransport{Transport: &quic.Transport{Conn: pc}, config: &quic.Config{
		Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, InitialPacketSize: 1200,
		HandshakeIdleTimeout: n.o.DialTimeout, MaxIncomingStreams: maxSessionStreams, MaxIncomingUniStreams: -1,
	}}
	if shared, ok := udp.(meshwire.SharedSocket); ok {
		shared.ConfigureMeshQUIC(t.Transport, t.config)
	}
	return t
}

// ID returns the certified overlay address pair.
func (n *Node) ID() PeerID { return n.id }

// MaxIPSize returns the configured inner packet limit in bytes.
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

// Cluster returns the immutable certified address plan.
func (n *Node) Cluster() pki.Cluster { return n.policy.Load().cluster }
