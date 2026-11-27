// Package nebula carries IP packets between authenticated peers over QUIC or TLS over TCP.
package nebula

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.d7z.net/nebula/meshwire"
	"gopkg.d7z.net/nebula/pki"

	quic "github.com/quic-go/quic-go"
)

var (
	ErrNodeNotStarted      = errors.New("node not started")
	ErrNodeAlreadyStarted  = errors.New("node already started")
	ErrNodeClosed          = errors.New("node closed")
	ErrInstanceConflict    = errors.New("peer instance conflict")
	ErrPeerUnavailable     = errors.New("peer unavailable")
	ErrPathPolicy          = errors.New("path denied")
	ErrPacketTooLarge      = errors.New("packet exceeds receive limit")
	ErrQueueFull           = errors.New("queue full")
	ErrPortClosed          = errors.New("IP port closed")
	ErrAddressUnauthorized = errors.New("address unauthorized")
	ErrNextHopRequired     = errors.New("next hop required")
)

// Options configures one node. Durations and limits use defaults when zero
// and reject negative values.
type Options struct {
	Auth      AuthOptions
	Transport TransportOptions
	Topology  Topology
	Probe     ProbeOptions
	// MaintenanceInterval sets the cadence of neighbor retries and expiry cleanup. Zero selects two seconds.
	MaintenanceInterval time.Duration
	// DialTimeout is the base timeout for dialing, handshakes, control exchanges
	// and transport writes. Circuit setup budgets one timeout per remaining hop.
	// Zero selects four seconds.
	DialTimeout time.Duration
	// MaxInboundHandshakes limits concurrent inbound direct session setup across
	// both address families. TCP reserves a slot before TLS, QUIC after TLS.
	// The slot is released when setup finishes. Zero selects 256.
	MaxInboundHandshakes int
	// MaxCircuits limits concurrent relay circuits originating, terminating or
	// forwarding at this node, including circuits under construction. Zero selects 512.
	MaxCircuits int
	// InboundCircuitLimits caps circuit reservations made by authenticated neighbors.
	InboundCircuitLimits InboundCircuitLimits
	// RelayWeights sets relative byte shares for backlogged relay traffic by
	// authenticated ingress neighbor. All circuits from the neighbor share its
	// weight. Missing or zero values use weight one.
	RelayWeights map[PeerID]uint16
	// MaxIPSize bounds a complete inner packet in bytes and is advertised to authenticated peers.
	// The range is 1280 through 65535. Zero selects 65535.
	MaxIPSize int
	// InboundPolicy optionally filters authenticated, address-authorized IP packets.
	// Calls run on receive tasks and may overlap.
	InboundPolicy func(peer PeerID, source, destination netip.Addr) bool
}

// ProbeOptions configures authenticated health checks for each established path.
type ProbeOptions struct {
	// Interval sets the target time between probes. Zero inherits MaintenanceInterval.
	Interval time.Duration
	// FailureThreshold closes a path after this many consecutive failed probes.
	// A successful probe resets the count. Zero selects three.
	FailureThreshold int
}

// AuthOptions sets the node's trust anchors, local credentials and chain policy.
type AuthOptions struct {
	// TrustedEntrypoints identifies approved first contacts in this cluster by public key.
	TrustedEntrypoints []PeerID
	// RootCA is the ordinary, self-signed authority for node identities.
	RootCA *x509.Certificate
	// ClusterCA pins the certificate defining this mesh under RootCA.
	ClusterCA *x509.Certificate
	// Certificates supplies the initial credentials for this identity.
	// Use Node.ReloadCertificates to replace them.
	Certificates LocalCertificates
	// CheckChain may deny a verified chain or shorten its lifetime. A zero deadline
	// accepts the chain until expiry. Calls may run concurrently. Call Node.Revalidate
	// after changing the host policy to recheck existing authorizations.
	CheckChain func(context.Context, ChainCheck) (time.Time, error)
}

// EndpointSource identifies how the node obtained a local address for publication.
type EndpointSource uint8

const (
	EndpointFromConfig      EndpointSource = iota // TransportOptions.AdvertiseEndpoints.
	EndpointFromTopology                          // The local Member.Endpoints.
	EndpointFromListener                          // A local UDP socket or TCP listener.
	EndpointFromObservation                       // A report from an authenticated QUIC neighbor.
)

// EndpointCandidate describes a physical address considered for the local signed introduction.
type EndpointCandidate struct {
	Endpoint Endpoint
	Source   EndpointSource
	// Observer is the reporting peer for EndpointFromObservation and zero otherwise.
	Observer PeerID
}

// TransportOptions configures mesh handshakes, physical transports and advertised endpoints.
type TransportOptions struct {
	// ALPN is the TLS application protocol for TCP, QUIC and end-to-end relay
	// sessions. Empty selects meshwire.ALPN. Peers and port sharers must use
	// the same identifier (1 to 255 bytes).
	ALPN string
	// CurvePreferences is the set of TLS key exchange groups allowed for inbound
	// and outbound TCP, QUIC and end-to-end relay sessions. An empty set uses
	// the crypto/tls defaults. Go chooses the group in its own preference order.
	CurvePreferences []tls.CurveID
	// UDP sockets carry QUIC and hole punches for their respective address families.
	// Sockets implementing meshwire.SharedSocket configure the node's QUIC transport at startup.
	UDP4, UDP6 net.PacketConn
	// TCP listeners accept inbound TLS connections, including from portshare.TCP.Mesh.
	TCP4, TCP6 net.Listener
	// DialTCP opens outbound TCP connections. Each connection must support
	// setting and clearing deadlines. The default is net.Dialer.DialContext.
	DialTCP func(context.Context, string, string) (net.Conn, error)
	// AdvertiseEndpoints adds reachable physical addresses outside the certified
	// member subnets and anycast pools to signed introductions.
	AdvertiseEndpoints []Endpoint
	// AllowAdvertiseEndpoint selects candidates for the local, forwardable signed
	// introduction. Observations are also checked before replacing a prior report.
	// Nil accepts all valid candidates. HideEndpoints takes precedence.
	AllowAdvertiseEndpoint func(EndpointCandidate) bool
	// AllowOutboundEndpoint permits active physical contact for ConnectEndpoint,
	// automatic TCP and QUIC dials, path probes and UDP hole punches. Nil permits
	// all destinations allowed by path policy. Existing sessions keep their paths.
	// Both endpoint callbacks may run concurrently and should return promptly.
	AllowOutboundEndpoint func(Endpoint) bool
	// HideEndpoints omits all physical endpoints from this node's signed introductions,
	// including AdvertiseEndpoints, local topology entries, listeners and NAT mappings.
	// Incoming rendezvous requests receive the signed record without a UDP punch.
	// Direct neighbors still see the connection address. Use Member.Restricted
	// and Member.Links to limit which members may connect directly.
	HideEndpoints bool
}

// Node manages the transports and peer sessions for one mesh identity.
type Node struct {
	clusterFingerprint     [sha256.Size]byte
	roots                  *x509.CertPool
	o                      Options
	id                     PeerID
	instance               InstanceID
	conflicts              map[PeerID]instanceConflict
	evidence               []claimObservation
	ctx                    context.Context
	cancel                 context.CancelFunc
	mu                     sync.Mutex
	udpWrites              sync.RWMutex
	state                  lifecycle
	wg                     sync.WaitGroup
	done                   chan struct{}
	cred                   atomic.Pointer[credentials]
	policy                 atomic.Pointer[topologyView]
	admissions             uint64 // generation of session, publication and conflict admissions
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
	handshakeRejections    uint64                     // Protected by mu.
	grantWrites            map[chan struct{}]struct{} // in-flight grant frames, protected by mu
	sizeQuery              []byte
	routeCursors           map[PeerID]*routeCursor
	probes                 probeBatch
	circuits               map[*circuitLease]struct{}
	relay                  RelayStatus
	shaper                 fairShaper
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

// prepareRuntime validates limits and takes ownership of the runtime option slices and maps.
func (o *Options) prepareRuntime(view *topologyView) error {
	if o.MaintenanceInterval < 0 {
		return errors.New("negative MaintenanceInterval")
	}
	o.MaintenanceInterval = cmp.Or(o.MaintenanceInterval, 2*time.Second)
	if o.Probe.Interval < 0 {
		return errors.New("negative Probe.Interval")
	}
	o.Probe.Interval = cmp.Or(o.Probe.Interval, o.MaintenanceInterval)
	if o.Probe.FailureThreshold < 0 {
		return errors.New("negative Probe.FailureThreshold")
	}
	o.Probe.FailureThreshold = cmp.Or(o.Probe.FailureThreshold, 3)
	if o.DialTimeout < 0 {
		return errors.New("negative DialTimeout")
	}
	o.DialTimeout = cmp.Or(o.DialTimeout, 4*time.Second)
	if o.MaxInboundHandshakes < 0 {
		return errors.New("negative MaxInboundHandshakes")
	}
	o.MaxInboundHandshakes = cmp.Or(o.MaxInboundHandshakes, 256)
	if o.MaxCircuits < 0 {
		return errors.New("negative MaxCircuits")
	}
	o.MaxCircuits = cmp.Or(o.MaxCircuits, 512)
	if o.InboundCircuitLimits.Default < 0 {
		return errors.New("negative default inbound circuit limit")
	}
	for peer, limit := range o.InboundCircuitLimits.ByPeer {
		if peer == (PeerID{}) || limit < 0 {
			return errors.New("invalid inbound circuit limit for peer")
		}
	}
	o.InboundCircuitLimits.ByPeer = maps.Clone(o.InboundCircuitLimits.ByPeer)
	if _, ok := o.RelayWeights[PeerID{}]; ok {
		return errors.New("invalid neighbor in RelayWeights")
	}
	o.RelayWeights = maps.Clone(o.RelayWeights)
	o.MaxIPSize = cmp.Or(o.MaxIPSize, MaxIPPacketSize)
	if o.MaxIPSize < 1280 || o.MaxIPSize > MaxIPPacketSize {
		return errors.New("invalid IP size")
	}
	alpn, err := meshwire.ResolveALPN(o.Transport.ALPN)
	if err != nil {
		return err
	}
	o.Transport.ALPN = alpn
	o.Transport.CurvePreferences = slices.Clone(o.Transport.CurvePreferences)
	if o.Transport.DialTCP == nil {
		o.Transport.DialTCP = (&net.Dialer{}).DialContext
	}
	for _, ep := range o.Transport.AdvertiseEndpoints {
		if !view.physicalEndpoint(ep) {
			return fmt.Errorf("invalid advertised physical endpoint %v", ep)
		}
	}
	o.Transport.AdvertiseEndpoints = slices.Clone(o.Transport.AdvertiseEndpoints)
	return nil
}

// New creates a node with the supplied credentials and topology. On success,
// the node owns the supplied sockets and listeners. Close releases them even before Start.
// With no sockets or listeners the node can still dial outbound TCP.
// Canceling parent shuts down a started node.
func New(parent context.Context, o Options) (*Node, error) {
	if parent == nil {
		return nil, errors.New("parent context required")
	}
	if o.Auth.RootCA == nil || o.Auth.ClusterCA == nil {
		return nil, errors.New("root CA and cluster CA required")
	}
	root, err := x509.ParseCertificate(slices.Clone(o.Auth.RootCA.Raw))
	if err != nil {
		return nil, err
	}
	o.Auth.RootCA = root
	if err := pki.ValidateRoot(root); err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	cluster, err := pki.ReadClusterCA(o.Auth.ClusterCA)
	if err != nil {
		return nil, err
	}
	if o.Auth.ClusterCA.CheckSignatureFrom(root) != nil {
		return nil, errors.New("cluster CA must be issued directly by root")
	}
	fingerprint := sha256.Sum256(o.Auth.ClusterCA.Raw)
	o.Auth.ClusterCA = nil
	view, err := o.Topology.compile(cluster)
	if err != nil {
		return nil, err
	}
	o.Topology = Topology{}
	c, err := prepareCertificates(o.Auth.Certificates)
	if err != nil {
		return nil, err
	}
	o.Auth.TrustedEntrypoints = slices.Clone(o.Auth.TrustedEntrypoints)
	o.Auth.Certificates = LocalCertificates{}
	if err := o.prepareRuntime(view); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	n := &Node{
		roots: roots, clusterFingerprint: fingerprint,
		o:                      o,
		id:                     c.identity.ID,
		ctx:                    ctx,
		cancel:                 cancel,
		done:                   make(chan struct{}),
		peers:                  make(map[PeerID]*peerPaths),
		conflicts:              make(map[PeerID]instanceConflict),
		modes:                  make(map[PeerID]PathMode),
		attempts:               make(map[PeerID]*peerAttempt),
		directDials:            make(map[endpointDialKey]*endpointAttempt),
		deniedUDP:              make(map[netip.AddrPort]deniedEndpoint),
		shaper:                 fairShaper{weights: o.RelayWeights},
		relay:                  RelayStatus{InboundCircuits: make(map[PeerID]int)},
		routeCursors:           make(map[PeerID]*routeCursor),
		circuits:               make(map[*circuitLease]struct{}),
		discovered:             make(map[PeerID]learnedIntroduction),
		discoveredOwners:       make(map[netip.Addr]PeerID),
		introduced:             make(map[Endpoint]map[PeerID]time.Time),
		observations:           make(map[observer]observation),
		resolutions:            make(map[netip.Addr]*ipResolution),
		queries:                make(map[string]time.Time),
		publications:           make(map[string]cachedPublication),
		subscriptions:          make(map[*Subscription]struct{}),
		handshakeSlots:         make(chan struct{}, o.MaxInboundHandshakes),
		grantWrites:            make(map[chan struct{}]struct{}),
		backgroundSlots:        make(chan struct{}, 8),
		neighborDialSlots:      make(chan struct{}, 4),
		sharedAddressDialSlots: make(chan struct{}, 8),
	}
	for n.instance == (InstanceID{}) {
		rand.Read(n.instance[:])
	}
	c.until, err = n.credentialDeadline(ctx, view, c)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := n.validateIntroduction(view, c); err != nil {
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
	n.shaper.setRate(n.ctx, view.members[n.id].BytesPerSecond)
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

func (n *Node) tryInboundHandshake(fn func()) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.tryTaskLocked(n.handshakeSlots, fn) {
		return true
	}
	if n.state == running && n.ctx.Err() == nil {
		n.handshakeRejections++
	}
	return false
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
	if n.o.Transport.UDP4 != nil || n.o.Transport.UDP6 != nil {
		n.sizeQuery = make([]byte, MaxIPPacketSize+1)
	}
	n.transports = make(map[bool]*udpTransport, 2)
	listeners := make(map[string]*quic.Listener, 2)
	for family, udp := range map[string]net.PacketConn{"udp4": n.o.Transport.UDP4, "udp6": n.o.Transport.UDP6} {
		if udp == nil {
			continue
		}
		transport := n.newUDPTransport(udp)
		n.transports[family == "udp6"] = transport
		listener, err := transport.Listen(n.tlsConfig(PeerID{}, false, nil), transport.config)
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
				if !n.tryInboundHandshake(func() {
					_, _ = n.attachQUIC(n.ctx, q, PeerID{}, false, q.Context().Value(credentialContextKey{}).(*credentials))
				}) {
					q.CloseWithError(0, "closing")
				}
			}
		})
	}
	for family, listener := range map[string]net.Listener{"tcp4": n.o.Transport.TCP4, "tcp6": n.o.Transport.TCP6} {
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
				if !n.tryInboundHandshake(func() { _, _ = n.attachTLS(n.ctx, c, PeerID{}, nil, false, nil) }) {
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
	n.probes.pending = nil
	p := n.port
	for sub := range n.subscriptions {
		close(sub.publications)
		delete(n.subscriptions, sub)
	}
	n.mu.Unlock()
	// Let QUIC flush its close frame, even when another service has the
	// physical writer. A stalled write must not hold up shutdown indefinitely.
	sockets := [...]net.PacketConn{n.o.Transport.UDP4, n.o.Transport.UDP6}
	deadline := time.Now().Add(n.o.DialTimeout)
	for i, pc := range sockets {
		if pc != nil && pc.SetWriteDeadline(deadline) != nil {
			pc.Close()
			sockets[i] = nil
		}
	}
	for _, s := range sessions {
		s.close()
	}
	for _, l := range []net.Listener{n.o.Transport.TCP4, n.o.Transport.TCP6} {
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
		HandshakeIdleTimeout: n.o.DialTimeout, MaxIncomingUniStreams: -1,
		MaxIncomingStreams: min(int64(n.o.MaxCircuits), (1<<60)-maxSessionStreams) + maxSessionStreams,
	}}
	if shared, ok := udp.(meshwire.SharedSocket); ok {
		shared.ConfigureMeshQUIC(t.Transport, t.config)
	}
	previous := t.ConnContext
	t.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		if previous != nil {
			var err error
			ctx, err = previous(ctx, info)
			if err != nil {
				return nil, err
			}
		}
		return context.WithValue(ctx, credentialContextKey{}, n.cred.Load()), nil
	}
	return t
}

// Addresses returns the primary addresses in the current local grant.
func (n *Node) Addresses() pki.Addresses { return n.cred.Load().identity.Addresses }

// ID returns the stable node public-key fingerprint.
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
