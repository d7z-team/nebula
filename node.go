package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
)

var (
	ErrNodeStarted    = errors.New("nebula node is already started")
	ErrNodeClosed     = errors.New("nebula node is closed")
	ErrNodeNotStarted = errors.New("nebula node is not started")
)

// positiveOr applies the package convention for optional sizes and intervals.
func positiveOr[T ~int | ~int64](value, fallback T) T {
	if value > 0 {
		return value
	}
	return fallback
}

// EndpointProvider supplies the node's current externally reachable transport
// endpoints. Calls are serialized. A provider must honor ctx and must not
// synchronously call AdvertiseNow or Rebind on the same Node.
type EndpointProvider func(context.Context) ([]netip.AddrPort, error)

type HandshakeOptions struct {
	TryInterval      time.Duration
	Retries          int
	TriggerBuffer    int
	ControlQueueSize int // Control packets retained per pending handshake. Default 100.
	RefreshAttempt   int // Retry on which to refresh discovery. Default 5.
}

type PunchyOptions struct {
	Punch            bool
	Respond          bool
	Delay            time.Duration
	RespondDelay     time.Duration
	TargetAllRemotes bool
	QueueSize        int // Maximum pending punch jobs. Default 64.
}

type ConnectionOptions struct {
	CheckInterval           time.Duration
	PendingDeletionInterval time.Duration
	InactivityTimeout       time.Duration
	DropInactive            bool
	MaxTunnelsPerAddress    int           // Concurrent tunnels retained across rehandshakes. Default 5.
	RoamSuppressInterval    time.Duration // Minimum interval between probe requests for the same roaming candidate. Default 2s.
}

type LighthouseOptions struct {
	AmLighthouse       bool
	Hosts              []netip.Addr
	StaticHosts        map[netip.Addr][]netip.AddrPort
	AdvertiseEndpoints []netip.AddrPort
	EndpointProvider   EndpointProvider
	UpdateInterval     time.Duration
	QueryBuffer        int // Queued peer queries. Default 1024.
	MaxReported        int // Candidates per report, separately for IPv4, IPv6, and relays. Default 10.
}

type RelayOptions struct {
	Serve           bool
	AdvertiseVia    []netip.Addr
	MaxMappings     int           // Local relay indices shared by all neighbors. Default 8192.
	PendingTimeout  time.Duration // Lifetime of a half-open mapping. Default 1m.
	RequestInterval time.Duration // Minimum interval between requests for one mapping. Default 100ms.
}

// Options configures the Nebula tunnel and its caller-supplied transport.
type Options struct {
	Identities        []Identity
	CAPool            *cert.CAPool
	InitiatingVersion cert.Version
	Cipher            string
	Transport         DatagramTransport
	// DatagramMagic prefixes each outer datagram, including hole punches.
	// Use the same bytes on every peer and relay. Empty uses upstream framing.
	DatagramMagic []byte

	Control         *ControlOptions
	IPPort          IPPortOptions
	Lighthouse      LighthouseOptions
	Punchy          PunchyOptions
	Relay           RelayOptions
	Paths           PathOptions
	Handshake       HandshakeOptions
	Connections     ConnectionOptions
	PreferredRanges []netip.Prefix
	InboundPolicy   InboundPolicy
	Logger          *slog.Logger
}

// Node owns Nebula tunnels and the outer datagram transport.
// New takes ownership of Options.Transport when it succeeds.
type Node struct {
	mu            sync.Mutex
	workers       sync.WaitGroup
	state         NodeState
	fatalErr      error
	ctx           context.Context
	cancel        context.CancelFunc
	transport     DatagramTransport
	portOptions   IPPortOptions
	engine        *packetEngine
	handshake     *handshakeManager
	connections   *connectionManager
	punchy        *punchManager
	lighthouse    *lighthouse
	transportAddr netip.AddrPort
}

func New(parent context.Context, options Options) (*Node, error) {
	if parent == nil {
		parent = context.Background()
	}
	if options.Transport == nil {
		return nil, errors.New("transport is required")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	pki, err := newPKI(options.Identities, options.CAPool, options.Cipher, options.InitiatingVersion)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	engine := newPacketEngine(pki, &options, logger)
	punchy := newPunchManager(logger, options.Punchy)
	lighthouse, err := newLighthouse(ctx, logger, pki.getCertState(), punchy, &options)
	if err != nil {
		cancel()
		return nil, err
	}
	handshake := newHandshakeManager(logger, engine.hostMap, lighthouse, options.Handshake)
	connections := newConnectionManager(logger, engine.hostMap, punchy, options.Connections)
	engine.handshakeManager = handshake
	engine.connectionManager = connections
	engine.lightHouse = lighthouse
	connections.engine = engine
	handshake.f = engine
	lighthouse.handshakeTrigger = handshake.trigger
	lighthouse.sender = engine
	punchy.engine = engine
	punchy.lh = lighthouse
	transportAddr, _ := options.Transport.LocalAddr()
	n := &Node{
		ctx: ctx, cancel: cancel, transport: options.Transport,
		portOptions: IPPortOptions{
			QueueSize:        positiveOr(options.IPPort.QueueSize, 512),
			PerPeerQueueSize: positiveOr(options.IPPort.PerPeerQueueSize, 100),
		},
		engine: engine, handshake: handshake, connections: connections,
		punchy: punchy, lighthouse: lighthouse,
		transportAddr: unmapAddrPort(transportAddr),
	}
	for _, relay := range lighthouse.relaysForMe {
		if err := n.validatePeerAddress(relay); err != nil {
			cancel()
			return nil, fmt.Errorf("advertised relay: %w", err)
		}
	}
	if err := engine.paths.init(n, options.Paths); err != nil {
		cancel()
		return nil, err
	}
	if options.Control != nil {
		if err := n.initControl(*options.Control); err != nil {
			cancel()
			return nil, err
		}
	}
	// Keep Wait blocked through shutdown, including when it is called before Start.
	n.workers.Add(1)
	return n, nil
}

func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch n.state {
	case NodeStateRunning:
		return ErrNodeStarted
	case NodeStateClosed:
		return ErrNodeClosed
	}
	if c := n.engine.control; c != nil && c.socket == nil {
		return errors.New("attach overlay control socket before Start")
	}
	transportAddr, err := n.transport.LocalAddr()
	if err != nil {
		n.state = NodeStateClosed
		n.cancel()
		_ = n.closeTransport()
		return fmt.Errorf("get datagram transport address: %w", err)
	}
	n.transportAddr = unmapAddrPort(transportAddr)
	n.state = NodeStateRunning
	n.engine.l.Info("Nebula node is active", "networks", n.engine.myVpnNetworks, "transportAddr", transportAddr)
	n.punchy.ctx = n.ctx
	n.workers.Go(func() { n.handshake.Run(n.ctx) })
	n.workers.Go(func() { n.punchy.run(n.ctx) })
	if c := n.engine.control; c != nil {
		n.workers.Go(c.run)
		n.workers.Go(c.read)
		n.workers.Go(c.runEvents)
		n.workers.Go(func() { c.shaper.run(c) })
	}
	n.workers.Go(n.runPathChecks)
	n.workers.Go(func() { n.connections.Start(n.ctx) })
	n.workers.Go(n.lighthouse.runQueryWorker)
	n.workers.Go(n.lighthouse.runUpdateWorker)
	n.workers.Go(func() { _ = n.shutdown(n.engine.receiveDatagrams()) })
	n.workers.Go(func() {
		<-n.ctx.Done()
		_ = n.Close()
	})
	return nil
}

func (n *Node) Close() error { return n.shutdown(nil) }

func (n *Node) shutdown(cause error) error {
	n.mu.Lock()
	if n.state == NodeStateClosed {
		n.mu.Unlock()
		return nil
	}
	if n.ctx.Err() != nil {
		cause = nil
	}
	n.fatalErr = cause
	n.state = NodeStateClosed
	n.cancel()
	n.mu.Unlock()
	if cause != nil {
		n.engine.l.Error("datagram transport reader failed", "error", cause)
	}
	return n.closeTransport()
}

// closeTransport is called once after the transition to NodeStateClosed.
func (n *Node) closeTransport() error {
	defer n.workers.Done()
	if c := n.engine.control; c != nil {
		if c.socket != nil {
			_ = c.socket.Close()
		}
		c.mu.Lock()
		for s := range c.subs {
			close(s.events)
			delete(c.subs, s)
		}
		c.mu.Unlock()
	}
	if port := n.engine.port.Load(); port != nil {
		port.Close()
	}
	return n.transport.Close()
}

func (n *Node) Wait() error {
	n.workers.Wait()
	return n.Err()
}

func (n *Node) Context() context.Context { return n.ctx }

func (n *Node) Rebind() error {
	if err := n.requireStarted(); err != nil {
		return err
	}
	rebindable, ok := n.transport.(RebindableTransport)
	if !ok {
		return errors.New("datagram transport does not support rebinding")
	}
	if err := rebindable.Rebind(); err != nil {
		return err
	}
	if addr, err := n.transport.LocalAddr(); err == nil {
		n.mu.Lock()
		n.transportAddr = unmapAddrPort(addr)
		n.mu.Unlock()
	}
	n.engine.rebindEpoch.Add(1)
	n.lighthouse.SendUpdate()
	return nil
}

func (n *Node) requireStarted() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == NodeStateClosed {
		return ErrNodeClosed
	}
	if n.state != NodeStateRunning {
		return ErrNodeNotStarted
	}
	if n.ctx.Err() != nil {
		return ErrNodeClosed
	}
	return nil
}

func cloneAddresses(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, len(in))
	for i, addr := range in {
		out[i] = addr.Unmap()
	}
	return out
}
