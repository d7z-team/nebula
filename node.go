package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
)

var (
	ErrNodeStarted    = errors.New("nebula node is already started")
	ErrNodeClosed     = errors.New("nebula node is closed")
	ErrNodeNotStarted = errors.New("nebula node is not started")
)

type EndpointProvider func(context.Context) ([]netip.AddrPort, error)

type HandshakeOptions struct {
	TryInterval   time.Duration
	Retries       int
	TriggerBuffer int
}

type PunchyOptions struct {
	Punch            bool
	Respond          bool
	Delay            time.Duration
	RespondDelay     time.Duration
	TargetAllRemotes bool
}

type ConnectionOptions struct {
	CheckInterval           time.Duration
	PendingDeletionInterval time.Duration
	InactivityTimeout       time.Duration
	DropInactive            bool
}

type LighthouseOptions struct {
	AmLighthouse       bool
	Hosts              []netip.Addr
	StaticHosts        map[netip.Addr][]netip.AddrPort
	AdvertiseEndpoints []netip.AddrPort
	EndpointProvider   EndpointProvider
	UpdateInterval     time.Duration
}

type RelayOptions struct {
	AmRelay   bool
	UseRelays bool
	Relays    []netip.Addr
}

// Options contains only in-process settings. It performs no file, YAML,
// socket, interface, route-table, or firewall configuration.
type Options struct {
	Identities        []Identity
	CAPool            *cert.CAPool
	InitiatingVersion cert.Version
	Cipher            string
	Transport         DatagramTransport

	Lighthouse       LighthouseOptions
	Punchy           PunchyOptions
	Relay            RelayOptions
	Handshake        HandshakeOptions
	Connections      ConnectionOptions
	PreferredRanges  []netip.Prefix
	VirtualAddresses []netip.Addr
	UnsafeRoutes     []Route
	MTU              uint32
	Logger           *slog.Logger
}

type nodeState uint8

const (
	nodeReady nodeState = iota
	nodeStarted
	nodeClosed
)

// Node is an embedded Nebula endpoint backed by a userspace TCP/IP stack.
// New takes ownership of Options.Transport when it succeeds.
type Node struct {
	mu          sync.Mutex
	workers     sync.WaitGroup
	state       nodeState
	ctx         context.Context
	cancel      context.CancelFunc
	transport   DatagramTransport
	netstack    *userNetstack
	engine      *packetEngine
	handshake   *handshakeManager
	connections *connectionManager
	punchy      *punchManager
	lighthouse  *lighthouse
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
	if options.MTU == 0 {
		options.MTU = 1300
	}
	if options.MTU < 1280 || options.MTU > mtu {
		return nil, fmt.Errorf("MTU must be between 1280 and %d", mtu)
	}

	pki, err := newPKI(options.Identities, options.CAPool, options.Cipher, options.InitiatingVersion)
	if err != nil {
		return nil, err
	}
	certificate := pki.getCertState().v2Cert
	if certificate == nil {
		certificate = pki.getCertState().v1Cert
	}
	for _, identity := range options.Identities {
		for _, addr := range options.VirtualAddresses {
			if !prefixesContain(identity.Certificate.UnsafeNetworks(), addr.Unmap()) {
				return nil, fmt.Errorf("%w: %s is not authorized by identity %q", ErrAddressNotCertified, addr, identity.Certificate.Name())
			}
		}
	}
	routes, err := newPacketRouteTable(certificate, options.VirtualAddresses, options.UnsafeRoutes)
	if err != nil {
		return nil, err
	}
	netstack, err := newUserNetstack(routes, pki.getCertState().myVpnNetworks, options.VirtualAddresses, options.MTU)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	fail := func(err error) (*Node, error) {
		cancel()
		netstack.destroy()
		return nil, err
	}
	hostMap := newHostMap(logger, options.PreferredRanges)
	punchy := newPunchy(logger, options.Transport, punchyConfig{
		punch:           options.Punchy.Punch,
		respond:         options.Punchy.Respond,
		delay:           options.Punchy.Delay,
		respondDelay:    options.Punchy.RespondDelay,
		punchEverything: options.Punchy.TargetAllRemotes,
	})
	connections := newConnectionManager(logger, hostMap, punchy, connectionManagerConfig{
		checkInterval:           options.Connections.CheckInterval,
		pendingDeletionInterval: options.Connections.PendingDeletionInterval,
		inactivityTimeout:       options.Connections.InactivityTimeout,
		dropInactive:            options.Connections.DropInactive,
	})
	updateInterval := options.Lighthouse.UpdateInterval
	if updateInterval == 0 && len(options.Lighthouse.Hosts) > 0 {
		updateInterval = 10 * time.Second
	} else if updateInterval < 0 {
		updateInterval = 0
	}
	lighthouse, err := newLightHouse(ctx, logger, pki.getCertState(), punchy, lighthouseConfig{
		amLighthouse:     options.Lighthouse.AmLighthouse,
		lighthouses:      cloneAddresses(options.Lighthouse.Hosts),
		staticHosts:      cloneStaticHosts(options.Lighthouse.StaticHosts),
		advertiseAddrs:   slices.Clone(options.Lighthouse.AdvertiseEndpoints),
		endpointProvider: options.Lighthouse.EndpointProvider,
		relays:           cloneAddresses(options.Relay.Relays),
		updateInterval:   updateInterval,
	})
	if err != nil {
		return fail(err)
	}
	handshakeConfig := defaultHandshakeConfig
	if options.Handshake.TryInterval > 0 {
		handshakeConfig.tryInterval = options.Handshake.TryInterval
	}
	if options.Handshake.Retries > 0 {
		handshakeConfig.retries = int64(options.Handshake.Retries)
	}
	if options.Handshake.TriggerBuffer > 0 {
		handshakeConfig.triggerBuffer = options.Handshake.TriggerBuffer
	}
	handshake := newHandshakeManager(logger, hostMap, lighthouse, options.Transport, handshakeConfig)
	lighthouse.handshakeTrigger = handshake.trigger
	relay := newRelayManager(logger, hostMap, options.Relay.AmRelay, options.Relay.UseRelays)
	engine, err := newPacketEngine(ctx, &packetEngineConfig{
		hostMap:           hostMap,
		Outside:           options.Transport,
		Netstack:          netstack,
		Routes:            routes,
		pki:               pki,
		handshakeManager:  handshake,
		lightHouse:        lighthouse,
		connectionManager: connections,
		relayManager:      relay,
		tryPromoteEvery:   defaultPromoteEvery,
		reQueryEvery:      defaultReQueryEvery,
		reQueryWait:       defaultReQueryWait,
		l:                 logger,
	})
	if err != nil {
		return fail(err)
	}
	handshake.f = engine
	lighthouse.ifce = engine
	n := &Node{
		ctx: ctx, cancel: cancel, transport: options.Transport, netstack: netstack,
		engine: engine, handshake: handshake, connections: connections,
		punchy: punchy, lighthouse: lighthouse,
	}
	engine.triggerShutdown = func() { _ = n.Close() }
	return n, nil
}

func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch n.state {
	case nodeStarted:
		return ErrNodeStarted
	case nodeClosed:
		return ErrNodeClosed
	}
	if err := n.engine.activate(); err != nil {
		n.state = nodeClosed
		n.cancel()
		_ = n.engine.Close()
		return err
	}
	n.state = nodeStarted
	n.punchy.configure(n.ctx, n.engine, n.engine.hostMap, n.lighthouse)
	n.workers.Go(func() { n.handshake.Run(n.ctx) })
	n.workers.Go(func() { n.punchy.run(n.ctx) })
	n.workers.Go(func() { n.connections.Start(n.ctx) })
	n.workers.Go(n.lighthouse.runQueryWorker)
	n.workers.Go(n.lighthouse.runUpdateWorker)
	n.engine.run()
	n.workers.Go(func() {
		<-n.ctx.Done()
		_ = n.Close()
	})
	return nil
}

func (n *Node) Close() error {
	n.mu.Lock()
	if n.state == nodeClosed {
		n.mu.Unlock()
		return nil
	}
	n.state = nodeClosed
	n.cancel()
	n.mu.Unlock()
	return n.engine.Close()
}

func (n *Node) Wait() error {
	err := n.engine.wait()
	n.workers.Wait()
	return err
}

func (n *Node) Context() context.Context { return n.ctx }

func (n *Node) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := n.requireStarted(); err != nil {
		return nil, err
	}
	return n.netstack.dialContext(ctx, network, address, netip.Addr{})
}

func (n *Node) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *Node) Listen(network, address string) (net.Listener, error) {
	if err := n.requireStarted(); err != nil {
		return nil, err
	}
	return n.netstack.listen(network, address)
}

func (n *Node) ListenPacket(network, address string) (net.PacketConn, error) {
	if err := n.requireStarted(); err != nil {
		return nil, err
	}
	return n.netstack.listenPacket(network, address)
}

type DialerOptions struct {
	LocalAddr netip.Addr
}

type Dialer struct {
	node  *Node
	local netip.Addr
}

func (n *Node) Dialer(options DialerOptions) *Dialer {
	return &Dialer{node: n, local: options.LocalAddr.Unmap()}
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.node == nil {
		return nil, errors.New("nil Nebula dialer")
	}
	if err := d.node.requireStarted(); err != nil {
		return nil, err
	}
	return d.node.netstack.dialContext(ctx, network, address, d.local)
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

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
	n.engine.rebindEpoch.Add(1)
	n.lighthouse.SendUpdate()
	return nil
}

func (n *Node) requireStarted() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == nodeClosed {
		return ErrNodeClosed
	}
	if n.state != nodeStarted {
		return ErrNodeNotStarted
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

func cloneStaticHosts(in map[netip.Addr][]netip.AddrPort) map[netip.Addr][]netip.AddrPort {
	out := make(map[netip.Addr][]netip.AddrPort, len(in))
	for addr, endpoints := range in {
		out[addr.Unmap()] = slices.Clone(endpoints)
	}
	return out
}
