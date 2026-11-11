package nebula

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/ratelimit"
)

const mtu = 9001

type packetEngineConfig struct {
	hostMap           *hostMap
	Outside           DatagramTransport
	Netstack          *userNetstack
	Routes            *packetRouteTable
	pki               *pkiState
	handshakeManager  *handshakeManager
	lightHouse        *lighthouse
	connectionManager *connectionManager
	relayManager      *relayManager

	tryPromoteEvery uint32
	reQueryEvery    uint32
	reQueryWait     time.Duration

	l *slog.Logger
}

type packetEngine struct {
	hostMap              *hostMap
	outside              DatagramTransport
	netstack             *userNetstack
	routes               *packetRouteTable
	pki                  *pkiState
	connectionManager    *connectionManager
	handshakeManager     *handshakeManager
	lightHouse           *lighthouse
	myVpnAddrs           []netip.Addr
	myVpnAddrsTable      *bart.Lite
	myVpnNetworks        []netip.Prefix
	myVpnNetworksTable   *bart.Lite
	closed               atomic.Bool
	relayManager         *relayManager
	tryPromoteEvery      uint32
	reQueryEvery         uint32
	reQueryWait          time.Duration
	rebindEpoch          atomic.Uint32
	ctx                  context.Context
	wg                   sync.WaitGroup
	udpTxErrLimiter      *ratelimit.Limiter
	udpRelayTxErrLimiter *ratelimit.Limiter
	txOversizeLimiter    *ratelimit.Limiter
	fatalErr             atomic.Pointer[error]
	triggerShutdown      func()
	l                    *slog.Logger
}

type encWriter interface {
	SendVia(via *hostInfo, relay *relay, ad, nb, out []byte, nocopy bool)
	SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte)
	SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hostinfo *hostInfo, p, nb, out []byte)
	Handshake(vpnAddr netip.Addr)
	GetHostInfo(vpnAddr netip.Addr) *hostInfo
	GetCertState() *certificateState
}

func newPacketEngine(ctx context.Context, c *packetEngineConfig) (*packetEngine, error) {
	if c.Outside == nil {
		return nil, errors.New("no datagram transport")
	}
	if c.Netstack == nil {
		return nil, errors.New("no userspace network stack")
	}
	if c.Routes == nil {
		return nil, errors.New("no packet route table")
	}
	if c.pki == nil {
		return nil, errors.New("no certificate state")
	}
	if c.connectionManager == nil {
		return nil, errors.New("no connection manager")
	}

	udpTxErrLimiter, err := ratelimit.New(1, time.Second)
	if err != nil {
		return nil, err
	}
	udpRelayTxErrLimiter, err := ratelimit.New(1, time.Second)
	if err != nil {
		return nil, err
	}
	txOversizeLimiter, err := ratelimit.New(1, time.Second)
	if err != nil {
		return nil, err
	}

	cs := c.pki.getCertState()
	f := &packetEngine{
		ctx:                  ctx,
		pki:                  c.pki,
		hostMap:              c.hostMap,
		outside:              c.Outside,
		netstack:             c.Netstack,
		routes:               c.Routes,
		handshakeManager:     c.handshakeManager,
		lightHouse:           c.lightHouse,
		myVpnNetworks:        cs.myVpnNetworks,
		myVpnNetworksTable:   cs.myVpnNetworksTable,
		myVpnAddrs:           cs.myVpnAddrs,
		myVpnAddrsTable:      cs.myVpnAddrsTable,
		relayManager:         c.relayManager,
		connectionManager:    c.connectionManager,
		udpTxErrLimiter:      udpTxErrLimiter,
		udpRelayTxErrLimiter: udpRelayTxErrLimiter,
		txOversizeLimiter:    txOversizeLimiter,
		tryPromoteEvery:      c.tryPromoteEvery,
		reQueryEvery:         c.reQueryEvery,
		reQueryWait:          c.reQueryWait,
		l:                    c.l,
	}
	f.connectionManager.engine = f
	f.wg.Add(1)
	return f, nil
}

func (f *packetEngine) activate() (netip.AddrPort, error) {
	addr, err := f.outside.LocalAddr()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("get datagram transport address: %w", err)
	}
	f.l.Info("Nebula node is active",
		"networks", f.myVpnNetworks,
		"transportAddr", addr,
	)
	return addr, nil
}

func (f *packetEngine) run() {
	f.wg.Go(f.listenOut)
	f.wg.Go(f.listenIn)
}

func (f *packetEngine) wait() error {
	f.wg.Wait()
	if err := f.fatalErr.Load(); err != nil {
		return *err
	}
	return nil
}

func (f *packetEngine) onFatal(err error) {
	if !f.fatalErr.CompareAndSwap(nil, &err) {
		return
	}
	if f.triggerShutdown != nil {
		f.triggerShutdown()
	}
}

type rxContext struct {
	scratch      []byte
	nb           []byte
	h            *header.H
	hostmapCache map[uint32]*hostInfo
	lhh          *lighthouseHandler
}

func newRxContext(f *packetEngine) *rxContext {
	return &rxContext{
		scratch:      make([]byte, mtu),
		nb:           make([]byte, 12, 12),
		h:            &header.H{},
		hostmapCache: make(map[uint32]*hostInfo),
		lhh:          f.lightHouse.NewRequestHandler(),
	}
}

func (f *packetEngine) listenOut() {
	rxc := newRxContext(f)
	packet := make([]byte, mtu+header.MaxOverhead)
	for {
		n, from, err := f.outside.ReadFrom(packet)
		if err != nil {
			if !f.closed.Load() && f.ctx.Err() == nil {
				f.l.Error("datagram transport reader failed", "error", err)
				f.onFatal(err)
			}
			return
		}
		if n <= 0 || n > len(packet) {
			continue
		}
		f.readOutsidePackets(packetSender{UdpAddr: from}, packet[:n], rxc)
		clear(rxc.hostmapCache)
	}
}

func (f *packetEngine) listenIn() {
	nonce := make([]byte, 12, 12)
	for {
		view, err := f.netstack.readPacket(f.ctx)
		if err != nil {
			if !f.closed.Load() && f.ctx.Err() == nil {
				f.l.Error("userspace network stack reader failed", "error", err)
				f.onFatal(err)
			}
			return
		}
		f.consumeInsidePacket(view.AsSlice(), nonce)
		view.Release()
	}
}

func (f *packetEngine) GetHostInfo(vpnAddr netip.Addr) *hostInfo {
	return f.hostMap.QueryVpnAddr(vpnAddr)
}

func (f *packetEngine) GetCertState() *certificateState {
	return f.pki.getCertState()
}

func (f *packetEngine) Close() error {
	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}
	var errs []error
	if err := f.outside.Close(); err != nil {
		errs = append(errs, err)
	}
	f.netstack.destroy()
	f.wg.Done()
	return errors.Join(errs...)
}
