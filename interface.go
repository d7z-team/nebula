package nebula

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/ratelimit"
)

const mtu = 9001

type packetEngine struct {
	hostMap              *hostMap
	outside              DatagramTransport
	port                 atomic.Pointer[IPPort]
	localUnsafe          bart.Lite
	overlayBroadcasts    map[netip.Addr]struct{}
	inboundPolicy        InboundPolicy
	pki                  *pkiState
	connectionManager    *connectionManager
	handshakeManager     *handshakeManager
	lightHouse           *lighthouse
	myVpnAddrs           []netip.Addr
	myVpnAddrsTable      *bart.Lite
	myVpnNetworks        []netip.Prefix
	myVpnNetworksTable   *bart.Lite
	relayManager         *relayManager
	rebindEpoch          atomic.Uint32
	udpTxErrLimiter      *ratelimit.Limiter
	udpRelayTxErrLimiter *ratelimit.Limiter
	txOversizeLimiter    *ratelimit.Limiter
	l                    *slog.Logger
}

func newPacketEngine(pki *pkiState, opts *Options, logger *slog.Logger) *packetEngine {
	// Each log site has its own one-event-per-second budget.
	newLogLimiter := func() *ratelimit.Limiter {
		limiter, err := ratelimit.New(1, time.Second)
		if err != nil {
			panic(err)
		}
		return limiter
	}
	cs := pki.getCertState()
	hosts := newHostMap(logger)
	f := &packetEngine{
		l:             logger,
		hostMap:       hosts,
		outside:       opts.Transport,
		inboundPolicy: opts.InboundPolicy,
		pki:           pki,
		relayManager: &relayManager{
			l: logger, hostmap: hosts,
			amRelay: opts.Relay.AmRelay, useRelays: opts.Relay.UseRelays && !opts.Relay.AmRelay,
		},
		myVpnNetworks:        cs.myVpnNetworks,
		myVpnNetworksTable:   cs.myVpnNetworksTable,
		myVpnAddrs:           cs.myVpnAddrs,
		myVpnAddrsTable:      cs.myVpnAddrsTable,
		overlayBroadcasts:    make(map[netip.Addr]struct{}),
		udpTxErrLimiter:      newLogLimiter(),
		udpRelayTxErrLimiter: newLogLimiter(),
		txOversizeLimiter:    newLogLimiter(),
	}
	for _, prefix := range cs.myVpnNetworks {
		if prefix.Addr().Is4() && prefix.Bits() < 31 {
			ip := prefix.Addr().As4()
			hostMask := ^uint32(0) >> prefix.Bits()
			binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])|hostMask)
			f.overlayBroadcasts[netip.AddrFrom4(ip)] = struct{}{}
		}
	}
	for _, prefix := range cs.GetDefaultCertificate().UnsafeNetworks() {
		f.localUnsafe.Insert(prefix)
	}
	return f
}

type rxContext struct {
	scratch []byte
	nb      []byte
	h       header.H
	lhh     *lighthouseHandler
}

func (f *packetEngine) receiveDatagrams() error {
	rxc := &rxContext{
		scratch: make([]byte, mtu),
		nb:      make([]byte, 12),
		lhh:     f.lightHouse.NewRequestHandler(),
	}
	packet := make([]byte, mtu+header.MaxOverhead)
	for {
		n, from, err := f.outside.ReadFrom(packet)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(packet) {
			continue
		}
		f.dispatchDatagram(packetSender{UdpAddr: from}, packet[:n], rxc)
	}
}

func (f *packetEngine) GetHostInfo(vpnAddr netip.Addr) *hostInfo {
	return f.hostMap.QueryVpnAddr(vpnAddr)
}

func (f *packetEngine) GetCertState() *certificateState {
	return f.pki.getCertState()
}
