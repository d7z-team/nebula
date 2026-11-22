package nebula

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/ratelimit"
)

const mtu = 9001

type packetEngine struct {
	paths                pathManager
	hostMap              *hostMap
	outside              DatagramTransport
	datagramMagic        []byte
	datagramBuffers      sync.Pool
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
	servesRelays         bool
	forwardedDatagrams   atomic.Uint64
	roamSuppressInterval time.Duration
	rebindEpoch          atomic.Uint32
	udpTxErrLimiter      *ratelimit.Limiter
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
	f := &packetEngine{
		l:                    logger,
		hostMap:              newHostMap(logger, opts),
		outside:              opts.Transport,
		datagramMagic:        slices.Clone(opts.DatagramMagic),
		inboundPolicy:        opts.InboundPolicy,
		pki:                  pki,
		servesRelays:         opts.Relay.Serve,
		roamSuppressInterval: positiveOr(opts.Connections.RoamSuppressInterval, 2*time.Second),
		myVpnNetworks:        cs.myVpnNetworks,
		myVpnNetworksTable:   cs.myVpnNetworksTable,
		myVpnAddrs:           cs.myVpnAddrs,
		myVpnAddrsTable:      cs.myVpnAddrsTable,
		overlayBroadcasts:    make(map[netip.Addr]struct{}),
		udpTxErrLimiter:      newLogLimiter(),
		txOversizeLimiter:    newLogLimiter(),
	}
	if len(f.datagramMagic) > 0 {
		f.datagramBuffers.New = func() any { return new(bytes.Buffer) }
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

func (f *packetEngine) GetHostInfo(vpnAddr netip.Addr) *hostInfo {
	return f.hostMap.QueryVpnAddr(vpnAddr)
}

func (f *packetEngine) GetCertState() *certificateState {
	return f.pki.getCertState()
}
