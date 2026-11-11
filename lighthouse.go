package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

var errBadDetailsVPNAddr = errors.New("invalid packet, malformed detailsVpnAddr")

type lighthouse struct {
	//TODO: We need a timer wheel to kick out vpnAddrs that haven't reported in a long time
	sync.RWMutex //Because we concurrently read and write to our maps
	ctx          context.Context
	amLighthouse bool

	myVpnNetworks      []netip.Prefix
	myVpnNetworksTable *bart.Lite
	// myVpnAddrsTable contains our overlay host addrs, as opposed to the overlay networks
	myVpnAddrsTable *bart.Lite
	punchy          *punchManager

	// Local cache of answers from light houses
	// map of vpn addr to answers
	addrMap map[netip.Addr]*remoteList

	endpointProvider func(context.Context) ([]netip.AddrPort, error)

	// used to trigger the handshakeManager when we receive HostQueryReply
	handshakeTrigger chan<- netip.Addr

	// staticList exists to avoid having a bool in each addrMap entry
	// since static should be rare
	staticList  map[netip.Addr]struct{}
	lighthouses []netip.Addr

	interval int64
	ifce     encWriter

	advertiseAddrs []netip.AddrPort

	// Addr's of relays that can be used by peers to access me
	relaysForMe []netip.Addr

	updateTrigger chan struct{}
	queryChan     chan netip.Addr

	l *slog.Logger
}

type lighthouseConfig struct {
	amLighthouse     bool
	lighthouses      []netip.Addr
	staticHosts      map[netip.Addr][]netip.AddrPort
	advertiseAddrs   []netip.AddrPort
	endpointProvider func(context.Context) ([]netip.AddrPort, error)
	relays           []netip.Addr
	updateInterval   time.Duration
	queryBuffer      int
}

func newLightHouse(ctx context.Context, l *slog.Logger, cs *certificateState, p *punchManager, cfg lighthouseConfig) (*lighthouse, error) {
	if cfg.queryBuffer <= 0 {
		cfg.queryBuffer = 1024
	}
	h := &lighthouse{
		ctx:                ctx,
		amLighthouse:       cfg.amLighthouse,
		myVpnNetworks:      cs.myVpnNetworks,
		myVpnNetworksTable: cs.myVpnNetworksTable,
		myVpnAddrsTable:    cs.myVpnAddrsTable,
		punchy:             p,
		addrMap:            make(map[netip.Addr]*remoteList),
		endpointProvider:   cfg.endpointProvider,
		updateTrigger:      make(chan struct{}, 1),
		queryChan:          make(chan netip.Addr, cfg.queryBuffer),
		l:                  l,
	}
	h.lighthouses = cfg.lighthouses
	h.advertiseAddrs = cfg.advertiseAddrs
	h.relaysForMe = cfg.relays
	staticList := make(map[netip.Addr]struct{}, len(cfg.staticHosts))
	owner := cs.myVpnNetworks[0].Addr()
	for vpnAddr, endpoints := range cfg.staticHosts {
		vpnAddr = vpnAddr.Unmap()
		if !cs.myVpnNetworksTable.Contains(vpnAddr) {
			return nil, fmt.Errorf("static host %s is outside the local overlay networks", vpnAddr)
		}
		remoteList := h.unlockedGetRemoteList([]netip.Addr{vpnAddr})
		remoteList.Lock()
		for _, endpoint := range endpoints {
			if !endpoint.IsValid() || !h.shouldAdd(endpoint.Addr()) {
				continue
			}
			if endpoint.Addr().Is4() {
				remoteList.unlockedPrependV4(owner, netAddrToProtoV4AddrPort(endpoint.Addr(), endpoint.Port()))
			} else {
				remoteList.unlockedPrependV6(owner, netAddrToProtoV6AddrPort(endpoint.Addr(), endpoint.Port()))
			}
		}
		remoteList.Unlock()
		staticList[vpnAddr] = struct{}{}
	}
	h.staticList = staticList
	for _, addr := range cfg.lighthouses {
		if _, ok := staticList[addr]; !ok {
			return nil, fmt.Errorf("lighthouse %s requires a static host endpoint", addr)
		}
	}
	seconds := int64(cfg.updateInterval / time.Second)
	if cfg.updateInterval > 0 && seconds == 0 {
		seconds = 1
	}
	h.interval = seconds
	return h, nil
}

func (lh *lighthouse) GetStaticHostList() map[netip.Addr]struct{} {
	return lh.staticList
}

func (lh *lighthouse) GetLighthouses() []netip.Addr {
	return lh.lighthouses
}

func (lh *lighthouse) GetAdvertiseAddrs() []netip.AddrPort {
	return lh.advertiseAddrs
}

func (lh *lighthouse) GetRelaysForMe() []netip.Addr {
	return lh.relaysForMe
}

func (lh *lighthouse) GetUpdateInterval() int64 {
	return lh.interval
}

func (lh *lighthouse) Query(vpnAddr netip.Addr) *remoteList {
	if !lh.IsLighthouseAddr(vpnAddr) {
		lh.QueryServer(vpnAddr)
	}
	lh.RLock()
	if v, ok := lh.addrMap[vpnAddr]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()
	return nil
}

// QueryServer is asynchronous and non-blocking, no reply should be expected.
// If the query channel is full, the query is dropped.
func (lh *lighthouse) QueryServer(vpnAddr netip.Addr) {
	// Don't put lighthouse addrs in the query channel because we can't query lighthouses about lighthouses
	if lh.amLighthouse || lh.IsLighthouseAddr(vpnAddr) {
		return
	}

	select {
	case lh.queryChan <- vpnAddr:
	default:
	}
}

func (lh *lighthouse) QueryCache(vpnAddrs []netip.Addr) *remoteList {
	lh.RLock()
	if v, ok := lh.addrMap[vpnAddrs[0]]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()

	lh.Lock()
	defer lh.Unlock()
	// Add an entry if we don't already have one
	return lh.unlockedGetRemoteList(vpnAddrs) //todo CERT-V2 this contains addrmap lookups we could potentially skip
}

// queryAndPrepMessage is a lock helper on remoteList, assisting the caller to build a lighthouse message containing
// details from the remote list. It looks for a hit in the addrMap and a hit in the remoteList under the owner vpnAddr
// If one is found then f() is called with proper locking, f() must return result of n.MarshalTo()
func (lh *lighthouse) queryAndPrepMessage(vpnAddr netip.Addr, f func(*cache) (int, error)) (bool, int, error) {
	lh.RLock()
	// Do we have an entry in the main cache?
	if v, ok := lh.addrMap[vpnAddr]; ok {
		// Swap lh lock for remote list lock
		v.RLock()
		defer v.RUnlock()

		lh.RUnlock()

		// We may be asking about a non primary address so lets get the primary address
		if slices.Contains(v.vpnAddrs, vpnAddr) {
			vpnAddr = v.vpnAddrs[0]
		}
		c := v.cache[vpnAddr]
		// Make sure we have
		if c != nil {
			n, err := f(c)
			return true, n, err
		}
		return false, 0, nil
	}
	lh.RUnlock()
	return false, 0, nil
}

func (lh *lighthouse) DeleteVpnAddrs(allVpnAddrs []netip.Addr) {
	// First we check the static host map. If any of the VpnAddrs to be deleted are present, do nothing.
	staticList := lh.GetStaticHostList()
	for _, addr := range allVpnAddrs {
		if _, ok := staticList[addr]; ok {
			return
		}
	}

	// None of the VpnAddrs were present. Now we can do the deletes.
	lh.Lock()
	rm, ok := lh.addrMap[allVpnAddrs[0]]
	if ok {
		debugEnabled := lh.l.Enabled(context.Background(), slog.LevelDebug)
		for _, addr := range allVpnAddrs {
			srm := lh.addrMap[addr]
			if srm == rm {
				delete(lh.addrMap, addr)
				if debugEnabled {
					lh.l.Debug("deleting from lighthouse", "vpnAddr", addr)
				}
			}
		}
	}
	lh.Unlock()
}

// unlockedGetRemoteList assumes you have the lh lock
func (lh *lighthouse) unlockedGetRemoteList(allAddrs []netip.Addr) *remoteList {
	// before we go and make a new remotelist, we need to make sure we don't have one for any of this set of vpnaddrs yet
	for i, addr := range allAddrs {
		am, ok := lh.addrMap[addr]
		if ok {
			if i != 0 {
				lh.addrMap[allAddrs[0]] = am
			}
			return am
		}
	}

	am := newRemoteList(allAddrs)
	for _, addr := range allAddrs {
		lh.addrMap[addr] = am
	}
	return am
}

func (lh *lighthouse) shouldAdd(to netip.Addr) bool {
	if lh.myVpnNetworksTable.Contains(to) {
		return false
	}

	return true
}

// unlockedShouldAddV4 rejects overlay addresses masquerading as underlay endpoints.
func (lh *lighthouse) unlockedShouldAddV4(_ netip.Addr, to *V4AddrPort) bool {
	udpAddr := protoV4AddrPortToNetAddrPort(to)
	if lh.myVpnNetworksTable.Contains(udpAddr.Addr()) {
		return false
	}

	return true
}

// unlockedShouldAddV6 rejects overlay addresses masquerading as underlay endpoints.
func (lh *lighthouse) unlockedShouldAddV6(_ netip.Addr, to *V6AddrPort) bool {
	udpAddr := protoV6AddrPortToNetAddrPort(to)
	if lh.myVpnNetworksTable.Contains(udpAddr.Addr()) {
		return false
	}

	return true
}

func (lh *lighthouse) IsLighthouseAddr(vpnAddr netip.Addr) bool {
	l := lh.GetLighthouses()
	return slices.Contains(l, vpnAddr)
}

func (lh *lighthouse) IsAnyLighthouseAddr(vpnAddrs []netip.Addr) bool {
	l := lh.GetLighthouses()
	for i := range vpnAddrs {
		if slices.Contains(l, vpnAddrs[i]) {
			return true
		}
	}
	return false
}

func (lh *lighthouse) runQueryWorker() {
	if lh.amLighthouse {
		return
	}

	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-lh.ctx.Done():
			return
		case addr := <-lh.queryChan:
			lh.innerQueryServer(addr, nb, out)
		}
	}
}

func (lh *lighthouse) innerQueryServer(addr netip.Addr, nb, out []byte) {
	if lh.IsLighthouseAddr(addr) {
		return
	}

	msg := &NebulaMeta{
		Type:    NebulaMeta_HostQuery,
		Details: &NebulaMetaDetails{},
	}

	var v1Query, v2Query []byte
	var err error
	var v cert.Version
	lighthouses := lh.GetLighthouses()

	for _, lhVpnAddr := range lighthouses {
		hi := lh.ifce.GetHostInfo(lhVpnAddr)
		if hi != nil {
			v = hi.connectionState.myCert.Version()
		} else {
			v = lh.ifce.GetCertState().initiatingVersion
		}

		if v == cert.Version1 {
			if !addr.Is4() {
				lh.l.Error("Can't query lighthouse for v6 address using a v1 protocol",
					"queryVpnAddr", addr,
					"lighthouseAddr", lhVpnAddr,
				)
				continue
			}

			if v1Query == nil {
				b := addr.As4()
				msg.Details.VpnAddr = nil
				msg.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])

				v1Query, err = msg.Marshal()
				if err != nil {
					lh.l.Error("Failed to marshal lighthouse v1 query payload",
						"error", err,
						"queryVpnAddr", addr,
						"lighthouseAddr", lhVpnAddr,
					)
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v1Query, nb, out)

		} else if v == cert.Version2 {
			if v2Query == nil {
				msg.Details.OldVpnAddr = 0
				msg.Details.VpnAddr = netAddrToProtoAddr(addr)

				v2Query, err = msg.Marshal()
				if err != nil {
					lh.l.Error("Failed to marshal lighthouse v2 query payload",
						"error", err,
						"queryVpnAddr", addr,
						"lighthouseAddr", lhVpnAddr,
					)
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v2Query, nb, out)

		} else {
			lh.l.Debug("unsupported protocol version",
				"op", "query",
				"queryVpnAddr", addr,
				"version", v,
			)
			continue
		}
	}

}

func (lh *lighthouse) runUpdateWorker() {
	interval := lh.GetUpdateInterval()
	if lh.amLighthouse || interval == 0 {
		return
	}

	clockSource := time.NewTicker(time.Second * time.Duration(interval))
	defer clockSource.Stop()

	for {
		lh.SendUpdate()

		select {
		case <-lh.ctx.Done():
			return
		case <-clockSource.C:
			continue
		case <-lh.updateTrigger:
			continue
		}
	}
}

// TriggerUpdate requests an immediate lighthouse update. This is a non-blocking
// operation intended to be called after a handshake completes with a lighthouse,
// so the lighthouse has our current addresses without waiting for the next
// periodic update.
func (lh *lighthouse) TriggerUpdate() {
	select {
	case lh.updateTrigger <- struct{}{}:
	default:
	}
}

func (lh *lighthouse) SendUpdate() {
	var v4 []*V4AddrPort
	var v6 []*V6AddrPort

	for _, e := range lh.GetAdvertiseAddrs() {
		if e.Addr().Is4() {
			v4 = append(v4, netAddrToProtoV4AddrPort(e.Addr(), e.Port()))
		} else {
			v6 = append(v6, netAddrToProtoV6AddrPort(e.Addr(), e.Port()))
		}
	}

	if lh.endpointProvider != nil {
		endpoints, err := lh.endpointProvider(lh.ctx)
		if err != nil {
			lh.l.Warn("endpoint provider failed", "error", err)
		} else {
			for _, endpoint := range endpoints {
				if !endpoint.IsValid() || lh.myVpnNetworksTable.Contains(endpoint.Addr()) {
					continue
				}
				if endpoint.Addr().Is4() {
					v4 = append(v4, netAddrToProtoV4AddrPort(endpoint.Addr(), endpoint.Port()))
				} else {
					v6 = append(v6, netAddrToProtoV6AddrPort(endpoint.Addr(), endpoint.Port()))
				}
			}
		}
	}

	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	var v1Update, v2Update []byte
	var err error
	lighthouses := lh.GetLighthouses()

	for _, lhVpnAddr := range lighthouses {
		var v cert.Version
		hi := lh.ifce.GetHostInfo(lhVpnAddr)
		if hi != nil {
			v = hi.connectionState.myCert.Version()
		} else {
			v = lh.ifce.GetCertState().initiatingVersion
		}
		if v == cert.Version1 {
			if v1Update == nil {
				if !lh.myVpnNetworks[0].Addr().Is4() {
					lh.l.Warn("cannot update lighthouse using v1 protocol without an IPv4 address",
						"lighthouseAddr", lhVpnAddr,
					)
					continue
				}
				var relays []uint32
				for _, r := range lh.GetRelaysForMe() {
					if !r.Is4() {
						continue
					}
					b := r.As4()
					relays = append(relays, binary.BigEndian.Uint32(b[:]))
				}
				b := lh.myVpnNetworks[0].Addr().As4()
				msg := NebulaMeta{
					Type: NebulaMeta_HostUpdateNotification,
					Details: &NebulaMetaDetails{
						V4AddrPorts:      v4,
						V6AddrPorts:      v6,
						OldRelayVpnAddrs: relays,
						OldVpnAddr:       binary.BigEndian.Uint32(b[:]),
					},
				}

				v1Update, err = msg.Marshal()
				if err != nil {
					lh.l.Error("Error while marshaling for lighthouse v1 update",
						"error", err,
						"lighthouseAddr", lhVpnAddr,
					)
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v1Update, nb, out)

		} else if v == cert.Version2 {
			if v2Update == nil {
				var relays []*Addr
				for _, r := range lh.GetRelaysForMe() {
					relays = append(relays, netAddrToProtoAddr(r))
				}

				msg := NebulaMeta{
					Type: NebulaMeta_HostUpdateNotification,
					Details: &NebulaMetaDetails{
						V4AddrPorts:   v4,
						V6AddrPorts:   v6,
						RelayVpnAddrs: relays,
					},
				}

				v2Update, err = msg.Marshal()
				if err != nil {
					lh.l.Error("Error while marshaling for lighthouse v2 update",
						"error", err,
						"lighthouseAddr", lhVpnAddr,
					)
					continue
				}
			}

			lh.ifce.SendMessageToVpnAddr(header.LightHouse, 0, lhVpnAddr, v2Update, nb, out)

		} else {
			lh.l.Debug("unsupported protocol version",
				"op", "update",
				"version", v,
			)
			continue
		}
	}

}

type lighthouseHandler struct {
	lh   *lighthouse
	nb   []byte
	out  []byte
	pb   []byte
	meta *NebulaMeta
	l    *slog.Logger
}

func (lh *lighthouse) NewRequestHandler() *lighthouseHandler {
	lhh := &lighthouseHandler{
		lh:  lh,
		nb:  make([]byte, 12, 12),
		out: make([]byte, mtu),
		l:   lh.l,
		pb:  make([]byte, mtu),

		meta: &NebulaMeta{
			Details: &NebulaMetaDetails{},
		},
	}

	return lhh
}

// This method is similar to Reset(), but it re-uses the pointer structs
// so that we don't have to re-allocate them
func (lhh *lighthouseHandler) resetMeta() *NebulaMeta {
	details := lhh.meta.Details
	lhh.meta.Reset()

	// Keep the array memory around
	details.V4AddrPorts = details.V4AddrPorts[:0]
	details.V6AddrPorts = details.V6AddrPorts[:0]
	details.RelayVpnAddrs = details.RelayVpnAddrs[:0]
	details.OldRelayVpnAddrs = details.OldRelayVpnAddrs[:0]
	details.OldVpnAddr = 0
	details.VpnAddr = nil
	lhh.meta.Details = details

	return lhh.meta
}

func (lhh *lighthouseHandler) HandleRequest(rAddr netip.AddrPort, fromVpnAddrs []netip.Addr, p []byte, w encWriter) {
	n := lhh.resetMeta()
	err := n.Unmarshal(p)
	if err != nil {
		lhh.l.Error("Failed to unmarshal lighthouse packet",
			"error", err,
			"vpnAddrs", fromVpnAddrs,
			"udpAddr", rAddr,
		)
		return
	}

	if n.Details == nil {
		lhh.l.Error("Invalid lighthouse update",
			"vpnAddrs", fromVpnAddrs,
			"udpAddr", rAddr,
		)
		return
	}

	switch n.Type {
	case NebulaMeta_HostQuery:
		lhh.handleHostQuery(n, fromVpnAddrs, rAddr, w)

	case NebulaMeta_HostQueryReply:
		lhh.handleHostQueryReply(n, fromVpnAddrs)

	case NebulaMeta_HostUpdateNotification:
		lhh.handleHostUpdateNotification(n, fromVpnAddrs, w)

	case NebulaMeta_HostMovedNotification:
	case NebulaMeta_HostPunchNotification:
		lhh.handleHostPunchNotification(n, fromVpnAddrs, w)

	case NebulaMeta_HostUpdateNotificationAck:
		// noop
	}
}

func (lhh *lighthouseHandler) handleHostQuery(n *NebulaMeta, fromVpnAddrs []netip.Addr, addr netip.AddrPort, w encWriter) {
	// Exit if we don't answer queries
	if !lhh.lh.amLighthouse {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("I don't answer queries, but received one", "from", addr)
		}
		return
	}

	queryVpnAddr, useVersion, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("Dropping malformed HostQuery",
				"from", fromVpnAddrs,
				"details", n.Details,
			)
		}
		return
	}
	if useVersion == cert.Version1 && queryVpnAddr.Is6() {
		// this case really shouldn't be possible to represent, but reject it anyway.
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("invalid vpn addr for v1 handleHostQuery",
				"vpnAddrs", fromVpnAddrs,
				"queryVpnAddr", queryVpnAddr,
			)
		}
		return
	}

	// Don't respond to requests for us.
	if lhh.lh.myVpnAddrsTable.Contains(queryVpnAddr) {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("Ignoring HostQuery for one of my own addresses",
				"fromVpnAddrs", fromVpnAddrs,
				"queryVpnAddr", queryVpnAddr,
			)
		}
		return
	}

	found, ln, err := lhh.lh.queryAndPrepMessage(queryVpnAddr, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostQueryReply
		if useVersion == cert.Version1 {
			b := queryVpnAddr.As4()
			n.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])
		} else {
			n.Details.VpnAddr = netAddrToProtoAddr(queryVpnAddr)
		}

		lhh.coalesceAnswers(useVersion, c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.Error("Failed to marshal lighthouse host query reply",
			"error", err,
			"vpnAddrs", fromVpnAddrs,
		)
		return
	}

	w.SendMessageToVpnAddr(header.LightHouse, 0, fromVpnAddrs[0], lhh.pb[:ln], lhh.nb, lhh.out[:0])

	lhh.sendHostPunchNotification(n, fromVpnAddrs, queryVpnAddr, w)
}

// sendHostPunchNotification signals the other side to punch some zero byte udp packets
func (lhh *lighthouseHandler) sendHostPunchNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, punchNotifDest netip.Addr, w encWriter) {
	whereToPunch := fromVpnAddrs[0]
	// Resolve the target before taking the querier's remoteList lock below. GetHostInfo takes the
	// hostmap lock, and the hostmap is taken before the lighthouse, which is taken before a
	// remoteList, so looking it up inside the callback would deadlock.
	targetHI := lhh.lh.ifce.GetHostInfo(punchNotifDest)
	found, ln, err := lhh.lh.queryAndPrepMessage(whereToPunch, func(c *cache) (int, error) {
		n = lhh.resetMeta()
		n.Type = NebulaMeta_HostPunchNotification
		var useVersion cert.Version
		if targetHI == nil {
			useVersion = lhh.lh.ifce.GetCertState().initiatingVersion
		} else {
			crt := targetHI.GetCert().Certificate
			useVersion = crt.Version()
			// we can only retarget if we have a hostinfo
			newDest, ok := findNetworkUnion(crt.Networks(), fromVpnAddrs)
			if ok {
				whereToPunch = newDest
			} else {
				if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
					lhh.l.Debug("unable to punch to host, no addresses in common",
						"to", crt.Networks(),
					)
				}
			}
		}

		if useVersion == cert.Version1 {
			if !whereToPunch.Is4() {
				return 0, fmt.Errorf("invalid vpn addr for v1 handleHostQuery")
			}
			b := whereToPunch.As4()
			n.Details.OldVpnAddr = binary.BigEndian.Uint32(b[:])
		} else if useVersion == cert.Version2 {
			n.Details.VpnAddr = netAddrToProtoAddr(whereToPunch)
		} else {
			return 0, errors.New("unsupported version")
		}
		lhh.coalesceAnswers(useVersion, c, n)

		return n.MarshalTo(lhh.pb)
	})

	if !found {
		return
	}

	if err != nil {
		lhh.l.Error("Failed to marshal lighthouse host was queried for",
			"error", err,
			"vpnAddrs", fromVpnAddrs,
		)
		return
	}

	w.SendMessageToVpnAddr(header.LightHouse, 0, punchNotifDest, lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *lighthouseHandler) coalesceAnswers(v cert.Version, c *cache, n *NebulaMeta) {
	if c.v4 != nil {
		if c.v4.learned != nil {
			n.Details.V4AddrPorts = append(n.Details.V4AddrPorts, c.v4.learned)
		}
		if c.v4.reported != nil && len(c.v4.reported) > 0 {
			n.Details.V4AddrPorts = append(n.Details.V4AddrPorts, c.v4.reported...)
		}
	}

	if c.v6 != nil {
		if c.v6.learned != nil {
			n.Details.V6AddrPorts = append(n.Details.V6AddrPorts, c.v6.learned)
		}
		if c.v6.reported != nil && len(c.v6.reported) > 0 {
			n.Details.V6AddrPorts = append(n.Details.V6AddrPorts, c.v6.reported...)
		}
	}

	if c.relay != nil {
		if v == cert.Version1 {
			b := [4]byte{}
			for _, r := range c.relay.relay {
				if !r.Is4() {
					continue
				}
				b = r.As4()
				n.Details.OldRelayVpnAddrs = append(n.Details.OldRelayVpnAddrs, binary.BigEndian.Uint32(b[:]))
			}
		} else if v == cert.Version2 {
			for _, r := range c.relay.relay {
				n.Details.RelayVpnAddrs = append(n.Details.RelayVpnAddrs, netAddrToProtoAddr(r))
			}
		} else {
			if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
				lhh.l.Debug("unsupported protocol version",
					"op", "coalesceAnswers",
					"version", v,
				)
			}
		}
	}
}

func (lhh *lighthouseHandler) handleHostQueryReply(n *NebulaMeta, fromVpnAddrs []netip.Addr) {
	if !lhh.lh.IsAnyLighthouseAddr(fromVpnAddrs) {
		return
	}

	certVpnAddr, _, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Error("dropping malformed HostQueryReply",
				"error", err,
				"vpnAddrs", fromVpnAddrs,
			)
		}
		return
	}
	relays := n.Details.GetRelays()

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList([]netip.Addr{certVpnAddr})
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(fromVpnAddrs[0], certVpnAddr, n.Details.V4AddrPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(fromVpnAddrs[0], certVpnAddr, n.Details.V6AddrPorts, lhh.lh.unlockedShouldAddV6)
	am.unlockedSetRelay(fromVpnAddrs[0], relays)
	am.Unlock()

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- certVpnAddr:
	default:
	}
}

func (lhh *lighthouseHandler) handleHostUpdateNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, w encWriter) {
	if !lhh.lh.amLighthouse {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("I am not a lighthouse, do not take host updates", "from", fromVpnAddrs)
		}
		return
	}

	// not using GetVpnAddrAndVersion because we don't want to error on a blank detailsVpnAddr
	var detailsVpnAddr netip.Addr
	var useVersion cert.Version
	if n.Details.OldVpnAddr != 0 { //v1 always sets this field
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], n.Details.OldVpnAddr)
		detailsVpnAddr = netip.AddrFrom4(b)
		useVersion = cert.Version1
	} else if n.Details.VpnAddr != nil { //this field is "optional" in v2, but if it's set, we should enforce it
		detailsVpnAddr = protoAddrToNetAddr(n.Details.VpnAddr)
		useVersion = cert.Version2
	} else {
		detailsVpnAddr = netip.Addr{}
		useVersion = cert.Version2
	}

	//Simple check that the host sent this not someone else, if detailsVpnAddr is filled
	if detailsVpnAddr.IsValid() && !slices.Contains(fromVpnAddrs, detailsVpnAddr) {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("Host sent invalid update",
				"vpnAddrs", fromVpnAddrs,
				"answer", detailsVpnAddr,
			)
		}
		return
	}

	relays := n.Details.GetRelays()

	lhh.lh.Lock()
	am := lhh.lh.unlockedGetRemoteList(fromVpnAddrs)
	am.Lock()
	lhh.lh.Unlock()

	am.unlockedSetV4(fromVpnAddrs[0], fromVpnAddrs[0], n.Details.V4AddrPorts, lhh.lh.unlockedShouldAddV4)
	am.unlockedSetV6(fromVpnAddrs[0], fromVpnAddrs[0], n.Details.V6AddrPorts, lhh.lh.unlockedShouldAddV6)
	am.unlockedSetRelay(fromVpnAddrs[0], relays)
	am.Unlock()

	n = lhh.resetMeta()
	n.Type = NebulaMeta_HostUpdateNotificationAck
	switch useVersion {
	case cert.Version1:
		if !fromVpnAddrs[0].Is4() {
			lhh.l.Error("Can not send HostUpdateNotificationAck for a ipv6 vpn ip in a v1 message",
				"vpnAddrs", fromVpnAddrs,
			)
			return
		}
		vpnAddrB := fromVpnAddrs[0].As4()
		n.Details.OldVpnAddr = binary.BigEndian.Uint32(vpnAddrB[:])
	case cert.Version2:
		// do nothing, we want to send a blank message
	default:
		lhh.l.Error("invalid protocol version", "useVersion", useVersion)
		return
	}

	ln, err := n.MarshalTo(lhh.pb)
	if err != nil {
		lhh.l.Error("Failed to marshal lighthouse host update ack",
			"error", err,
			"vpnAddrs", fromVpnAddrs,
		)
		return
	}

	w.SendMessageToVpnAddr(header.LightHouse, 0, fromVpnAddrs[0], lhh.pb[:ln], lhh.nb, lhh.out[:0])
}

func (lhh *lighthouseHandler) handleHostPunchNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr, w encWriter) {
	//It's possible the lighthouse is communicating with us using a non primary vpn addr,
	//which means we need to compare all fromVpnAddrs against all configured lighthouse vpn addrs.
	if !lhh.lh.IsAnyLighthouseAddr(fromVpnAddrs) {
		return
	}

	detailsVpnAddr, _, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("dropping invalid HostPunchNotification",
				"details", n.Details,
				"error", err,
			)
		}
		return
	}

	for _, a := range n.Details.V4AddrPorts {
		if a == nil {
			continue
		}
		b := protoV4AddrPortToNetAddrPort(a)
		lhh.lh.punchy.Schedule(b, detailsVpnAddr)
	}

	for _, a := range n.Details.V6AddrPorts {
		if a == nil {
			continue
		}
		b := protoV6AddrPortToNetAddrPort(a)
		lhh.lh.punchy.Schedule(b, detailsVpnAddr)
	}

	// This sends a nebula test packet to the host trying to contact us. In the case
	// of a double nat or other difficult scenario, this may help establish
	// a tunnel. ScheduleRespond is a no-op when punchy.respond is disabled.
	lhh.lh.punchy.ScheduleRespond(detailsVpnAddr)
}

func protoAddrToNetAddr(addr *Addr) netip.Addr {
	b := [16]byte{}
	binary.BigEndian.PutUint64(b[:8], addr.Hi)
	binary.BigEndian.PutUint64(b[8:], addr.Lo)
	return netip.AddrFrom16(b).Unmap()
}

func protoV4AddrPortToNetAddrPort(ap *V4AddrPort) netip.AddrPort {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], ap.Addr)
	return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(ap.Port))
}

func protoV6AddrPortToNetAddrPort(ap *V6AddrPort) netip.AddrPort {
	b := [16]byte{}
	binary.BigEndian.PutUint64(b[:8], ap.Hi)
	binary.BigEndian.PutUint64(b[8:], ap.Lo)
	return netip.AddrPortFrom(netip.AddrFrom16(b).Unmap(), uint16(ap.Port))
}

func netAddrToProtoAddr(addr netip.Addr) *Addr {
	b := addr.As16()
	return &Addr{
		Hi: binary.BigEndian.Uint64(b[:8]),
		Lo: binary.BigEndian.Uint64(b[8:]),
	}
}

func netAddrToProtoV4AddrPort(addr netip.Addr, port uint16) *V4AddrPort {
	v4Addr := addr.As4()
	return &V4AddrPort{
		Addr: binary.BigEndian.Uint32(v4Addr[:]),
		Port: uint32(port),
	}
}

func netAddrToProtoV6AddrPort(addr netip.Addr, port uint16) *V6AddrPort {
	v6Addr := addr.As16()
	return &V6AddrPort{
		Hi:   binary.BigEndian.Uint64(v6Addr[:8]),
		Lo:   binary.BigEndian.Uint64(v6Addr[8:]),
		Port: uint32(port),
	}
}

func (d *NebulaMetaDetails) GetRelays() []netip.Addr {
	var relays []netip.Addr
	if len(d.OldRelayVpnAddrs) > 0 {
		b := [4]byte{}
		for _, r := range d.OldRelayVpnAddrs {
			binary.BigEndian.PutUint32(b[:], r)
			relays = append(relays, netip.AddrFrom4(b))
		}
	}

	if len(d.RelayVpnAddrs) > 0 {
		for _, r := range d.RelayVpnAddrs {
			if r != nil {
				relays = append(relays, protoAddrToNetAddr(r))
			}
		}
	}
	return relays
}

// FindNetworkUnion returns the first netip.Addr contained in the list of provided netip.Prefix, if able
func findNetworkUnion(prefixes []netip.Prefix, addrs []netip.Addr) (netip.Addr, bool) {
	for i := range prefixes {
		for j := range addrs {
			if prefixes[i].Contains(addrs[j]) {
				return addrs[j], true
			}
		}
	}
	return netip.Addr{}, false
}

func (d *NebulaMetaDetails) GetVpnAddrAndVersion() (netip.Addr, cert.Version, error) {
	if d.OldVpnAddr != 0 {
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], d.OldVpnAddr)
		detailsVpnAddr := netip.AddrFrom4(b)
		return detailsVpnAddr, cert.Version1, nil
	} else if d.VpnAddr != nil {
		detailsVpnAddr := protoAddrToNetAddr(d.VpnAddr)
		return detailsVpnAddr, cert.Version2, nil
	} else {
		return netip.Addr{}, cert.Version1, errBadDetailsVPNAddr
	}
}
