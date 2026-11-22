package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

var errBadDetailsVPNAddr = errors.New("invalid packet, malformed detailsVpnAddr")

type discoverySender interface {
	SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, addr netip.Addr, payload, nonce, out []byte)
	GetHostInfo(addr netip.Addr) *hostInfo
	GetCertState() *certificateState
}

type lighthouse struct {
	sync.RWMutex
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

	updateInterval  time.Duration
	preferredRanges []netip.Prefix
	sender          discoverySender

	advertiseAddrs []netip.AddrPort

	// Addr's of relays that can be used by peers to access me
	relaysForMe []netip.Addr

	updateTrigger chan struct{}
	maxReported   int
	queryChan     chan netip.Addr
	queuedQueries sync.Map // overlay address to *pendingQuery, while enqueueing or sending
	updateGate    chan struct{}

	l *slog.Logger
}

func newLighthouse(ctx context.Context, l *slog.Logger, cs *certificateState, p *punchManager, opts *Options) (*lighthouse, error) {
	cfg := opts.Lighthouse
	interval := cfg.UpdateInterval
	switch {
	case interval == 0 && len(cfg.Hosts) > 0:
		interval = 10 * time.Second
	case interval > 0:
		interval = max(time.Second, interval.Truncate(time.Second))
	default:
		interval = 0
	}
	h := &lighthouse{
		ctx:                ctx,
		amLighthouse:       cfg.AmLighthouse,
		myVpnNetworks:      cs.myVpnNetworks,
		myVpnNetworksTable: cs.myVpnNetworksTable,
		myVpnAddrsTable:    cs.myVpnAddrsTable,
		punchy:             p,
		addrMap:            make(map[netip.Addr]*remoteList),
		endpointProvider:   cfg.EndpointProvider,
		maxReported:        positiveOr(cfg.MaxReported, 10),
		updateTrigger:      make(chan struct{}, 1),
		queryChan:          make(chan netip.Addr, positiveOr(cfg.QueryBuffer, 1024)),
		updateGate:         make(chan struct{}, 1),
		lighthouses:        cloneAddresses(cfg.Hosts),
		advertiseAddrs:     slices.Clone(cfg.AdvertiseEndpoints),
		relaysForMe:        cloneAddresses(opts.Relay.AdvertiseVia),
		preferredRanges:    slices.Clone(opts.PreferredRanges),
		updateInterval:     interval,
		staticList:         make(map[netip.Addr]struct{}, len(cfg.StaticHosts)),
		l:                  l,
	}
	h.updateGate <- struct{}{}
	for addr, endpoints := range cfg.StaticHosts {
		if err := h.setStaticEndpoints(addr.Unmap(), endpoints); err != nil {
			return nil, err
		}
	}
	for _, addr := range h.lighthouses {
		if _, ok := h.staticList[addr]; !ok {
			return nil, fmt.Errorf("lighthouse %s requires a static host endpoint", addr)
		}
	}
	return h, nil
}

func (lh *lighthouse) isStaticHost(addr netip.Addr) bool {
	lh.RLock()
	defer lh.RUnlock()
	_, ok := lh.staticList[addr]
	return ok
}

func (lh *lighthouse) setStaticEndpoints(addr netip.Addr, endpoints []netip.AddrPort) error {
	if !lh.myVpnNetworksTable.Contains(addr) || lh.myVpnAddrsTable.Contains(addr) {
		return fmt.Errorf("static host %s must be a remote overlay address", addr)
	}
	if len(endpoints) == 0 && lh.IsLighthouseAddr(addr) {
		return fmt.Errorf("lighthouse %s requires a static host endpoint", addr)
	}
	updated := make([]netip.AddrPort, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = unmapAddrPort(endpoint)
		ip := endpoint.Addr()
		if !endpoint.IsValid() || endpoint.Port() == 0 || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || lh.myVpnNetworksTable.Contains(ip) {
			return fmt.Errorf("invalid static underlay endpoint %s", endpoint)
		}
		if !slices.Contains(updated, endpoint) {
			updated = append(updated, endpoint)
		}
	}
	lh.Lock()
	defer lh.Unlock()
	remotes := lh.addrMap[addr]
	if remotes == nil {
		if len(updated) == 0 {
			return nil
		}
		remotes = lh.getOrCreateRemotesLocked([]netip.Addr{addr})
	}
	remotes.Lock()
	defer remotes.Unlock()
	if len(updated) == 0 {
		delete(lh.staticList, addr)
		delete(remotes.staticEndpoints, addr)
	} else {
		lh.staticList[addr] = struct{}{}
		if remotes.staticEndpoints == nil {
			remotes.staticEndpoints = make(map[netip.Addr][]netip.AddrPort)
		}
		remotes.staticEndpoints[addr] = updated
	}
	remotes.cached = nil
	return nil
}

type pendingQuery struct {
	ready chan struct{}
	sent  bool
}

// QueryServer schedules a best-effort discovery query. Identical pending queries share one send.
func (lh *lighthouse) QueryServer(addr netip.Addr) { _ = lh.queryServerContext(nil, addr) }

// A non-nil context requests reliable enqueueing, including when the queue is full.
func (lh *lighthouse) queryServerContext(ctx context.Context, addr netip.Addr) error {
	addr = addr.Unmap()
	if lh.amLighthouse || len(lh.lighthouses) == 0 || lh.IsLighthouseAddr(addr) {
		return nil
	}
	for {
		if lh.ctx.Err() != nil {
			return ErrNodeClosed
		}
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		var request *pendingQuery
		existing, joined := lh.queuedQueries.Load(addr)
		if !joined {
			request = &pendingQuery{ready: make(chan struct{})}
			existing, joined = lh.queuedQueries.LoadOrStore(addr, request)
		}
		if joined {
			if ctx == nil {
				return nil
			}
			other := existing.(*pendingQuery)
			select {
			case <-other.ready:
				if other.sent {
					return nil
				}
				continue
			case <-ctx.Done():
				return ctx.Err()
			case <-lh.ctx.Done():
				return ErrNodeClosed
			}
		}
		var err error
		if ctx == nil {
			select {
			case lh.queryChan <- addr:
				request.sent = true
			default:
			}
		} else {
			select {
			case lh.queryChan <- addr:
				request.sent = true
			case <-ctx.Done():
				err = ctx.Err()
			case <-lh.ctx.Done():
				err = ErrNodeClosed
			}
		}
		if !request.sent {
			lh.queuedQueries.Delete(addr)
		}
		close(request.ready)
		return err
	}
}

func (lh *lighthouse) getOrCreateRemotes(vpnAddrs []netip.Addr) *remoteList {
	lh.RLock()
	if v, ok := lh.addrMap[vpnAddrs[0]]; ok {
		lh.RUnlock()
		return v
	}
	lh.RUnlock()

	lh.Lock()
	defer lh.Unlock()
	// Add an entry if we don't already have one
	return lh.getOrCreateRemotesLocked(vpnAddrs)
}

func (lh *lighthouse) DeleteVpnAddrs(allVpnAddrs []netip.Addr) {
	// First we check the static host map. If any of the VpnAddrs to be deleted are present, do nothing.
	lh.Lock()
	defer lh.Unlock()
	for _, addr := range allVpnAddrs {
		if _, ok := lh.staticList[addr]; ok {
			return
		}
	}

	// None of the VpnAddrs were present. Now we can do the deletes.
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
}

// getOrCreateRemotesLocked assumes you have the lh lock
func (lh *lighthouse) getOrCreateRemotesLocked(allAddrs []netip.Addr) *remoteList {
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

	am := &remoteList{
		vpnAddrs:        slices.Clone(allAddrs),
		preferredRanges: lh.preferredRanges,
		records:         make(map[netip.Addr]*discoveryRecord),
	}
	for _, addr := range allAddrs {
		lh.addrMap[addr] = am
	}
	return am
}

// replaceReport updates both address families and the relay list for one source.
func (lh *lighthouse) replaceReport(addrs []netip.Addr, owner netip.Addr, details *NebulaMetaDetails) {
	relays := details.GetRelays()
	lh.Lock()
	remotes := lh.getOrCreateRemotesLocked(addrs)
	remotes.Lock()
	lh.Unlock()
	defer remotes.Unlock()

	record := remotes.recordForUpdate(owner)
	record.v4.replaceReported(details.V4AddrPorts, lh.maxReported, lh.myVpnNetworksTable, protoV4AddrPortToNetAddrPort)
	record.v6.replaceReported(details.V6AddrPorts, lh.maxReported, lh.myVpnNetworksTable, protoV6AddrPortToNetAddrPort)
	record.relays = append(record.relays[:0], relays[:min(len(relays), lh.maxReported)]...)
}

func (lh *lighthouse) IsLighthouseAddr(vpnAddr netip.Addr) bool {
	return slices.Contains(lh.lighthouses, vpnAddr)
}

func (lh *lighthouse) IsAnyLighthouseAddr(vpnAddrs []netip.Addr) bool {
	for _, addr := range vpnAddrs {
		if lh.IsLighthouseAddr(addr.Unmap()) {
			return true
		}
	}
	return false
}

func (lh *lighthouse) runQueryWorker() {
	if lh.amLighthouse {
		return
	}

	nb := make([]byte, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-lh.ctx.Done():
			return
		case addr := <-lh.queryChan:
			_ = lh.sendToLighthouses(lh.ctx, NebulaMeta_HostQuery, addr, nil, nb, out)
			lh.queuedQueries.Delete(addr)
		}
	}
}

// sendToLighthouses encodes a query or self-advertisement once per wire version.
func (lh *lighthouse) sendToLighthouses(ctx context.Context, kind NebulaMeta_MessageType, addr netip.Addr, record *discoveryRecord, nonce, out []byte) error {
	var encoded [cert.Version2 + 1][]byte
	for _, server := range lh.lighthouses {
		if err := ctx.Err(); err != nil {
			return err
		}
		if lh.ctx.Err() != nil {
			return ErrNodeClosed
		}
		var v cert.Version
		if h := lh.sender.GetHostInfo(server); h != nil {
			v = h.connectionState.myCert.Version()
		} else {
			v = lh.sender.GetCertState().initiatingVersion
		}
		if v != cert.Version1 && v != cert.Version2 {
			lh.l.Debug("unsupported lighthouse wire version", "version", v)
			continue
		}
		if encoded[v] == nil {
			details := &NebulaMetaDetails{}
			// A v2 update identifies its sender through the authenticated session.
			if kind == NebulaMeta_HostQuery || v == cert.Version1 {
				if err := details.setVPNAddr(addr, v); err != nil {
					lh.l.Debug("invalid lighthouse message address", "addr", addr, "error", err)
					continue
				}
			}
			if record != nil {
				record.appendTo(details, v)
			}
			msg := NebulaMeta{Type: kind, Details: details}
			data, err := msg.marshalDiscovery(nil)
			if err != nil {
				lh.l.Error("failed to marshal lighthouse message", "type", kind, "error", err)
				continue
			}
			encoded[v] = data
		}
		lh.sender.SendMessageToVpnAddr(header.LightHouse, 0, server, encoded[v], nonce, out)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lh.ctx.Err() != nil {
		return ErrNodeClosed
	}
	return nil
}

func (lh *lighthouse) runUpdateWorker() {
	if lh.amLighthouse || lh.updateInterval == 0 {
		return
	}

	clockSource := time.NewTicker(lh.updateInterval)
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
	if err := lh.sendUpdateContext(lh.ctx); err != nil && lh.ctx.Err() == nil {
		lh.l.Warn("lighthouse update failed", "error", err)
	}
}

func (lh *lighthouse) sendUpdateContext(ctx context.Context) error {
	if lh.amLighthouse || len(lh.lighthouses) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lh.ctx.Err() != nil {
		return ErrNodeClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-lh.ctx.Done():
		return ErrNodeClosed
	case <-lh.updateGate:
	}
	defer func() { lh.updateGate <- struct{}{} }()

	record := discoveryRecord{relays: lh.relaysForMe}
	addEndpoints := func(endpoints []netip.AddrPort, learned bool) {
		for _, ep := range endpoints {
			addr := ep.Addr().Unmap()
			if !addr.IsValid() || (learned && lh.myVpnNetworksTable.Contains(addr)) {
				continue
			}
			if addr.Is4() {
				record.v4.reported = append(record.v4.reported, netAddrToProtoV4AddrPort(addr, ep.Port()))
			} else {
				record.v6.reported = append(record.v6.reported, netAddrToProtoV6AddrPort(addr, ep.Port()))
			}
		}
	}
	addEndpoints(lh.advertiseAddrs, false)
	var providerErr error

	if lh.endpointProvider != nil {
		providerCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(lh.ctx, cancel)
		endpoints, err := lh.endpointProvider(providerCtx)
		stop()
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if lh.ctx.Err() != nil {
				return ErrNodeClosed
			}
			providerErr = fmt.Errorf("get advertised endpoints: %w", err)
		} else {
			addEndpoints(endpoints, true)
		}
	}
	if err := lh.sendToLighthouses(ctx, NebulaMeta_HostUpdateNotification, lh.myVpnNetworks[0].Addr(), &record, make([]byte, 12), make([]byte, mtu)); err != nil {
		return err
	}
	return providerErr
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
	return &lighthouseHandler{
		lh:   lh,
		nb:   make([]byte, 12),
		out:  make([]byte, mtu),
		l:    lh.l,
		pb:   make([]byte, mtu-header.MaxOverhead),
		meta: &NebulaMeta{Details: &NebulaMetaDetails{}},
	}
}

// Reset scalar fields while retaining scratch space for the next message.
func (lhh *lighthouseHandler) resetMeta(kind NebulaMeta_MessageType) *NebulaMeta {
	details := lhh.meta.Details
	*details = NebulaMetaDetails{
		V4AddrPorts: details.V4AddrPorts[:0], V6AddrPorts: details.V6AddrPorts[:0],
		RelayVpnAddrs: details.RelayVpnAddrs[:0], OldRelayVpnAddrs: details.OldRelayVpnAddrs[:0],
	}
	*lhh.meta = NebulaMeta{Type: kind, Details: details}
	return lhh.meta
}

// marshalDiscovery fits the largest common per-list cap in one relayed datagram.
// Each list retains its original order. The caller owns msg and may reuse buf.
func (msg *NebulaMeta) marshalDiscovery(buf []byte) ([]byte, error) {
	const limit = mtu - header.MaxOverhead
	size := msg.Size()
	if size > limit {
		d := msg.Details
		original := *d
		trim := func(n int) {
			d.V4AddrPorts = original.V4AddrPorts[:min(n, len(original.V4AddrPorts))]
			d.V6AddrPorts = original.V6AddrPorts[:min(n, len(original.V6AddrPorts))]
			d.RelayVpnAddrs = original.RelayVpnAddrs[:min(n, len(original.RelayVpnAddrs))]
			d.OldRelayVpnAddrs = original.OldRelayVpnAddrs[:min(n, len(original.OldRelayVpnAddrs))]
		}
		count := max(len(d.V4AddrPorts), len(d.V6AddrPorts), len(d.RelayVpnAddrs), len(d.OldRelayVpnAddrs))
		firstTooLarge := sort.Search(count, func(n int) bool {
			trim(n)
			return msg.Size() > limit
		})
		if firstTooLarge == 0 {
			return nil, io.ErrShortBuffer
		}
		trim(firstTooLarge - 1)
		size = msg.Size()
	}
	if cap(buf) < size {
		buf = make([]byte, size)
	}
	n, err := msg.MarshalToSizedBuffer(buf[:size])
	return buf[:n], err
}

func (lhh *lighthouseHandler) HandleRequest(rAddr netip.AddrPort, fromVpnAddrs []netip.Addr, p []byte) {
	n := lhh.resetMeta(NebulaMeta_None)
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
		lhh.handleHostQuery(n, fromVpnAddrs, rAddr)

	case NebulaMeta_HostQueryReply:
		lhh.handleHostQueryReply(n, fromVpnAddrs)

	case NebulaMeta_HostUpdateNotification:
		lhh.handleHostUpdateNotification(n, fromVpnAddrs)

	case NebulaMeta_HostPunchNotification:
		lhh.handleHostPunchNotification(n, fromVpnAddrs)

	}
}

func (lhh *lighthouseHandler) handleHostQuery(n *NebulaMeta, fromVpnAddrs []netip.Addr, addr netip.AddrPort) {
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

	requester := fromVpnAddrs[0]
	if !lhh.sendPeerRecord(NebulaMeta_HostQueryReply, requester, queryVpnAddr, queryVpnAddr, useVersion) {
		return
	}

	// Tell the queried peer where to punch, using an address it can route to.
	punchAddr := requester
	if target := lhh.lh.sender.GetHostInfo(queryVpnAddr); target != nil {
		crt := target.GetCert().Certificate
		useVersion = crt.Version()
		punchAddr = netip.Addr{}
		for _, network := range crt.Networks() {
			if i := slices.IndexFunc(fromVpnAddrs, network.Contains); i >= 0 {
				punchAddr = fromVpnAddrs[i]
				break
			}
		}
		if !punchAddr.IsValid() {
			lhh.l.Debug("using primary punch address outside recipient networks", "address", requester)
			punchAddr = requester
		}
	} else {
		useVersion = lhh.lh.sender.GetCertState().initiatingVersion
	}
	lhh.sendPeerRecord(NebulaMeta_HostPunchNotification, queryVpnAddr, requester, punchAddr, useVersion)
}

// owner selects the self-reported record. advertised can be another address
// on that peer's certificate, chosen for the recipient's network and version.
func (lhh *lighthouseHandler) sendPeerRecord(kind NebulaMeta_MessageType, to, owner, advertised netip.Addr, version cert.Version) bool {
	lh := lhh.lh
	lh.RLock()
	remotes := lh.addrMap[owner]
	if remotes == nil {
		lh.RUnlock()
		return false
	}
	remotes.RLock()
	lh.RUnlock()
	if slices.Contains(remotes.vpnAddrs, owner) {
		owner = remotes.vpnAddrs[0]
	}
	record := remotes.records[owner]
	if record == nil {
		remotes.RUnlock()
		return false
	}
	msg := lhh.resetMeta(kind)
	record.appendTo(msg.Details, version)
	remotes.RUnlock()

	if err := msg.Details.setVPNAddr(advertised, version); err != nil {
		lhh.l.Error("invalid discovery record address", "address", advertised, "error", err)
		return false
	}
	payload, err := msg.marshalDiscovery(lhh.pb)
	if err != nil {
		lhh.l.Error("failed to marshal discovery record", "type", kind, "peer", owner, "error", err)
		return false
	}
	lh.sender.SendMessageToVpnAddr(header.LightHouse, 0, to, payload, lhh.nb, lhh.out[:0])
	return true
}

func (c *discoveryRecord) appendTo(d *NebulaMetaDetails, v cert.Version) {
	d.V4AddrPorts = c.v4.appendWire(d.V4AddrPorts)
	d.V6AddrPorts = c.v6.appendWire(d.V6AddrPorts)
	switch v {
	case cert.Version1:
		for _, addr := range c.relays {
			if addr.Is4() {
				b := addr.As4()
				d.OldRelayVpnAddrs = append(d.OldRelayVpnAddrs, binary.BigEndian.Uint32(b[:]))
			}
		}
	case cert.Version2:
		for _, addr := range c.relays {
			d.RelayVpnAddrs = append(d.RelayVpnAddrs, netAddrToProtoAddr(addr))
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
	lhh.lh.replaceReport([]netip.Addr{certVpnAddr}, fromVpnAddrs[0], n.Details)

	// Non-blocking attempt to trigger, skip if it would block
	select {
	case lhh.lh.handshakeTrigger <- certVpnAddr:
	default:
	}
}

func (lhh *lighthouseHandler) handleHostUpdateNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr) {
	if !lhh.lh.amLighthouse {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("I am not a lighthouse, do not take host updates", "from", fromVpnAddrs)
		}
		return
	}

	detailsVpnAddr, useVersion, err := n.Details.GetVpnAddrAndVersion()
	if err != nil {
		// A v2 update may identify its sender solely through the authenticated session.
		useVersion = cert.Version2
	} else if !slices.Contains(fromVpnAddrs, detailsVpnAddr) {
		if lhh.l.Enabled(context.Background(), slog.LevelDebug) {
			lhh.l.Debug("Host sent invalid update",
				"vpnAddrs", fromVpnAddrs,
				"answer", detailsVpnAddr,
			)
		}
		return
	}

	lhh.lh.replaceReport(fromVpnAddrs, fromVpnAddrs[0], n.Details)

	n = lhh.resetMeta(NebulaMeta_HostUpdateNotificationAck)
	if useVersion == cert.Version1 {
		if err := n.Details.setVPNAddr(fromVpnAddrs[0], useVersion); err != nil {
			lhh.l.Error("invalid lighthouse acknowledgement address", "error", err)
			return
		}
	}

	payload, err := n.marshalDiscovery(lhh.pb)
	if err != nil {
		lhh.l.Error("Failed to marshal lighthouse host update ack",
			"error", err,
			"vpnAddrs", fromVpnAddrs,
		)
		return
	}

	lhh.lh.sender.SendMessageToVpnAddr(header.LightHouse, 0, fromVpnAddrs[0], payload, lhh.nb, lhh.out[:0])
}

func (lhh *lighthouseHandler) handleHostPunchNotification(n *NebulaMeta, fromVpnAddrs []netip.Addr) {
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

func (d *NebulaMetaDetails) setVPNAddr(addr netip.Addr, v cert.Version) error {
	switch v {
	case cert.Version1:
		if !addr.Is4() {
			return fmt.Errorf("v1 lighthouse message requires IPv4, got %v", addr)
		}
		b := addr.As4()
		d.OldVpnAddr = binary.BigEndian.Uint32(b[:])
	case cert.Version2:
		d.VpnAddr = netAddrToProtoAddr(addr)
	default:
		return fmt.Errorf("unknown certificate version %d", v)
	}
	return nil
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
