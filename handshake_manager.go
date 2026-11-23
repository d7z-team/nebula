package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
)

const (
	// HandshakePacket map keys mirror the IX protocol stage convention:
	//   stage 0 = the initiator's first message (and what the responder
	//             receives, stripped of header)
	//   stage 2 = the responder's reply
	// Other handshake patterns will need new keys when added.
	handshakePacketStage0 uint8 = 0
	handshakePacketStage2 uint8 = 2
)

type outboundHandshakeTimerItem struct {
	vpnAddr    netip.Addr
	generation *handshakeHostInfo
}

type handshakeManager struct {
	// Mutex for interacting with the vpnIps and indexes maps.
	// Lock order is hostmap, then this lock, then the lighthouse, then a remoteList.
	sync.RWMutex

	vpnIps  map[netip.Addr]*handshakeHostInfo
	indexes map[uint32]*handshakeHostInfo

	mainHostMap *hostMap
	lightHouse  *lighthouse

	config     HandshakeOptions
	retryTimer *timerWheel[outboundHandshakeTimerItem]
	f          *packetEngine
	l          *slog.Logger

	// can be used to trigger outbound handshake for the given vpnIp
	trigger chan netip.Addr
}

type queuedControlPacket struct {
	messageType    header.MessageType
	messageSubType header.MessageSubType
	payload        []byte
}

type handshakeHostInfo struct {
	directOnly atomic.Bool
	sync.Mutex

	startTime                 time.Time        // Time that we first started trying with this handshake
	ready                     bool             // Is the handshake ready
	initiatingVersionOverride cert.Version     // Protected by handshakeManager while the handshake is pending.
	counter                   int              // How many attempts have we made so far
	lastRemotes               []netip.AddrPort // Remotes that we sent to during the previous attempt
	lastRelays                []netip.Addr     // Relays we attempted to use during the previous attempt
	controlQueue              []queuedControlPacket

	hostinfo *hostInfo
	machine  *handshake.Machine // The handshake state machine, set during stage 0 (initiator) or beginHandshake (responder multi-message)
}

func newHandshakeManager(l *slog.Logger, mainHostMap *hostMap, lightHouse *lighthouse, config HandshakeOptions) *handshakeManager {
	config.TryInterval = positiveOr(config.TryInterval, 100*time.Millisecond)
	config.Retries = positiveOr(config.Retries, 10)
	config.TriggerBuffer = positiveOr(config.TriggerBuffer, 64)
	config.ControlQueueSize = positiveOr(config.ControlQueueSize, 100)
	config.RefreshAttempt = positiveOr(config.RefreshAttempt, 5)
	// The longest individual retry delay determines the wheel size.
	return &handshakeManager{
		vpnIps:      map[netip.Addr]*handshakeHostInfo{},
		indexes:     map[uint32]*handshakeHostInfo{},
		mainHostMap: mainHostMap,
		lightHouse:  lightHouse,

		config:     config,
		trigger:    make(chan netip.Addr, config.TriggerBuffer),
		retryTimer: newTimerWheel[outboundHandshakeTimerItem](config.TryInterval, time.Duration(config.Retries)*config.TryInterval),
		l:          l,
	}
}

func (hm *handshakeManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(hm.config.TryInterval)
	defer clockSource.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-hm.trigger:
			hm.handleOutbound(vpnIP, nil, true)
		case now := <-clockSource.C:
			hm.NextOutboundHandshakeTimerTick(now)
		}
	}
}

func (hm *handshakeManager) HandleIncoming(via packetSender, packet []byte, h *header.H) {
	// Gate on known handshake subtypes. Unknown subtypes (or future ones we
	// don't yet support) are dropped here rather than silently routed through
	// the IX path. Add a case when introducing a new pattern.
	switch h.Subtype {
	case header.HandshakeIXPSK0:
		// supported
	default:
		hm.l.Debug("dropping handshake with unsupported subtype",
			"from", via, "subtype", h.Subtype)
		return
	}

	// First message of a new handshake. The wire format requires RemoteIndex
	// to be zero here (the initiator has no responder index to fill in yet),
	// and generateIndex never allocates 0, so any non-zero RemoteIndex on a
	// stage-1 packet is malformed or someone probing for an index collision.
	// Drop without paying the cost of running noise on a pending Machine.
	if h.MessageCounter == 1 {
		if h.RemoteIndex != 0 {
			hm.l.Debug("dropping stage-1 handshake with non-zero RemoteIndex",
				"from", via, "remoteIndex", h.RemoteIndex)
			return
		}
		hm.beginHandshake(via, packet, h)
		return
	}

	// Continuation message must match a pending handshake by index.
	// Anything else is an orphaned packet (e.g., late retransmit after
	// timeout) and is dropped.
	if hh := hm.queryIndex(h.RemoteIndex); hh != nil {
		hm.continueHandshake(via, hh, packet)
		return
	}
}

func (hm *handshakeManager) NextOutboundHandshakeTimerTick(now time.Time) {
	hm.retryTimer.Advance(now)
	for {
		item, has := hm.retryTimer.Purge()
		if !has {
			break
		}
		hm.handleOutbound(item.vpnAddr, item.generation, false)
	}
}

func (hm *handshakeManager) handleOutbound(vpnIp netip.Addr, generation *handshakeHostInfo, lighthouseTriggered bool) {
	var hh *handshakeHostInfo
	for {
		if generation == nil {
			hh = hm.queryVpnIp(vpnIp)
		} else {
			hh = generation
		}
		if hh == nil {
			return
		}

		hh.Lock()
		hm.RLock()
		current := hm.vpnIps[vpnIp]
		hm.RUnlock()
		if current == hh {
			break
		}
		hh.Unlock()
		if generation != nil {
			return
		}
	}
	defer hh.Unlock()

	hostinfo := hh.hostinfo
	candidates := hostinfo.remotes.candidates()
	cfg := hm.f.paths.config.Load()
	remotes := cfg.network.endpoints(vpnIp, candidates.endpoints)
	ids := hostinfo.vpnAddrs
	if known := hm.mainHostMap.QueryVpnAddr(vpnIp); known != nil {
		ids = known.vpnAddrs
	}
	relays := cfg.effectivePolicy(ids, hm.mainHostMap).Relays
	if len(relays) == 0 {
		relays = candidates.relays
	}
	if hh.directOnly.Load() {
		relays = nil
	}
	if !cfg.allows(ids, netip.Addr{}, hostinfo.remotes) {
		remotes = nil
	}
	if lighthouseTriggered && slices.Equal(remotes, hh.lastRemotes) && slices.Equal(relays, hh.lastRelays) {
		return
	}
	hh.lastRemotes, hh.lastRelays = remotes, relays
	// If we are out of time, clean up
	tries := time.Duration(hm.config.Retries)
	if hh.counter >= hm.config.Retries || time.Since(hh.startTime) > hm.config.TryInterval*(tries+1)*(tries+2)/2+time.Second {
		fields := []any{
			"udpAddrs", remotes,
			"initiatorIndex", hh.hostinfo.localIndexId,
			"durationNs", time.Since(hh.startTime).Nanoseconds(),
		}
		// hh.machine can be nil here if buildStage0Packet never succeeded
		// (e.g., no certificate available). In that case there's no useful
		// handshake metadata to log.
		if hh.machine != nil {
			fields = append(fields, "handshake", structuredMap{
				"stage": uint64(hh.machine.MessageIndex()),
				"style": header.SubTypeName(header.Handshake, hh.machine.Subtype()),
			})
		}
		hh.hostinfo.logger(hm.l).Info("Handshake timed out", fields...)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	// Increment the counter to increase our delay, linear backoff
	hh.counter++

	// Check if we have a handshake packet to transmit yet
	if !hh.ready && !hm.buildStage0Packet(hh) {
		if !lighthouseTriggered {
			hm.retryTimer.Add(outboundHandshakeTimerItem{vpnAddr: vpnIp, generation: hh}, hm.config.TryInterval*time.Duration(hh.counter))
		}
		return
	}

	// IX initiators retransmit their first handshake message.
	stage0 := hostinfo.HandshakePacket[handshakePacketStage0]
	if hh.counter == hm.config.RefreshAttempt {
		hm.lightHouse.QueryServer(vpnIp)
	}
	// Give direct connectivity the first attempt, then rotate through alternatives.
	if len(remotes) > 0 {
		endpoint := remotes[(hh.counter-1)%len(remotes)]
		err := hm.f.writePath(hostinfo, tunnelRoute{TunnelPath: TunnelPath{Endpoint: endpoint}}, stage0, true, nil)
		if errors.Is(err, errPathBudget) {
			hh.counter--
			if !lighthouseTriggered {
				hm.retryTimer.Add(outboundHandshakeTimerItem{vpnAddr: vpnIp, generation: hh}, hm.config.TryInterval)
			}
			return
		}
	}
	if len(relays) > 0 && (len(remotes) == 0 || hh.counter > 1) {
		// Allow several attempts for the neighbor handshake and CreateRelay round trip.
		relayAddr := relays[((hh.counter-1)/3)%len(relays)]
		if route, ok := hm.f.ensureRelay(hostinfo, relayAddr); ok {
			hm.f.sendVia(hostinfo, route, stage0, make([]byte, 12), make([]byte, mtu), false, true)
		}
	}
	// If a lighthouse triggered this attempt then we are still in the timer wheel and do not need to re-add
	if !lighthouseTriggered {
		hm.retryTimer.Add(outboundHandshakeTimerItem{vpnAddr: vpnIp, generation: hh}, hm.config.TryInterval*time.Duration(hh.counter))
	}
}

// GetOrHandshake will try to find a hostinfo with a fully formed tunnel or start a new handshake if one is not present
// The 2nd argument will be true if the hostinfo is ready to transmit traffic
func (hm *handshakeManager) GetOrHandshake(vpnIp netip.Addr, cacheCb func(*handshakeHostInfo)) (*hostInfo, bool) {
	hm.mainHostMap.RLock()
	h, ok := hm.mainHostMap.Hosts[vpnIp]
	hm.mainHostMap.RUnlock()

	if ok {
		return h, true
	}

	return hm.StartHandshake(vpnIp, cacheCb), false
}

// StartHandshake will ensure a handshake is currently being attempted for the provided vpn ip
func (hm *handshakeManager) StartHandshake(vpnAddr netip.Addr, cacheCb func(*handshakeHostInfo)) *hostInfo {
	return hm.startHandshake(vpnAddr, cacheCb, false)
}

func (hm *handshakeManager) startHandshake(vpnAddr netip.Addr, cacheCb func(*handshakeHostInfo), directOnly bool) *hostInfo {
	hm.Lock()

	if hh, ok := hm.vpnIps[vpnAddr]; ok {
		if !directOnly {
			hh.directOnly.Store(false)
		}
		// We are already trying to handshake with this vpn ip
		if cacheCb != nil {
			cacheCb(hh)
		}
		hm.Unlock()
		return hh.hostinfo
	}

	hostinfo := &hostInfo{
		vpnAddrs:        []netip.Addr{vpnAddr},
		HandshakePacket: make(map[uint8][]byte, 0),
		// A pending tunnel can learn an endpoint before its first handshake attempt.
		remotes: hm.lightHouse.getOrCreateRemotes([]netip.Addr{vpnAddr}),
	}

	hh := &handshakeHostInfo{
		hostinfo:  hostinfo,
		startTime: time.Now(),
	}
	hh.directOnly.Store(directOnly)
	hm.vpnIps[vpnAddr] = hh
	hm.retryTimer.Add(outboundHandshakeTimerItem{vpnAddr: vpnAddr, generation: hh}, hm.config.TryInterval)

	if cacheCb != nil {
		cacheCb(hh)
	}

	// If this is a static host, we don't need to wait for the HostQueryReply
	// We can trigger the handshake right now
	if hm.lightHouse.isStaticHost(vpnAddr) {
		select {
		case hm.trigger <- vpnAddr:
		default:
		}
	}

	hm.Unlock()
	hm.lightHouse.QueryServer(vpnAddr)
	return hostinfo
}

var (
	errExistingHostInfo    = errors.New("existing hostinfo")
	errAlreadySeen         = errors.New("already seen")
	errLocalIndexCollision = errors.New("local index collision")
)

// CheckAndComplete checks for any conflicts in the main and pending hostmap
// before adding hostinfo to main. If err is nil, it was added. Otherwise err will be:
//
// errAlreadySeen if we already have an entry in the hostmap that has seen the
// exact same handshake packet
//
// errExistingHostInfo if we already have an entry in the hostmap for this
// VpnIp and the new handshake was older than the one we currently have
//
// errLocalIndexCollision if we already have an entry in the main or pending
// hostmap for the hostinfo.localIndexId.
func (hm *handshakeManager) CheckAndComplete(hostinfo *hostInfo, handshakePacket uint8, f *packetEngine) (*hostInfo, error) {
	hm.mainHostMap.Lock()
	defer hm.mainHostMap.Unlock()
	hm.Lock()
	defer hm.Unlock()

	if f.paths.config.Load().network.denies(hostinfo.GetCert()) {
		return nil, cert.ErrBlockListed
	}
	// Check if we already have a tunnel with this vpn ip
	existingHostInfo, found := hm.mainHostMap.Hosts[hostinfo.vpnAddrs[0]]
	if found && existingHostInfo != nil {
		// Is it just a delayed handshake packet? Check every hostinfo we hold for this address.
		for _, testHostInfo := range hm.mainHostMap.unlockedGetHostList(hostinfo.vpnAddrs[0]) {
			if bytes.Equal(hostinfo.HandshakePacket[handshakePacket], testHostInfo.HandshakePacket[handshakePacket]) {
				return testHostInfo, errAlreadySeen
			}
		}

		// Is this a newer handshake?
		if existingHostInfo.lastHandshakeTime >= hostinfo.lastHandshakeTime && !existingHostInfo.connectionState.initiator {
			return existingHostInfo, errExistingHostInfo
		}

		existingHostInfo.logger(hm.l).Info("Taking new handshake")
	}

	existingIndex, found := hm.mainHostMap.Indexes[hostinfo.localIndexId]
	if found {
		// We have a collision, but for a different hostinfo
		return existingIndex, errLocalIndexCollision
	}

	existingPendingIndex, found := hm.indexes[hostinfo.localIndexId]
	if found && existingPendingIndex.hostinfo != hostinfo {
		// We have a collision, but for a different hostinfo
		return existingPendingIndex.hostinfo, errLocalIndexCollision
	}

	existingRemoteIndex, found := hm.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil && existingRemoteIndex.vpnAddrs[0] != hostinfo.vpnAddrs[0] {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(hm.l).Info("New host shadows existing host remoteIndex",
			"collision", existingRemoteIndex.vpnAddrs,
		)
	}

	hm.mainHostMap.unlockedAddHostInfo(hostinfo, f)
	return existingHostInfo, nil
}

// completeOutbound replaces the pending dial target with the certified addresses
// and publishes the authenticated session.
func (hm *handshakeManager) completeOutbound(hostinfo *hostInfo, vpnAddrs []netip.Addr) bool {
	hm.mainHostMap.Lock()
	defer hm.mainHostMap.Unlock()
	hm.Lock()
	defer hm.Unlock()

	if hm.f.paths.config.Load().network.denies(hostinfo.GetCert()) {
		hm.unlockedDeleteHostInfo(hostinfo)
		return false
	}
	existingRemoteIndex, found := hm.mainHostMap.RemoteIndexes[hostinfo.remoteIndexId]
	if found && existingRemoteIndex != nil {
		// We have a collision, but this can happen since we can't control
		// the remote ID. Just log about the situation as a note.
		hostinfo.logger(hm.l).Info("New host shadows existing host remoteIndex",
			"collision", existingRemoteIndex.vpnAddrs,
		)
	}

	hm.unlockedDeleteHostInfo(hostinfo)
	hostinfo.vpnAddrs = vpnAddrs
	hm.mainHostMap.unlockedAddHostInfo(hostinfo, hm.f)
	return true
}

// allocateIndex generates a unique localIndexId for this hostInfo
// and adds it to the pendingHostMap. Will error if we are unable to generate
// a unique localIndexId
func (hm *handshakeManager) allocateIndex(hh *handshakeHostInfo) (uint32, error) {
	hm.mainHostMap.RLock()
	defer hm.mainHostMap.RUnlock()
	hm.Lock()
	defer hm.Unlock()

	for range 32 {
		index, err := generateIndex(hm.l)
		if err != nil {
			return 0, err
		}

		_, inPending := hm.indexes[index]
		_, inMain := hm.mainHostMap.Indexes[index]

		if !inMain && !inPending {
			hh.hostinfo.localIndexId = index
			hm.indexes[index] = hh
			return index, nil
		}
	}

	return 0, errors.New("failed to generate unique localIndexId")
}

func (hm *handshakeManager) DeleteHostInfo(hostinfo *hostInfo) {
	hm.Lock()
	defer hm.Unlock()
	hm.unlockedDeleteHostInfo(hostinfo)
}

func (hm *handshakeManager) unlockedDeleteHostInfo(hostinfo *hostInfo) {
	for _, addr := range hostinfo.vpnAddrs {
		if cur, ok := hm.vpnIps[addr]; ok && cur.hostinfo == hostinfo {
			delete(hm.vpnIps, addr)
		}
	}

	if len(hm.vpnIps) == 0 {
		hm.vpnIps = map[netip.Addr]*handshakeHostInfo{}
	}

	delete(hm.indexes, hostinfo.localIndexId)
	if len(hm.indexes) == 0 {
		hm.indexes = map[uint32]*handshakeHostInfo{}
	}

	if hm.l.Enabled(context.Background(), slog.LevelDebug) {
		hm.l.Debug("Pending hostmap hostInfo deleted",
			"hostMap", structuredMap{"mapTotalSize": len(hm.vpnIps),
				"vpnAddrs": hostinfo.vpnAddrs, "indexNumber": hostinfo.localIndexId, "remoteIndexNumber": hostinfo.remoteIndexId},
		)
	}
}

func (hm *handshakeManager) queryVpnIp(vpnIp netip.Addr) *handshakeHostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.vpnIps[vpnIp]
}

func (hm *handshakeManager) queryIndex(index uint32) *handshakeHostInfo {
	hm.RLock()
	defer hm.RUnlock()
	return hm.indexes[index]
}

func generateIndex(l *slog.Logger) (uint32, error) {
	b := make([]byte, 4)

	// Let zero mean we don't know the ID, so don't generate zero
	var index uint32
	for index == 0 {
		_, err := rand.Read(b)
		if err != nil {
			l.Error("Failed to generate index", "error", err)
			return 0, err
		}

		index = binary.BigEndian.Uint32(b)
	}

	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("Generated index", "index", index)
	}
	return index, nil
}

// buildStage0Packet creates the initial handshake packet for the initiator.
func (hm *handshakeManager) buildStage0Packet(hh *handshakeHostInfo) bool {
	cs := hm.f.pki.getCertState()
	v := cs.DefaultVersion()
	hm.RLock()
	override := hh.initiatingVersionOverride
	hm.RUnlock()
	if override != cert.VersionPre1 {
		v = override
	} else if v < cert.Version2 {
		for _, a := range hh.hostinfo.vpnAddrs {
			if a.Is6() {
				v = cert.Version2
				break
			}
		}
	}

	cred := cs.GetCredential(v)
	if cred == nil {
		hm.f.l.Error("Unable to handshake with host because no certificate is available",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "certVersion", v)
		return false
	}

	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return hm.allocateIndex(hh) },
		true, header.HandshakeIXPSK0,
	)
	if err != nil {
		hm.f.l.Error("Failed to create handshake machine",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		return false
	}

	msg, err := machine.Initiate(nil)
	if err != nil {
		hm.f.l.Error("Failed to initiate handshake",
			"vpnAddrs", hh.hostinfo.vpnAddrs, "error", err)
		return false
	}

	// hostinfo.connectionState stays nil until the handshake completes in
	// continueHandshake. Pre-completion control surfaces guard with nil
	// checks; the data plane never observes a pending hostinfo.
	hh.hostinfo.HandshakePacket[handshakePacketStage0] = msg
	hh.machine = machine
	hh.ready = true
	return true
}

// beginHandshake handles an incoming handshake packet that doesn't match any
// existing pending handshake. It creates a new responder Machine and processes
// the first message.
func (hm *handshakeManager) beginHandshake(via packetSender, packet []byte, h *header.H) {
	f := hm.f
	cs := f.pki.getCertState()

	v := cs.DefaultVersion()
	if cs.GetCredential(v) == nil {
		f.l.Error("Unable to handshake with host because no certificate is available",
			"from", via, "certVersion", v)
		return
	}

	machine, err := handshake.NewMachine(
		v, cs.GetCredential,
		hm.certVerifier(), func() (uint32, error) { return generateIndex(f.l) },
		false, header.HandshakeIXPSK0,
	)
	if err != nil {
		f.l.Error("Failed to create handshake machine", "from", via, "error", err)
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		level := slog.LevelError
		if errors.Is(err, cert.ErrBlockListed) {
			level = slog.LevelDebug
		}
		f.l.Log(context.Background(), level, "Failed to process handshake packet", "from", via, "error", err)
		return
	}

	if result == nil {
		// Multi-message pattern: the responder Machine would need to be
		// registered in hm.indexes so a future inbound packet finds it via
		// continueHandshake. The current manager doesn't do that yet, so
		// fail loudly rather than silently dropping the in-flight handshake.
		// TODO: support multi-message responder flows (XX, pqIX, etc.).
		// See also the IX-shaped cipher key assignment in handshake.Machine.
		f.l.Error("multi-message handshake responder is not supported",
			"from", via, "error", handshake.ErrMultiMessageUnsupported)
		return
	}

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.Error("Handshake did not produce a peer certificate", "from", via)
		return
	}

	// Validate peer identity
	vpnAddrs, anyVpnAddrsInCommon, ok := hm.validatePeerCert(via, remoteCert)
	if !ok {
		return
	}

	remotes := f.lightHouse.getOrCreateRemotes(vpnAddrs)
	if !f.handshakeAllowed(vpnAddrs, via, remotes) {
		return
	}
	connState, err := newConnectionStateFromResult(result)
	if err != nil {
		f.l.Error("Discarding handshake with an invalid message index", "error", err, "vpnAddrs", vpnAddrs)
		return
	}

	hostinfo := &hostInfo{
		connectionState:   connState,
		localIndexId:      result.LocalIndex,
		remoteIndexId:     result.RemoteIndex,
		vpnAddrs:          vpnAddrs,
		HandshakePacket:   make(map[uint8][]byte, 0),
		lastHandshakeTime: result.HandshakeTime,
	}

	msg := "Handshake message received"
	if !anyVpnAddrsInCommon {
		msg = "Handshake message received, but no vpnNetworks in common."
	}
	f.l.Info(msg,
		"vpnAddrs", vpnAddrs,
		"from", via,
		"certName", remoteCert.Certificate.Name(),
		"certVersion", remoteCert.Certificate.Version(),
		"fingerprint", remoteCert.Fingerprint,
		"issuer", remoteCert.Certificate.Issuer(),
		"initiatorIndex", result.RemoteIndex,
		"responderIndex", result.LocalIndex,
		"handshake", structuredMap{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
	)

	// packet aliases the listener's incoming buffer, so this copy must stay.
	hostinfo.HandshakePacket[handshakePacketStage0] = make([]byte, len(packet[header.Len:]))
	copy(hostinfo.HandshakePacket[handshakePacketStage0], packet[header.Len:])

	// response was freshly allocated by ProcessPacket; safe to retain directly.
	if response != nil {
		hostinfo.HandshakePacket[handshakePacketStage2] = response
	}

	hostinfo.remotes = remotes
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	}
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	hostinfo.paths.setHandshakeRoute(receivedRoute(via), time.Now(), f.paths.probes.ActiveInterval)
	existing, err := hm.CheckAndComplete(hostinfo, handshakePacketStage0, f)
	if err != nil {
		hm.handleCheckAndCompleteError(err, existing, hostinfo, via)
		return
	}

	hm.sendHandshakeResponse(via, response, hostinfo, false)
	f.lightHouse.refreshAfterHandshake(hostinfo)
}

// continueHandshake feeds an incoming packet to an existing pending handshake Machine.
func (hm *handshakeManager) continueHandshake(via packetSender, hh *handshakeHostInfo, packet []byte) {
	f := hm.f

	hh.Lock()
	defer hh.Unlock()

	// Re-verify hh is still tracked. Between queryIndex returning and us taking
	// hh.Lock, handleOutbound may have timed out and deleted it. Once we hold
	// hh.Lock no other deleter can race our index: handleOutbound also takes
	// hh.Lock first, and handleRecvError targets a main-hostmap entry with a
	// different localIndexId.
	hm.RLock()
	cur, ok := hm.indexes[hh.hostinfo.localIndexId]
	hm.RUnlock()
	if !ok || cur != hh {
		return
	}

	hostinfo := hh.hostinfo

	if (hh.directOnly.Load() && via.IsRelayed) || !f.handshakeAllowed(hostinfo.vpnAddrs, via, hostinfo.remotes) {
		return
	}
	machine := hh.machine
	if machine == nil {
		f.l.Error("No handshake machine available for continuation",
			"vpnAddrs", hostinfo.vpnAddrs, "from", via)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	response, result, err := machine.ProcessPacket(nil, packet)
	if err != nil {
		// Recoverable errors are routine noise, log at Debug. Fatal errors get a Warn.
		if machine.Failed() {
			f.l.Warn("Failed to process handshake packet, abandoning",
				"vpnAddrs", hostinfo.vpnAddrs, "from", via, "error", err)
			hm.DeleteHostInfo(hostinfo)
		} else {
			f.l.Debug("Failed to process handshake packet",
				"vpnAddrs", hostinfo.vpnAddrs, "from", via, "error", err)
		}
		return
	}

	if response != nil {
		hm.sendHandshakeResponse(via, response, hostinfo, false)
	}

	if result == nil {
		return
	}

	// Handshake complete; build the connectionState now that we have keys and a verified peer cert.
	cs, err := newConnectionStateFromResult(result)
	if err != nil {
		f.l.Error("Discarding handshake with an invalid message index", "error", err, "vpnAddrs", hostinfo.vpnAddrs)
		hm.DeleteHostInfo(hostinfo)
		return
	}
	hostinfo.connectionState = cs

	remoteCert := result.RemoteCert
	if remoteCert == nil {
		f.l.Error("Handshake completed without peer certificate",
			"vpnAddrs", hostinfo.vpnAddrs, "from", via)
		hm.DeleteHostInfo(hostinfo)
		return
	}

	vpnNetworks := remoteCert.Certificate.Networks()
	hostinfo.remoteIndexId = result.RemoteIndex
	hostinfo.lastHandshakeTime = result.HandshakeTime

	// Verify correct host responded (initiator check)
	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	correctHostResponded := false
	anyVpnAddrsInCommon := false
	for i, network := range vpnNetworks {
		// Packet identity checks drop self-routed traffic, but avoid letting a
		// self-handshake complete in the first place: it
		// wastes a hostmap slot, suppresses no log, and obscures routing
		// misconfig. Explicit refusal here mirrors the responder-side check
		// in validatePeerCert.
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.Error("Refusing to handshake with myself",
				"vpnNetworks", vpnNetworks,
				"from", via,
				"certName", remoteCert.Certificate.Name(),
				"certVersion", remoteCert.Certificate.Version(),
				"fingerprint", remoteCert.Fingerprint,
				"issuer", remoteCert.Certificate.Issuer(),
				"handshake", structuredMap{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
			)
			hm.DeleteHostInfo(hostinfo)
			return
		}
		vpnAddrs[i] = network.Addr()
		if hostinfo.vpnAddrs[0] == network.Addr() {
			correctHostResponded = true
		}
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
	}

	if !f.handshakeAllowed(vpnAddrs, via, hostinfo.remotes) {
		hm.DeleteHostInfo(hostinfo)
		return
	}
	if !correctHostResponded {
		f.l.Info("Incorrect host responded to handshake",
			"intendedVpnAddrs", hostinfo.vpnAddrs,
			"haveVpnNetworks", vpnNetworks,
			"from", via,
			"certName", remoteCert.Certificate.Name(),
			"certVersion", remoteCert.Certificate.Version(),
			"fingerprint", remoteCert.Fingerprint,
			"issuer", remoteCert.Certificate.Issuer(),
			"handshake", structuredMap{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
		)

		hm.DeleteHostInfo(hostinfo)
		hm.StartHandshake(hostinfo.vpnAddrs[0], func(newHH *handshakeHostInfo) {
			newHH.hostinfo.remotes.BlockRemote(via)
			newHH.controlQueue = hh.controlQueue
			hh.controlQueue = nil
		})
		// sendCloseTunnel may take the hostmap lock, so it must not run under the handshake
		// manager lock that StartHandshake holds around the callback.
		hostinfo.vpnAddrs = vpnAddrs
		f.sendCloseTunnel(hostinfo)
		return
	}

	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	} else {
		hostinfo.relayState.addRelayAddress(via.relayHI.vpnAddrs[0])
	}

	duration := time.Since(hh.startTime).Nanoseconds()
	msg := "Handshake message received"
	if !anyVpnAddrsInCommon {
		msg = "Handshake message received, but no vpnNetworks in common."
	}
	f.l.Info(msg,
		"vpnAddrs", vpnAddrs,
		"from", via,
		"certName", remoteCert.Certificate.Name(),
		"certVersion", remoteCert.Certificate.Version(),
		"fingerprint", remoteCert.Fingerprint,
		"issuer", remoteCert.Certificate.Issuer(),
		"initiatorIndex", result.LocalIndex,
		"responderIndex", result.RemoteIndex,
		"handshake", structuredMap{"stage": uint64(machine.MessageIndex()), "style": header.SubTypeName(header.Handshake, machine.Subtype())},
		"durationNs", duration,
	)

	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	hostinfo.paths.setHandshakeRoute(receivedRoute(via), time.Now(), f.paths.probes.ActiveInterval)
	target := hostinfo.vpnAddrs[0]
	if !hm.completeOutbound(hostinfo, vpnAddrs) {
		return
	}
	f.lightHouse.refreshAfterHandshake(hostinfo)
	if len(hh.controlQueue) == 0 {
		return
	}
	peer := hm.mainHostMap.QueryVpnAddr(target)
	if peer == nil {
		return
	}
	peer.logger(f.l).Debug("Sending stored packets", "count", len(hh.controlQueue))
	nonce, out := make([]byte, 12), make([]byte, mtu)
	for _, p := range hh.controlQueue {
		f.SendMessageToHostInfo(p.messageType, p.messageSubType, peer, p.payload, nonce, out)
	}
}

// validatePeerCert checks the peer certificate for self-connection.
// Returns the VPN addrs, whether any of them fall within one of our own VPN
// networks, and true if valid; false if rejected.
func (hm *handshakeManager) validatePeerCert(via packetSender, remoteCert *cert.CachedCertificate) ([]netip.Addr, bool, bool) {
	f := hm.f
	vpnNetworks := remoteCert.Certificate.Networks()

	// The cert package rejects host certs with no networks at parse time, so
	// reaching this state would mean an invariant was bypassed elsewhere.
	// Refuse explicitly so downstream code (which indexes vpnAddrs[0]) can't
	// panic if that invariant ever changes.
	if len(vpnNetworks) == 0 {
		f.l.Info("No networks in certificate",
			"from", via, "cert", remoteCert)
		return nil, false, false
	}

	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	anyVpnAddrsInCommon := false

	for i, network := range vpnNetworks {
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.Error("Refusing to handshake with myself",
				"vpnNetworks", vpnNetworks,
				"from", via,
				"certName", remoteCert.Certificate.Name(),
				"certVersion", remoteCert.Certificate.Version(),
				"fingerprint", remoteCert.Fingerprint,
				"issuer", remoteCert.Certificate.Issuer(),
			)
			return nil, false, false
		}
		vpnAddrs[i] = network.Addr()
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
	}

	return vpnAddrs, anyVpnAddrsInCommon, true
}

// sendHandshakeResponse sends a handshake response via the appropriate transport.
// cached is true when msg is a stored response being retransmitted because
// the peer's stage-1 retransmit landed (the errAlreadySeen path); false on a
// fresh response.
func (hm *handshakeManager) sendHandshakeResponse(via packetSender, msg []byte, hostinfo *hostInfo, cached bool) {
	if msg == nil {
		return
	}

	f := hm.f

	// Common log fields. peerCert may be nil during intermediate
	// multi-message flows (handshake hasn't completed yet); skip the cert
	// block if so.
	logFields := []any{
		"vpnAddrs", hostinfo.vpnAddrs,
		"handshake", structuredMap{"stage": uint64(2), "style": header.SubTypeName(header.Handshake, header.HandshakeIXPSK0)},
		"cached", cached,
		"initiatorIndex", hostinfo.remoteIndexId,
		"responderIndex", hostinfo.localIndexId,
	}
	if peerCert := hostinfo.connectionState.peerCert; peerCert != nil {
		logFields = append(logFields,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
		)
	}

	var err error
	path := receivedRoute(via)
	if via.IsRelayed {
		hostinfo.relayState.addRelayAddress(path.Relay)
		via.relayHI.relayState.setStateByIndex(path.local, relayEstablished)
		_, err = f.sendVia(hostinfo, path, msg, make([]byte, 12), make([]byte, mtu), false, true)
	} else {
		err = f.writePath(hostinfo, path, msg, true, nil)
	}
	fields := append(logFields, "path", path.TunnelPath)
	if err != nil {
		f.l.Debug("Handshake response not sent", append(fields, "error", err)...)
		return
	}
	f.l.Info("Handshake message sent", fields...)
}

// handleCheckAndCompleteError handles errors from CheckAndComplete.
// This only fires from the responder-side beginHandshake path, after the
// peer cert has been validated and connectionState populated, so peerCert
// is always non-nil for the cases that log it.
func (hm *handshakeManager) handleCheckAndCompleteError(err error, existing, hostinfo *hostInfo, via packetSender) {
	f := hm.f
	peerCert := hostinfo.connectionState.peerCert
	hsFields := structuredMap{"stage": uint64(1), "style": header.SubTypeName(header.Handshake, header.HandshakeIXPSK0)}

	switch err {
	case errAlreadySeen:
		// Resend the original response. The peer is committed to that response's
		// ephemeral keys; a freshly-built one would have different keys and break
		// the tunnel even though both sides "completed" the handshake.
		if msg := existing.HandshakePacket[handshakePacketStage2]; msg != nil {
			hm.sendHandshakeResponse(via, msg, existing, true)
		}

	case errExistingHostInfo:
		f.l.Info("Handshake too old",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"oldHandshakeTime", existing.lastHandshakeTime,
			"newHandshakeTime", hostinfo.lastHandshakeTime,
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
		f.SendMessageToVpnAddr(header.Test, header.TestRequest, hostinfo.vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))

	case errLocalIndexCollision:
		f.l.Error("Failed to add hostInfo due to localIndex collision",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"localIndex", hostinfo.localIndexId,
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)

	default:
		f.l.Error("Failed to add hostInfo to hostMap",
			"vpnAddrs", hostinfo.vpnAddrs,
			"from", via,
			"error", err,
			"certName", peerCert.Certificate.Name(),
			"certVersion", peerCert.Certificate.Version(),
			"fingerprint", peerCert.Fingerprint,
			"issuer", peerCert.Certificate.Issuer(),
			"initiatorIndex", hostinfo.remoteIndexId,
			"responderIndex", hostinfo.localIndexId,
			"handshake", hsFields,
		)
	}
}

// certVerifier returns a CertVerifier that validates certs against the current CA pool.
func (hm *handshakeManager) certVerifier() handshake.CertVerifier {
	return func(c cert.Certificate) (*cert.CachedCertificate, error) {
		cc, err := hm.f.pki.GetCAPool().VerifyCertificate(time.Now(), c)
		if err == nil && hm.f.paths.config.Load().network.denies(cc) {
			return nil, cert.ErrBlockListed
		}
		return cc, err
	}
}
