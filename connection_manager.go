package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

type trafficDecision int

const (
	doNothing      trafficDecision = 0
	deleteTunnel   trafficDecision = 1 // delete the hostinfo on our side, do not notify the remote
	closeTunnel    trafficDecision = 2 // delete the hostinfo and notify the remote
	swapPrimary    trafficDecision = 3
	migrateRelays  trafficDecision = 4
	tryRehandshake trafficDecision = 5
	sendTestPacket trafficDecision = 6
)

type connectionManager struct {
	// relayUsed holds which relay localIndexs are in use
	relayUsed     map[uint32]struct{}
	relayUsedLock *sync.RWMutex

	hostMap      *hostMap
	trafficTimer *lockingTimerWheel[uint32]
	engine       *packetEngine
	punchy       *punchManager

	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	inactivityTimeout       time.Duration
	dropInactive            bool

	l *slog.Logger
}

type connectionManagerConfig struct {
	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	inactivityTimeout       time.Duration
	dropInactive            bool
}

func newConnectionManager(l *slog.Logger, hm *hostMap, p *punchManager, cfg connectionManagerConfig) *connectionManager {
	if cfg.checkInterval <= 0 {
		cfg.checkInterval = 5 * time.Second
	}
	if cfg.pendingDeletionInterval <= 0 {
		cfg.pendingDeletionInterval = 10 * time.Second
	}
	if cfg.inactivityTimeout <= 0 {
		cfg.inactivityTimeout = 10 * time.Minute
	}
	cm := &connectionManager{
		hostMap:                 hm,
		l:                       l,
		punchy:                  p,
		relayUsed:               make(map[uint32]struct{}),
		relayUsedLock:           &sync.RWMutex{},
		checkInterval:           cfg.checkInterval,
		pendingDeletionInterval: cfg.pendingDeletionInterval,
	}
	minimum := min(500*time.Millisecond, cfg.checkInterval, cfg.pendingDeletionInterval)
	maximum := max(cfg.checkInterval, cfg.pendingDeletionInterval)
	cm.trafficTimer = newLockingTimerWheel[uint32](minimum, maximum)
	cm.inactivityTimeout = cfg.inactivityTimeout
	cm.dropInactive = cfg.dropInactive
	return cm
}

func (cm *connectionManager) getInactivityTimeout() time.Duration {
	return cm.inactivityTimeout
}

func (cm *connectionManager) recordInbound(h *hostInfo) {
	h.markIn()
}

// recordOutboundNoRebind records outbound traffic without consuming the rebind epoch; the direct path
// to the relay consumes the edge, the via send must not.
func (cm *connectionManager) recordOutboundNoRebind(h *hostInfo) {
	h.markOutOnly()
}

// recordOutbound records outbound traffic and reports whether we rebound since this tunnel last sent.
func (cm *connectionManager) recordOutbound(h *hostInfo) bool {
	return h.markOut(cm.engine.rebindEpoch.Load())
}

func (cm *connectionManager) recordRelayUse(localIndex uint32) {
	cm.relayUsedLock.RLock()
	// If this already exists, return
	if _, ok := cm.relayUsed[localIndex]; ok {
		cm.relayUsedLock.RUnlock()
		return
	}
	cm.relayUsedLock.RUnlock()
	cm.relayUsedLock.Lock()
	cm.relayUsed[localIndex] = struct{}{}
	cm.relayUsedLock.Unlock()
}

// getAndResetTrafficCheck returns if there was any inbound or outbound traffic within the last tick and
// resets the state for this local index
func (cm *connectionManager) getAndResetTrafficCheck(h *hostInfo, now time.Time) (bool, bool) {
	in, out := h.takeTraffic()
	if in || out {
		h.lastUsed = now
	}
	return in, out
}

func (cm *connectionManager) Start(ctx context.Context) {
	clockSource := time.NewTicker(cm.trafficTimer.t.tickDuration)
	defer clockSource.Stop()

	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-clockSource.C:
			cm.trafficTimer.Advance(now)
			for {
				localIndex, has := cm.trafficTimer.Purge()
				if !has {
					break
				}

				cm.doTrafficCheck(localIndex, p, nb, out, now)
			}
		}
	}
}

func (cm *connectionManager) doTrafficCheck(localIndex uint32, p, nb, out []byte, now time.Time) {
	decision, hostinfo, primary := cm.makeTrafficDecision(localIndex, now)

	switch decision {
	case deleteTunnel:
		// Local delete only, clearing the lighthouse cache if this was the last hostinfo for the vpn addr
		cm.engine.closeTunnel(hostinfo)

	case closeTunnel:
		cm.engine.sendCloseTunnel(hostinfo)
		cm.engine.closeTunnel(hostinfo)

	case swapPrimary:
		cm.swapPrimary(hostinfo, primary)

	case migrateRelays:
		cm.migrateRelayUsed(hostinfo, primary)

	case tryRehandshake:
		cm.tryRehandshake(hostinfo)

	case sendTestPacket:
		cm.engine.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, p, nb, out)
	}

	cm.resetRelayTrafficCheck(hostinfo)
}

func (cm *connectionManager) resetRelayTrafficCheck(hostinfo *hostInfo) {
	if hostinfo != nil {
		cm.relayUsedLock.Lock()
		defer cm.relayUsedLock.Unlock()
		// No need to migrate any relays, delete usage info now.
		for _, idx := range hostinfo.relayState.CopyRelayForIdxs() {
			delete(cm.relayUsed, idx)
		}
	}
}

func (cm *connectionManager) migrateRelayUsed(oldhostinfo, newhostinfo *hostInfo) {
	relayFor := oldhostinfo.relayState.CopyAllRelayFor()

	for _, r := range relayFor {
		existing, ok := newhostinfo.relayState.QueryRelayForByIp(r.PeerAddr)

		var index uint32
		var relayFrom netip.Addr
		var relayTo netip.Addr
		switch {
		case ok:
			switch existing.State {
			case relayEstablished, relayPeerRequested, relayDisestablished:
				// This relay already exists in newhostinfo, then do nothing.
				continue
			case relayRequested:
				// The relay exists in a requested state; re-send the request.
				index = existing.LocalIndex
				switch r.Type {
				case relayTypeTerminal:
					relayFrom = cm.engine.myVpnAddrs[0]
					relayTo = existing.PeerAddr
				case relayTypeForwarding:
					relayFrom = existing.PeerAddr
					relayTo = newhostinfo.vpnAddrs[0]
				default:
					// should never happen
					panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
				}
			}
		case !ok:
			cm.relayUsedLock.RLock()
			if _, relayUsed := cm.relayUsed[r.LocalIndex]; !relayUsed {
				// The relay hasn't been used; don't migrate it.
				cm.relayUsedLock.RUnlock()
				continue
			}
			cm.relayUsedLock.RUnlock()
			// The relay doesn't exist at all; create some relay state and send the request.
			var err error
			index, err = addRelay(cm.l, newhostinfo, cm.hostMap, r.PeerAddr, nil, r.Type, relayRequested)
			if err != nil {
				cm.l.Error("failed to migrate relay to new hostinfo", "error", err)
				continue
			}
			switch r.Type {
			case relayTypeTerminal:
				relayFrom = cm.engine.myVpnAddrs[0]
				relayTo = r.PeerAddr
			case relayTypeForwarding:
				relayFrom = r.PeerAddr
				relayTo = newhostinfo.vpnAddrs[0]
			default:
				// should never happen
				panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
			}
		}

		// Send a CreateRelayRequest to the peer.
		req := NebulaControl{
			Type:                NebulaControl_CreateRelayRequest,
			InitiatorRelayIndex: index,
		}

		switch newhostinfo.GetCert().Certificate.Version() {
		case cert.Version1:
			if !relayFrom.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 network because the relay is not running a current nebula version")
				continue
			}

			if !relayTo.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 remote network because the relay is not running a current nebula version")
				continue
			}

			b := relayFrom.As4()
			req.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = relayTo.As4()
			req.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		case cert.Version2:
			req.RelayFromAddr = netAddrToProtoAddr(relayFrom)
			req.RelayToAddr = netAddrToProtoAddr(relayTo)
		default:
			newhostinfo.logger(cm.l).Error("Unknown certificate version found while attempting to migrate relay")
			continue
		}

		msg, err := req.Marshal()
		if err != nil {
			cm.l.Error("failed to marshal Control message to migrate relay", "error", err)
		} else {
			cm.engine.SendMessageToHostInfo(header.Control, 0, newhostinfo, msg, make([]byte, 12), make([]byte, mtu))
			cm.l.Info("send CreateRelayRequest",
				"relayFrom", relayFrom,
				"relayTo", relayTo,
				"initiatorRelayIndex", req.InitiatorRelayIndex,
				"responderRelayIndex", req.ResponderRelayIndex,
				"vpnAddrs", newhostinfo.vpnAddrs,
			)
		}
	}
}

func (cm *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *hostInfo, *hostInfo) {
	// Read lock the main hostmap to order decisions based on tunnels being the primary tunnel
	cm.hostMap.RLock()
	defer cm.hostMap.RUnlock()

	hostinfo := cm.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		cm.l.Debug("Not found in hostmap", "localIndex", localIndex)
		return doNothing, nil, nil
	}

	if cm.isInvalidCertificate(now, hostinfo) {
		return closeTunnel, hostinfo, nil
	}

	if hostinfo.connectionState != nil && hostinfo.connectionState.messageCounter.Load() >= rejectAfterMessages {
		// Send path can't encrypt a CloseTunnel notify, so just delete locally; the peer recovers via recv_error.
		hostinfo.logger(cm.l).Error("Dropping tunnel, message counter is exhausted")
		return deleteTunnel, hostinfo, nil
	}

	primary := cm.hostMap.Hosts[hostinfo.vpnAddrs[0]]
	mainHostInfo := true
	if primary != nil && primary != hostinfo {
		mainHostInfo = false
	}

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := cm.getAndResetTrafficCheck(hostinfo, now)

	// A hostinfo is determined alive if there is incoming traffic
	if inTraffic {
		decision := doNothing
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", structuredMap{"state": "alive", "method": "passive"},
			)
		}
		hostinfo.setPendingDeletion(false)

		if mainHostInfo {
			decision = tryRehandshake
		} else {
			if cm.shouldSwapPrimary(hostinfo) {
				decision = swapPrimary
			} else {
				// migrate the relays to the primary, if in use.
				decision = migrateRelays
			}
		}

		cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			cm.punchy.SendPunch(hostinfo)
		}

		return decision, hostinfo, primary
	}

	if hostinfo.isPendingDeletion() {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(cm.l).Info("Tunnel status",
			"tunnelCheck", structuredMap{"state": "dead", "method": "active"},
		)

		return deleteTunnel, hostinfo, nil
	}

	decision := doNothing
	if hostinfo != nil && hostinfo.connectionState != nil && mainHostInfo {
		if !outTraffic {
			inactiveFor, isInactive := cm.isInactive(hostinfo, now)
			if isInactive {
				// Tunnel is inactive, tear it down
				hostinfo.logger(cm.l).Info("Dropping tunnel due to inactivity",
					"inactiveDuration", inactiveFor,
					"primary", mainHostInfo,
				)

				return closeTunnel, hostinfo, primary
			}

			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			cm.punchy.SendPunch(hostinfo)
			cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)
			return doNothing, nil, nil
		}

		// We aren't receiving traffic but we are sending it. The outbound
		// traffic itself refreshes the primary remote's NAT state; this
		// fans out to non-primary remotes, but only if target_all_remotes
		// is configured.
		cm.punchy.SendPunchToAll(hostinfo)

		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", structuredMap{"state": "testing", "method": "active"},
			)
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		decision = sendTestPacket

	} else {
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Hostinfo sadness")
		}
	}

	hostinfo.setPendingDeletion(true)
	cm.trafficTimer.Add(hostinfo.localIndexId, cm.pendingDeletionInterval)
	return decision, hostinfo, nil
}

func (cm *connectionManager) isInactive(hostinfo *hostInfo, now time.Time) (time.Duration, bool) {
	if !cm.dropInactive {
		// We aren't configured to drop inactive tunnels
		return 0, false
	}

	inactiveDuration := now.Sub(hostinfo.lastUsed)
	if inactiveDuration < cm.getInactivityTimeout() {
		// It's not considered inactive
		return inactiveDuration, false
	}

	// The tunnel is inactive
	return inactiveDuration, true
}

func (cm *connectionManager) shouldSwapPrimary(current *hostInfo) bool {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	// Only one side should swap because if both swap then we may never resolve to a single tunnel.
	// vpn addr is static across all tunnels for this host pair so lets
	// use that to determine if we should consider swapping.
	if current.vpnAddrs[0].Compare(cm.engine.myVpnAddrs[0]) < 0 {
		// Their primary vpn addr is less than mine. Do not swap.
		return false
	}

	if current.connectionState.messageCounter.Load() >= rehandshakeAfterMessages {
		// This tunnel is being rolled for counter exhaustion, never swap back onto its spent key.
		return false
	}

	return true
}

func (cm *connectionManager) swapPrimary(current, primary *hostInfo) {
	cm.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if cm.hostMap.Hosts[current.vpnAddrs[0]] == primary {
		cm.hostMap.unlockedMakePrimary(current)
	}
	cm.hostMap.Unlock()
}

// isInvalidCertificate decides whether a tunnel must be destroyed because its
// peer certificate is blocked, expired, or no longer trusted.
func (cm *connectionManager) isInvalidCertificate(now time.Time, hostinfo *hostInfo) bool {
	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false //don't tear down tunnels for handshakes in progress
	}

	caPool := cm.engine.pki.GetCAPool()
	err := caPool.VerifyCachedCertificate(now, remoteCert)
	if err == nil {
		return false //cert is still valid! yay!
	} else if err == cert.ErrBlockListed { //avoiding errors.Is for speed
		// Block listed certificates should always be disconnected
		hostinfo.logger(cm.l).Info("Remote certificate is blocked, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	} else {
		hostinfo.logger(cm.l).Info("Remote certificate is no longer valid, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	}
}

func (cm *connectionManager) tryRehandshake(hostinfo *hostInfo) {
	cs := cm.engine.pki.getCertState()
	curCrtVersion := hostinfo.connectionState.myCert.Version()
	peerCrt := hostinfo.connectionState.peerCert
	if peerCrt != nil && curCrtVersion < peerCrt.Certificate.Version() {
		// if our certificate version is less than theirs, and we have a matching version available, rehandshake?
		if cs.getCertificate(peerCrt.Certificate.Version()) != nil {
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", hostinfo.vpnAddrs,
				"version", curCrtVersion,
				"peerVersion", peerCrt.Certificate.Version(),
				"reason", "local certificate version lower than peer, attempting to correct",
			)
			cm.engine.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(hh *handshakeHostInfo) {
				hh.initiatingVersionOverride = peerCrt.Certificate.Version()
			})
			return
		}
	}
	if curCrtVersion < cs.initiatingVersion {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "current cert version < pki.initiatingVersion",
		)

		cm.engine.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	if hostinfo.connectionState.messageCounter.Load() >= rehandshakeAfterMessages {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "message counter rehandshake threshold reached",
		)

		cm.engine.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
}
