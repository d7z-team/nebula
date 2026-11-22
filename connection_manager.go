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
	relayUsedLock sync.RWMutex

	hostMap      *hostMap
	trafficTimer *timerWheel[uint32]
	engine       *packetEngine
	punchy       *punchManager

	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	inactivityTimeout       time.Duration
	dropInactive            bool

	l *slog.Logger
}

func newConnectionManager(l *slog.Logger, hm *hostMap, p *punchManager, cfg ConnectionOptions) *connectionManager {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 5 * time.Second
	}
	if cfg.PendingDeletionInterval <= 0 {
		cfg.PendingDeletionInterval = 10 * time.Second
	}
	if cfg.InactivityTimeout <= 0 {
		cfg.InactivityTimeout = 10 * time.Minute
	}
	minimum := min(500*time.Millisecond, cfg.CheckInterval, cfg.PendingDeletionInterval)
	maximum := max(cfg.CheckInterval, cfg.PendingDeletionInterval)
	return &connectionManager{
		hostMap: hm, l: l, punchy: p,
		relayUsed:               make(map[uint32]struct{}),
		trafficTimer:            newTimerWheel[uint32](minimum, maximum),
		checkInterval:           cfg.CheckInterval,
		pendingDeletionInterval: cfg.PendingDeletionInterval,
		inactivityTimeout:       cfg.InactivityTimeout,
		dropInactive:            cfg.DropInactive,
	}
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

func (cm *connectionManager) Start(ctx context.Context) {
	clockSource := time.NewTicker(cm.trafficTimer.tickDuration)
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
		if ok {
			if existing.State != relayRequested {
				continue
			}
			index = existing.LocalIndex
		} else {
			cm.relayUsedLock.RLock()
			_, used := cm.relayUsed[r.LocalIndex]
			cm.relayUsedLock.RUnlock()
			if !used {
				continue
			}
			var err error
			index, err = addRelay(cm.l, newhostinfo, cm.hostMap, r.PeerAddr, nil, r.Type, relayRequested)
			if err != nil {
				cm.l.Error("failed to migrate relay to new hostinfo", "error", err)
				continue
			}
		}

		var relayFrom, relayTo netip.Addr
		switch r.Type {
		case relayTypeTerminal:
			relayFrom, relayTo = cm.engine.myVpnAddrs[0], r.PeerAddr
		case relayTypeForwarding:
			relayFrom, relayTo = r.PeerAddr, newhostinfo.vpnAddrs[0]
		default:
			panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
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
	mainHostInfo := primary == nil || primary == hostinfo

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := hostinfo.takeTraffic()
	if inTraffic || outTraffic {
		hostinfo.lastUsed = now
	}

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
	if hostinfo.connectionState != nil && mainHostInfo {
		if !outTraffic {
			inactiveFor := now.Sub(hostinfo.lastUsed)
			if cm.dropInactive && inactiveFor >= cm.inactivityTimeout {
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
