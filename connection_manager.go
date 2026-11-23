package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
)

type trafficDecision int

const (
	doNothing      trafficDecision = 0
	deleteTunnel   trafficDecision = 1 // delete the hostinfo on our side, do not notify the remote
	closeTunnel    trafficDecision = 2 // delete the hostinfo and notify the remote
	swapPrimary    trafficDecision = 3
	migrateRelays  trafficDecision = 4
	tryRehandshake trafficDecision = 5
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
	cfg.CheckInterval = positiveOr(cfg.CheckInterval, 5*time.Second)
	cfg.PendingDeletionInterval = positiveOr(cfg.PendingDeletionInterval, 10*time.Second)
	cfg.InactivityTimeout = positiveOr(cfg.InactivityTimeout, 10*time.Minute)
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

				cm.doTrafficCheck(localIndex, now)
			}
		}
	}
}

func (cm *connectionManager) doTrafficCheck(localIndex uint32, now time.Time) {
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
	}

	cm.resetRelayTrafficCheck(hostinfo)
}

func (cm *connectionManager) resetRelayTrafficCheck(hostinfo *hostInfo) {
	if hostinfo != nil {
		cm.relayUsedLock.Lock()
		defer cm.relayUsedLock.Unlock()
		// No need to migrate any relays, delete usage info now.
		for _, idx := range hostinfo.relayState.localIndexes() {
			delete(cm.relayUsed, idx)
		}
	}
}

func (cm *connectionManager) migrateRelayUsed(oldhostinfo, newhostinfo *hostInfo) {
	relayFor := oldhostinfo.relayState.mappings()

	for _, r := range relayFor {
		if r.Circuit != "" {
			continue
		}
		existing, ok := newhostinfo.relayState.mappingByAddr(r.PeerAddr)

		if ok {
			if existing.State != relayRequested {
				continue
			}
		} else {
			cm.relayUsedLock.RLock()
			_, used := cm.relayUsed[r.LocalIndex]
			cm.relayUsedLock.RUnlock()
			if !used {
				continue
			}
			var err error
			existing, err = cm.hostMap.getOrAddRelay(newhostinfo, r.PeerAddr, 0, r.Type, relayRequested)
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

		cm.engine.sendRelayControl(newhostinfo, relayFrom, relayTo, existing.LocalIndex, 0)
	}
}

func (cm *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *hostInfo, *hostInfo) {
	// Read lock the main hostmap to order decisions based on tunnels being the primary tunnel
	cm.hostMap.RLock()

	hostinfo := cm.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		cm.hostMap.RUnlock()
		cm.l.Debug("Not found in hostmap", "localIndex", localIndex)
		return doNothing, nil, nil
	}

	primary := cm.hostMap.Hosts[hostinfo.vpnAddrs[0]]
	cm.hostMap.RUnlock()
	if cm.isInvalidCertificate(now, hostinfo) {
		return closeTunnel, hostinfo, nil
	}

	if hostinfo.connectionState != nil && hostinfo.connectionState.messageCounter.Load() >= rejectAfterMessages {
		// Send path can't encrypt a CloseTunnel notify, so just delete locally; the peer recovers via recv_error.
		hostinfo.logger(cm.l).Error("Dropping tunnel, message counter is exhausted")
		return deleteTunnel, hostinfo, nil
	}

	mainHostInfo := primary == nil || primary == hostinfo

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := hostinfo.takeTraffic()
	paths := &hostinfo.paths
	paths.mu.Lock()
	if inTraffic || outTraffic {
		hostinfo.lastUsed = now
		paths.demand = now
	}
	if outTraffic && !inTraffic && paths.last.At.Before(now.Add(-cm.checkInterval)) {
		paths.nextActive = time.Time{}
	}
	unavailable := !paths.active.Endpoint.IsValid() && now.Sub(paths.changed) > cm.pendingDeletionInterval
	paths.mu.Unlock()
	if !mainHostInfo && !inTraffic && hostinfo.isPendingDeletion() {
		return deleteTunnel, hostinfo, nil
	}
	if mainHostInfo && unavailable && cm.engine.handshakeManager.queryVpnIp(hostinfo.vpnAddrs[0]) == nil {
		return deleteTunnel, hostinfo, nil
	}
	if mainHostInfo && !inTraffic && !outTraffic && cm.dropInactive && now.Sub(hostinfo.lastUsed) >= cm.inactivityTimeout && cm.engine.paths.config.Load().effectivePolicy(hostinfo.vpnAddrs, cm.hostMap).MonitorInterval == 0 {
		return closeTunnel, hostinfo, primary
	}
	hostinfo.setPendingDeletion(!mainHostInfo && !inTraffic)
	cm.trafficTimer.Add(localIndex, cm.checkInterval)
	if !outTraffic {
		cm.punchy.SendPunch(hostinfo)
	} else if !inTraffic {
		cm.punchy.SendPunchToAll(hostinfo)
	}
	if mainHostInfo {
		return tryRehandshake, hostinfo, primary
	}
	if inTraffic {
		if cm.shouldSwapPrimary(hostinfo) {
			return swapPrimary, hostinfo, primary
		}
		return migrateRelays, hostinfo, primary
	}
	return doNothing, hostinfo, primary
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
	if cm.engine.paths.config.Load().network.denies(remoteCert) {
		err = cert.ErrBlockListed
	}
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
	v := max(cs.initiatingVersion, curCrtVersion)
	if peerCrt != nil && curCrtVersion < peerCrt.Certificate.Version() && cs.GetCredential(peerCrt.Certificate.Version()) != nil {
		v = peerCrt.Certificate.Version()
	}
	if curCrtVersion >= v && hostinfo.connectionState.messageCounter.Load() < rehandshakeAfterMessages {
		return
	}
	cm.l.Info("Renewing tunnel keys", "vpnAddrs", hostinfo.vpnAddrs, "certificateVersion", v, "messageCounter", hostinfo.connectionState.messageCounter.Load())
	cm.engine.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(hh *handshakeHostInfo) { hh.initiatingVersionOverride = v })
}
