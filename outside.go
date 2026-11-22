package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/header"
)

// dispatchDatagram processes one received underlay packet. Message payloads
// are decrypted in place, so the caller must not reuse packet until it returns.
func (f *packetEngine) dispatchDatagram(via packetSender, packet []byte, rxc *rxContext) {
	h := &rxc.h
	err := h.Parse(packet)
	if err != nil {
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		if len(packet) > 1 {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				f.l.Debug("Error while parsing inbound packet",
					"from", via,
					"error", err,
					"packet", packet,
				)
			}
		}
		return
	}

	if h.Version != header.Version {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Unexpected header version received", "from", via)
		}
		return
	}

	// Check before processing to see if this is a expected type/subtype
	if !h.IsValidSubType() {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Unexpected packet received", "from", via)
		}
		return
	}

	if !via.IsRelayed {
		if f.myVpnNetworksTable.Contains(via.UdpAddr.Addr()) {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				f.l.Debug("Refusing to process double encrypted packet", "from", via)
			}
			return
		}
	}

	// Unencrypted packets
	switch h.Type {
	case header.Handshake:
		f.handshakeManager.HandleIncoming(via, packet, h)
		return

	case header.RecvError:
		if !via.IsRelayed {
			f.handleRecvError(via.UdpAddr, h)
		}
		return
	}

	// relay packets are special
	isMessageRelay := (h.Type == header.Message && h.Subtype == header.MessageRelay)

	var hostinfo *hostInfo
	if isMessageRelay {
		hostinfo = f.hostMap.QueryRelayIndex(h.RemoteIndex)
	} else {
		hostinfo = f.hostMap.QueryIndex(h.RemoteIndex)
	}

	// At this point we should have a valid existing tunnel, verify and send
	// recvError if necessary
	if hostinfo == nil || hostinfo.connectionState == nil {
		if !via.IsRelayed {
			f.sendRecvError(via.UdpAddr, h.RemoteIndex)
		}
		return
	}

	if len(packet) < header.Len+hostinfo.connectionState.dKey.Overhead() {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("packet too small", "from", via, "length", len(packet))
		}
		return
	}

	// All remaining packets are encrypted
	if isMessageRelay {
		// relay packets are special, this branch should always early-return
		err = hostinfo.connectionState.VerifyRelay(f.l, h.MessageCounter, packet, rxc.nb)
		if err != nil {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Failed to verify relay packet", "error", err, "from", via, "header", h)
			}
			return
		}
		f.handleOutsideRelayPacket(hostinfo, via, packet, rxc)
		return
	}

	out, err := hostinfo.connectionState.Decrypt(f.l, h.MessageCounter, packet, rxc.nb)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Failed to decrypt packet", "error", err, "from", via, "header", h)
		}
		return
	}

	path := receivedRoute(via)
	if via.IsRelayed && !slices.Contains(hostinfo.vpnAddrs, via.relay.PeerAddr) {
		return
	}
	permitted := f.allowed(hostinfo, path)
	probe := h.Type == header.Test && isPathProbe(out)
	if probe && h.Subtype == header.TestReply {
		f.finishReply(hostinfo, path, out, permitted)
		return
	}
	if !permitted {
		// A peer can echo Test on the incoming relay while still sending IP over
		// its former direct exit. Re-establish over our verified relay so that
		// it also selects the permitted return path for ordinary traffic.
		if !via.IsRelayed && h.Type == header.Message && h.Subtype == header.MessageNone {
			active := f.currentRoute(hostinfo)
			if active.leg != nil {
				now := time.Now()
				s := &hostinfo.paths
				s.mu.Lock()
				due := !now.Before(s.recoverAfter)
				if due {
					s.recoverAfter = now.Add(30 * time.Second)
				}
				s.mu.Unlock()
				if due {
					f.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
				}
			}
		}
		return
	}
	if via.IsRelayed {
		hostinfo.relayState.addRelayAddress(via.relayHI.vpnAddrs[0])
	}
	if !probe {
		f.handleHostRoaming(hostinfo, via)
		if h.Type != header.Test {
			hostinfo.markIn()
		}
	}
	switch h.Type {
	case header.Message:
		switch h.Subtype {
		case header.MessageNone:
			f.deliverIP(hostinfo, out)
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message subtype seen", "from", via, "header", h)
			return
		}

	case header.LightHouse:
		rxc.lhh.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, out)

	case header.Test:
		switch h.Subtype {
		case header.TestReply:
			// No-op, useful for the Roaming and connectionManager side-effects above
		case header.TestRequest:
			if header.MaxOverhead+len(out) > len(rxc.scratch) {
				// A reply that cannot fit in scratch is dropped no matter the log level.
				if f.l.Enabled(context.Background(), slog.LevelDebug) {
					hostinfo.logger(f.l).Debug("dropping oversized test request", "payloadLen", len(out), "from", via)
				}
				return
			}
			f.sendOnRoute(header.Test, header.TestReply, hostinfo, path, out, rxc.nb, rxc.scratch[:0])
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected test subtype seen", "from", via, "header", h)
			return
		}

	case header.CloseTunnel:
		hostinfo.logger(f.l).Info("Close tunnel received, tearing down.", "from", via)
		f.closeTunnel(hostinfo)

	case header.Control:
		if !via.IsRelayed {
			f.handleRelayControl(hostinfo, out)
		}

	default:
		hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message type seen", "from", via, "header", h)
	}
}

func (f *packetEngine) handleOutsideRelayPacket(hostinfo *hostInfo, via packetSender, packet []byte, rxc *rxContext) {
	h := &rxc.h
	// The outer header and authentication tag surround the inner Nebula datagram.
	signedPayload := packet[header.Len : len(packet)-hostinfo.connectionState.dKey.Overhead()]
	var inner header.H
	if via.IsRelayed || !f.allowed(hostinfo, receivedRoute(via)) || inner.Parse(signedPayload) != nil || (inner.Type == header.Message && inner.Subtype == header.MessageRelay) {
		return
	}
	f.handleHostRoaming(hostinfo, via)
	// Track usage of both the hostInfo and the relay for the received & authenticated packet
	if inner.Type != header.Test {
		hostinfo.markIn()
		f.connectionManager.recordRelayUse(h.RemoteIndex)
	}

	relay, ok := hostinfo.relayState.mappingByIndex(h.RemoteIndex)
	if !ok {
		// The only way this happens is if hostmap has an index to the correct hostInfo, but the hostInfo is missing
		// its internal mapping. This should never happen.
		hostinfo.logger(f.l).Error("hostInfo missing remote relay index", "relayRemoteIndex", h.RemoteIndex)
		return
	}

	switch relay.Type {
	case relayTypeTerminal:
		if relay.State != relayEstablished && inner.Type != header.Handshake {
			return
		}
		// If I am the target of this relay, process the unwrapped packet
		// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
		via = packetSender{
			UdpAddr:   via.UdpAddr,
			relayHI:   hostinfo,
			relay:     relay,
			IsRelayed: true,
		}
		f.dispatchDatagram(via, signedPayload, rxc)
	case relayTypeForwarding:
		// Find the target hostInfo relay object
		targetHI, targetRelay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relay.PeerAddr)
		if err != nil {
			hostinfo.logger(f.l).Info("Failed to find target host info by ip",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"error", err,
			)
			return
		}

		if relay.State != relayEstablished || targetRelay.State != relayEstablished || targetRelay.Type != relayTypeForwarding {
			hostinfo.logger(f.l).Debug("relay mapping unavailable", "relayTo", relay.PeerAddr, "state", relay.State, "targetState", targetRelay.State, "targetType", targetRelay.Type)
			return
		}
		endpoint := targetHI.GetRemote()
		if !endpoint.IsValid() || targetHI.paths.failedDirect(endpoint) {
			return
		}
		if inner.Type != header.Test {
			targetHI.markOutOnly()
		}
		// Reuse the authenticated frame's outer header and tag space.
		out, err := f.prepareSendVia(targetHI, targetRelay, signedPayload, rxc.nb, packet[:0], true)
		if err == nil {
			err = f.writePath(targetHI, tunnelRoute{TunnelPath: TunnelPath{Endpoint: endpoint}}, out, false, hostinfo)
		}
		if err != nil {
			targetHI.logger(f.l).Debug("failed to forward relay datagram", "error", err)
		}
	default:
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Unexpected relay type", "from", via, "relayType", relay.Type)
		}
	}
}

// closeTunnel closes a tunnel locally, it does not send a closeTunnel packet to the remote.
// It reports false when another goroutine already removed this exact tunnel.
func (f *packetEngine) closeTunnel(hostInfo *hostInfo) bool {
	// Hold the hostmap lock across both the delete and the lighthouse eviction,
	// to avoid a race with handshake completion.
	f.hostMap.Lock()
	defer f.hostMap.Unlock()
	if f.hostMap.Indexes[hostInfo.localIndexId] != hostInfo {
		return false
	}
	if !f.hostMap.unlockedDeleteHostInfo(hostInfo) {
		return true
	}

	// We no longer have any tunnels with this vpn addr, clear learned lighthouse state to lower memory usage
	f.lightHouse.DeleteVpnAddrs(hostInfo.vpnAddrs)
	return true
}

// sendCloseTunnel is a helper function to send a proper close tunnel packet to a remote
func (f *packetEngine) sendCloseTunnel(h *hostInfo) {
	f.SendMessageToHostInfo(header.CloseTunnel, 0, h, nil, make([]byte, 12), make([]byte, mtu))
}

func (f *packetEngine) handleHostRoaming(hostinfo *hostInfo, via packetSender) {
	if via.IsRelayed || via.UdpAddr == hostinfo.GetRemote() {
		return
	}
	if via.UdpAddr == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < roamingSuppressDuration {
		return
	}
	hostinfo.lastRoam, hostinfo.lastRoamRemote = time.Now(), via.UdpAddr
	hostinfo.remotes.LearnRemote(hostinfo.vpnAddrs[0], via.UdpAddr)
	s := &hostinfo.paths
	s.mu.Lock()
	s.roam = via.UdpAddr
	s.nextBackup = time.Time{}
	s.mu.Unlock()
}

func (f *packetEngine) deliverIP(hostinfo *hostInfo, packet []byte) {
	port := f.port.Load()
	if port == nil || port.ctx.Err() != nil {
		return
	}
	ip, err := parseInnerPacket(packet)
	peer := hostinfo.vpnAddrs[0]
	var reason string
	switch {
	case err != nil:
		reason = "invalid inner IP packet"
	case !f.authorizesLocal(ip.destination):
		reason = "local certificate does not authorize destination"
	case !hostinfo.authorizes(ip.source):
		reason = "peer certificate does not authorize source"
	case f.inboundPolicy != nil && !f.inboundPolicy(peer, ip.source, ip.destination):
		reason = "inbound policy denied packet"
	default:
		port.deliver(packet)
		return
	}
	port.recordDrop(true, peer, ip, reason, 1)
}

func (f *packetEngine) sendRecvError(endpoint netip.AddrPort, index uint32) {
	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	if _, ok := f.paths.control.Allow(); ok {
		_ = f.outside.WriteTo(b, endpoint)
	}
	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error sent",
			"index", index,
			"udpAddr", endpoint,
		)
	}
}

func (f *packetEngine) handleRecvError(addr netip.AddrPort, h *header.H) {
	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error received",
			"index", h.RemoteIndex,
			"udpAddr", addr,
		)
	}

	hostinfo := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if hostinfo == nil {
		f.l.Debug("Did not find remote index in main hostmap", "remoteIndex", h.RemoteIndex)
		return
	}

	hr := hostinfo.GetRemote()
	if hr.IsValid() && hr != addr {
		f.l.Info("Someone spoofing recv_errors?",
			"addr", addr,
			"hostinfoRemote", hr,
		)
		return
	}

	// RecvError is unauthenticated. Confirm the tunnel before retiring it.
	hostinfo.paths.mu.Lock()
	hostinfo.paths.nextActive = time.Time{}
	hostinfo.paths.demand = time.Now()
	hostinfo.paths.mu.Unlock()
}
