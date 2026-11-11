package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/header"
)

// readOutsidePackets processes one received underlay packet. Message payloads
// are decrypted in place, so the caller must not reuse packet until it returns.
func (f *packetEngine) readOutsidePackets(via packetSender, packet []byte, rxc *rxContext) {
	h := rxc.h
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
		f.handleRecvError(via.UdpAddr, h)
		return
	}

	// relay packets are special
	isMessageRelay := (h.Type == header.Message && h.Subtype == header.MessageRelay)

	var hostinfo *hostInfo
	if isMessageRelay {
		hostinfo = f.hostMap.QueryRelayIndex(h.RemoteIndex)
	} else {
		hostinfo = f.hostMap.QueryIndexCached(h.RemoteIndex, rxc.hostmapCache)
	}

	// At this point we should have a valid existing tunnel, verify and send
	// recvError if necessary
	if hostinfo == nil || hostinfo.connectionState == nil {
		if !via.IsRelayed {
			f.maybeSendRecvError(via.UdpAddr, h.RemoteIndex)
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

	// Roam before we respond
	f.handleHostRoaming(hostinfo, via)
	f.connectionManager.recordInbound(hostinfo)

	switch h.Type {
	case header.Message:
		switch h.Subtype {
		case header.MessageNone:
			f.handleOutsideMessagePacket(hostinfo, h.MessageCounter, out, rxc)
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message subtype seen", "from", via, "header", h)
			return
		}

	case header.LightHouse:
		//TODO: assert via is not relayed
		rxc.lhh.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, out, f)

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
			f.send(header.Test, header.TestReply, hostinfo.connectionState, hostinfo, out, rxc.nb, rxc.scratch[:0])
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected test subtype seen", "from", via, "header", h)
			return
		}

	case header.CloseTunnel:
		hostinfo.logger(f.l).Info("Close tunnel received, tearing down.", "from", via)
		f.closeTunnel(hostinfo)

	case header.Control:
		f.relayManager.HandleControlMsg(hostinfo, out, f)

	default:
		hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message type seen", "from", via, "header", h)
	}
}

func (f *packetEngine) handleOutsideRelayPacket(hostinfo *hostInfo, via packetSender, packet []byte, rxc *rxContext) {
	h := rxc.h
	// Successfully validated the thing. Get rid of the relay header and the AEAD tag
	signedPayload := packet[header.Len : len(packet)-hostinfo.connectionState.dKey.Overhead()]
	// Pull the Roaming parts up here, and return in all call paths.
	f.handleHostRoaming(hostinfo, via)
	// Track usage of both the hostInfo and the relay for the received & authenticated packet
	f.connectionManager.recordInbound(hostinfo)
	f.connectionManager.recordRelayUse(h.RemoteIndex)

	relay, ok := hostinfo.relayState.QueryRelayForByIdx(h.RemoteIndex)
	if !ok {
		// The only way this happens is if hostmap has an index to the correct hostInfo, but the hostInfo is missing
		// its internal mapping. This should never happen.
		hostinfo.logger(f.l).Error("hostInfo missing remote relay index", "relayRemoteIndex", h.RemoteIndex)
		return
	}

	switch relay.Type {
	case relayTypeTerminal:
		// If I am the target of this relay, process the unwrapped packet
		// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
		via = packetSender{
			UdpAddr:   via.UdpAddr,
			relayHI:   hostinfo,
			relay:     relay,
			IsRelayed: true,
		}
		f.readOutsidePackets(via, signedPayload, rxc)
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

		// If that relay is established, forward the payload through it.
		if targetRelay.State == relayEstablished {
			switch targetRelay.Type {
			case relayTypeForwarding:
				// Forward this packet through the relay tunnel, rebuilding it in place.
				// Encode overwrites the old outer header, and the new AEAD tag lands where the old one was
				fwdBuf := packet[:0]
				out, err := f.prepareSendVia(targetHI, targetRelay, signedPayload, rxc.nb, fwdBuf, true)
				if err == nil {
					if err := f.outside.WriteTo(out, targetHI.GetRemote()); err != nil {
						targetHI.logger(f.l).Debug("failed to forward relay datagram", "error", err)
					}
				}
			case relayTypeTerminal:
				hostinfo.logger(f.l).Error("Unexpected relay Type of Terminal")
				return
			default:
				if f.l.Enabled(context.Background(), slog.LevelDebug) {
					hostinfo.logger(f.l).Debug("Unexpected targetRelay Type", "from", via, "relayType", targetRelay.Type)
				}
				return
			}
		} else {
			hostinfo.logger(f.l).Info("Unexpected target relay state",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"targetRelayState", targetRelay.State,
			)
			return
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
	f.send(header.CloseTunnel, 0, h.connectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

// sendCloseTunnelWithRoute uses a route captured before local tunnel removal.
// Removal may disestablish the relay maps, but the immutable relay value and
// hostInfo remain safe for this final best-effort protocol notification.
func (f *packetEngine) sendCloseTunnelWithRoute(h *hostInfo, remote netip.AddrPort, relayHostInfo *hostInfo, relayRoute *relay) {
	f.sendEncryptedWithRoute(header.CloseTunnel, 0, h.connectionState, h, remote, relayHostInfo, relayRoute, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

func (f *packetEngine) handleHostRoaming(hostinfo *hostInfo, via packetSender) {
	curRemote := hostinfo.GetRemote()
	if !via.IsRelayed && curRemote != via.UdpAddr {
		if !hostinfo.lastRoam.IsZero() && via.UdpAddr == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < roamingSuppressDuration {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Suppressing roam back to previous remote",
					"suppressDuration", roamingSuppressDuration,
					"udpAddr", curRemote,
					"newAddr", via.UdpAddr,
				)
			}
			return
		}

		hostinfo.logger(f.l).Info("Host roamed to new udp ip/port.",
			"udpAddr", curRemote,
			"newAddr", via.UdpAddr,
		)
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = curRemote
		hostinfo.SetRemote(via.UdpAddr)
	}

}

func (f *packetEngine) handleOutsideMessagePacket(hostinfo *hostInfo, _ uint64, packet []byte, _ *rxContext) {
	inner, err := parseInnerPacket(packet)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping invalid inbound packet", "error", err)
		}
		return
	}
	if err := f.routes.validateInbound(inner, hostinfo); err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping unauthorized inbound packet", "error", err)
		}
		return
	}
	if err := f.netstack.inject(packet); err != nil && f.l.Enabled(context.Background(), slog.LevelDebug) {
		hostinfo.logger(f.l).Debug("failed to inject inbound packet into userspace stack", "error", err)
	}
}

func (f *packetEngine) maybeSendRecvError(endpoint netip.AddrPort, index uint32) {
	f.sendRecvError(endpoint, index)
}

func (f *packetEngine) sendRecvError(endpoint netip.AddrPort, index uint32) {
	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	_ = f.outside.WriteTo(b, endpoint)
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

	f.closeTunnel(hostinfo)
	// We also delete it from pending hostmap to allow for fast reconnect.
	f.handshakeManager.DeleteHostInfo(hostinfo)
}
