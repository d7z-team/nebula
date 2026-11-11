package nebula

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/noiseutil"
)

var errTunnelCounterExhausted = errors.New("tunnel message counter is exhausted")

func (f *packetEngine) consumeInsidePacket(packet, nonce []byte) {
	p, err := parseInnerPacket(packet)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping invalid outbound packet", "error", err)
		}
		return
	}

	via, ok := f.routes.resolve(p.destination)
	if !ok {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping outbound packet without a route", "destination", p.destination)
		}
		return
	}

	hostinfo, ready := f.handshakeManager.GetOrHandshake(via, func(hh *handshakeHostInfo) {
		hh.cachePacket(f.l, header.Message, header.MessageNone, packet, f.sendMessageNow)
	})
	if hostinfo == nil || !ready {
		return
	}
	if err := f.routes.validateOutbound(p, hostinfo); err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping unauthorized outbound packet", "error", err)
		}
		return
	}

	f.sendEncrypted(header.Message, header.MessageNone, hostinfo.connectionState, hostinfo, netip.AddrPort{}, packet, nonce, make([]byte, 0, len(packet)+header.MaxOverhead))
}

// Handshake starts a tunnel handshake with an overlay address. It is a no-op
// when a usable tunnel already exists or a handshake is already in progress.
func (f *packetEngine) Handshake(vpnAddr netip.Addr) {
	f.handshakeManager.GetOrHandshake(vpnAddr.Unmap(), nil)
}

func (f *packetEngine) sendMessageNow(t header.MessageType, st header.MessageSubType, hostinfo *hostInfo, packet, nonce, out []byte) {
	if t == header.Message {
		p, err := parseInnerPacket(packet)
		if err != nil || f.routes.validateOutbound(p, hostinfo) != nil {
			return
		}
	}
	f.sendEncrypted(t, st, hostinfo.connectionState, hostinfo, netip.AddrPort{}, packet, nonce, out)
}

// SendMessageToVpnAddr resolves vpnAddr to a tunnel and sends an encrypted
// Nebula protocol message. It intentionally accepts overlay addresses only;
// unsafe routing is used solely for inner IP packets.
func (f *packetEngine) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte) {
	hostInfo, ready := f.handshakeManager.GetOrHandshake(vpnAddr.Unmap(), func(hh *handshakeHostInfo) {
		hh.cachePacket(f.l, t, st, p, f.SendMessageToHostInfo)
	})
	if hostInfo == nil || !ready {
		return
	}
	f.SendMessageToHostInfo(t, st, hostInfo, p, nb, out)
}

func (f *packetEngine) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hi *hostInfo, p, nb, out []byte) {
	f.send(t, st, hi.connectionState, hi, p, nb, out)
}

func (f *packetEngine) send(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, p, nb, out []byte) {
	f.sendEncrypted(t, st, ci, hostinfo, netip.AddrPort{}, p, nb, out)
}

func (f *packetEngine) sendTo(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, remote netip.AddrPort, p, nb, out []byte) {
	f.sendEncrypted(t, st, ci, hostinfo, remote, p, nb, out)
}

func (f *packetEngine) dropExhausted(hostinfo *hostInfo, counter uint64, message string) {
	if counter == rejectAfterMessages {
		hostinfo.logger(f.l).Error(message)
	}
}

func (f *packetEngine) prepareSendVia(via *hostInfo, relay *relay, authenticatedData, nonce, out []byte, noCopy bool) ([]byte, error) {
	if noiseutil.EncryptLockNeeded {
		via.connectionState.writeLock.Lock()
	}
	counter, ok := via.connectionState.NextMessageCounter()
	if !ok {
		if noiseutil.EncryptLockNeeded {
			via.connectionState.writeLock.Unlock()
		}
		f.dropExhausted(via, counter, "dropping outbound relay packet: tunnel message counter is exhausted")
		return nil, errTunnelCounterExhausted
	}

	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, relay.RemoteIndex, counter)
	f.connectionManager.recordOutboundNoRebind(via)
	if len(out)+len(authenticatedData)+via.connectionState.eKey.Overhead() > cap(out) {
		if noiseutil.EncryptLockNeeded {
			via.connectionState.writeLock.Unlock()
		}
		return nil, io.ErrShortBuffer
	}
	offset := len(out)
	out = out[:offset+len(authenticatedData)]
	if !noCopy {
		copy(out[offset:], authenticatedData)
	}

	var err error
	out, err = via.connectionState.eKey.EncryptDanger(out, out, nil, counter, nonce)
	if noiseutil.EncryptLockNeeded {
		via.connectionState.writeLock.Unlock()
	}
	if err != nil {
		return nil, err
	}
	f.connectionManager.recordRelayUse(relay.LocalIndex)
	return out, nil
}

// SendVia authenticates an already Nebula-framed packet through an established
// relay tunnel. End-to-end encryption belongs to the inner packet.
func (f *packetEngine) SendVia(via *hostInfo, relay *relay, authenticatedData, nonce, out []byte, noCopy bool) {
	toSend, err := f.prepareSendVia(via, relay, authenticatedData, nonce, out, noCopy)
	if err != nil {
		return
	}
	if err := f.outside.WriteTo(toSend, via.GetRemote()); err != nil {
		if l, ok := logging.RateLimited(f.l, f.udpRelayTxErrLimiter); ok {
			via.logger(l).Info("failed to write relayed datagram", "error", err)
		}
	}
}

func (f *packetEngine) sendEncrypted(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, remote netip.AddrPort, payload, nonce, out []byte) {
	f.sendEncryptedWithRoute(t, st, ci, hostinfo, remote, nil, nil, payload, nonce, out)
}

func (f *packetEngine) sendEncryptedWithRoute(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, remote netip.AddrPort, relayHostInfo *hostInfo, relayRoute *relay, payload, nonce, out []byte) {
	if ci == nil || ci.eKey == nil {
		return
	}
	useRelay := !remote.IsValid() && !hostinfo.GetRemote().IsValid()
	need := header.Len + len(payload) + ci.eKey.Overhead()
	if useRelay {
		need += header.Len + ci.eKey.Overhead()
	}
	if cap(out) < need {
		if l, ok := logging.RateLimited(f.l, f.txOversizeLimiter); ok {
			hostinfo.logger(l).Error("dropping oversized outbound packet", "bufferCapacity", cap(out), "required", need)
		}
		return
	}

	fullOut := out[:0]
	if useRelay {
		out = fullOut[header.Len:header.Len]
	} else {
		out = fullOut
	}
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Lock()
	}
	counter, ok := ci.NextMessageCounter()
	if !ok {
		if noiseutil.EncryptLockNeeded {
			ci.writeLock.Unlock()
		}
		f.dropExhausted(hostinfo, counter, "dropping outbound packet: tunnel message counter is exhausted")
		return
	}
	out = header.Encode(out, header.Version, t, st, hostinfo.remoteIndexId, counter)
	if t != header.CloseTunnel && f.connectionManager.recordOutbound(hostinfo) {
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
	}

	var err error
	out, err = ci.eKey.EncryptDanger(out, out, payload, counter, nonce)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if err != nil {
		hostinfo.logger(f.l).Error("failed to encrypt outgoing packet", "error", err, "counter", counter)
		return
	}

	if !remote.IsValid() {
		remote = hostinfo.GetRemote()
	}
	if remote.IsValid() {
		if err := f.outside.WriteTo(out, remote); err != nil {
			if l, ok := logging.RateLimited(f.l, f.udpTxErrLimiter); ok {
				hostinfo.logger(l).Error("failed to write outgoing datagram", "error", err, "remote", remote)
			}
		}
		return
	}
	if relayHostInfo != nil && relayRoute != nil {
		f.SendVia(relayHostInfo, relayRoute, out, nonce, fullOut[:header.Len+len(out)], true)
		return
	}

	for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
		relayHostInfo, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
		if err != nil {
			hostinfo.relayState.DeleteRelay(relayIP)
			continue
		}
		f.SendVia(relayHostInfo, relay, out, nonce, fullOut[:header.Len+len(out)], true)
		return
	}
}
