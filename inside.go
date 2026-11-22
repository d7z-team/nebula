package nebula

import (
	"errors"
	"io"
	"net/netip"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/noiseutil"
)

var errTunnelCounterExhausted = errors.New("tunnel message counter is exhausted")

// Handshake starts a tunnel handshake with an overlay address. It is a no-op
// when a usable tunnel already exists or a handshake is already in progress.
func (f *packetEngine) Handshake(vpnAddr netip.Addr) {
	f.handshakeManager.GetOrHandshake(vpnAddr.Unmap(), nil)
}

// SendMessageToVpnAddr resolves vpnAddr to a tunnel and sends an encrypted
// Nebula protocol message. It intentionally accepts overlay addresses only;
// unsafe routing is used solely for inner IP packets.
func (f *packetEngine) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte) {
	hostInfo, ready := f.handshakeManager.GetOrHandshake(vpnAddr.Unmap(), func(hh *handshakeHostInfo) {
		hh.cacheControlPacket(f.l, t, st, p)
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
	f.sendTo(t, st, ci, hostinfo, netip.AddrPort{}, p, nb, out)
}

func (f *packetEngine) sendTo(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, remote netip.AddrPort, p, nb, out []byte) (TunnelPath, error) {
	return f.sendEncryptedWithRoute(t, st, ci, hostinfo, remote, nil, nil, p, nb, out)
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
	via.markOutOnly() // The direct path consumes the rebind epoch.
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

// sendVia authenticates an already encrypted Nebula packet for the relay.
func (f *packetEngine) sendVia(via *hostInfo, relay *relay, data, nonce, out []byte, noCopy bool) (TunnelPath, error) {
	toSend, err := f.prepareSendVia(via, relay, data, nonce, out, noCopy)
	if err != nil {
		return TunnelPath{}, err
	}
	path := TunnelPath{Endpoint: via.GetRemote(), Relay: via.vpnAddrs[0]}
	if err := f.outside.WriteTo(toSend, path.Endpoint); err != nil {
		if l, ok := logging.RateLimited(f.l, f.udpRelayTxErrLimiter); ok {
			via.logger(l).Info("failed to write relayed datagram", "error", err)
		}
		return path, err
	}
	return path, nil
}

func (f *packetEngine) sendEncryptedWithRoute(t header.MessageType, st header.MessageSubType, ci *connectionState, hostinfo *hostInfo, remote netip.AddrPort, relayHostInfo *hostInfo, relayRoute *relay, payload, nonce, out []byte) (TunnelPath, error) {
	if ci == nil || ci.eKey == nil {
		return TunnelPath{}, ErrPeerUnavailable
	}
	if !remote.IsValid() {
		remote = hostinfo.GetRemote()
	}
	useRelay := !remote.IsValid()
	need := header.Len + len(payload) + ci.eKey.Overhead()
	if useRelay {
		need += header.Len + ci.eKey.Overhead()
	}
	if cap(out) < need {
		if l, ok := logging.RateLimited(f.l, f.txOversizeLimiter); ok {
			hostinfo.logger(l).Error("dropping oversized outbound packet", "bufferCapacity", cap(out), "required", need)
		}
		return TunnelPath{}, io.ErrShortBuffer
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
		return TunnelPath{}, errTunnelCounterExhausted
	}
	out = header.Encode(out, header.Version, t, st, hostinfo.remoteIndexId, counter)
	if t != header.CloseTunnel && hostinfo.markOut(f.rebindEpoch.Load()) {
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
	}

	var err error
	out, err = ci.eKey.EncryptDanger(out, out, payload, counter, nonce)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if err != nil {
		hostinfo.logger(f.l).Error("failed to encrypt outgoing packet", "error", err, "counter", counter)
		return TunnelPath{}, err
	}

	if remote.IsValid() {
		err := f.outside.WriteTo(out, remote)
		if err != nil {
			if l, ok := logging.RateLimited(f.l, f.udpTxErrLimiter); ok {
				hostinfo.logger(l).Error("failed to write outgoing datagram", "error", err, "remote", remote)
			}
		}
		return TunnelPath{Endpoint: remote}, err
	}
	if relayHostInfo != nil && relayRoute != nil {
		return f.sendVia(relayHostInfo, relayRoute, out, nonce, fullOut[:header.Len+len(out)], true)
	}

	for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
		relayHostInfo, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
		if err != nil {
			hostinfo.relayState.DeleteRelay(relayIP)
			continue
		}
		return f.sendVia(relayHostInfo, relay, out, nonce, fullOut[:header.Len+len(out)], true)
	}
	return TunnelPath{}, ErrPeerUnavailable
}
