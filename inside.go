package nebula

import (
	"errors"
	"io"
	"net/netip"
	"slices"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/noiseutil"
)

var errTunnelCounterExhausted = errors.New("tunnel message counter is exhausted")

// SendMessageToVpnAddr resolves vpnAddr to a tunnel and sends an encrypted
// Nebula protocol message. It intentionally accepts overlay addresses only;
// unsafe routing is used solely for inner IP packets.
func (f *packetEngine) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte) {
	hostInfo, ready := f.handshakeManager.GetOrHandshake(vpnAddr.Unmap(), func(hh *handshakeHostInfo) {
		if len(hh.controlQueue) >= f.handshakeManager.config.ControlQueueSize {
			hh.hostinfo.logger(f.l).Debug("handshake control queue full")
			return
		}
		hh.controlQueue = append(hh.controlQueue, queuedControlPacket{t, st, slices.Clone(p)})
	})
	if hostInfo == nil || !ready {
		return
	}
	f.SendMessageToHostInfo(t, st, hostInfo, p, nb, out)
}

func (f *packetEngine) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hi *hostInfo, p, nb, out []byte) {
	f.sendOnRoute(t, st, hi, f.currentRoute(hi), p, nb, out)
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

	return out, nil
}

// sendVia authenticates an already encrypted Nebula packet for the relay.
func (f *packetEngine) sendVia(end *hostInfo, path tunnelRoute, data, nonce, out []byte, noCopy, control bool) (TunnelPath, error) {
	if !f.routeLive(end, path) {
		return TunnelPath{}, ErrPeerUnavailable
	}
	entry, ok := path.leg.relayState.mappingByIndex(path.local)
	if !ok || entry.RemoteIndex != path.remote || entry.State != relayEstablished {
		return TunnelPath{}, ErrPeerUnavailable
	}
	wire, err := f.prepareSendVia(path.leg, entry, data, nonce, out, noCopy)
	if err == nil {
		err = f.writePath(end, path, wire, control, nil)
	}
	if err == nil && !control {
		path.leg.markOutOnly()
		f.connectionManager.recordRelayUse(path.local)
	}
	return path.TunnelPath, err
}

func (f *packetEngine) sendOnRoute(t header.MessageType, st header.MessageSubType, hostinfo *hostInfo, path tunnelRoute, payload, nonce, out []byte) (TunnelPath, error) {
	ci := hostinfo.connectionState
	if !path.Endpoint.IsValid() {
		return TunnelPath{}, ErrPeerUnavailable
	}
	if ci == nil || ci.eKey == nil {
		return TunnelPath{}, ErrPeerUnavailable
	}
	useRelay := path.leg != nil
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
	if t != header.Test && t != header.CloseTunnel && hostinfo.markOut(f.rebindEpoch.Load()) {
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

	if useRelay {
		return f.sendVia(hostinfo, path, out, nonce, fullOut[:header.Len+len(out)], true, t != header.Message)
	}
	err = f.writePath(hostinfo, path, out, t != header.Message, nil)
	if err != nil && !errors.Is(err, errPathBudget) {
		if l, ok := logging.RateLimited(f.l, f.txErrLimiter); ok {
			hostinfo.logger(l).Debug("path write failed", "path", path.TunnelPath, "error", err)
		}
	}
	return path.TunnelPath, err
}
