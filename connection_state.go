package nebula

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
)

const (
	replayWindowSize = 8192

	// rehandshakeAfterMessages rolls keys inside the AES-GCM data-volume margin (~2^-36 advantage at 64KB frames).
	rehandshakeAfterMessages = uint64(1) << 34

	// rejectAfterMessages is the nonce ceiling enforced by noiseutil; a tunnel here is deleted locally, not notified.
	rejectAfterMessages = noiseutil.RejectAfterMessages
)

// rehandshakeAfterMessages must stay below rejectAfterMessages so tunnels roll before the hard send stop.
const _ = rejectAfterMessages - rehandshakeAfterMessages

type connectionState struct {
	eKey           noiseutil.CipherState
	dKey           noiseutil.CipherState
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *replayWindowBits
	decryptLock    sync.Mutex
	writeLock      sync.Mutex
}

// newConnectionStateFromResult builds a fully-populated connectionState from a
// completed handshake.Result. It seeds messageCounter and the replay window so
// that the post-handshake message indices already used on the wire don't count
// as missed traffic in the data plane.
func newConnectionStateFromResult(r *handshake.Result) (*connectionState, error) {
	// Refuse a MessageIndex too big for the replay window: it can only be a bug, and would spin the seed loop below.
	if r.MessageIndex >= replayWindowSize {
		return nil, fmt.Errorf("handshake message index %d exceeds replay window", r.MessageIndex)
	}

	ci := &connectionState{
		myCert:    r.MyCert,
		initiator: r.Initiator,
		peerCert:  r.RemoteCert,
		eKey:      noiseutil.NewCipherState(r.EKey, r.Cipher),
		dKey:      noiseutil.NewCipherState(r.DKey, r.Cipher),
		window:    newReplayWindow(replayWindowSize),
	}
	ci.messageCounter.Add(r.MessageIndex)
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	return ci, nil
}

// NextMessageCounter reserves the next 1-based counter; rejectAfterMessages is the first we refuse, pinned to not wrap.
func (cs *connectionState) NextMessageCounter() (uint64, bool) {
	c := cs.messageCounter.Add(1)
	if c >= rejectAfterMessages {
		cs.messageCounter.Store(rejectAfterMessages)
		return c, false
	}
	return c, true
}

func (cs *connectionState) Curve() cert.Curve {
	return cs.myCert.Curve()
}

func (cs *connectionState) Decrypt(l *slog.Logger, messageCounter uint64, packet []byte, nb []byte) ([]byte, error) {
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return nil, errAlreadySeen
	}

	out, err := cs.dKey.DecryptDanger(packet[header.Len:header.Len], packet[:header.Len], packet[header.Len:], messageCounter, nb)
	if err != nil {
		return nil, err
	}

	cs.decryptLock.Lock()
	result = cs.window.Update(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return nil, errAlreadySeen
	}
	return out, nil
}

func (cs *connectionState) VerifyRelay(l *slog.Logger, messageCounter uint64, packet []byte, nb []byte) error {
	cs.decryptLock.Lock()
	result := cs.window.Check(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return errAlreadySeen
	}

	// The entire body is sent as AD, not encrypted.
	// The packet consists of a 16-byte parsed Nebula header, Associated Data-protected payload, and a trailing 16-byte AEAD signature value.
	// The packet is guaranteed to be at least 16 bytes at this point, b/c it got past the h.Parse() call above. If it's
	// otherwise malformed (meaning, there is no trailing 16 byte AEAD value), then this will result in at worst a 0-length slice
	// which will gracefully fail in the DecryptDanger call.
	signedPayload := packet[:len(packet)-cs.dKey.Overhead()]
	signatureValue := packet[len(packet)-cs.dKey.Overhead():]
	_, err := cs.dKey.DecryptDanger(nil, signedPayload, signatureValue, messageCounter, nb)
	if err != nil {
		return err
	}

	cs.decryptLock.Lock()
	result = cs.window.Update(l, messageCounter)
	cs.decryptLock.Unlock()
	if !result {
		return errAlreadySeen
	}
	return nil
}
