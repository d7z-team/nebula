package nebula

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/quic-go/quic-go"
)

// The next queued packet may establish a fresh path. An actual dial failure
// still discards the backlog for that peer.
var errNoOutboundPath = fmt.Errorf("%w: no usable outbound path", ErrPeerUnavailable)

func (p *IPPort) drain(peer PeerID, q *ipQueue) {
	n := p.node
	for {
		p.mu.Lock()
		if p.queues[peer] != q {
			p.mu.Unlock()
			return
		}
		if len(q.packets) == 0 {
			delete(p.queues, peer)
			p.mu.Unlock()
			return
		}
		b := q.packets[0]
		packetCtx, stop := context.WithCancelCause(n.ctx)
		q.current = ipSubmission{outboundPacket: b, stop: stop}
		q.packets[0] = nil
		q.packets = q.packets[1:]
		p.stats.Queued--
		p.mu.Unlock()
		session, err := n.transmitIP(packetCtx, peer, q)
		p.mu.Lock()
		cause := context.Cause(packetCtx)
		stop(nil)
		q.current = ipSubmission{}
		if err == nil {
			p.stats.SentPackets++
			p.stats.SentBytes += uint64(len(b.data))
		} else {
			if cause != nil {
				err = cause
			}
			p.stats.RejectedOutbound++
			p.stats.LastDrop = err.Error()
			keepQueued := errors.Is(err, errNoOutboundPath) || errors.Is(err, ErrAddressUnauthorized) || errors.Is(err, ErrPacketTooLarge) ||
				session != nil && errors.Is(err, ErrPathPolicy)
			if !keepQueued && cause == nil && p.queues[peer] == q {
				p.stats.RejectedOutbound += uint64(p.discardQueueLocked(peer, err))
			}
		}
		p.mu.Unlock()
		if observe := p.opts.ObserveTransmit; observe != nil {
			result := TransmitResult{Peer: peer, Source: b.source, Destination: b.destination, Err: err}
			if session != nil {
				result.Transport = session.kind
				result.Endpoint = session.remoteEndpoint()
				result.Circuit = slices.Clone(session.path)
			}
			observe(result)
		}
	}
}

// transmitIP keeps the selected end-to-end peer through dialing and shaping.
// It returns the session used for submission, including on a transport error.
func (n *Node) transmitIP(ctx context.Context, peer PeerID, q *ipQueue) (*session, error) {
	packet := q.current.outboundPacket
	s, err := n.outboundSession(peer, q, false)
	if err == errNoOutboundPath {
		cfg := n.policy.Load()
		_, group, _ := cfg.groupRecipients(packet.destination)
		var slots chan struct{}
		if group || cfg.cluster.InAnycastPool(packet.destination) {
			slots = n.sharedAddressDialSlots
		}
		if err := n.connectPeer(ctx, peer, slots); err != nil {
			return nil, err
		}
		s, err = n.outboundSession(peer, q, false)
	}
	if err != nil {
		return s, err
	}
	if _, err := n.shaper.schedule(ctx, PeerID{}, len(packet.data)); err != nil {
		return nil, err
	}
	s, err = n.outboundSession(peer, q, true)
	if err != nil {
		return s, err
	}
	err = s.sendIP(ctx, packet)
	if err != nil {
		// A concurrent withdrawal can also surface as a stream or socket error.
		if reason := s.checkIPSubmission(ctx, packet); reason != nil {
			return s, reason
		}
	}
	return s, err
}

// Only the final selection before submission records the general-purpose path.
func (n *Node) outboundSession(peer PeerID, q *ipQueue, submitting bool) (*session, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.modeLocked(peer) == Blocked {
		return nil, ErrPathPolicy
	}
	cfg, paths := n.policy.Load(), n.peers[peer]
	preferred := n.preferredSessionLocked(paths, false, nil)
	if hold := n.conflicts[peer]; !hold.confirmedAt.IsZero() && (preferred == nil && !hold.selected || !q.bindInstance(hold.keep)) {
		return nil, ErrInstanceConflict
	}
	packet := &q.current
	if preferred == nil {
		if !packet.authorizedBy(n, n.id, peer) {
			return nil, ErrAddressUnauthorized
		}
		return nil, errNoOutboundPath
	}
	if !q.bindInstance(preferred.instance) {
		return nil, ErrInstanceConflict
	}
	s := preferred
	if !packet.authorizedOn(cfg, s.localIdentity, s.remoteIdentity) {
		s = n.preferredSessionLocked(paths, false, &packet.innerPacket)
		if s == nil {
			return nil, ErrAddressUnauthorized
		}
	}
	if len(packet.data) > s.remoteIPLimit {
		return s, ErrPacketTooLarge
	}
	if submitting && s == preferred {
		paths.active = s
	}
	packet.path = s
	return s, nil
}

func (s *session) checkIPSubmission(ctx context.Context, packet *outboundPacket) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.usableLocked(s) {
		if len(s.path) == 0 && !n.modeLocked(s.peer).allowsDirect() || len(s.path) > 0 && !n.circuitAllowedLocked(s.path) {
			return ErrPathPolicy
		}
		if !packet.authorizedBy(n, n.id, s.peer) {
			return ErrAddressUnauthorized
		}
		return errNoOutboundPath
	}
	if !packet.authorizedOn(n.policy.Load(), s.localIdentity, s.remoteIdentity) {
		return ErrAddressUnauthorized
	}
	return nil
}

func (s *session) sendIP(ctx context.Context, packet *outboundPacket) error {
	if s.q != nil {
		if err := s.checkIPSubmission(ctx, packet); err != nil {
			return err
		}
		err := s.q.SendDatagram(packet.data)
		if err == nil {
			return nil
		}
		size, ok := errors.AsType[*quic.DatagramTooLargeError](err)
		if !ok {
			return err
		}
		s.budget.Store(size.MaxDatagramPayloadSize)
		s.overflow.Add(1)
	}
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if s.data == nil {
		openCtx, cancel := context.WithTimeout(ctx, s.n.o.DialTimeout)
		c, err := s.open(openCtx)
		cancel()
		if err != nil {
			return err
		}
		if err = c.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout)); err == nil {
			_, err = c.Write([]byte{opIP})
		}
		if err != nil {
			c.Close()
			return err
		}
		s.data = c
	}
	if err := s.checkIPSubmission(ctx, packet); err != nil {
		return err
	}
	err := s.data.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout))
	if err == nil {
		err = writeFrame(s.data, packet.data)
	}
	if err != nil {
		s.data.Close()
		s.data = nil
	}
	return err
}

func (p *IPPort) revalidateQueues(expiredPeers map[PeerID]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.node
	n.mu.Lock()
	defer n.mu.Unlock()
	for peer, q := range p.queues {
		p.reconcileQueueLocked(peer)
		if p.queues[peer] == nil {
			continue
		}
		if n.modeLocked(peer) == Blocked || expiredPeers[peer] && n.peers[peer] == nil {
			p.stats.RejectedOutbound += uint64(p.discardQueueLocked(peer, ErrPathPolicy))
			p.stats.LastDrop = ErrPathPolicy.Error()
			continue
		}
		unauthorized := func(packet *outboundPacket) bool {
			return !packet.authorizedBy(n, n.id, peer)
		}
		if current := &q.current; current.stop != nil {
			switch {
			case unauthorized(current.outboundPacket):
				current.stop(ErrAddressUnauthorized)
			case current.path != nil && !n.sessionAllowedLocked(current.path):
				current.stop(ErrPathPolicy)
			}
		}
		before := len(q.packets)
		q.packets = slices.DeleteFunc(q.packets, unauthorized)
		dropped := before - len(q.packets)
		p.stats.Queued -= dropped
		p.stats.RejectedOutbound += uint64(dropped)
		if dropped > 0 {
			p.stats.LastDrop = ErrAddressUnauthorized.Error()
		}
	}
}
