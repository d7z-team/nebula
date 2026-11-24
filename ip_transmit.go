package nebula

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/quic-go/quic-go"
)

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
		packetCtx, stop := context.WithCancel(n.ctx)
		q.current, q.stopCurrent = b, stop
		q.packets[0] = nil
		q.packets = q.packets[1:]
		p.stats.Queued--
		p.mu.Unlock()
		session, err := n.transmitIP(packetCtx, peer, b)
		p.mu.Lock()
		interrupted := packetCtx.Err() != nil
		stop()
		q.current, q.stopCurrent = nil, nil
		if err == nil {
			p.stats.SentPackets++
			p.stats.SentBytes += uint64(len(b.data))
		} else {
			p.stats.RejectedOutbound++
			p.stats.LastDrop = err.Error()
			if !errors.Is(err, ErrAddressUnauthorized) && !errors.Is(err, ErrPacketTooLarge) && !interrupted && p.queues[peer] == q {
				p.stats.RejectedOutbound += uint64(p.discardQueueLocked(peer))
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
func (n *Node) transmitIP(ctx context.Context, peer PeerID, packet *outboundPacket) (*session, error) {
	s, err := n.outboundSession(peer, packet, false)
	if err != nil {
		return s, err
	}
	if s == nil {
		cfg := n.policy.Load()
		_, group, _ := cfg.groupRecipients(n.id, packet.destination)
		var slots chan struct{}
		if group || cfg.cluster.InAnycastPool(packet.destination) {
			slots = n.sharedAddressDialSlots
		}
		if err := n.connectPeer(ctx, peer, slots); err != nil {
			return nil, err
		}
		s, err = n.outboundSession(peer, packet, false)
		if err != nil {
			return s, err
		}
		if s == nil {
			return nil, ErrAddressUnauthorized
		}
	}
	if err := n.shape(ctx, len(packet.data)); err != nil {
		return nil, err
	}
	s, err = n.outboundSession(peer, packet, true)
	if err != nil {
		return s, err
	}
	if s == nil {
		return nil, ErrAddressUnauthorized
	}
	return s, s.sendIP(ctx, packet)
}

// outboundSession returns nil, nil when an authorized packet needs a connection.
// Only the final selection before submission records the general-purpose path.
func (n *Node) outboundSession(peer PeerID, packet *outboundPacket, submitting bool) (*session, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.modeLocked(peer) == Blocked {
		return nil, ErrPathPolicy
	}
	cfg, paths := n.policy.Load(), n.peers[peer]
	preferred := n.preferredSessionLocked(paths, false, nil)
	if preferred == nil {
		if !packet.authorizedBy(cfg, n.id, peer) {
			return nil, ErrAddressUnauthorized
		}
		return nil, nil
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
	return s, nil
}

func (s *session) sendIP(ctx context.Context, packet *outboundPacket) error {
	authorize := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := s.n
		n.mu.Lock()
		defer n.mu.Unlock()
		if !n.usableLocked(s) || !packet.authorizedOn(n.policy.Load(), s.localIdentity, s.remoteIdentity) {
			return ErrAddressUnauthorized
		}
		return nil
	}
	if s.q != nil {
		if err := authorize(); err != nil {
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
		c.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout))
		if _, err = c.Write([]byte{opIP}); err != nil {
			c.Close()
			return err
		}
		s.data = c
	}
	if err := authorize(); err != nil {
		return err
	}
	s.data.SetWriteDeadline(time.Now().Add(s.n.o.DialTimeout))
	if err := writeFrame(s.data, packet.data); err != nil {
		s.data.Close()
		s.data = nil
		return err
	}
	return nil
}

func (p *IPPort) revalidateQueues(disconnected map[PeerID]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.node
	n.mu.Lock()
	defer n.mu.Unlock()
	cfg := n.policy.Load()
	for peer, q := range p.queues {
		if disconnected[peer] || n.modeLocked(peer) == Blocked {
			p.stats.RejectedOutbound += uint64(p.discardQueueLocked(peer))
			p.stats.LastDrop = ErrPathPolicy.Error()
			continue
		}
		unauthorized := func(packet *outboundPacket) bool {
			return !packet.authorizedBy(cfg, n.id, peer)
		}
		if q.current != nil && unauthorized(q.current) {
			q.stopCurrent()
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
