package nebula

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"code.d7z.net/d7z-team/nebula/pki"
)

const MaxIPPacketSize = 65535

type PortStats struct {
	ReceivedPackets, ReceivedBytes    uint64
	SentPackets, SentBytes            uint64
	RejectedInbound, RejectedOutbound uint64
	Queued                            int
	LastDrop                          string
}

type ipQueue struct {
	packets     [][]byte
	current     []byte
	stopCurrent context.CancelFunc
}

type IPPort struct {
	node    *Node
	deliver func([]byte)
	mu      sync.Mutex
	closed  bool
	queues  map[PeerID]*ipQueue
	stats   PortStats
}

func (n *Node) OpenIPPort(deliver func([]byte)) (*IPPort, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == closed {
		return nil, ErrNodeClosed
	}
	if n.port != nil || deliver == nil {
		return nil, errors.New("IP receiver already attached or nil")
	}
	p := &IPPort{node: n, deliver: deliver, queues: map[PeerID]*ipQueue{}}
	n.port = p
	return p, nil
}

func (p *IPPort) Close() {
	p.mu.Lock()
	p.closed = true
	for peer := range p.queues {
		p.discardQueueLocked(peer)
	}
	p.mu.Unlock()
	n := p.node
	n.mu.Lock()
	if n.port == p {
		n.port = nil
	}
	n.mu.Unlock()
}

// ClearPending discards the peer's backlog and cancels a send waiting for a path or bandwidth.
// The count includes only packets that were still waiting in the queue.
func (p *IPPort) ClearPending(address netip.Addr) int {
	peer := p.node.policy.Load().owners[address]
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discardQueueLocked(peer)
}

func (p *IPPort) discardQueueLocked(peer PeerID) int {
	q := p.queues[peer]
	if q == nil {
		return 0
	}
	if q.stopCurrent != nil {
		q.stopCurrent()
	}
	delete(p.queues, peer)
	count := len(q.packets)
	q.packets = nil
	p.stats.Queued -= count
	return count
}

func (p *IPPort) Stats() PortStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

func (ip innerPacket) authorizedBy(cfg *topologyView, from, to PeerID) bool {
	return cfg.authorizes(from, ip.source) && cfg.authorizes(to, ip.destination)
}

func (ip innerPacket) authorizedOn(cfg *topologyView, from, to pki.Identity) bool {
	return ip.authorizedBy(cfg, from.ID, to.ID) && from.AllowsIP(ip.source) && to.AllowsIP(ip.destination)
}

// WriteIP queues a copy of a complete IP packet. A zero peer selects the member
// that owns the destination address. For a downstream subnet, pass its gateway.
func (p *IPPort) WriteIP(via netip.Addr, b []byte) error {
	n := p.node
	ip, err := parseInnerPacket(b)
	if err != nil || len(b) > n.o.MaxIPSize {
		return ErrInvalidPacketAddress
	}
	cfg := n.policy.Load()
	if !n.memberOf(cfg) {
		return ErrPathPolicy
	}
	if !via.IsValid() {
		via = ip.destination
	}
	peer := cfg.owners[via]
	if peer == (PeerID{}) {
		return ErrMissingGateway
	}
	if !ip.authorizedBy(cfg, n.id, peer) {
		return ErrAddressUnauthorized
	}
	n.mu.Lock()
	state, mode := n.state, n.modeLocked(peer)
	if !n.ready(cfg) && n.selectSessionLocked(peer, false) == nil {
		mode = Blocked
	}
	n.mu.Unlock()
	if state != running {
		return ErrNodeNotStarted
	}
	if mode == Blocked {
		return ErrPathPolicy
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrPortClosed
	}
	q := p.queues[peer]
	if p.stats.Queued >= 512 || q != nil && len(q.packets) >= 64 {
		p.stats.RejectedOutbound++
		return ErrQueueFull
	}
	if q == nil {
		q = &ipQueue{}
		p.queues[peer] = q
		if !n.task(func() { p.drain(peer, q) }) {
			delete(p.queues, peer)
			return ErrNodeClosed
		}
	}
	q.packets = append(q.packets, slices.Clone(b))
	p.stats.Queued++
	return nil
}

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
		err := n.connectPeer(packetCtx, peer)
		if err == nil {
			err = n.shape(packetCtx, len(b))
		}
		if err == nil {
			ip, _ := parseInnerPacket(b)
			n.mu.Lock()
			cfg := n.policy.Load()
			var s *session
			if n.memberOf(cfg) && ip.authorizedBy(cfg, n.id, peer) {
				s = n.preferredSessionLocked(n.peers[peer], false, &ip)
			}
			n.mu.Unlock()
			if s == nil || packetCtx.Err() != nil {
				err = ErrAddressUnauthorized
			} else {
				err = s.sendIP(b)
			}
		}
		p.mu.Lock()
		interrupted := packetCtx.Err() != nil
		stop()
		q.current, q.stopCurrent = nil, nil
		if err == nil {
			p.stats.SentPackets++
			p.stats.SentBytes += uint64(len(b))
		} else {
			p.stats.RejectedOutbound++
			p.stats.LastDrop = err.Error()
			if !errors.Is(err, ErrAddressUnauthorized) && !interrupted && p.queues[peer] == q {
				p.stats.RejectedOutbound += uint64(p.discardQueueLocked(peer))
			}
		}
		p.mu.Unlock()
	}
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
		unauthorized := func(b []byte) bool {
			ip, err := parseInnerPacket(b)
			return err != nil || !ip.authorizedBy(cfg, n.id, peer)
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

func (n *Node) receiveIP(s *session, b []byte) {
	ip, err := parseInnerPacket(b)
	n.mu.Lock()
	port := n.port
	cfg := n.policy.Load()
	if err == nil && (len(b) > n.o.MaxIPSize || !n.usableLocked(s) || !ip.authorizedOn(cfg, s.remoteIdentity, s.localIdentity)) {
		err = ErrAddressUnauthorized
	}
	n.mu.Unlock()
	if port == nil {
		return
	}
	if err == nil && n.o.InboundPolicy != nil {
		if !n.o.InboundPolicy(s.peer, ip.source, ip.destination) {
			err = ErrPathPolicy
		} else {
			// A host callback may revalidate the node before returning.
			n.mu.Lock()
			if current := n.policy.Load(); !n.usableLocked(s) || current != cfg && !ip.authorizedOn(current, s.remoteIdentity, s.localIdentity) {
				err = ErrAddressUnauthorized
			}
			n.mu.Unlock()
		}
	}
	port.mu.Lock()
	if port.closed {
		port.mu.Unlock()
		return
	}
	if err != nil {
		port.stats.RejectedInbound++
		port.stats.LastDrop = err.Error()
		port.mu.Unlock()
		return
	}
	port.stats.ReceivedPackets++
	port.stats.ReceivedBytes += uint64(len(b))
	port.mu.Unlock()
	port.deliver(b)
}
