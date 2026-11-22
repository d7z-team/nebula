package nebula

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/slackhq/nebula/header"
)

const (
	// MaxIPPacketSize is the largest complete IP frame carried by a Nebula NIC.
	MaxIPPacketSize    = mtu
	maxQueuedIPPackets = 512
)

var (
	ErrPortInUse           = errors.New("node already has an IP port")
	ErrPortClosed          = errors.New("IP port is closed")
	ErrQueueFull           = errors.New("IP transmit queue is full")
	ErrMissingGateway      = errors.New("off-overlay destination requires an overlay gateway")
	ErrAddressNotCertified = errors.New("certificate does not authorize inner IP address")
)

// InboundPolicy may narrow the certificate checks on authenticated IP packets.
// peer is the first overlay address in the authenticated peer's certificate.
// It runs on the receive worker and must return promptly.
type InboundPolicy func(peer, source, destination netip.Addr) bool

// IPPort connects one L3 device to a Node. Each frame is a complete IP packet.
type IPPort struct {
	node    *Node
	ctx     context.Context
	cancel  context.CancelFunc
	deliver func([]byte)
	mu      sync.Mutex
	queues  map[netip.Addr]*peerQueue
	queued  int
	workers int
	diagMu  sync.Mutex
	stats   PortStats
}

type queuedIP struct {
	innerPacket
	data []byte
}

type peerQueue struct {
	packets []queuedIP
	cancel  context.CancelFunc
}

// OpenIPPort reserves the node's sole data port. deliver borrows a packet only
// for the duration of the call. It must return promptly. Start enables traffic.
func (n *Node) OpenIPPort(deliver func([]byte)) (*IPPort, error) {
	if deliver == nil {
		return nil, errors.New("IP receiver is required")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == NodeStateClosed || n.ctx.Err() != nil {
		return nil, ErrNodeClosed
	}
	if n.engine.port.Load() != nil {
		return nil, ErrPortInUse
	}
	ctx, cancel := context.WithCancel(n.ctx)
	p := &IPPort{node: n, ctx: ctx, cancel: cancel, deliver: deliver, queues: make(map[netip.Addr]*peerQueue)}
	n.engine.port.Store(p)
	return p, nil
}

// Close releases this port and drops queued frames. A frame already being
// transmitted or delivered may finish. The outer transport belongs to Node.
func (p *IPPort) Close() {
	p.mu.Lock()
	p.cancel()
	for _, q := range p.queues {
		q.packets = nil
	}
	clear(p.queues)
	p.queued = 0
	p.node.engine.port.CompareAndSwap(p, nil)
	p.mu.Unlock()
}

// ClearPending discards packets still queued for this overlay next hop.
// An in-flight datagram and the shared Nebula handshake are independent.
func (p *IPPort) ClearPending(peer netip.Addr) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	peer = peer.Unmap()
	q := p.queues[peer]
	if q == nil {
		return 0
	}
	n := len(q.packets)
	delete(p.queues, peer)
	q.packets = nil
	q.cancel()
	p.queued -= n
	return n
}

// PacketDrop describes the last rejected IP frame. Address fields may be empty
// when the packet could not be parsed.
type PacketDrop struct {
	Inbound                   bool
	Peer, Source, Destination netip.Addr
	Reason                    string
}

// PortStats reports queue depth and observed IP admission and transmit errors.
// Explicit ClearPending and Close are excluded from the rejection counts.
type PortStats struct {
	Queued                            int
	RejectedInbound, RejectedOutbound uint64
	LastDrop                          PacketDrop
}

func (p *IPPort) recordDrop(inbound bool, peer netip.Addr, ip innerPacket, reason string, count int) {
	p.diagMu.Lock()
	defer p.diagMu.Unlock()
	if inbound {
		p.stats.RejectedInbound += uint64(count)
	} else {
		p.stats.RejectedOutbound += uint64(count)
	}
	p.stats.LastDrop = PacketDrop{Inbound: inbound, Peer: peer, Source: ip.source, Destination: ip.destination, Reason: reason}
}

func (p *IPPort) Stats() PortStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.diagMu.Lock()
	defer p.diagMu.Unlock()
	stats := p.stats
	stats.Queued = p.queued
	return stats
}

// WriteIP accepts a copy into a bounded queue. An empty next hop selects a
// directly connected overlay destination. The authenticated peer is checked
// again when the queue is serviced, including after a pending handshake.
func (p *IPPort) WriteIP(nextHop netip.Addr, packet []byte) (err error) {
	var ip innerPacket
	peer := nextHop.Unmap()
	defer func() {
		if err != nil {
			p.recordDrop(false, peer, ip, err.Error(), 1)
		}
	}()
	if err := p.node.requireStarted(); err != nil {
		return err
	}
	if p.ctx.Err() != nil {
		return ErrPortClosed
	}
	ip, err = parseInnerPacket(packet)
	if err != nil {
		return err
	}
	f := p.node.engine
	if !f.authorizesLocal(ip.source) {
		return fmt.Errorf("%w: source %s", ErrAddressNotCertified, ip.source)
	}
	if !peer.IsValid() {
		if !f.myVpnNetworksTable.Contains(ip.destination) {
			return ErrMissingGateway
		}
		peer = ip.destination
	}
	if err := p.node.validatePeerAddress(peer); err != nil {
		return err
	}
	if h := f.hostMap.QueryVpnAddr(peer); h != nil && !h.authorizes(ip.destination) {
		return fmt.Errorf("%w: destination %s via %s", ErrAddressNotCertified, ip.destination, peer)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return ErrPortClosed
	}
	q := p.queues[peer]
	if p.queued >= maxQueuedIPPackets || (q != nil && len(q.packets) >= maxCachedPackets) {
		return ErrQueueFull
	}
	if q == nil {
		if p.workers >= maxQueuedIPPackets {
			return ErrQueueFull
		}
		ctx, cancel := context.WithCancel(p.ctx)
		q = &peerQueue{cancel: cancel}
		p.queues[peer] = q
		p.workers++
		p.node.workers.Go(func() { p.drainPeer(ctx, peer, q) })
	}
	q.packets = append(q.packets, queuedIP{ip, slices.Clone(packet)})
	p.queued++
	return nil
}

func (p *IPPort) drainPeer(ctx context.Context, peer netip.Addr, q *peerQueue) {
	defer q.cancel()
	f := p.node.engine
	var connectErr error
	nonce := make([]byte, 12)
	var out []byte
	for {
		p.mu.Lock()
		if p.queues[peer] != q || len(q.packets) == 0 || ctx.Err() != nil || connectErr != nil {
			if p.queues[peer] == q {
				p.queued -= len(q.packets)
				delete(p.queues, peer)
				if connectErr != nil && len(q.packets) != 0 && ctx.Err() == nil {
					p.recordDrop(false, peer, q.packets[0].innerPacket, connectErr.Error(), len(q.packets))
				}
			}
			p.workers--
			p.mu.Unlock()
			if connectErr != nil && ctx.Err() == nil {
				f.l.Debug("IP queue handshake failed", "peer", peer, "error", connectErr)
			}
			return
		}
		h := f.hostMap.QueryVpnAddr(peer)
		var route tunnelRoute
		if h != nil {
			route = f.currentRoute(h)
		}
		if !route.Endpoint.IsValid() {
			p.mu.Unlock()
			connectErr = p.node.ConnectPeer(ctx, peer)
			continue
		}
		packet := q.packets[0]
		q.packets[0] = queuedIP{}
		q.packets = q.packets[1:]
		p.queued--
		p.mu.Unlock()

		ip := packet.innerPacket
		if !h.authorizes(ip.destination) {
			p.recordDrop(false, peer, ip, "peer certificate does not authorize destination", 1)
			continue
		}
		if cap(out) < len(packet.data)+header.MaxOverhead {
			out = make([]byte, 0, len(packet.data)+header.MaxOverhead)
		}
		path, err := f.sendOnRoute(header.Message, header.MessageNone, h, route, packet.data, nonce, out)
		if err == errWritePolicy || (path == (TunnelPath{}) && errors.Is(err, ErrPeerUnavailable)) {
			// No datagram was submitted. Keep this frame ahead of later packets
			// if the original queue is still attached and has room.
			p.mu.Lock()
			if p.queues[peer] == q && len(q.packets) < maxCachedPackets && p.queued < maxQueuedIPPackets {
				q.packets = append(q.packets, queuedIP{})
				copy(q.packets[1:], q.packets[:len(q.packets)-1])
				q.packets[0] = packet
				p.queued++
				p.mu.Unlock()
				continue
			}
			p.mu.Unlock()
		}
		if err != nil {
			p.recordDrop(false, peer, ip, err.Error(), 1)
		} else if last := h.lastDataPath.Load(); last == nil || *last != path {
			h.lastDataPath.Store(&path)
		}
	}
}
