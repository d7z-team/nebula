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

// MaxIPPacketSize is the largest complete IP frame carried by a Nebula NIC.
const MaxIPPacketSize = mtu

// IPPortOptions bounds queued IP packets for both OpenIPPort and gVisor endpoints.
type IPPortOptions struct {
	QueueSize        int // Maximum across all next hops. Default 512.
	PerPeerQueueSize int // Maximum per next hop. Default 100.
}

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

	queueMu sync.Mutex
	queues  map[netip.Addr]*peerQueue
	queued  int
	workers int

	statsMu sync.Mutex
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
	p.queueMu.Lock()
	p.cancel()
	for _, q := range p.queues {
		q.packets = nil
	}
	clear(p.queues)
	p.queued = 0
	p.node.engine.port.CompareAndSwap(p, nil)
	p.queueMu.Unlock()
}

// ClearPending discards packets still queued for this overlay next hop.
// An in-flight datagram and the shared Nebula handshake are independent.
func (p *IPPort) ClearPending(peer netip.Addr) int {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
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

// PortStats reports queue depth and cumulative traffic for one IP port.
// Sent counts successful transport submissions. Received counts delivery to
// the port callback. Byte counts include the complete inner IP packet.
// Explicit ClearPending and Close are excluded from the rejection counts.
type PortStats struct {
	Queued                            int
	SentPackets, SentBytes            uint64
	ReceivedPackets, ReceivedBytes    uint64
	RejectedInbound, RejectedOutbound uint64
	LastDrop                          PacketDrop
}

func (p *IPPort) recordDrop(inbound bool, peer netip.Addr, ip innerPacket, reason string, count int) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if inbound {
		p.stats.RejectedInbound += uint64(count)
	} else {
		p.stats.RejectedOutbound += uint64(count)
	}
	p.stats.LastDrop = PacketDrop{Inbound: inbound, Peer: peer, Source: ip.source, Destination: ip.destination, Reason: reason}
}

// Stats returns a snapshot of this port's queue and traffic counters.
func (p *IPPort) Stats() PortStats {
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	stats := p.stats
	stats.Queued = p.queued
	return stats
}

func (p *IPPort) receiveIP(hostinfo *hostInfo, packet []byte) {
	if p.ctx.Err() != nil {
		return
	}
	f := p.node.engine
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
		p.statsMu.Lock()
		p.stats.ReceivedPackets++
		p.stats.ReceivedBytes += uint64(len(packet))
		p.statsMu.Unlock()
		p.deliver(packet)
		return
	}
	p.recordDrop(true, peer, ip, reason, 1)
}

// queueFull is called under p.queueMu for both initial admission and a route retry.
func (p *IPPort) queueFull(q *peerQueue) bool {
	limits := p.node.portOptions
	return p.queued >= limits.QueueSize || (q != nil && len(q.packets) >= limits.PerPeerQueueSize)
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

	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if p.ctx.Err() != nil {
		return ErrPortClosed
	}
	q := p.queues[peer]
	if p.queueFull(q) {
		return ErrQueueFull
	}
	if q == nil {
		if p.workers >= p.node.portOptions.QueueSize {
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
		p.queueMu.Lock()
		if p.queues[peer] != q || len(q.packets) == 0 || ctx.Err() != nil || connectErr != nil {
			break
		}
		h := f.hostMap.QueryVpnAddr(peer)
		var route tunnelRoute
		if h != nil {
			route = f.currentRoute(h)
		}
		if !route.Endpoint.IsValid() {
			p.queueMu.Unlock()
			connectErr = p.node.ConnectPeer(ctx, peer)
			continue
		}
		packet := q.packets[0]
		q.packets[0] = queuedIP{}
		q.packets = q.packets[1:]
		p.queued--
		p.queueMu.Unlock()

		ip := packet.innerPacket
		if !h.authorizes(ip.destination) {
			p.recordDrop(false, peer, ip, "peer certificate does not authorize destination", 1)
			continue
		}
		if cap(out) < len(packet.data)+header.MaxOverhead {
			out = make([]byte, 0, len(packet.data)+header.MaxOverhead)
		}
		path, err := f.sendOnRoute(header.Message, header.MessageNone, h, route, packet.data, nonce, out)
		if err == nil {
			p.statsMu.Lock()
			p.stats.SentPackets++
			p.stats.SentBytes += uint64(len(packet.data))
			p.statsMu.Unlock()
			if last := h.lastDataPath.Load(); last == nil || *last != path {
				h.lastDataPath.Store(&path)
			}
			continue
		}

		if err == errWritePolicy || (path == (TunnelPath{}) && errors.Is(err, ErrPeerUnavailable)) {
			// Retry at the head of the original queue if it is still attached.
			p.queueMu.Lock()
			if p.queues[peer] == q && !p.queueFull(q) {
				q.packets = slices.Insert(q.packets, 0, packet)
				p.queued++
				p.queueMu.Unlock()
				continue
			}
			p.queueMu.Unlock()
		}
		p.recordDrop(false, peer, ip, err.Error(), 1)
	}

	// The loop exits with queueMu held so a concurrent writer sees either
	// the existing worker or a detached queue.
	if p.queues[peer] == q {
		delete(p.queues, peer)
		p.queued -= len(q.packets)
		if connectErr != nil && len(q.packets) > 0 && ctx.Err() == nil {
			p.recordDrop(false, peer, q.packets[0].innerPacket, connectErr.Error(), len(q.packets))
		}
	}
	p.workers--
	p.queueMu.Unlock()
	if connectErr != nil && ctx.Err() == nil {
		f.l.Debug("IP queue handshake failed", "peer", peer, "error", connectErr)
	}
}
