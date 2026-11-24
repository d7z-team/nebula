package nebula

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
)

// MaxIPPacketSize is the largest inner packet accepted by a node, in bytes.
const MaxIPPacketSize = 65535

const (
	maxPortQueue   = 512
	maxTargetQueue = 64
)

// PortStats holds counters for this attachment. Queued excludes in-flight packets.
type PortStats struct {
	ReceivedPackets, ReceivedBytes    uint64
	SentPackets, SentBytes            uint64
	RejectedInbound, RejectedOutbound uint64
	Queued                            int
	LastDrop                          string
}

// TransmitResult describes a dequeued packet's local submission attempt.
// A nil Err means the local transport accepted the packet. Transport is "udp",
// "tcp", or "relay" when a path was selected, including a remote size-limit
// rejection. It is empty if no path was selected.
type TransmitResult struct {
	Peer                PeerID
	Source, Destination netip.Addr
	Transport           string
	// Endpoint reports the remote address observed on a direct transport.
	Endpoint netip.AddrPort
	// Circuit contains both endpoints and the intermediate members on a relay.
	Circuit []PeerID
	Err     error
}

// IPPortOptions attaches host callbacks. They run without node or port locks
// and may overlap. Call Node.Close outside receive and transmit callbacks.
type IPPortOptions struct {
	// Deliver receives a complete packet and its authenticated end-to-end sender.
	Deliver func(from PeerID, packet []byte)
	// ResolveNextHop chooses a member synchronously for a VIP or downstream
	// destination when WriteIP has no explicit next hop. The packet is read-only
	// for the duration of the call. Return a nonzero ID or a routing error.
	ResolveNextHop func(destination netip.Addr, packet []byte) (PeerID, error)
	// ObserveTransmit receives the result of each dequeued attempt. Stats counts
	// queue overflow and policy drops while waiting. Keep the callback brief.
	ObserveTransmit func(TransmitResult)
}

type outboundPacket struct {
	innerPacket
	data []byte
}

type ipQueue struct {
	packets     []*outboundPacket
	current     *outboundPacket
	stopCurrent context.CancelFunc
}

// IPPort delivers complete IPv4 and IPv6 packets for one attachment.
type IPPort struct {
	node   *Node
	opts   IPPortOptions
	mu     sync.Mutex
	closed bool
	queues map[PeerID]*ipQueue
	stats  PortStats
}

// OpenIPPort attaches the sole IP receiver, including before Start.
func (n *Node) OpenIPPort(opts IPPortOptions) (*IPPort, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == closed {
		return nil, ErrNodeClosed
	}
	if n.port != nil || opts.Deliver == nil {
		return nil, errors.New("IP receiver already attached or nil")
	}
	p := &IPPort{node: n, opts: opts, queues: make(map[PeerID]*ipQueue)}
	n.port = p
	return p, nil
}

// Close detaches this receiver and discards pending sends.
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

// ClearPending discards the member's backlog and cancels its in-flight packet.
// The returned count excludes the in-flight packet.
func (p *IPPort) ClearPending(peer PeerID) int {
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

// Stats returns a snapshot of this attachment's queues and traffic.
func (p *IPPort) Stats() PortStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// WriteIP queues a copy for the specified member. With a zero next hop, primary
// addresses and groups resolve locally. VIPs and downstream destinations use
// ResolveNextHop. Group delivery can succeed for a subset when queues fill.
// A packet exceeding the selected peer's receive limit reports ErrPacketTooLarge
// through ObserveTransmit when dequeued.
func (p *IPPort) WriteIP(via PeerID, b []byte) error {
	if len(b) > p.node.o.MaxIPSize {
		return ErrPacketTooLarge
	}
	ip, err := parseInnerPacket(b)
	if err != nil {
		return err
	}
	err = p.enqueue(via, ip, b)
	if err != ErrNextHopRequired || p.opts.ResolveNextHop == nil {
		return err
	}
	via, err = p.opts.ResolveNextHop(ip.destination, b)
	if err != nil {
		return err
	}
	if via == (PeerID{}) {
		return ErrNextHopRequired
	}
	// A callback may have installed a new topology or closed this port.
	return p.enqueue(via, ip, b)
}

func (p *IPPort) enqueue(via PeerID, ip innerPacket, b []byte) error {
	n := p.node
	p.mu.Lock()
	defer p.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	cfg := n.policy.Load()
	if err := n.state.runningError(); err != nil {
		return err
	}
	if p.closed {
		return ErrPortClosed
	}
	if !n.memberOf(cfg) {
		return ErrPathPolicy
	}
	if !cfg.allowsAddress(n.id, ip.source, nil) {
		return ErrAddressUnauthorized
	}
	peers, group, err := cfg.groupRecipients(n.id, ip.destination)
	if err != nil {
		return err
	}
	if group && via != (PeerID{}) {
		return ErrAddressUnauthorized
	}
	if !group {
		peer, err := n.unicastNextHopLocked(via, ip.destination)
		if err != nil {
			return err
		}
		peers = []PeerID{peer}
	}
	var packet *outboundPacket
	full, denied := false, false
	for _, peer := range peers {
		if peer == n.id {
			continue
		}
		if n.modeLocked(peer) == Blocked || !n.ready(cfg) && n.preferredSessionLocked(n.peers[peer], false, &ip) == nil {
			denied = true
			continue
		}
		q := p.queues[peer]
		if p.stats.Queued >= maxPortQueue || q == nil && len(p.queues) >= maxPortQueue || q != nil && len(q.packets) >= maxTargetQueue {
			p.stats.RejectedOutbound++
			p.stats.LastDrop = ErrQueueFull.Error()
			full = true
			continue
		}
		if packet == nil {
			packet = &outboundPacket{innerPacket: ip, data: slices.Clone(b)}
		}
		if q == nil {
			q = &ipQueue{}
			p.queues[peer] = q
			n.wg.Go(func() { p.drain(peer, q) })
		}
		q.packets = append(q.packets, packet)
		p.stats.Queued++
	}
	switch {
	case packet != nil:
		return nil
	case full:
		return ErrQueueFull
	case denied:
		return ErrPathPolicy
	case group:
		return nil
	default:
		return ErrPeerUnavailable
	}
}

func (n *Node) receiveIP(s *session, b []byte) {
	ip, err := parseInnerPacket(b)
	n.mu.Lock()
	port := n.port
	cfg := n.policy.Load()
	if len(b) > n.o.MaxIPSize {
		err = ErrPacketTooLarge
	}
	if err == nil && (!n.usableLocked(s) || !ip.authorizedOn(cfg, s.remoteIdentity, s.localIdentity)) {
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
	port.opts.Deliver(s.peer, b)
}
