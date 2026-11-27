package nebula

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net"
	"slices"
	"time"
)

const (
	circuitReady byte = 0x01

	maxCircuitNodes = 16
)

// InboundCircuitLimits applies to both terminating and forwarding circuits.
type InboundCircuitLimits struct {
	// Default is the per-neighbor ceiling. Zero uses the node's total capacity.
	Default int
	// ByPeer overrides Default by authenticated neighbor, including across sessions.
	ByPeer map[PeerID]int
}

// RelayStatus is a snapshot of local circuit admission and maintenance.
type RelayStatus struct {
	Draining bool
	// TransitCircuits includes forwarding circuits under construction.
	TransitCircuits int
	// InboundCircuits counts live inbound reservations by the requesting neighbor.
	InboundCircuits map[PeerID]int
	// Rejections are cumulative over this Node's lifetime.
	RejectedCapacity, RejectedPeerLimit, RejectedDraining uint64
}

// RelayStatus reports current reservations and cumulative admission rejections.
func (n *Node) RelayStatus() RelayStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	status := n.relay
	status.InboundCircuits = maps.Clone(status.InboundCircuits)
	return status
}

// SetTransitDraining controls admission of new forwarding circuits at this node.
// Existing reservations continue until closed or their authorization is withdrawn.
func (n *Node) SetTransitDraining(draining bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == closed || n.ctx.Err() != nil {
		return ErrNodeClosed
	}
	n.relay.Draining = draining
	return nil
}

type circuitRequest struct {
	Path []PeerID `json:"path"`
}

type circuitLease struct {
	n       *Node
	ctx     context.Context
	cancel  context.CancelFunc
	path    []PeerID
	legs    []*session // adjacent direct sessions, protected by n.mu
	ends    []net.Conn // streams owned by this reservation, protected by n.mu
	inbound PeerID
	transit bool
}

func (l *circuitLease) reserve() bool {
	n := l.n
	n.mu.Lock()
	defer n.mu.Unlock()
	l.ctx = n.ctx
	if !l.allowedLocked() {
		return false
	}
	if l.transit && n.relay.Draining {
		n.relay.RejectedDraining++
		return false
	}
	if len(n.circuits) >= n.o.MaxCircuits {
		n.relay.RejectedCapacity++
		return false
	}
	if l.inbound != (PeerID{}) {
		limit, ok := n.o.InboundCircuitLimits.ByPeer[l.inbound]
		if !ok {
			limit = n.o.InboundCircuitLimits.Default
		}
		if limit > 0 && n.relay.InboundCircuits[l.inbound] >= limit {
			n.relay.RejectedPeerLimit++
			return false
		}
		n.relay.InboundCircuits[l.inbound]++
	}
	if l.transit {
		n.relay.TransitCircuits++
	}
	l.ctx, l.cancel = context.WithCancel(n.ctx)
	n.circuits[l] = struct{}{}
	return true
}

func (l *circuitLease) close() {
	n := l.n
	n.mu.Lock()
	if l.cancel == nil {
		n.mu.Unlock()
		return
	}
	l.cancel()
	l.cancel = nil
	ends := l.ends
	n.mu.Unlock()
	for _, c := range ends {
		// A yamux stream may keep reading after a local FIN.
		c.SetDeadline(time.Now())
		c.Close()
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.circuits, l)
	if l.transit {
		n.relay.TransitCircuits--
	}
	if l.inbound != (PeerID{}) {
		counts := n.relay.InboundCircuits
		counts[l.inbound]--
		if counts[l.inbound] == 0 {
			delete(counts, l.inbound)
		}
	}
}

func (l *circuitLease) allowedLocked() bool {
	if l.ctx.Err() != nil || !l.n.circuitAllowedLocked(l.path) {
		return false
	}
	for _, s := range l.legs {
		if s.closed.Load() || !l.n.sessionAllowedLocked(s) {
			return false
		}
	}
	return true
}

// Called under n.mu. Each relay checks the route against its local topology and its adjacent peers.
func (n *Node) circuitAllowedLocked(path []PeerID) bool {
	p := n.policy.Load()
	if !n.memberOf(p) || len(path) < 3 || len(path) > maxCircuitNodes {
		return false
	}
	pos := slices.Index(path, n.id)
	if pos < 0 {
		return false
	}
	if pos == 0 || pos == len(path)-1 {
		mode := n.modeLocked(path[len(path)-1-pos])
		if !mode.allowsRelay() {
			return false
		}
	}
	for i, a := range path {
		m, ok := p.members[a]
		if !ok || slices.Contains(path[:i], a) || i > 0 && !slices.Contains(m.Links, path[i-1]) || i > 0 && i < len(path)-1 && !m.Transit {
			return false
		}
		if i == pos-1 || i == pos+1 {
			mode := n.modeLocked(a)
			if !mode.allowsDirect() {
				return false
			}
		}
	}
	return true
}

func (l *circuitLease) openNextLeg(ctx context.Context, next PeerID) (net.Conn, error) {
	n := l.n
	s := n.preferredSession(next, true)
	if s == nil {
		var err error
		s, err = n.dialDirect(ctx, next)
		if err != nil {
			return nil, err
		}
	}
	n.mu.Lock()
	l.legs = append(l.legs, s)
	allowed := l.allowedLocked()
	n.mu.Unlock()
	if !allowed {
		return nil, ErrPathPolicy
	}
	c, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline() // Both callers budget for the remaining hops.
	c.SetDeadline(deadline)
	// Own the stream before requesting the route so withdrawal interrupts the ready wait.
	n.mu.Lock()
	if !l.allowedLocked() {
		n.mu.Unlock()
		c.Close()
		return nil, ErrPathPolicy
	}
	l.ends = append(l.ends, c)
	n.mu.Unlock()
	if _, err = c.Write([]byte{opCircuit}); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(circuitRequest{l.path})
	if err = writeFrame(c, b); err != nil {
		return nil, err
	}
	var ack [1]byte
	if _, err = io.ReadFull(c, ack[:]); err != nil {
		return nil, err
	}
	if ack[0] != circuitReady {
		return nil, ErrPathPolicy
	}
	return c, nil
}

func (n *Node) startCircuit(path []PeerID) error {
	l := &circuitLease{n: n, path: path}
	if len(path) == 0 || path[0] != n.id || !l.reserve() {
		return ErrPathPolicy
	}
	ctx, cancel := context.WithTimeout(l.ctx, n.o.DialTimeout*time.Duration(len(path)))
	defer cancel()
	c, err := l.openNextLeg(ctx, path[1])
	if err != nil {
		l.close()
		return err
	}
	return l.attachEndpoint(ctx, c, true)
}

func (l *circuitLease) attachEndpoint(ctx context.Context, c net.Conn, out bool) error {
	path := l.path
	if !out {
		path = slices.Clone(path)
		slices.Reverse(path)
	}
	s, err := l.n.attachTLS(ctx, c, path[len(path)-1], path, out, l)
	if err != nil || s.lease != l {
		l.close()
	}
	return err
}

func (n *Node) forwardCircuit(s *session, c net.Conn, b []byte) bool {
	var req circuitRequest
	if json.Unmarshal(b, &req) != nil {
		return false
	}
	pos := slices.Index(req.Path, n.id)
	if pos <= 0 || s.peer != req.Path[pos-1] {
		return false
	}
	l := &circuitLease{n: n, path: req.Path, inbound: s.peer, transit: pos < len(req.Path)-1, ends: []net.Conn{c}, legs: []*session{s}}
	if !l.reserve() {
		return false
	}
	var next net.Conn
	if l.transit {
		// The upstream ready reply waits for all remaining cold legs.
		ctx, cancel := context.WithTimeout(l.ctx, n.o.DialTimeout*time.Duration(len(req.Path)-pos))
		deadline, _ := ctx.Deadline()
		c.SetDeadline(deadline)
		var err error
		next, err = l.openNextLeg(ctx, req.Path[pos+1])
		cancel()
		if err != nil {
			l.close()
			return true
		}
	}
	if _, err := c.Write([]byte{circuitReady}); err != nil {
		l.close()
		return true
	}
	if !l.transit {
		l.attachEndpoint(l.ctx, c, false)
		return true
	}
	c.SetDeadline(time.Time{})
	next.SetDeadline(time.Time{})
	// The lease owns both streams. Release the incoming request slot once ready.
	n.wg.Go(func() { l.forward(next, c, relayDirection{s.peer, req.Path[pos+1]}) })
	n.wg.Go(func() { l.forward(c, next, relayDirection{req.Path[pos+1], s.peer}) })
	return true
}

func (l *circuitLease) forward(dst, src net.Conn, direction relayDirection) {
	defer l.close()
	n := l.n
	window := n.shaper.openWindow(direction)
	defer n.shaper.closeWindow(direction)
	buf := make([]byte, relayBlockSize)
	for l.ctx.Err() == nil {
		count, err := src.Read(buf)
		for data := buf[:count]; len(data) > 0; {
			select {
			case window.slots <- struct{}{}:
			case <-l.ctx.Done():
				return
			}
			size, err := n.shaper.schedule(l.ctx, direction.from, len(data))
			if err != nil {
				<-window.slots
				return
			}
			n.mu.Lock()
			permit := l.allowedLocked()
			n.mu.Unlock()
			if permit {
				_, err = dst.Write(data[:size])
			}
			n.shaper.finishWrite(direction.from)
			<-window.slots
			if !permit || err != nil {
				return
			}
			data = data[size:]
		}
		if err != nil {
			return
		}
	}
}
