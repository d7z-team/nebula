package nebula

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	circuitReady byte = 0x01

	maxCircuitNodes    = 16
	maxCircuitAttempts = 8
	maxSearchEdges     = 4096
)

type circuitRequest struct {
	Path []PeerID `json:"path"`
}

type circuitLease struct {
	n      *Node
	ctx    context.Context
	cancel context.CancelFunc
	path   []PeerID
	mu     sync.Mutex
	legs   []*session // adjacent direct sessions, protected by n.mu
	ends   []net.Conn
	closed bool
}

func (l *circuitLease) reserve() bool {
	n := l.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.circuits) >= n.o.MaxCircuits {
		return false
	}
	l.ctx, l.cancel = context.WithCancel(n.ctx)
	if !l.allowedLocked() {
		l.cancel()
		return false
	}
	n.circuits[l] = struct{}{}
	return true
}

func (l *circuitLease) bind(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		c.Close()
		return false
	}
	l.ends = append(l.ends, c)
	return true
}

func (l *circuitLease) close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.cancel()
	ends := l.ends
	l.mu.Unlock()
	for _, c := range ends {
		// A yamux stream may keep reading after a local FIN.
		c.SetReadDeadline(time.Now())
		c.Close()
	}
	l.n.mu.Lock()
	delete(l.n.circuits, l)
	l.n.mu.Unlock()
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

// routeCursor enumerates simple paths in increasing hop count. Only the bounded
// traversal stack survives between attempts; the topology owns the adjacency lists.
type routeCursor struct {
	mu    sync.Mutex
	depth int
	path  []PeerID
	edge  [maxCircuitNodes]int
}

// next resumes after the last examined edge, even when a work budget expires.
func (r *routeCursor) next(p *topologyView, source, target PeerID, distance map[PeerID]int, work *int) []PeerID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.depth == 0 {
		r.depth = 3
	}
	for r.depth <= min(maxCircuitNodes, len(p.members)) {
		if len(r.path) == 0 {
			r.path = append(r.path, source)
		}
		for len(r.path) > 0 {
			i := len(r.path) - 1
			links := p.members[r.path[i]].Links
			if r.edge[i] >= len(links) {
				r.edge[i] = 0
				r.path = r.path[:i]
				continue
			}
			if *work == 0 {
				return nil
			}
			(*work)--
			next := links[r.edge[i]]
			r.edge[i]++
			left := r.depth - i - 2
			if next == target {
				if left == 0 {
					return append(slices.Clone(r.path), next)
				}
				continue
			}
			hops, reachable := distance[next]
			if reachable && hops <= left && p.members[next].Transit && !slices.Contains(r.path, next) {
				r.path = append(r.path, next)
			}
		}
		r.depth++
	}
	r.depth = 0
	return nil
}

func (n *Node) dialRelay(ctx context.Context, target PeerID, attempts int) error {
	n.mu.Lock()
	p := n.policy.Load()
	if !n.memberOf(p) || !n.modeLocked(target).allowsRelay() {
		n.mu.Unlock()
		return ErrPathPolicy
	}
	n.mu.Unlock()
	if len(p.members[n.id].Links) == 0 || len(p.members[target].Links) == 0 {
		return ErrPeerUnavailable
	}

	// Reverse distances prune branches that cannot reach the destination
	// within the remaining depth. Never route back through the origin.
	distance := map[PeerID]int{target: 0}
	queue := []PeerID{target}
	for len(queue) > 0 {
		peer := queue[0]
		queue = queue[1:]
		if distance[peer] >= maxCircuitNodes-2 {
			continue
		}
		for _, id := range p.members[peer].Links {
			if _, seen := distance[id]; !seen && id != n.id && p.members[id].Transit {
				distance[id] = distance[peer] + 1
				queue = append(queue, id)
			}
		}
	}
	// A relay route must start with a transit neighbor that can reach target.
	if !slices.ContainsFunc(p.members[n.id].Links, func(id PeerID) bool { return distance[id] > 0 }) {
		return ErrPeerUnavailable
	}
	n.mu.Lock()
	if n.policy.Load() != p {
		n.mu.Unlock()
		return ErrPathPolicy
	}
	cursor, resumed := n.routeCursors[target]
	if !resumed {
		cursor = &routeCursor{}
		n.routeCursors[target] = cursor
	}
	n.mu.Unlock()
	work := maxSearchEdges
	var last error
	for attempts > 0 && work > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := cursor.next(p, n.id, target, distance, &work)
		if n.policy.Load() != p {
			return ErrPathPolicy
		}
		if path == nil {
			// A previous call may have spent its last attempt on the last
			// candidate. Start a fresh pass within this call's remaining budget.
			if resumed && work > 0 {
				resumed = false
				continue
			}
			break
		}
		resumed = false
		n.mu.Lock()
		paths := n.peers[target]
		established := paths != nil && slices.ContainsFunc(paths.sessions, func(s *session) bool {
			return slices.Equal(s.path, path) && !s.closed.Load() && n.sessionAllowedLocked(s)
		})
		n.mu.Unlock()
		if established {
			continue
		}
		attempts--
		dialCtx, cancel := context.WithTimeout(ctx, n.o.DialTimeout*time.Duration(len(path)))
		last = n.startCircuit(dialCtx, path)
		cancel()
		if last == nil {
			n.mu.Lock()
			if n.routeCursors[target] == cursor {
				delete(n.routeCursors, target)
			}
			n.mu.Unlock()
			return nil
		}
	}
	return errors.Join(ErrPeerUnavailable, last)
}

func (n *Node) openLeg(ctx context.Context, next PeerID, l *circuitLease) (net.Conn, error) {
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
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	deadline := time.Now().Add(n.o.DialTimeout)
	if t, yes := ctx.Deadline(); yes {
		deadline = t
	}
	c.SetDeadline(deadline)
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
	c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

func (n *Node) startCircuit(ctx context.Context, path []PeerID) error {
	l := &circuitLease{n: n, path: path}
	if len(path) == 0 || path[0] != n.id || !l.reserve() {
		return ErrPathPolicy
	}
	c, err := n.openLeg(ctx, path[1], l)
	if err != nil {
		l.close()
		return err
	}
	if !l.bind(c) {
		return ErrPathPolicy
	}
	return n.attachCircuit(ctx, c, l, true)
}

func (n *Node) attachCircuit(ctx context.Context, c net.Conn, l *circuitLease, out bool) error {
	path := slices.Clone(l.path)
	if !out {
		slices.Reverse(path)
	}
	s, err := n.attachTLS(ctx, c, path[len(path)-1], path, out, l)
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
	l := &circuitLease{n: n, path: req.Path, ends: []net.Conn{c}, legs: []*session{s}}
	if !l.reserve() {
		return false
	}
	if pos == len(req.Path)-1 {
		if _, err := c.Write([]byte{circuitReady}); err != nil {
			l.close()
			return true
		}
		n.attachCircuit(n.ctx, c, l, false)
		return true
	}
	// The upstream ready reply waits for all remaining cold legs.
	ctx, cancel := context.WithTimeout(l.ctx, n.o.DialTimeout*time.Duration(len(req.Path)-pos))
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	next, err := n.openLeg(ctx, req.Path[pos+1], l)
	cancel()
	if err != nil {
		l.close()
		return true
	}
	if !l.bind(next) {
		return true
	}
	if _, err = c.Write([]byte{circuitReady}); err != nil {
		l.close()
		return true
	}
	c.SetDeadline(time.Time{})
	// The lease owns both streams. Release the incoming request slot once ready.
	n.wg.Go(func() { l.forward(next, c) })
	n.wg.Go(func() { l.forward(c, next) })
	return true
}

func (l *circuitLease) forward(dst, src net.Conn) {
	defer l.close()
	n := l.n
	buf := make([]byte, 16<<10)
	for l.ctx.Err() == nil {
		count, err := src.Read(buf)
		if count > 0 {
			if n.shape(l.ctx, count) != nil {
				return
			}
			n.mu.Lock()
			permit := l.allowedLocked()
			n.mu.Unlock()
			if !permit {
				return
			}
			if _, err := dst.Write(buf[:count]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
