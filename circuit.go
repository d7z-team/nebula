package nebula

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

const maxCircuitNodes = 16

type circuitRequest struct {
	Path []PeerID
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
		c.Close()
	}
	l.n.mu.Lock()
	delete(l.n.circuits, l)
	l.n.mu.Unlock()
}

func (l *circuitLease) allowedLocked() bool {
	if l.ctx.Err() != nil || !l.n.permitCircuit(l.path) {
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
func (n *Node) permitCircuit(path []PeerID) bool {
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

func (n *Node) routes(target PeerID) [][]PeerID {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.policy.Load()
	if !n.memberOf(p) || !n.modeLocked(target).allowsRelay() {
		return nil
	}
	var out [][]PeerID
	for _, first := range p.members[n.id].Links {
		if first == target || !p.members[first].Transit {
			continue
		}
		// Retain a second route through the same first hop when an interior edge can be bypassed.
		shortest := func(skipA, skipB PeerID) []PeerID {
			visited := map[PeerID]bool{n.id: true, first: true}
			q := [][]PeerID{{n.id, first}}
			for len(q) > 0 {
				path := q[0]
				q = q[1:]
				last := path[len(path)-1]
				if len(path) >= maxCircuitNodes {
					continue
				}
				for _, a := range p.members[last].Links {
					if visited[a] || last == skipA && a == skipB || last == skipB && a == skipA {
						continue
					}
					visited[a] = true
					next := append(slices.Clone(path), a)
					if a == target {
						return next
					}
					if p.members[a].Transit {
						q = append(q, next)
					}
				}
			}
			return nil
		}
		path := shortest(PeerID{}, PeerID{})
		if !n.permitCircuit(path) {
			continue
		}
		out = append(out, path)
		for i := 1; i < len(path)-1; i++ {
			alt := shortest(path[i], path[i+1])
			if n.permitCircuit(alt) {
				out = append(out, alt)
				break
			}
		}
	}
	slices.SortStableFunc(out, func(a, b []PeerID) int { return len(a) - len(b) })
	return out
}

func (n *Node) openLeg(ctx context.Context, next PeerID, l *circuitLease) (net.Conn, error) {
	s := n.selectSession(next, true)
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
	if ack[0] != 1 {
		return nil, ErrPathPolicy
	}
	c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

func (n *Node) startCircuit(ctx context.Context, path []PeerID) (*session, error) {
	n.mu.Lock()
	if !n.permitCircuit(path) || path[0] != n.id || len(n.circuits) >= n.o.MaxCircuits {
		n.mu.Unlock()
		return nil, ErrPathPolicy
	}
	l := &circuitLease{n: n, path: path}
	l.ctx, l.cancel = context.WithCancel(n.ctx)
	n.circuits[l] = struct{}{}
	n.mu.Unlock()
	c, err := n.openLeg(ctx, path[1], l)
	if err != nil {
		l.close()
		return nil, err
	}
	if !l.bind(c) {
		return nil, ErrPathPolicy
	}
	return n.attachCircuit(ctx, c, l, true)
}

func (n *Node) attachCircuit(ctx context.Context, c net.Conn, l *circuitLease, out bool) (*session, error) {
	path := slices.Clone(l.path)
	if !out {
		slices.Reverse(path)
	}
	s, err := n.attachTLS(ctx, c, path[len(path)-1], path, out, l)
	if err != nil || s.lease != l {
		l.close()
	}
	return s, err
}

func (n *Node) forwardCircuit(s *session, c net.Conn, b []byte) bool {
	var req circuitRequest
	if json.Unmarshal(b, &req) != nil {
		return false
	}
	n.mu.Lock()
	pos := slices.Index(req.Path, n.id)
	if !n.sessionAllowedLocked(s) || !n.permitCircuit(req.Path) || pos <= 0 || s.peer != req.Path[pos-1] || len(n.circuits) >= n.o.MaxCircuits {
		n.mu.Unlock()
		return false
	}
	l := &circuitLease{n: n, path: req.Path, ends: []net.Conn{c}, legs: []*session{s}}
	l.ctx, l.cancel = context.WithCancel(n.ctx)
	n.circuits[l] = struct{}{}
	n.mu.Unlock()
	if pos == len(req.Path)-1 {
		if _, err := c.Write([]byte{1}); err != nil {
			l.close()
			return true
		}
		n.attachCircuit(n.ctx, c, l, false)
		return true
	}
	ctx, cancel := context.WithTimeout(n.ctx, n.o.DialTimeout*time.Duration(len(req.Path)-pos))
	next, err := n.openLeg(ctx, req.Path[pos+1], l)
	cancel()
	if err != nil {
		l.close()
		return true
	}
	if !l.bind(next) {
		return true
	}
	if _, err = c.Write([]byte{1}); err != nil {
		l.close()
		return true
	}
	c.SetDeadline(time.Time{})
	pump := func(dst, src net.Conn) {
		defer l.close()
		buf := make([]byte, 16<<10)
		for {
			count, err := src.Read(buf)
			if count > 0 {
				if e := n.shape(l.ctx, count); e != nil {
					return
				}
				n.mu.Lock()
				permit := l.allowedLocked()
				n.mu.Unlock()
				if !permit {
					return
				}
				if _, e := dst.Write(buf[:count]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	if !n.task(func() { pump(next, c) }) {
		l.close()
		return true
	}
	pump(c, next)
	return true
}
