package nebula

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
)

const (
	maxCircuitAttempts = 8
	maxSearchEdges     = 4096
)

type relayBranch struct {
	first PeerID
	rank  [sha256.Size]byte
	path  []PeerID
	edges []int
	done  bool
}

// A cursor resumes bounded depth-first searches, rotating first hops after
// each complete candidate at the same depth. Each branch retains its DFS stack.
type routeCursor struct {
	mu                       sync.Mutex
	branches                 []relayBranch
	depth, branch, remaining int
}

func (r *routeCursor) next(p *topologyView, source, target PeerID, distance map[PeerID]int, work *int) []PeerID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.branches == nil {
		r.depth = 2 // The first search adds at least one transit node.
		var key [3 * len(source)]byte
		copy(key[:], source[:])
		copy(key[len(source):], target[:])
		for _, first := range p.members[source].Links {
			if distance[first] <= 0 {
				continue
			}
			copy(key[2*len(source):], first[:])
			r.branches = append(r.branches, relayBranch{first: first, rank: sha256.Sum256(key[:])})
		}
		slices.SortFunc(r.branches, func(a, b relayBranch) int {
			if order := bytes.Compare(b.rank[:], a.rank[:]); order != 0 {
				return order
			}
			return comparePeer(a.first, b.first)
		})
	}
	for *work > 0 {
		if r.remaining == 0 {
			r.depth++
			if r.depth > min(maxCircuitNodes, len(p.members)) {
				r.branches = nil
				return nil
			}
			r.branch = 0
			for i := range r.branches {
				b := &r.branches[i]
				b.done = distance[b.first] > r.depth-2
				if !b.done {
					r.remaining++
				}
			}
			if r.remaining == 0 {
				continue
			}
		}
		b := &r.branches[r.branch]
		if !b.done {
			if path := b.nextPath(p, source, target, r.depth, distance, work); path != nil {
				r.branch = (r.branch + 1) % len(r.branches)
				return path
			}
			if !b.done {
				// This call used its edge budget partway through the branch.
				return nil
			}
			r.remaining--
		}
		r.branch = (r.branch + 1) % len(r.branches)
	}
	return nil
}

// nextPath resumes at the next unexamined edge of this first hop.
func (b *relayBranch) nextPath(p *topologyView, source, target PeerID, depth int, distance map[PeerID]int, work *int) []PeerID {
	if len(b.path) == 0 {
		(*work)--
		b.path = append(b.path, source, b.first)
		b.edges = append(b.edges, 0)
	}
	for len(b.edges) > 0 {
		top := len(b.edges) - 1
		links := p.members[b.path[top+1]].Links
		if b.edges[top] == len(links) {
			b.edges = b.edges[:top]
			b.path = b.path[:top+1]
			continue
		}
		if *work == 0 {
			return nil
		}
		(*work)--
		next := links[b.edges[top]]
		b.edges[top]++
		left := depth - len(b.path) - 1
		if next == target && left == 0 {
			return append(slices.Clone(b.path), next)
		}
		if hops, ok := distance[next]; ok && next != target && hops <= left && !slices.Contains(b.path, next) {
			b.path = append(b.path, next)
			b.edges = append(b.edges, 0)
		}
	}
	b.path = b.path[:0]
	b.done = true
	return nil
}

// relayDistances returns remaining hop counts for transit nodes that can reach
// the target, or nil when none of the source's neighbors can start a circuit.
func (p *topologyView) relayDistances(source, target PeerID) map[PeerID]int {
	if len(p.members[source].Links) == 0 || len(p.members[target].Links) == 0 {
		return nil
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
			if _, seen := distance[id]; !seen && id != source && p.members[id].Transit {
				distance[id] = distance[peer] + 1
				queue = append(queue, id)
			}
		}
	}
	// A relay route must start with a transit neighbor that can reach target.
	if !slices.ContainsFunc(p.members[source].Links, func(id PeerID) bool { return distance[id] > 0 }) {
		return nil
	}
	return distance
}

func (n *Node) dialRelay(target PeerID, attempts int) error {
	n.mu.Lock()
	p := n.policy.Load()
	if !n.memberOf(p) || !n.modeLocked(target).allowsRelay() {
		n.mu.Unlock()
		return ErrPathPolicy
	}
	n.mu.Unlock()
	distance := p.relayDistances(n.id, target)
	if distance == nil {
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
		if err := n.ctx.Err(); err != nil {
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
		allowed := n.circuitAllowedLocked(path)
		established := paths != nil && slices.ContainsFunc(paths.sessions, func(s *session) bool {
			return slices.Equal(s.path, path) && !s.closed.Load() && n.sessionAllowedLocked(s)
		})
		n.mu.Unlock()
		if !allowed || established {
			continue
		}
		attempts--
		last = n.startCircuit(path)
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
