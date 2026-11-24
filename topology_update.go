package nebula

import (
	"context"
	"maps"
	"slices"
	"time"
)

// ApplyTopology installs a private copy of the complete host-approved view.
// An invalid view leaves the current one in place. A valid view can withdraw
// the local member, in which case it succeeds and ControlStatus().Ready is false.
func (n *Node) ApplyTopology(ctx context.Context, t Topology) error {
	p, err := t.compile(n.Cluster())
	if err != nil {
		return err
	}
	return n.updateView(ctx, p)
}

// Revalidate reapplies the host's current chain decisions to local credentials,
// sessions and cached publications. Success means the review completed, including
// any withdrawals. Use ControlStatus and Paths to inspect the outcome.
func (n *Node) Revalidate(ctx context.Context) error { return n.updateView(ctx, nil) }

// Evaluate application callbacks outside node locks. Admissions and credential
// changes racing the evaluation are included before publishing the result.
func (n *Node) updateView(ctx context.Context, next *topologyView) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n.mu.Lock()
		old, c, seq := n.policy.Load(), n.cred.Load(), n.admissions
		ss, publications := n.sessionListLocked(), maps.Clone(n.publications)
		n.mu.Unlock()
		p := next
		if p == nil {
			// A new snapshot pointer invalidates authorizations in flight.
			view := *old
			p = &view
		}
		// A valid view may withdraw the local member. A zero deadline marks
		// current credentials unusable while the new topology takes effect.
		end, _ := n.credentialDeadline(ctx, p, c)
		if after, local := p.members[n.id]; next != nil && local {
			before, existed := old.members[n.id]
			if !existed || !slices.Equal(before.RoutedPrefixes, after.RoutedPrefixes) || !slices.Equal(before.Endpoints, after.Endpoints) {
				if err := n.validateIntroduction(next, c.Object); err != nil {
					return err
				}
			}
		}
		deadlines := make([]time.Time, len(ss))
		for i, s := range ss {
			d, err := s.authorizationDeadline(ctx, p)
			if err == nil {
				deadlines[i] = d
			}
		}
		for id, publication := range publications {
			_, until, err := n.verifyPublication(ctx, p, publication.record)
			if err != nil {
				delete(publications, id)
				continue
			}
			publication.expires = until
			publications[id] = publication
		}
		n.mu.Lock()
		if n.ctx.Err() != nil {
			n.mu.Unlock()
			return ErrNodeClosed
		}
		if err := ctx.Err(); err != nil {
			n.mu.Unlock()
			return err
		}
		if old != n.policy.Load() || c != n.cred.Load() || seq != n.admissions {
			n.mu.Unlock()
			continue
		}
		for i, s := range ss {
			s.until = deadlines[i]
		}
		for id := range n.publications {
			if publication, ok := publications[id]; ok {
				n.publications[id] = publication
			} else {
				delete(n.publications, id)
			}
		}
		updated := *c
		updated.until = end
		n.cred.Store(&updated)
		n.policy.Store(p)
		clear(n.routeCursors)
		clear(n.introduced)
		clear(n.discovered)
		clear(n.discoveredOwners)
		clear(n.observations)
		if next != nil {
			n.setShapingRate(p.members[n.id].BytesPerSecond)
		}
		n.mu.Unlock()
		n.enforcePathPolicy()
		return nil
	}
}
