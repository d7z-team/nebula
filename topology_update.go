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
// Like Revalidate, it waits for pending grant writes after committing the view.
func (n *Node) ApplyTopology(ctx context.Context, t Topology) error {
	p, err := t.compile(n.Cluster())
	if err != nil {
		return err
	}
	return n.updateView(ctx, p)
}

// Revalidate reapplies the host's current chain decisions to local credentials,
// sessions and instance conflict claims. It clears cached introductions on commit.
// Concurrent admissions may restart the review. Cancellation or timeout before
// commit leaves this review unapplied.
// After commit it waits for grant frames admitted under the previous policy to
// finish writing or reach their handshake deadline, even if ctx is canceled.
// ControlStatus, Paths and InspectIP report the outcome.
func (n *Node) Revalidate(ctx context.Context) error { return n.updateView(ctx, nil) }

// Evaluate application callbacks outside node locks. Admissions and credential
// changes racing the evaluation are included before publishing the result.
func (n *Node) updateView(ctx context.Context, next *topologyView) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n.mu.Lock()
		old, creds, admissions := n.policy.Load(), n.cred.Load(), n.admissions
		conflicts := maps.Clone(n.conflicts)
		sessions := n.sessionListLocked()
		n.mu.Unlock()
		p := next
		if p == nil {
			// A new snapshot pointer invalidates authorizations in flight.
			view := *old
			p = &view
		}
		// A valid view may withdraw the local member. A zero deadline marks
		// current credentials unusable while the new topology takes effect.
		end, _ := n.credentialDeadline(ctx, p, creds)
		if after, local := p.members[n.id]; next != nil && local {
			before, existed := old.members[n.id]
			if !existed || !slices.Equal(before.RoutedPrefixes, after.RoutedPrefixes) || !slices.Equal(before.Endpoints, after.Endpoints) {
				if err := n.checkLocalIntroductionBudget(next, creds); err != nil {
					return err
				}
			}
		}
		deadlines := make([]time.Time, len(sessions))
		for i, s := range sessions {
			d, err := s.authorizationDeadline(ctx, p)
			if err == nil && p.acceptsIdentity(s.remoteIdentity) {
				deadlines[i] = d
			}
		}
		n.recheckConflicts(ctx, p, conflicts)
		n.mu.Lock()
		if n.ctx.Err() != nil {
			n.mu.Unlock()
			return ErrNodeClosed
		}
		if err := ctx.Err(); err != nil {
			n.mu.Unlock()
			return err
		}
		if old != n.policy.Load() || creds != n.cred.Load() || admissions != n.admissions {
			n.mu.Unlock()
			continue
		}
		n.conflicts = conflicts
		for i, s := range sessions {
			s.until = deadlines[i]
			if hold, ok := conflicts[s.peer]; ok && hold.selected && hold.keep == s.instance && time.Now().Before(s.until) && !s.closed.Load() {
				delete(conflicts, s.peer)
			}
		}
		updated := *creds
		updated.until = end
		n.cred.Store(&updated)
		n.policy.Store(p)
		pendingGrants := slices.Collect(maps.Keys(n.grantWrites))
		clear(n.routeCursors)
		clear(n.introduced)
		clear(n.discovered)
		clear(n.discoveredOwners)
		clear(n.observations)
		if next != nil {
			n.shaper.setRate(n.ctx, p.members[n.id].BytesPerSecond)
		}
		n.mu.Unlock()
		n.enforcePathPolicy()
		for _, done := range pendingGrants {
			<-done
		}
		return nil
	}
}
