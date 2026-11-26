package nebula

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

// InstanceID identifies one Node lifetime. The zero value means unknown.
type InstanceID [16]byte

func (id InstanceID) String() string               { return hex.EncodeToString(id[:]) }
func (id InstanceID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *InstanceID) UnmarshalText(text []byte) error {
	var v InstanceID
	if len(text) != hex.EncodedLen(len(v)) {
		return errors.New("invalid instance ID length")
	}
	if _, err := hex.Decode(v[:], text); err != nil {
		return err
	}
	*id = v
	return nil
}

type instanceClaim struct {
	instance  InstanceID
	chain     []*x509.Certificate
	node      *x509.Certificate
	addresses pki.Addresses
	usage     x509.ExtKeyUsage
}

func (s *session) handshakeClaim() instanceClaim {
	_, usage := handshakeUsages(s.outgoing)
	return instanceClaim{s.instance, s.remoteGrant, s.state.PeerCertificates[0], s.remoteIdentity.Addresses, usage}
}

// A fresh ping to the incumbent promotes a challenge into a hold that survives
// losing the last path. A selection lasts until a fresh path to it is admitted.
type instanceConflict struct {
	keep                          InstanceID
	claims                        []instanceClaim
	since, confirmBy, confirmedAt time.Time
	selected, overflow            bool
}

// InstanceConflict describes a confirmed local conflict for Peer. Retained is
// the instance named by the hold, even when it has no remaining path.
type InstanceConflict struct {
	Peer        PeerID
	Retained    InstanceID
	ConfirmedAt time.Time
	// Selected means a resolution has chosen Retained and awaits its admission.
	Selected bool
	// EvidenceTruncated means the claim limit was reached. Credential
	// revalidation alone cannot resolve this hold.
	EvidenceTruncated bool
}

// InstanceConflicts returns confirmed local conflicts ordered by peer. Use
// InspectIP on either primary address for the individual observations.
func (n *Node) InstanceConflicts() []InstanceConflict {
	n.mu.Lock()
	var out []InstanceConflict
	for peer, c := range n.conflicts {
		if !c.confirmedAt.IsZero() {
			out = append(out, InstanceConflict{
				Peer: peer, Retained: c.keep, ConfirmedAt: c.confirmedAt,
				Selected: c.selected, EvidenceTruncated: c.overflow,
			})
		}
	}
	n.mu.Unlock()
	slices.SortFunc(out, func(a, b InstanceConflict) int { return comparePeer(a.Peer, b.Peer) })
	return out
}

// Claims are append-only under Node.mu. Revalidation builds a separate slice.
// At capacity the hold requires a host decision even if some claims are revoked.
func (c *instanceConflict) addClaim(w instanceClaim) bool {
	if c.overflow {
		return false
	}
	for _, known := range c.claims {
		if known.instance == w.instance && known.usage == w.usage && known.node.Equal(w.node) && slices.EqualFunc(known.chain, w.chain, (*x509.Certificate).Equal) {
			return false
		}
	}
	if len(c.claims) == 16 {
		c.overflow = true
	} else {
		c.claims = append(c.claims, w)
	}
	return true
}

// deliveryInstanceLocked returns the bound run and whether a confirmed
// collision has suspended delivery after the incumbent lost its last path.
func (n *Node) deliveryInstanceLocked(peer PeerID) (InstanceID, bool) {
	if paths := n.peers[peer]; paths != nil {
		for _, s := range paths.sessions {
			if !s.closed.Load() && n.sessionAllowedLocked(s) {
				return s.instance, false
			}
		}
	}
	if c, ok := n.conflicts[peer]; ok && !c.confirmedAt.IsZero() {
		return c.keep, !c.selected
	}
	return InstanceID{}, false
}

// admitSessionLocked checks path policy and pins the member to one run before
// register can replace or reuse an existing path.
func (n *Node) admitSessionLocked(s *session) error {
	if n.addressConflictLocked(s.remoteIdentity) {
		n.recordObservationLocked(s.observation("address conflict"), nil)
		return ErrPathPolicy
	}
	if n.state != running || !n.sessionAllowedLocked(s) {
		return ErrPathPolicy
	}
	c, recorded := n.conflicts[s.peer]
	paths := n.peers[s.peer]
	incumbent := n.preferredSessionLocked(paths, false, nil)
	if recorded && c.confirmedAt.IsZero() && (incumbent == nil || !time.Now().Before(c.confirmBy)) {
		delete(n.conflicts, s.peer)
		n.admissions++
		recorded = false
	}
	if !recorded && incumbent != nil && incumbent.instance != s.instance {
		now := time.Now()
		c = instanceConflict{keep: incumbent.instance, since: now, confirmBy: earlierDeadline(s.until, now.Add(2*n.o.DialTimeout))}
		n.recordObservationLocked(incumbent.observation("incumbent at collision"), nil)
		// The run may have established multiple paths with distinct credentials
		// or roles. Keep their evidence even if the paths close before review.
		for _, path := range paths.sessions {
			if !path.closed.Load() && path.instance == incumbent.instance {
				c.addClaim(path.handshakeClaim())
			}
		}
		n.conflicts[s.peer] = c
		n.admissions++
		recorded = true
		if !incumbent.probing && n.tryTaskLocked(n.probeSlots, func() { n.probeSession(incumbent) }) {
			incumbent.probing = true
		}
	}
	if recorded {
		if !c.selected && c.addClaim(s.handshakeClaim()) {
			n.conflicts[s.peer] = c
			n.admissions++
		}
		if c.keep != s.instance {
			n.recordObservationLocked(s.observation(rejectedInstance), nil)
			return ErrInstanceConflict
		}
		if c.selected {
			delete(n.conflicts, s.peer)
			n.admissions++
		}
	}
	// A disconnected run may still have readers unwinding in serveSession.
	for _, old := range n.detachOtherInstancesLocked(s.peer, s.instance) {
		n.wg.Go(old.close)
	}
	if old := n.discovered[s.peer]; len(old.record) > 0 && old.Instance != s.instance {
		n.recordObservationLocked(old.observation(s.peer, "different signed instance"), old.RoutedPrefixes)
		n.forgetIntroductionLocked(s.peer, old)
	}
	return nil
}

// ResolveInstanceConflict selects an observed run in a confirmed local
// conflict and withdraws paths to competing runs. A selected
// run must still pass ordinary admission. The decision is local to this Node.
func (n *Node) ResolveInstanceConflict(peer PeerID, keep InstanceID) error {
	n.mu.Lock()
	if err := n.state.runningError(); err != nil {
		n.mu.Unlock()
		return err
	}
	c, ok := n.conflicts[peer]
	known := slices.ContainsFunc(c.claims, func(w instanceClaim) bool { return w.instance == keep })
	if !known && c.overflow {
		known = slices.ContainsFunc(n.evidence, func(e claimObservation) bool {
			return e.Peer == peer && e.Instance == keep && e.Source == sessionSource && e.Decision == rejectedInstance && time.Since(e.LastSeen) <= evidenceLifetime
		})
	}
	if !ok || c.confirmedAt.IsZero() || keep == (InstanceID{}) || !known {
		n.mu.Unlock()
		return ErrInstanceConflict
	}
	c.keep = keep
	c.selected = true
	n.conflicts[peer] = c
	dead := n.detachOtherInstancesLocked(peer, keep)
	if active := n.preferredSessionLocked(n.peers[peer], false, nil); active != nil && active.instance == keep {
		delete(n.conflicts, peer)
	}
	if intro, ok := n.discovered[peer]; ok && intro.Instance != keep {
		n.forgetIntroductionLocked(peer, intro)
	}
	n.admissions++
	port := n.port
	n.mu.Unlock()
	for _, s := range dead {
		s.close()
	}
	if port != nil {
		port.syncInstanceQueue(peer)
	}
	return nil
}

// Detached transports can be closed without holding Node.mu.
func (n *Node) detachOtherInstancesLocked(peer PeerID, keep InstanceID) []*session {
	var detached []*session
	if paths := n.peers[peer]; paths != nil {
		for i := len(paths.sessions) - 1; i >= 0; i-- {
			s := paths.sessions[i]
			if s.instance != keep {
				n.removeSessionLocked(s)
				detached = append(detached, s)
			}
		}
	}
	return detached
}

// recheckConflicts reviews the immutable handshake evidence outside the node lock.
func (n *Node) recheckConflicts(ctx context.Context, p *topologyView, conflicts map[PeerID]instanceConflict) {
	for peer, c := range conflicts {
		if _, local := p.members[n.id]; !local {
			delete(conflicts, peer)
			continue
		}
		if c.overflow {
			continue
		}
		var valid []instanceClaim
		var survivor InstanceID
		multiple := false
		for _, w := range c.claims {
			if !p.acceptsIdentity(pki.Identity{ID: peer, Addresses: w.addresses}) {
				continue
			}
			if _, err := n.memberDeadline(ctx, p, peer, w.node, w.chain, w.usage); err != nil {
				continue
			}
			valid = append(valid, w)
			if survivor != (InstanceID{}) && survivor != w.instance {
				multiple = true
			}
			survivor = w.instance
		}
		if len(valid) == 0 || c.confirmedAt.IsZero() && !multiple {
			delete(conflicts, peer)
			continue
		}
		c.claims = valid
		if !multiple {
			c.keep = survivor
			c.selected = true
		} else if c.selected {
			c.selected = slices.ContainsFunc(valid, func(w instanceClaim) bool { return w.instance == c.keep })
		}
		conflicts[peer] = c
	}
}
