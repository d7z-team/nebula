package nebula

import (
	"crypto/rand"
	"slices"
	"time"
)

const maxPathProbes = 4

// The node lock protects both the batch and each session's probe schedule.
type probeBatch struct {
	pending []*session
	active  int
	rescan  bool
}

// Even a slow health probe must leave time to renew signed introductions.
func (p ProbeOptions) scanInterval() time.Duration {
	return min(p.Interval, introductionRefreshLead/2)
}

// Registration and collision detection request work on one known path.
// A full batch coalesces requests until the next slot becomes available.
func (n *Node) requestProbeLocked(s *session) {
	if s.probing {
		return // The active worker checks confirmProbe before releasing its slot.
	}
	if n.probes.active == maxPathProbes {
		n.probes.rescan = true
		return
	}
	n.probes.pending = append(n.probes.pending, s)
	n.dispatchProbesLocked()
}

func (n *Node) dispatchProbesLocked() {
	batch := &n.probes
	if n.state != running || batch.active == maxPathProbes {
		return
	}
	now := time.Now()
	// Allow a late start in the preceding round without skipping a whole tick.
	probeAfter := n.o.Probe.Interval - n.o.Probe.scanInterval()/4
	if batch.rescan {
		clear(batch.pending)
		batch.pending = batch.pending[:0]
		for _, paths := range n.peers {
			for _, s := range paths.sessions {
				if !s.probing && (s.confirmProbe || now.Sub(s.lastProbe) >= probeAfter || !now.Before(s.nextHello)) {
					batch.pending = append(batch.pending, s)
				}
			}
		}
		// Pop from the end so subsequent scans can reuse the whole buffer.
		slices.SortFunc(batch.pending, func(a, b *session) int {
			if a.confirmProbe != b.confirmProbe {
				if a.confirmProbe {
					return 1
				}
				return -1
			}
			return b.lastProbe.Compare(a.lastProbe)
		})
		batch.rescan = false
	}
	for batch.active < maxPathProbes && len(batch.pending) > 0 {
		last := len(batch.pending) - 1
		s := batch.pending[last]
		batch.pending[last] = nil
		batch.pending = batch.pending[:last]
		if !n.usableLocked(s) {
			continue
		}
		ping := now.Sub(s.lastProbe) >= probeAfter
		if s.confirmProbe {
			c := n.conflicts[s.peer]
			ping = ping || c.keep == s.instance && c.confirmedAt.IsZero() && now.Before(c.confirmBy)
			s.confirmProbe = false
		}
		if !ping && now.Before(s.nextHello) {
			continue
		}
		if ping {
			s.lastProbe = now
		}
		batch.active++
		s.probing = true
		n.wg.Go(func() {
			if ping {
				n.probeSession(s)
			} else {
				n.exchangeAdvert(s)
			}
			n.mu.Lock()
			batch.active--
			s.probing = false
			// A collision during an exchange needs a fresh ping after it.
			batch.rescan = batch.rescan || s.confirmProbe
			n.dispatchProbesLocked()
			n.mu.Unlock()
		})
	}
}

func (n *Node) probeSession(s *session) {
	s.refreshBudget()
	var nonce [8]byte
	rand.Read(nonce[:])
	at := time.Now()
	b, err := s.request(s.ctx, opPing, nonce[:], 8)
	rtt := time.Since(at)
	s.healthMu.Lock()
	if s.q != nil {
		q := s.q.ConnectionStats()
		if q.PacketsSent > s.sent {
			var lost uint64
			if q.PacketsLost > s.lost {
				lost = q.PacketsLost - s.lost
			}
			sample := min(1.0, float64(lost)/float64(q.PacketsSent-s.sent))
			s.loss = (s.loss + sample) / 2
		}
		s.sent, s.lost = q.PacketsSent, q.PacketsLost
	}
	if err != nil || !slices.Equal(b, nonce[:]) {
		s.failures++
	} else {
		s.failures = 0
		if s.rtt != 0 {
			s.jitter = (3*s.jitter + (rtt - s.rtt).Abs()) / 4
			s.rtt = (3*s.rtt + rtt) / 4
		} else {
			s.rtt = rtt
		}
	}
	failures := s.failures
	s.healthMu.Unlock()
	if failures >= n.o.Probe.FailureThreshold {
		s.close()
		return
	}
	if failures == 0 {
		n.mu.Lock()
		s.lastAlive = time.Now()
		if c, ok := n.conflicts[s.peer]; ok && c.confirmedAt.IsZero() && !at.Before(c.since) && s.lastAlive.Before(c.confirmBy) && n.usableLocked(s) && c.keep == s.instance {
			c.confirmedAt = s.lastAlive
			n.conflicts[s.peer] = c
			n.admissions++
		}
		n.mu.Unlock()
		n.exchangeAdvert(s)
	}
	n.tryTask(n.backgroundSlots, func() { n.probeAlternatePaths(s, failures) })
}
