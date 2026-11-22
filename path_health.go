package nebula

import (
	"math/bits"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// PathCheckResult records what the authenticated round trip actually traversed.
type PathCheckResult struct {
	Sent, Received TunnelPath
	SamePath       bool  // Both directions used the same local route and relay mapping.
	Err            error // Outcome retained in the peer snapshot.
	RTT            time.Duration
	At             time.Time
}

type PathQuality struct {
	Path                    TunnelPath
	Degraded                bool
	LastProbe               time.Time
	Interval                time.Duration // Actual time between completed samples on this path.
	SRTT, Jitter            time.Duration
	Samples, Timeouts       int // Completed checks in the configured rolling sample window.
	LastSuccess, RetryAfter time.Time
}

type PeerPathSnapshot struct {
	Policy          PeerPathPolicy
	Active, Standby PathQuality
	LastCheck       PathCheckResult
	Changed         time.Time
	Reason          string
}

type pathSample struct {
	PathQuality
	window                    uint64
	failures, wins, symmetric int
	previous, deviation       time.Duration
	measured                  time.Time
}

func (s *pathSample) observe(result PathCheckResult, cfg *PathSelectionOptions) {
	now, rtt := result.At, result.RTT
	if !s.LastProbe.IsZero() {
		s.Interval = now.Sub(s.LastProbe)
	}
	s.LastProbe = now
	s.window = (s.window << 1) & (uint64(1)<<cfg.SampleWindow - 1)
	s.Samples = min(s.Samples+1, cfg.SampleWindow)
	if result.Err != nil {
		s.window |= 1
		s.failures++
		s.wins = 0
		if s.failures >= cfg.FailureThreshold {
			delay := cfg.MinBackoff
			for i := cfg.FailureThreshold; i < s.failures && delay < cfg.MaxBackoff; i++ {
				delay += min(delay, cfg.MaxBackoff-delay)
			}
			s.RetryAfter = now.Add(delay)
		}
	} else {
		s.LastSuccess = now
		s.failures = 0
		s.RetryAfter = time.Time{}
		if result.SamePath {
			if s.SRTT == 0 || now.Sub(s.measured) > cfg.MeasurementTTL {
				s.SRTT = rtt
				s.deviation = rtt / 2
				s.Jitter = 0
				s.symmetric = 0
			} else {
				s.deviation += ((rtt - s.SRTT).Abs() - s.deviation) / 4
				s.SRTT += (rtt - s.SRTT) / 8
				s.Jitter += ((rtt - s.previous).Abs() - s.Jitter) / 4
			}
			s.previous = rtt
			s.symmetric++
			s.measured = now
		} else {
			s.wins = 0
			s.symmetric = 0
		}
	}
	s.Timeouts = bits.OnesCount64(s.window)
	s.Degraded = s.failures > 0 || (s.symmetric >= 3 && s.Jitter >= max(cfg.JitterThreshold, percentage(s.SRTT, cfg.JitterPercent)))
}

// percentage avoids multiplying a full-width duration before division.
func percentage(d time.Duration, pct int) time.Duration {
	return (d/100)*time.Duration(pct) + (d%100)*time.Duration(pct)/100
}

// readyForFailover reports whether a standby has a recent, uninterrupted success.
func (s *pathSample) readyForFailover(now time.Time, freshness time.Duration) bool {
	return s != nil && s.failures == 0 && now.Sub(s.LastSuccess) < freshness
}

func (s *pathSample) cost() time.Duration {
	return s.SRTT + 2*s.Jitter + time.Duration(s.Timeouts)*max(200*time.Millisecond, 4*s.SRTT)/time.Duration(max(s.Samples, 1))
}

type pathProbe struct {
	id              [probeSize]byte
	route           tunnelRoute
	policyVersion   uint64
	epoch           uint32
	start, deadline time.Time
	done            chan struct{}
	result          PathCheckResult
}

type sessionPaths struct {
	mu              sync.Mutex
	retired         bool
	policyVersion   uint64
	epoch           uint32
	active, standby tunnelRoute
	samples         map[tunnelRoute]*pathSample
	pending         *pathProbe

	last                 PathCheckResult
	reason               string
	changed, demand      time.Time
	roamCandidate        netip.AddrPort
	lastRoamProbeRequest time.Time

	nextActive, nextBackup   time.Time
	nextDiscovery, nextBuild time.Time
	neighborCheck            bool
	nextNeighbor             time.Time
	building                 netip.Addr
	mappingPending           bool
	buildUntil, recoverAfter time.Time
	cursor                   int
}

func (s *sessionPaths) setHandshakeRoute(r tunnelRoute, now time.Time, activeInterval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.changed, s.reason = r, now, "handshake"
	s.demand = now
	s.nextActive = now.Add(activeInterval)
}

// syncEpoch discards measurements made on a previous local binding. Caller holds mu.
func (s *sessionPaths) syncEpoch(epoch uint32, now time.Time) {
	if s.epoch == epoch {
		return
	}
	s.epoch = epoch
	s.samples = nil
	s.standby = tunnelRoute{}
	s.nextActive, s.nextBackup = now, now
}

func (s *sessionPaths) failedDirect(addr netip.AddrPort, threshold int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sample := s.samples[tunnelRoute{TunnelPath: TunnelPath{Endpoint: addr}}]
	return sample != nil && sample.failures >= threshold
}

// verifyNeighbor coalesces dependent peers' recovery checks on the direct adjacency.
func (h *hostInfo) verifyNeighbor(since, now time.Time) bool {
	s := &h.paths
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.samples[tunnelRoute{TunnelPath: TunnelPath{Endpoint: h.GetRemote()}}]
	if q != nil && q.failures == 0 && !q.LastSuccess.Before(since) {
		return true
	}
	if !now.Before(s.nextNeighbor) && (q == nil || !now.Before(q.RetryAfter)) {
		s.neighborCheck = true
		s.nextNeighbor = now.Add(time.Second)
	}
	return false
}

func (f *packetEngine) currentRoute(h *hostInfo) tunnelRoute {
	s := &h.paths
	s.mu.Lock()
	r := s.active
	s.mu.Unlock()
	if f.routeLive(h, r) {
		return r
	}
	return tunnelRoute{}
}

func (f *packetEngine) pathSnapshot(h *hostInfo) PeerPathSnapshot {
	s := &h.paths
	policy := f.paths.config.Load().policy(h.vpnAddrs, f.hostMap)
	policy.Relays = slices.Clone(policy.Relays)
	s.mu.Lock()
	r, alt := s.active, s.standby
	v := PeerPathSnapshot{Policy: policy, Changed: s.changed, Reason: s.reason, LastCheck: s.last}
	v.Active.Path = r.TunnelPath
	if q := s.samples[r]; q != nil {
		v.Active = q.PathQuality
	}
	if q := s.samples[alt]; q != nil {
		v.Standby = q.PathQuality
	}
	s.mu.Unlock()
	if !f.routeLive(h, r) {
		v.Active = PathQuality{}
	}
	if !f.routeLive(h, alt) {
		v.Standby = PathQuality{}
	}
	return v
}

func (s *sessionPaths) complete(p *pathProbe, result PathCheckResult) {
	s.pending = nil
	if result.At.IsZero() {
		result.At = time.Now()
	}
	s.last = result
	p.result = result
	close(p.done)
}

// record runs under the session lock, after the reply or timeout has been attributed.
func (s *sessionPaths) record(r tunnelRoute, result PathCheckResult, cfg *PathSelectionOptions) {
	now := result.At
	if s.samples == nil {
		s.samples = make(map[tunnelRoute]*pathSample)
	}
	q := s.samples[r]
	if q == nil {
		if len(s.samples) >= 8 {
			for old := range s.samples {
				if old != s.active && old != s.standby {
					delete(s.samples, old)
					break
				}
			}
		}
		q = &pathSample{PathQuality: PathQuality{Path: r.TunnelPath}}
		s.samples[r] = q
	}
	q.observe(result, cfg)
	if result.Err != nil {
		if r == s.active {
			s.nextActive = now.Add(cfg.RetryInterval)
			if q.failures >= cfg.FailureThreshold {
				s.active = tunnelRoute{}
				s.reason = "probe timeout"
				if alt := s.samples[s.standby]; alt.readyForFailover(now, cfg.Freshness) {
					s.active = s.standby
					s.reason = "failover"
				}
				s.standby = tunnelRoute{}
				s.changed = now
				s.nextBackup = now
			}
		} else if r == s.standby && q.failures >= cfg.FailureThreshold {
			s.standby = tunnelRoute{}
		}
		return
	}
	if !s.active.Endpoint.IsValid() {
		s.active = r
		s.changed = now
		s.reason = "verified"
		s.standby = tunnelRoute{}
		return
	}
	if r == s.active {
		return
	}
	previous := s.samples[s.standby]
	if previous == nil || previous.failures != 0 || now.Sub(previous.LastSuccess) > cfg.Freshness || r == s.standby || (q.symmetric > 0 && (previous.symmetric == 0 || q.cost() < previous.cost())) {
		s.standby = r
	}
	cur := s.samples[s.active]
	if cur == nil || cur.symmetric == 0 || q.symmetric == 0 || now.Sub(cur.measured) > cfg.Freshness || cur.cost()-q.cost() < max(cfg.MinImprovement, percentage(cur.cost(), cfg.ImprovementPercent)) {
		q.wins = 0
		return
	}
	q.wins++
	if q.wins >= cfg.SwitchThreshold && q.symmetric >= cfg.SwitchThreshold && now.Sub(s.changed) >= cfg.HoldTime {
		s.active, s.standby = r, s.active
		s.changed = now
		s.reason = "better quality"
		q.wins = 0
	}
}
