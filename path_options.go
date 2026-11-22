package nebula

import (
	"errors"
	"net/netip"
	"time"
)

// PathOptions configures node-wide probing, route selection and peer policies.
type PathOptions struct {
	Probes    PathProbeOptions
	Selection PathSelectionOptions
	Default   PeerPathPolicy
	Peers     map[netip.Addr]PeerPathPolicy
}

// PacketBudget limits a node to a burst followed by one packet per Every.
type PacketBudget struct {
	Burst int
	Every time.Duration
}

// PathProbeOptions controls node-wide sampling. Nonpositive values use defaults.
// MonitorInterval on a peer overrides the active interval while idle and the
// standby is then checked about three times less frequently.
type PathProbeOptions struct {
	TickInterval    time.Duration // Scheduler resolution. Default 125ms.
	SweepInterval   time.Duration // Check pending relays and disconnected monitored peers. Default 10s.
	ActiveInterval  time.Duration // Active path while busy. Default 10s.
	StandbyInterval time.Duration // Healthy standby while busy. Default 30s.
	IdleTimeout     time.Duration // Time since last demand before idle scheduling. Default 1m.
	InitialTimeout  time.Duration // Reply timeout before the first RTT estimate. Default 1s.
	MinTimeout      time.Duration // Lower bound on the reply timeout. Default 300ms.
	MaxTimeout      time.Duration // Upper bound on the reply timeout. Default 5s.
	CheckTimeout    time.Duration // CheckPeerPath wait after connection setup. Default 10s.
	ControlBudget   PacketBudget  // All rate-limited control traffic. Default 40, one per 10ms.
	ProbeBudget     PacketBudget  // Budget for scheduled and manual path samples. Default 10, one per 50ms.
}

// PathSelectionOptions controls automatic switching between authenticated paths.
// Nonpositive fields use their defaults.
type PathSelectionOptions struct {
	SampleWindow       int           // Recent checks used to count losses, 1 through 64. Default 16.
	ImprovementPercent int           // Minimum improvement as a percentage of active path cost. Default 20.
	JitterPercent      int           // Jitter threshold as a percentage of smoothed RTT. Default 20.
	FailureThreshold   int           // Consecutive timeouts before failover and backoff. Default 3.
	SwitchThreshold    int           // Consecutive wins and same-path samples for a performance switch. Default 3.
	HoldTime           time.Duration // Minimum time on the active path before a performance switch. Default 30s.
	Freshness          time.Duration // Maximum age of a standby success or active comparison sample. Default 45s.
	MeasurementTTL     time.Duration // Reset the RTT estimator after this gap. Default 90s.
	MinImprovement     time.Duration // Absolute floor on the required cost improvement. Default 15ms.
	JitterThreshold    time.Duration // Absolute floor for degraded jitter. Default 15ms.
	RetryInterval      time.Duration // Delay after an active path timeout. Default 250ms.
	MinBackoff         time.Duration // Initial cooldown for a failed path. Default 30s.
	MaxBackoff         time.Duration // Maximum cooldown for consecutive failures. Default 5m.
	RecoveryInterval   time.Duration // Minimum interval between recovery handshakes. Default 30s.
}

func (opts *PathOptions) normalizeTuning() error {
	p := &opts.Probes
	p.TickInterval = positiveOr(p.TickInterval, 125*time.Millisecond)
	p.SweepInterval = positiveOr(p.SweepInterval, 10*time.Second)
	p.ActiveInterval = positiveOr(p.ActiveInterval, 10*time.Second)
	p.StandbyInterval = positiveOr(p.StandbyInterval, 30*time.Second)
	p.IdleTimeout = positiveOr(p.IdleTimeout, time.Minute)
	p.InitialTimeout = positiveOr(p.InitialTimeout, time.Second)
	p.MinTimeout = positiveOr(p.MinTimeout, 300*time.Millisecond)
	p.MaxTimeout = positiveOr(p.MaxTimeout, 5*time.Second)
	p.CheckTimeout = positiveOr(p.CheckTimeout, 10*time.Second)
	p.ControlBudget.Burst = positiveOr(p.ControlBudget.Burst, 40)
	p.ControlBudget.Every = positiveOr(p.ControlBudget.Every, 10*time.Millisecond)
	p.ProbeBudget.Burst = positiveOr(p.ProbeBudget.Burst, 10)
	p.ProbeBudget.Every = positiveOr(p.ProbeBudget.Every, 50*time.Millisecond)
	if p.MinTimeout > p.MaxTimeout {
		return errors.New("path probes: MinTimeout exceeds MaxTimeout")
	}

	s := &opts.Selection
	s.SampleWindow = positiveOr(s.SampleWindow, 16)
	s.ImprovementPercent = positiveOr(s.ImprovementPercent, 20)
	s.JitterPercent = positiveOr(s.JitterPercent, 20)
	s.FailureThreshold = positiveOr(s.FailureThreshold, 3)
	s.SwitchThreshold = positiveOr(s.SwitchThreshold, 3)
	s.HoldTime = positiveOr(s.HoldTime, 30*time.Second)
	s.Freshness = positiveOr(s.Freshness, 45*time.Second)
	s.MeasurementTTL = positiveOr(s.MeasurementTTL, 90*time.Second)
	s.MinImprovement = positiveOr(s.MinImprovement, 15*time.Millisecond)
	s.JitterThreshold = positiveOr(s.JitterThreshold, 15*time.Millisecond)
	s.RetryInterval = positiveOr(s.RetryInterval, 250*time.Millisecond)
	s.MinBackoff = positiveOr(s.MinBackoff, 30*time.Second)
	s.MaxBackoff = positiveOr(s.MaxBackoff, 5*time.Minute)
	s.RecoveryInterval = positiveOr(s.RecoveryInterval, 30*time.Second)
	if s.SampleWindow > 64 {
		return errors.New("path selection: SampleWindow exceeds 64")
	}
	if s.ImprovementPercent > 100 || s.JitterPercent > 100 {
		return errors.New("path selection: percentages must be at most 100")
	}
	if s.MinBackoff > s.MaxBackoff {
		return errors.New("path selection: MinBackoff exceeds MaxBackoff")
	}
	return nil
}
