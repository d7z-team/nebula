package nebula

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/header"
)

// holepunchQueueSize buffers the channel that pending holepunchJobs land on after their delay timer fires.
const holepunchQueueSize = 64

var punchPacket = []byte{1}

// holepunchJob is one scheduled item delivered to the worker goroutine.
//   - target valid -> send a UDP punch to target. vpnAddr, if set, is the peer's vpn addr carried for log context.
//   - target invalid, vpnAddr valid -> send an encrypted test packet to vpnAddr (a "punchback").
type holepunchJob struct {
	target  netip.AddrPort
	vpnAddr netip.Addr
}

type punchManager struct {
	punch           bool
	respond         bool
	delay           time.Duration
	respondDelay    time.Duration
	punchEverything bool

	sched     *scheduler[holepunchJob]
	punchConn DatagramTransport

	ctx    context.Context
	engine *packetEngine
	lh     *lighthouse

	l *slog.Logger
}

func newPunchManager(l *slog.Logger, transport DatagramTransport, cfg PunchyOptions) *punchManager {
	if cfg.Delay <= 0 {
		cfg.Delay = time.Second
	}
	if cfg.RespondDelay <= 0 {
		cfg.RespondDelay = 5 * time.Second
	}
	return &punchManager{
		l: l, punchConn: transport,
		sched: newScheduler[holepunchJob](holepunchQueueSize),
		punch: cfg.Punch, respond: cfg.Respond,
		delay: cfg.Delay, respondDelay: cfg.RespondDelay,
		punchEverything: cfg.TargetAllRemotes,
	}
}

// Schedule queues a punch packet to target, to be sent after the configured delay.
// vpnAddr is the peer's vpn addr, used for log context when the packet actually fires.
// No-op if target is not a valid AddrPort or if Start has not yet been called. Safe to call from any goroutine.
func (p *punchManager) Schedule(target netip.AddrPort, vpnAddr netip.Addr) {
	if !target.IsValid() || p.ctx == nil {
		return
	}
	p.sched.Schedule(p.ctx, holepunchJob{target: target, vpnAddr: vpnAddr}, p.delay)
}

// ScheduleRespond queues a punchback test packet to vpnAddr after the configured respond delay,
// gated on punchy.respond. No-op when respond is disabled or before Start has been called.
func (p *punchManager) ScheduleRespond(vpnAddr netip.Addr) {
	if !p.respond || p.ctx == nil {
		return
	}
	p.sched.Schedule(p.ctx, holepunchJob{vpnAddr: vpnAddr}, p.respondDelay)
}

// SendPunch sends an immediate keepalive punch for an idle hostinfo.
// Target-all-remotes mode picks the targets. It is gated by PunchyOptions.Punch and the lighthouse-skip rule
// (lighthouses don't get keepalive punches because the regular update interval keeps their NAT state warm).
func (p *punchManager) SendPunch(hostinfo *hostInfo) {
	if !p.punch {
		return
	}
	if p.lh.IsAnyLighthouseAddr(hostinfo.vpnAddrs) {
		return
	}

	if p.punchEverything {
		p.sendPunchToAllRemotes(hostinfo)
	} else if hr := hostinfo.GetRemote(); hr.IsValid() {
		p.punchConn.WriteTo(punchPacket, hr)
	}
}

// SendPunchToAll punches every known remote for hostinfo, but only when punchy.target_all_remotes is enabled.
// The connection manager calls this during outbound-only traffic: the outbound traffic itself keeps the primary's
// NAT state warm, but non-primary remotes need separate refresh, so we fan out to all of them (the redundant
// primary punch is harmless). Gated on punchy.punch and the lighthouse-skip rule.
func (p *punchManager) SendPunchToAll(hostinfo *hostInfo) {
	if !p.punchEverything || !p.punch || p.lh.IsAnyLighthouseAddr(hostinfo.vpnAddrs) {
		return
	}
	p.sendPunchToAllRemotes(hostinfo)
}

func (p *punchManager) sendPunchToAllRemotes(hostinfo *hostInfo) {
	for _, addr := range hostinfo.remotes.candidates().endpoints {
		p.punchConn.WriteTo(punchPacket, addr)
	}
}

// run drains scheduled punch work until the node context is cancelled.
func (p *punchManager) run(ctx context.Context) {
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)
	empty := []byte{0}

	p.sched.Run(ctx, func(job holepunchJob) {
		switch {
		case job.target.IsValid():
			if p.l.Enabled(context.Background(), slog.LevelDebug) {
				p.l.Debug("Punching", "target", job.target, "vpnAddr", job.vpnAddr)
			}
			p.punchConn.WriteTo(empty, job.target)
		case job.vpnAddr.IsValid():
			// A nebula test packet to the host trying to contact us.
			// In the case of a double nat or other difficult scenario, this may help establish a tunnel.
			if p.l.Enabled(context.Background(), slog.LevelDebug) {
				p.l.Debug("Sending a nebula test packet", "vpnAddr", job.vpnAddr)
			}
			p.engine.SendMessageToVpnAddr(header.Test, header.TestRequest, job.vpnAddr, []byte(""), nb, out)
		}
	})
}
