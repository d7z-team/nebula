package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.d7z.net/nebula"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

var (
	runExtended = flag.Bool("extended", false, "run extended mesh fault scenarios")
	chaosSeed   = flag.Int64("seed", 1, "seed for the bounded chaos scenario")
)

func extended(t *testing.T) {
	t.Helper()
	if !*runExtended {
		t.Skip("enable with -extended")
	}
}

// Keep the same application sockets across path and credential changes.
func receipt(t *testing.T, a, b net.Conn, seq int) {
	t.Helper()
	data := bytes.Repeat([]byte(fmt.Sprintf("payload-%d/", seq)), 256)
	sum := sha256.Sum256(data)
	deadline := time.Now().Add(12 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))
	_, err := a.Write(data)
	require.NoError(t, err)
	in := make([]byte, len(data))
	_, err = io.ReadFull(b, in)
	require.NoError(t, err)
	ack := sha256.Sum256(in)
	_, err = b.Write(ack[:])
	require.NoError(t, err)
	_, err = io.ReadFull(a, ack[:])
	require.NoError(t, err)
	require.Equal(t, sum, ack)
	t.Logf("receipt seq=%d bytes=%d sha256=%x", seq, len(data), ack)
}

func TestLossAndNarrowPath(t *testing.T) {
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "udp", true)
	b := l.host("wan", "192.0.2.2", "", "udp", true)
	a.options.DialTimeout = 4 * time.Second
	var dropped, delayed atomic.Int32
	l.net.disturb(func(d datagram) disturbance {
		if d.protocol != 17 {
			return disturbance{}
		}
		if d.size > 1200 || d.from.Addr() == netip.MustParseAddr("192.0.2.1") && (d.number == 1 || d.number == 6 || d.number == 7) {
			dropped.Add(1)
			return disturbance{drop: true}
		}
		if d.number%3 == 0 {
			delayed.Add(1)
			return disturbance{delay: 8 * time.Millisecond}
		}
		return disturbance{}
	})
	l.start()
	l.connect(a, b, "udp")
	left, right := l.business(a), l.business(b)
	dest := tcpip.FullAddress{Addr: addr("fd42::2"), Port: 7001}
	server, err := gonet.DialUDP(right, &dest, nil, ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer server.Close()
	client, err := gonet.DialUDP(left, nil, &dest, ipv6.ProtocolNumber)
	require.NoError(t, err)
	defer client.Close()
	data := bytes.Repeat([]byte{0xc5}, 1232) // IPv6 + UDP + payload is exactly 1280 bytes.
	_, err = client.Write(data)
	require.NoError(t, err)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(4*time.Second)))
	got := make([]byte, 1500)
	n, remote, err := server.ReadFrom(got)
	require.NoError(t, err)
	require.Equal(t, data, got[:n])
	_, err = server.WriteTo(got[:n], remote)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(4*time.Second)))
	n, err = client.Read(got)
	require.NoError(t, err)
	require.Equal(t, data, got[:n])
	path := waitPath(t, a, b, "udp")
	require.Positive(t, path.StreamFallbacks)
	require.Less(t, path.DatagramSize, int64(1280))
	require.GreaterOrEqual(t, dropped.Load(), int32(3))
	require.Positive(t, delayed.Load())
}

func TestChaosFailoverAndRenewal(t *testing.T) {
	extended(t)
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "both", true)
	b := l.host("wan", "192.0.2.2", "", "both", true)
	l.net.disturb(func(d datagram) disturbance { return disturbance{drop: d.protocol == 6} })
	l.start()
	old := l.connect(a, b, "udp")
	c, d := tcpPair(t, l.business(a), l.business(b), b.ip.String(), ipv4.ProtocolNumber)
	receipt(t, c, d, 0)
	fresh := l.issueCredentials(b, l.issuer)
	require.NoError(t, b.node.ReloadCertificates(t.Context(), fresh))
	require.Equal(t, old.GrantSerial, waitPath(t, a, b, "udp").GrantSerial)
	// Isolate one direction after renewal. A TCP standby must authenticate
	// with the new leaf before it can carry the original inner stream.
	var lost atomic.Int64
	l.net.disturb(func(d datagram) disturbance {
		drop := d.protocol == 17 && d.from.Addr() == netip.MustParseAddr("192.0.2.1")
		if drop {
			lost.Add(1)
		}
		return disturbance{drop: drop}
	})
	receipt(t, c, d, 1)
	path := waitPath(t, a, b, "tcp")
	require.Equal(t, fresh.Node.Leaf.SerialNumber.String(), path.NodeSerial)
	require.Positive(t, lost.Load())
	receipt(t, c, d, 2)
	l.net.disturb(nil)
	waitPath(t, a, b, "udp")
	receipt(t, c, d, 3)
}

func TestChaosNATRebindAndWithdrawal(t *testing.T) {
	extended(t)
	l := newLab(t)
	g := edge("lan", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, portFilter)
	g.install(t, l.net)
	a := l.host("lan", "10.1.0.2", "10.1.0.1", "udp", false)
	b := l.host("wan", "192.0.2.20", "", "udp", true)
	l.link(a, b)
	l.start()
	l.connect(a, b, "udp")
	require.Equal(t, "192.0.2.1:45001", waitPath(t, b, a, "udp").Endpoint.String())
	left, right := l.business(a), l.business(b)
	c, d := tcpPair(t, left, right, b.ip.String(), ipv4.ProtocolNumber)
	receipt(t, c, d, 0)
	g.bindings[0].port = 45002
	g.install(t, l.net)
	require.Eventually(t, func() bool {
		p, ok := b.node.PreferredPath(a.node.ID())
		return ok && p.Endpoint.String() == "192.0.2.1:45002"
	}, 15*time.Second, 50*time.Millisecond)
	receipt(t, c, d, 1)
	before := flow{"wan", netip.MustParseAddrPort("192.0.2.1:45002"), netip.MustParseAddrPort("192.0.2.20:4242"), 17}
	require.Positive(t, l.net.packets(before))
	require.NoError(t, a.node.SetPeerPathPolicy(b.node.ID(), nebula.Blocked))
	require.ErrorIs(t, a.node.ConnectPeer(t.Context(), b.ip), nebula.ErrPathPolicy)
	require.Empty(t, a.node.Paths())
	dest := tcpip.FullAddress{Addr: gvisorAddr(b.ip), Port: 7011}
	rx, err := gonet.DialUDP(right, &dest, nil, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer rx.Close()
	tx, err := gonet.DialUDP(left, nil, &dest, ipv4.ProtocolNumber)
	require.NoError(t, err)
	defer tx.Close()
	// UDP may report the policy rejection at write time or drop the packet.
	_, _ = tx.Write([]byte("withdrawn"))
	var msg [64]byte
	require.NoError(t, rx.SetReadDeadline(time.Now().Add(2*a.options.MaintenanceInterval)))
	_, err = rx.Read(msg[:])
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	require.NoError(t, a.node.SetPeerPathPolicy(b.node.ID(), nebula.Auto))
	l.connect(a, b, "udp")
	_, err = tx.Write([]byte("restored"))
	require.NoError(t, err)
	require.NoError(t, rx.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err := rx.Read(msg[:])
	require.NoError(t, err)
	require.Equal(t, "restored", string(msg[:n]))
	receipt(t, c, d, 2)
}

func TestChaosMobileHandover(t *testing.T) {
	extended(t)
	l := newLab(t)
	g := edge("lan", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, portFilter)
	g.install(t, l.net)
	mobile := l.host("lan", "10.1.0.2", "10.1.0.1", "udp", false)
	fixed := l.host("wan", "192.0.2.20", "", "udp", true)
	for _, h := range l.hosts {
		// Exercise the node's production probe and dial timing.
		h.options.MaintenanceInterval, h.options.DialTimeout = 0, 0
	}
	l.start()
	l.connect(mobile, fixed, "udp")
	initial := waitPath(t, fixed, mobile, "udp")
	require.Equal(t, netip.AddrPortFrom(g.public.Addr(), g.bindings[0].port), initial.Endpoint)
	client, server := tcpPair(t, l.business(mobile), l.business(fixed), fixed.ip.String(), ipv4.ProtocolNumber)
	receipt(t, client, server, 0)

	for step := 1; step <= 4; step++ {
		g.public = netip.PrefixFrom(g.public.Addr().Next(), g.public.Bits())
		g.bindings[0].port++
		endpoint := netip.AddrPortFrom(g.public.Addr(), g.bindings[0].port)
		t.Logf("handover %d to %s", step, endpoint)
		var reopen time.Time // Fault callbacks run under the network lock.
		var dropped atomic.Int32
		start := time.Now()
		l.net.disturb(func(d datagram) disturbance {
			if d.segment != "wan" {
				return disturbance{}
			}
			if d.from != endpoint && d.to != endpoint {
				return disturbance{drop: true}
			}
			// Start the outage on the first packet using the new mapping.
			now := time.Now()
			if reopen.IsZero() {
				reopen = now.Add(400 * time.Millisecond)
			}
			if now.Before(reopen) {
				dropped.Add(1)
				return disturbance{drop: true}
			}
			return disturbance{delay: time.Duration(1+d.number%4) * 20 * time.Millisecond}
		})
		g.install(t, l.net)
		receipt(t, client, server, step)
		t.Logf("handover %d receipt after %s, dropped %d packets during outage", step, time.Since(start), dropped.Load())
		require.Positive(t, dropped.Load())
		require.Eventually(t, func() bool {
			p, ok := fixed.node.PreferredPath(mobile.node.ID())
			return ok && p.Transport == "udp" && p.Endpoint == endpoint
		}, 12*time.Second, 20*time.Millisecond, "handover %d: expected active endpoint %s", step, endpoint)
	}
}

func TestChaosCanaryAfterNATRebind(t *testing.T) {
	extended(t)
	l := newLab(t)
	g := edge("lan", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, portFilter)
	g.install(t, l.net)
	mobile := l.host("lan", "10.1.0.2", "10.1.0.1", "udp", false)
	fixed := l.host("wan", "192.0.2.20", "", "udp", true)
	observer := l.host("wan", "192.0.2.50", "", "udp", true)
	old := netip.AddrPortFrom(g.public.Addr(), g.bindings[0].port)
	l.top.Members[observer.index].Transit = true
	observerID := l.top.Members[observer.index].ID
	mobile.options.Transport.AllowAdvertiseEndpoint = func(c nebula.EndpointCandidate) bool {
		return c.Source == nebula.EndpointFromObservation && c.Observer == observerID
	}
	wan := netip.MustParsePrefix("192.0.2.0/24")
	fixed.options.Transport.AllowOutboundEndpoint = func(ep nebula.Endpoint) bool {
		return wan.Contains(ep.Address.Addr())
	}
	l.link(fixed, observer)
	l.link(mobile, observer)
	// The mobile peer answers rendezvous but leaves direct dialing to the fixed peer.
	mobile.options.Probe.Interval = time.Minute
	fixed.options.DialTimeout = 2 * time.Second
	l.start()
	l.top.Members[mobile.index].Endpoints = []nebula.Endpoint{{Network: "udp", Address: old}}
	require.NoError(t, fixed.node.ApplyTopology(t.Context(), l.top))
	l.connect(mobile, observer, "udp")
	l.connect(fixed, observer, "udp")
	require.NoError(t, fixed.node.SetPeerPathPolicy(mobile.node.ID(), nebula.RelayOnly))
	l.connect(fixed, mobile, "relay")
	mobileStack := l.business(mobile)
	c, d := tcpPair(t, l.business(fixed), mobileStack, mobile.ip.String(), ipv4.ProtocolNumber)
	receipt(t, c, d, 0)

	first := make(chan time.Time, 1)
	from := l.top.Members[fixed.index].Endpoints[0].Address
	l.net.disturb(func(d datagram) disturbance {
		if d.from == from && d.to == old && d.protocol == 17 {
			if d.size >= 1200 {
				select {
				case first <- time.Now():
				default:
				}
			}
			return disturbance{drop: true}
		}
		return disturbance{}
	})
	require.NoError(t, fixed.node.SetPeerPathPolicy(mobile.node.ID(), nebula.Auto))
	var started time.Time
	select {
	case started = <-first:
	case <-time.After(12 * time.Second):
		t.Fatal("no QUIC handshake to the old mapping")
	}
	g.bindings[0].port++
	g.install(t, l.net)
	next := netip.AddrPortFrom(g.public.Addr(), g.bindings[0].port)
	up, down := tcpPair(t, mobileStack, l.business(observer), observer.ip.String(), ipv4.ProtocolNumber)
	roundTrip(t, up, down)
	// The next healthy canary is at least five seconds away.
	require.Eventually(t, func() bool {
		p, ok := fixed.node.PreferredPath(mobile.node.ID())
		return ok && p.Transport == "udp" && p.Endpoint == next
	}, time.Until(started.Add(4500*time.Millisecond)), 15*time.Millisecond)
	require.True(t, slices.ContainsFunc(observer.node.Paths(), func(p nebula.PathStatus) bool {
		return p.Peer == mobile.node.ID() && p.Endpoint == next
	}))
	require.Positive(t, l.net.punches(flow{"wan", from, next, 17}))
	require.NoError(t, fixed.node.SetPeerPathPolicy(mobile.node.ID(), nebula.DirectOnly))
	require.NoError(t, mobile.node.SetPeerPathPolicy(fixed.node.ID(), nebula.DirectOnly))
	receipt(t, c, d, 1)
}

func TestChaosRelayPartition(t *testing.T) {
	extended(t)
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "tcp", true)
	b := l.host("wan", "192.0.2.2", "", "udp", true)
	b.options.Transport.CurvePreferences = []tls.CurveID{tls.CurveP384}
	last := l.host("wan", "192.0.2.5", "", "both", true)
	l.top.Members[last.index].Transit = true
	l.link(last, b)
	relays := map[nebula.PeerID]*host{}
	for _, ip := range []string{"192.0.2.3", "192.0.2.4"} {
		r := l.host("wan", ip, "", "tcp", true)
		relays[l.top.Members[r.index].ID] = r
		l.link(a, r)
		l.link(last, r)
		l.top.Members[r.index].Transit = true
	}
	for _, h := range []*host{a, b} {
		l.top.Members[h.index].Restricted = true
	}
	l.start()
	for _, r := range relays {
		l.connect(a, r, "tcp")
		l.connect(last, r, "tcp")
	}
	l.connect(b, last, "udp")
	path := l.connect(a, b, "relay")
	require.Equal(t, tls.CurveP384, path.TLSGroup)
	require.Len(t, path.Circuit, 4)
	require.Equal(t, l.top.Members[last.index].ID, path.Circuit[2])
	c, d := tcpPair(t, l.business(a), l.business(b), b.ip.String(), ipv4.ProtocolNumber)
	receipt(t, c, d, 0)
	primary := relays[path.Circuit[1]]
	var alternate *host
	for _, r := range relays {
		if r != primary {
			alternate = r
		}
	}
	alternateIP := l.top.Members[alternate.index].Endpoints[0].Address.Addr()
	peerIP := netip.MustParseAddr("192.0.2.1")
	l.net.disturb(func(d datagram) disturbance {
		return disturbance{drop: d.from.Addr() == peerIP && d.to.Addr() == alternateIP || d.from.Addr() == alternateIP && d.to.Addr() == peerIP}
	})
	require.NoError(t, primary.node.SetTransitDraining(true))
	receipt(t, c, d, 2)
	require.Positive(t, primary.node.RelayStatus().TransitCircuits)
	require.NoError(t, primary.node.Close())
	require.Eventually(t, func() bool {
		_, ok := a.node.PreferredPath(b.node.ID())
		return !ok
	}, 10*time.Second, 50*time.Millisecond)
	require.Error(t, a.node.ConnectPeer(t.Context(), b.ip))
	l.net.disturb(nil)
	require.Eventually(t, func() bool { return a.node.ConnectPeer(t.Context(), b.ip) == nil }, 12*time.Second, 100*time.Millisecond)
	path = waitPath(t, a, b, "relay")
	require.Equal(t, tls.CurveP384, path.TLSGroup)
	require.Equal(t, []nebula.PeerID{l.top.Members[a.index].ID, l.top.Members[alternate.index].ID, l.top.Members[last.index].ID, l.top.Members[b.index].ID}, path.Circuit)
	receipt(t, c, d, 1)
	l.net.mu.Lock()
	direct := 0
	for f, n := range l.net.count {
		if f.from.Addr() == peerIP && f.to.Addr() == netip.MustParseAddr("192.0.2.2") {
			direct += n
		}
	}
	l.net.mu.Unlock()
	require.Zero(t, direct)
}

// The five-node circuit and withdrawal run in the standard suite. Extended
// runs also interrupt the NATed relay's right adjacency on the same inner TCP flow.
func TestChaosHiddenTransit(t *testing.T) {
	l := newLab(t)
	nat := edge("lan", "10.1.0.1/24", "192.0.2.30/24", "10.1.0.2:4242", 45001, portFilter)
	nat.install(t, l.net)
	a := l.host("wan", "192.0.2.1", "", "udp", true)
	left := l.host("wan", "192.0.2.2", "", "udp", true)
	h := l.host("lan", "10.1.0.2", "10.1.0.1", "udp", false)
	right := l.host("wan", "192.0.2.4", "", "udp", true)
	b := l.host("wan", "192.0.2.5", "", "udp", true)
	l.link(a, left)
	l.link(left, h)
	l.link(h, right)
	l.link(right, b)
	for _, relay := range []*host{left, h, right} {
		l.top.Members[relay.index].Transit = true
	}
	for _, restricted := range []*host{a, h, b} {
		l.top.Members[restricted.index].Restricted = true
	}
	h.options.Transport.HideEndpoints = true
	mapped := netip.AddrPortFrom(nat.public.Addr(), nat.bindings[0].port)
	h.options.Transport.AdvertiseEndpoints = []nebula.Endpoint{{Network: "udp", Address: mapped}}
	l.start()
	l.connect(a, left, "udp")
	l.connect(b, right, "udp")
	l.connect(h, left, "udp")
	l.connect(h, right, "udp")
	require.Equal(t, mapped, waitPath(t, right, h, "udp").Endpoint)

	circuit := []nebula.PeerID{a.node.ID(), left.node.ID(), h.node.ID(), right.node.ID(), b.node.ID()}
	path := l.connect(a, b, "relay")
	require.Equal(t, circuit, path.Circuit)
	path.Circuit[1] = nebula.PeerID{}
	path, ok := a.node.PreferredPath(b.node.ID())
	require.True(t, ok)
	require.Equal(t, circuit, path.Circuit)
	back := slices.Clone(circuit)
	slices.Reverse(back)
	require.Equal(t, back, waitPath(t, b, a, "relay").Circuit)

	var submitted atomic.Bool
	a.nicOptions.ObserveTransmit = func(r nebula.TransmitResult) {
		if r.Err == nil && r.Peer == b.node.ID() && r.Transport == "relay" && slices.Equal(r.Circuit, circuit) {
			submitted.Store(true)
		}
	}
	client, server := l.business(a), l.business(b)
	c, d := tcpPair(t, client, server, b.node.Addresses().IPv6.String(), ipv6.ProtocolNumber)
	receipt(t, c, d, 0)
	require.Eventually(t, submitted.Load, time.Second, time.Millisecond)
	c4, d4 := tcpPair(t, client, server, b.ip.String(), ipv4.ProtocolNumber)
	roundTrip(t, c4, d4)

	if *runExtended {
		neighbor := l.top.Members[right.index].Endpoints[0].Address
		var dropped atomic.Uint64
		l.net.disturb(func(d datagram) disturbance {
			if (d.from == mapped && d.to == neighbor) || (d.from == neighbor && d.to == mapped) {
				dropped.Add(1)
				return disturbance{drop: true}
			}
			return disturbance{}
		})
		defer l.net.disturb(nil)
		require.Eventually(t, func() bool {
			_, leg := h.node.PreferredPath(right.node.ID())
			_, route := a.node.PreferredPath(b.node.ID())
			return !leg && !route
		}, 12*time.Second, 20*time.Millisecond)
		require.Positive(t, dropped.Load())
		l.net.disturb(nil)
		waitPath(t, h, right, "udp")
		require.Equal(t, circuit, l.connect(a, b, "relay").Circuit)
		receipt(t, c, d, 1)
	}
	matches, err := b.node.ResolveIP(t.Context(), h.ip)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, h.node.ID(), matches[0].Peer)
	require.Empty(t, matches[0].Endpoints)

	// Only H withdraws transit. Its neighbors and its own applications stay reachable.
	view := l.top
	view.Members = slices.Clone(view.Members)
	view.Members[h.index].Transit = false
	require.NoError(t, h.node.ApplyTopology(t.Context(), view))
	require.Eventually(t, func() bool {
		_, ok := a.node.PreferredPath(b.node.ID())
		return !ok
	}, 5*time.Second, 10*time.Millisecond)
	require.Error(t, a.node.ConnectPeerID(t.Context(), b.node.ID()))
	l.connect(a, h, "relay")
	hc, hd := tcpPair(t, client, l.business(h), h.ip.String(), ipv4.ProtocolNumber)
	roundTrip(t, hc, hd)
	leftAddr := l.top.Members[left.index].Endpoints[0].Address
	rightAddr := l.top.Members[right.index].Endpoints[0].Address
	var destinations []netip.AddrPort
	l.net.mu.Lock()
	for f := range l.net.count {
		if f.segment == "lan" && f.from.Addr() == nat.bindings[0].inside.Addr() {
			destinations = append(destinations, f.to)
		}
	}
	l.net.mu.Unlock()
	require.ElementsMatch(t, []netip.AddrPort{leftAddr, rightAddr}, destinations)
}

func TestMemberWithdrawalIsolation(t *testing.T) {
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "tcp", true)
	b := l.host("wan", "192.0.2.2", "", "tcp", true)
	x := l.host("wan", "192.0.2.3", "", "tcp", true)
	withdrawnID := l.top.Members[x.index].ID
	observers := []*host{a, b}
	var denied atomic.Bool
	for _, h := range observers {
		h.options.Auth.CheckChain = func(ctx context.Context, check nebula.ChainCheck) (time.Time, error) {
			if denied.Load() && check.Member == withdrawnID {
				return time.Time{}, errors.New("member withdrawn")
			}
			return time.Time{}, ctx.Err()
		}
	}
	l.start()
	l.connect(a, b, "tcp")
	l.connect(a, x, "tcp")
	l.connect(x, b, "tcp")
	client := l.business(a)
	healthy, server := tcpPair(t, client, l.business(b), b.ip.String(), ipv4.ProtocolNumber)
	toX, atX := tcpPair(t, client, l.business(x), x.ip.String(), ipv4.ProtocolNumber)
	receipt(t, healthy, server, 1)
	receipt(t, toX, atX, 2)

	denied.Store(true)
	for _, h := range observers {
		require.NoError(t, h.node.Revalidate(t.Context()))
		_, active := h.node.PreferredPath(withdrawnID)
		require.False(t, active)
	}
	receipt(t, healthy, server, 3)
	_, err := toX.Write([]byte("after withdrawal"))
	require.NoError(t, err)
	require.NoError(t, atX.SetReadDeadline(time.Now().Add(time.Second)))
	var received [1]byte
	n, err := atX.Read(received[:])
	require.Zero(t, n)
	require.Error(t, err)
	for _, pair := range [][2]*host{{a, x}, {x, a}, {b, x}, {x, b}} {
		_, err := pair[0].node.ConnectEndpoint(t.Context(), l.top.Members[pair[1].index].Endpoints[0])
		require.Errorf(t, err, "%s connected to %s after withdrawal", pair[0].ip, pair[1].ip)
	}

	// Restart an honest node with the host decision and its original key.
	require.NoError(t, a.node.Close())
	require.Eventually(t, func() bool {
		_, active := b.node.PreferredPath(a.node.ID())
		return !active
	}, 3*time.Second, time.Millisecond)
	o := a.options
	o.Transport = nebula.TransportOptions{DialTCP: o.Transport.DialTCP}
	o.Topology = nebula.Topology{Network: l.top.Network, Members: []nebula.Member{l.top.Members[a.index]}}
	o.Auth.TrustedEntrypoints = []nebula.PeerID{b.node.ID(), withdrawnID}
	restarted, err := nebula.New(t.Context(), o)
	require.NoError(t, err)
	defer restarted.Close()
	require.NoError(t, restarted.Start())
	id, err := restarted.ConnectEndpoint(t.Context(), l.top.Members[b.index].Endpoints[0])
	require.NoError(t, err)
	require.Equal(t, b.node.ID(), id)
	_, err = restarted.ConnectEndpoint(t.Context(), l.top.Members[x.index].Endpoints[0])
	require.ErrorIs(t, err, nebula.ErrPathPolicy)
}

func TestChaosCloseWithBacklog(t *testing.T) {
	extended(t)
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "both", true)
	b := l.host("wan", "192.0.2.2", "", "both", true)
	c := l.host("wan", "192.0.2.3", "", "both", true)
	l.top.Members[a.index].BytesPerSecond = 1
	l.start()
	l.connect(a, b, "udp")
	var received atomic.Int32
	_, err := b.node.OpenIPPort(nebula.IPPortOptions{Deliver: func(nebula.PeerID, []byte) { received.Add(1) }})
	require.NoError(t, err)
	port, err := a.node.OpenIPPort(nebula.IPPortOptions{Deliver: func(nebula.PeerID, []byte) {}})
	require.NoError(t, err)
	pkt := make([]byte, 16000)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 253
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[12:16], a.ip.AsSlice())
	copy(pkt[16:20], b.ip.AsSlice())
	for range 12 {
		require.NoError(t, port.WriteIP(b.node.ID(), pkt))
	}
	require.Eventually(t, func() bool { return received.Load() >= 4 && port.Stats().Queued > 0 }, 3*time.Second, 10*time.Millisecond)
	var attempts atomic.Int32
	l.net.disturb(func(d datagram) disturbance {
		if d.to.Addr() == netip.MustParseAddr("192.0.2.3") {
			attempts.Add(1)
			return disturbance{drop: true}
		}
		return disturbance{}
	})
	waiter, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- a.node.ConnectPeer(waiter, c.ip) }()
	require.Eventually(t, func() bool { return attempts.Load() > 0 }, time.Second, time.Millisecond)
	dial := make(chan error, 1)
	go func() { dial <- a.node.ConnectPeer(t.Context(), c.node.Addresses().IPv6) }()
	cancel()
	select {
	case err := <-first:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled caller still waiting for the unreachable peer")
	}
	done := make(chan error, 1)
	go func() { done <- a.node.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("close stalled with pending work")
	}
	select {
	case err := <-dial:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("dial still waiting after close")
	}
	require.Zero(t, port.Stats().Queued)
	require.True(t, a.node.ControlStatus().Closed)
}

func TestSeededChaos(t *testing.T) {
	extended(t)
	l := newLab(t)
	a := l.host("wan", "192.0.2.1", "", "both", true)
	b := l.host("wan", "192.0.2.2", "", "both", true)
	l.start()
	l.connect(a, b, "udp")
	c, d := tcpPair(t, l.business(a), l.business(b), b.ip.String(), ipv4.ProtocolNumber)
	current := b.options.Auth.Certificates
	rng := rand.New(rand.NewSource(*chaosSeed))
	for step := range 8 {
		action := rng.Intn(5)
		t.Logf("seed=%d step=%d action=%s", *chaosSeed, step, []string{"delay and reorder", "UDP outage", "renew credentials", "withdraw and restore", "burst loss"}[action])
		var affected atomic.Int32
		switch action {
		case 0, 4:
			n := 0
			l.net.disturb(func(d datagram) disturbance {
				if d.protocol != 17 {
					return disturbance{}
				}
				n++
				if action == 0 && n%3 == 1 {
					affected.Add(1)
					return disturbance{delay: 5 * time.Millisecond}
				}
				if action == 4 && n <= 3 {
					affected.Add(1)
					return disturbance{drop: true}
				}
				return disturbance{}
			})
		case 1:
			l.net.disturb(func(d datagram) disturbance { return disturbance{drop: d.protocol == 17} })
			waitPath(t, a, b, "tcp")
		case 2:
			fresh := l.issueCredentials(b, l.issuer)
			if step%2 == 0 {
				current.Node = fresh.Node
			} else {
				current.Grant = fresh.Grant
			}
			require.NoError(t, b.node.ReloadCertificates(t.Context(), current))
			status := b.node.ControlStatus()
			grant, err := x509.ParseCertificate(current.Grant[0])
			require.NoError(t, err)
			require.Equal(t, grant.SerialNumber.String(), status.GrantSerial)
			require.Equal(t, current.Node.Leaf.SerialNumber.String(), status.NodeSerial)
		case 3:
			require.NoError(t, a.node.SetPeerPathPolicy(b.node.ID(), nebula.Blocked))
			require.ErrorIs(t, a.node.ConnectPeer(t.Context(), b.ip), nebula.ErrPathPolicy)
			require.NoError(t, a.node.SetPeerPathPolicy(b.node.ID(), nebula.Auto))
			l.connect(a, b, "udp")
		}
		receipt(t, c, d, step)
		if action == 0 || action == 4 {
			require.Positive(t, affected.Load())
		}
		l.net.disturb(nil)
		waitPath(t, a, b, "udp")
	}
}
