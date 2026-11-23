package e2e_test

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type linkAddress struct {
	segment string
	ip      netip.Addr
}

type flow struct {
	segment  string
	from, to netip.AddrPort
	protocol byte
}

type datagram struct {
	flow
	size   int // transport payload for UDP
	number int // sequence on this directed flow
}

type disturbance struct {
	drop  bool
	delay time.Duration
}

type network struct {
	mu    sync.Mutex
	links map[linkAddress]*channel.Endpoint
	count map[flow]int
	punch map[flow]int
	fault func(datagram) disturbance
	// NAT ingress filtering is independent of the translation gVisor performs.
	gates          map[linkAddress]*natGate
	forwardHeaders sync.Map // *stack.PacketBuffer to owned IPv4 header
}

func newNetwork() *network {
	return &network{links: make(map[linkAddress]*channel.Endpoint), count: make(map[flow]int), punch: make(map[flow]int), gates: make(map[linkAddress]*natGate)}
}

func (n *network) disturb(f func(datagram) disturbance) {
	n.mu.Lock()
	n.fault = f
	n.mu.Unlock()
}

func (n *network) packets(f flow) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.count[f]
}

// The virtual links carry IP without Ethernet headers or IPv6 extension headers.
func decodeDatagram(seg string, b []byte) datagram {
	var src, dst netip.Addr
	var protocol byte
	var off int
	switch b[0] >> 4 {
	case 4:
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		protocol, off = b[9], int(b[0]&15)*4
	case 6:
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		protocol, off = b[6], 40
	default:
		return datagram{}
	}
	var sport, dport uint16
	if (protocol == 6 || protocol == 17) && len(b) >= off+4 {
		sport = binary.BigEndian.Uint16(b[off:])
		dport = binary.BigEndian.Uint16(b[off+2:])
	}
	d := datagram{flow: flow{seg, netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport), protocol}, size: len(b) - off}
	if protocol == 17 {
		d.size -= 8
	}
	return d
}

// attach joins one L3 segment. A destination on another segment is reachable
// only through the configured next hop. Each stack still performs IP routing.
func (n *network) attach(t *testing.T, s *stack.Stack, id tcpip.NICID, seg, address, via string) {
	t.Helper()
	local := linkAddress{seg, netip.MustParseAddr(address)}
	var gateway netip.Addr
	if via != "" {
		gateway = netip.MustParseAddr(via)
	}
	ep := channel.New(256, 1500, "")
	addNIC(t, s, id, ep, address)
	n.mu.Lock()
	n.links[local] = ep
	n.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	var work sync.WaitGroup
	work.Go(func() {
		for ctx.Err() == nil {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			proto := pkt.NetworkProtocolNumber
			pkt.DecRef()
			b := v.AsSlice()
			d := decodeDatagram(seg, b)
			if !d.from.IsValid() {
				v.Release()
				continue
			}
			f := d.flow
			n.mu.Lock()
			n.count[f]++
			d.number = n.count[f]
			if d.protocol == 17 && d.size == 1 && b[len(b)-1] == 0 {
				n.punch[f]++
			}
			dest := linkAddress{seg, f.to.Addr()}
			if n.links[dest] == nil {
				dest.ip = gateway
			}
			next := n.links[dest]
			var action disturbance
			if n.fault != nil {
				action = n.fault(d)
			}
			if d.protocol == 17 {
				if g := n.gates[local]; g != nil {
					g.sent(f.from, f.to)
				}
				if g := n.gates[dest]; g != nil && !g.accepts(f.to, f.from) {
					action.drop = true
				}
			}
			n.mu.Unlock()
			if next == nil || action.drop {
				v.Release()
				continue
			}
			frame := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
			deliver := func() {
				next.InjectInbound(proto, frame)
				if h, ok := n.forwardHeaders.LoadAndDelete(frame); ok {
					h.(*buffer.View).Release()
				}
				frame.DecRef()
			}
			if action.delay == 0 {
				deliver()
				continue
			}
			work.Go(func() {
				timer := time.NewTimer(action.delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					frame.DecRef()
				case <-timer.C:
					deliver()
				}
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		work.Wait()
		n.mu.Lock()
		if n.links[local] == ep {
			delete(n.links, local)
		}
		n.mu.Unlock()
		ep.Close()
	})
}

type natFilter int

const (
	openFilter natFilter = iota
	addressFilter
	portFilter
)

// A binding is opened on the first outbound packet. Record permissions per
// translated endpoint, including when one client has multiple public ports.
type natGate struct {
	filter      natFilter
	permissions map[netip.AddrPort]map[netip.AddrPort]bool
}

func (g *natGate) sent(public, remote netip.AddrPort) {
	p := g.permissions[public]
	if p == nil {
		p = make(map[netip.AddrPort]bool)
		g.permissions[public] = p
	}
	p[g.permission(remote)] = true
}
func (g *natGate) accepts(public, remote netip.AddrPort) bool {
	return g.permissions[public][g.permission(remote)]
}
func (g *natGate) permission(remote netip.AddrPort) netip.AddrPort {
	switch g.filter {
	case openFilter:
		return netip.AddrPort{}
	case addressFilter:
		return netip.AddrPortFrom(remote.Addr(), 0)
	default:
		return remote
	}
}

func (n *network) snapshot(t *testing.T) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for f, count := range n.count {
		t.Logf("segment=%s protocol=%d %s -> %s packets=%d punches=%d", f.segment, f.protocol, f.from, f.to, count, n.punch[f])
	}
}

func (n *network) punches(f flow) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.punch[f]
}

func TestLinkDeliveryOrder(t *testing.T) {
	n := newNetwork()
	var sockets []*gonet.UDPConn
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		s := newStack(t)
		n.attach(t, s, 1, "wan", ip, "")
		s.SetRouteTable([]tcpip.Route{route("192.0.2.0/24", "", 1)})
		pc, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: addr(ip), Port: 4242}, nil, ipv4.ProtocolNumber)
		require.NoError(t, err)
		t.Cleanup(func() { pc.Close() })
		sockets = append(sockets, pc)
	}
	left, right := sockets[0], sockets[1]
	n.disturb(func(d datagram) disturbance {
		if d.protocol != 17 || d.from.Addr() != netip.MustParseAddr("192.0.2.1") {
			return disturbance{}
		}
		switch d.number {
		case 1, 4, 5:
			return disturbance{drop: true}
		case 2:
			return disturbance{delay: 200 * time.Millisecond}
		default:
			return disturbance{}
		}
	})
	for i := 1; i <= 7; i++ {
		_, err := left.WriteTo([]byte{byte(i)}, right.LocalAddr())
		require.NoError(t, err)
	}
	require.NoError(t, right.SetReadDeadline(time.Now().Add(2*time.Second)))
	var seen []byte
	var b [1]byte
	for range 4 {
		_, _, err := right.ReadFrom(b[:])
		require.NoError(t, err)
		seen = append(seen, b[0])
	}
	require.Equal(t, []byte{3, 6, 7, 2}, seen)
	_, err := right.WriteTo([]byte{9}, left.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, left.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err = left.ReadFrom(b[:])
	require.NoError(t, err)
	require.Equal(t, byte(9), b[0])
}
