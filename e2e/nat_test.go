package e2e_test

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type forwardHeader struct{ network *network }

func (h forwardHeader) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	h.network.forwardHeaders.Store(pkt, pkt.NetworkHeader().View())
	return true, false
}

type ports struct{ src, dst uint16 }

func (p ports) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	b := pkt.TransportHeader().Slice()
	return len(b) >= 4 && (p.src == 0 || p.src == binary.BigEndian.Uint16(b)) && (p.dst == 0 || p.dst == binary.BigEndian.Uint16(b[2:])), false
}

// More specific remote endpoints precede the default binding for a client.
type binding struct {
	inside netip.AddrPort
	port   uint16
	remote netip.AddrPort
}
type gateway struct {
	lan, wan        string
	private, public netip.Prefix // interface addresses, including subnet lengths
	upstream        string
	filter          natFilter
	bindings        []binding
	hairpin         bool
}

func (g gateway) install(t *testing.T, n *network) {
	t.Helper()
	s := newStack(t)
	lan, wan := g.private.Addr().String(), g.public.Addr().String()
	n.attach(t, s, 1, g.lan, lan, "")
	n.attach(t, s, 2, g.wan, wan, g.upstream)
	routes := []tcpip.Route{route(g.private.Masked().String(), "", 1), route(g.public.Masked().String(), "", 2)}
	if g.upstream != "" {
		routes = append(routes, route("0.0.0.0/0", g.upstream, 2))
	}
	s.SetRouteTable(routes)
	for _, id := range []tcpip.NICID{1, 2} {
		_, err := s.SetNICForwarding(id, ipv4.ProtocolNumber, true)
		require.Nil(t, err)
	}
	n.mu.Lock()
	n.gates[linkAddress{g.wan, g.public.Addr()}] = &natGate{g.filter, make(map[netip.AddrPort]map[netip.AddrPort]bool)}
	n.mu.Unlock()
	// gVisor reads the ingress TTL after DeepCopyForForwarding,
	// which may recycle its backing chunk. Retain the header across dispatch.
	forward := s.IPTables().GetTable(stack.FilterID, false)
	forward.Rules[forward.BuiltinChains[stack.Forward]].Matchers = []stack.Matcher{forwardHeader{network: n}}
	s.IPTables().ReplaceTable(stack.FilterID, forward, false)
	table := s.IPTables().GetTable(stack.NATID, false)
	all := addr("255.255.255.255")
	filter := stack.EmptyFilter4()
	filter.CheckProtocol = true
	filter.Protocol = 17
	var pre, post []stack.Rule
	for _, b := range g.bindings {
		out := filter
		out.Src, out.SrcMask = addr(b.inside.Addr().String()), all
		if b.remote.IsValid() {
			out.Dst, out.DstMask = addr(b.remote.Addr().String()), all
		}
		post = append(post, stack.Rule{Filter: out, Matchers: []stack.Matcher{ports{src: b.inside.Port(), dst: b.remote.Port()}}, Target: &stack.SNATTarget{
			Addr: addr(wan), Port: b.port, ChangeAddress: true, ChangePort: true, NetworkProtocol: ipv4.ProtocolNumber,
		}})
		in := filter
		in.Dst, in.DstMask = addr(wan), all
		pre = append(pre, stack.Rule{Filter: in, Matchers: []stack.Matcher{ports{dst: b.port}}, Target: &stack.DNATTarget{
			Addr: addr(b.inside.Addr().String()), Port: b.inside.Port(), ChangeAddress: true, ChangePort: true, NetworkProtocol: ipv4.ProtocolNumber,
		}})
	}
	if g.hairpin {
		local := filter
		local.Dst = gvisorAddr(g.private.Masked().Addr())
		local.DstMask = tcpip.AddrFromSlice(net.CIDRMask(g.private.Bits(), 32))
		post = append([]stack.Rule{{Filter: local, Target: &stack.SNATTarget{Addr: addr(lan), ChangeAddress: true, NetworkProtocol: ipv4.ProtocolNumber}}}, post...)
	}
	// TCP connections use ordinary stateful masquerading.
	tcpFilter := stack.EmptyFilter4()
	tcpFilter.CheckProtocol = true
	tcpFilter.Protocol = 6
	post = append(post, stack.Rule{Filter: tcpFilter, Target: &stack.MasqueradeTarget{NetworkProtocol: ipv4.ProtocolNumber}})
	accept := stack.Rule{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: ipv4.ProtocolNumber}}
	for hook, rules := range map[stack.Hook][]stack.Rule{stack.Prerouting: pre, stack.Postrouting: post} {
		table.BuiltinChains[hook] = len(table.Rules)
		table.Rules = append(table.Rules, rules...)
		table.Underflows[hook] = len(table.Rules)
		table.Rules = append(table.Rules, accept)
	}
	s.IPTables().ReplaceTable(stack.NATID, table, false)
}

func gvisorAddr(ip netip.Addr) tcpip.Address { return tcpip.AddrFromSlice(ip.AsSlice()) }

func edge(lan, private, public, inside string, port uint16, filter natFilter) gateway {
	return gateway{
		lan: lan, wan: "wan", private: netip.MustParsePrefix(private), public: netip.MustParsePrefix(public), filter: filter,
		bindings: []binding{{inside: netip.MustParseAddrPort(inside), port: port}},
	}
}

func TestNATCalibration(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		filter                natFilter
		otherPort, sameIPPort uint16
	}{
		{"endpoint-independent", openFilter, 45001, 45001},
		{"address-restricted", addressFilter, 45001, 45001},
		{"port-restricted", portFilter, 45001, 45001},
		{"address-dependent", portFilter, 45002, 45001},
		{"address-and-port-dependent", portFilter, 45002, 45003},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNetwork()
			g := edge("inside", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, tc.filter)
			inside := g.bindings[0].inside
			if tc.otherPort != 45001 {
				g.bindings = append([]binding{{inside: inside, port: tc.otherPort, remote: netip.MustParseAddrPort("192.0.2.11:0")}}, g.bindings...)
			}
			if tc.sameIPPort != 45001 {
				g.bindings = append([]binding{{inside: inside, port: tc.sameIPPort, remote: netip.MustParseAddrPort("192.0.2.10:5001")}}, g.bindings...)
			}
			g.install(t, n)
			socket := func(s *stack.Stack, ip string, port uint16) *gonet.UDPConn {
				conn, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: addr(ip), Port: port}, nil, ipv4.ProtocolNumber)
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				return conn
			}
			host := func(seg, ip, via string) *stack.Stack {
				s := newStack(t)
				n.attach(t, s, 1, seg, ip, via)
				s.SetRouteTable([]tcpip.Route{route("0.0.0.0/0", via, 1)})
				return s
			}
			private := socket(host("inside", "10.1.0.2", "10.1.0.1"), "10.1.0.2", 4242)
			r1 := host("wan", "192.0.2.10", "")
			contact := socket(r1, "192.0.2.10", 5000)
			sameAddr := socket(r1, "192.0.2.10", 5001)
			other := socket(host("wan", "192.0.2.11", ""), "192.0.2.11", 5000)
			exchange := func(from, to *gonet.UDPConn, dest net.Addr, allowed bool, tag string) net.Addr {
				t.Helper()
				_, err := from.WriteTo([]byte(tag), dest)
				require.NoError(t, err)
				wait := time.Second
				if !allowed {
					wait = 80 * time.Millisecond
				}
				require.NoError(t, to.SetReadDeadline(time.Now().Add(wait)))
				var b [64]byte
				size, peer, err := to.ReadFrom(b[:])
				if !allowed {
					var timeout net.Error
					require.ErrorAs(t, err, &timeout)
					require.True(t, timeout.Timeout())
					return nil
				}
				require.NoError(t, err)
				require.Equal(t, tag, string(b[:size]))
				return peer
			}
			public := exchange(private, contact, contact.LocalAddr(), true, "mapping")
			require.Equal(t, "192.0.2.1:45001", public.String())
			exchange(contact, private, public, true, "reply")
			exchange(sameAddr, private, public, tc.filter != portFilter, "same address")
			exchange(other, private, public, tc.filter == openFilter, "other address")
			for _, target := range []struct {
				socket *gonet.UDPConn
				port   uint16
			}{{other, tc.otherPort}, {sameAddr, tc.sameIPPort}} {
				mapped := exchange(private, target.socket, target.socket.LocalAddr(), true, "second destination")
				require.Equal(t, netip.AddrPortFrom(g.public.Addr(), target.port).String(), mapped.String())
				exchange(target.socket, private, mapped, true, "second reply")
			}
		})
	}
}

func TestNATPaths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		filter    natFilter
		dependent bool
	}{
		{"open", openFilter, false}, {"address", addressFilter, false}, {"port", portFilter, false}, {"configured-port", portFilter, false}, {"destination-specific", portFilter, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLab(t)
			ga := edge("a", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, tc.filter)
			gb := edge("b", "10.2.0.1/24", "192.0.2.2/24", "10.2.0.2:4242", 45002, tc.filter)
			if tc.dependent {
				for _, g := range []*gateway{&ga, &gb} {
					g.bindings = append([]binding{{inside: g.bindings[0].inside, port: g.bindings[0].port + 1000, remote: netip.MustParseAddrPort("192.0.2.50:4242")}}, g.bindings...)
				}
			}
			ga.install(t, l.net)
			gb.install(t, l.net)
			a := l.host("a", "10.1.0.2", "10.1.0.1", "udp", false)
			b := l.host("b", "10.2.0.2", "10.2.0.1", "udp", false)
			r := l.host("wan", "192.0.2.50", "", "udp", true)
			l.top.Members[r.index].Transit = true
			if tc.name == "configured-port" {
				for _, entry := range []struct {
					h  *host
					ep string
				}{{a, "192.0.2.1:45001"}, {b, "192.0.2.2:45002"}} {
					l.top.Members[entry.h.index].Endpoints = []nebula.Endpoint{{Network: "udp", Address: netip.MustParseAddrPort(entry.ep)}}
				}
			}
			l.link(a, r)
			l.link(b, r)
			l.start()
			for _, pair := range [][2]*host{{a, b}, {b, a}} {
				require.NoError(t, pair[0].node.SetPeerPathPolicy(pair[1].ip, nebula.DirectOnly))
			}
			for _, h := range []*host{a, b} {
				l.connect(h, r, "udp")
				waitPath(t, r, h, "udp")
			}
			// A delivered signed event confirms both adjacency sessions carry control traffic.
			eventReceipt(t, a, r, "A ready")
			eventReceipt(t, b, r, "B ready")
			if tc.dependent {
				probe := flow{"wan", netip.MustParseAddrPort("192.0.2.1:45001"), netip.MustParseAddrPort("192.0.2.2:46002"), 17}
				// The first signed introduction may predate the observer's first hello.
				until := time.Now().Add(10 * time.Second)
				for l.net.packets(probe) == 0 && time.Now().Before(until) {
					require.ErrorIs(t, a.node.ConnectPeer(t.Context(), b.ip), nebula.ErrPeerUnavailable)
				}
				require.Positive(t, l.net.packets(probe))
				require.NoError(t, a.node.SetPeerPathPolicy(b.ip, nebula.Auto))
				require.NoError(t, b.node.SetPeerPathPolicy(a.ip, nebula.Auto))
				p := l.connect(a, b, "relay")
				require.Equal(t, []nebula.PeerID{labPeer(a.ip), labPeer(r.ip), labPeer(b.ip)}, p.Circuit)
			} else {
				require.Eventually(t, func() bool { return a.node.ConnectPeer(t.Context(), b.ip) == nil }, 10*time.Second, 50*time.Millisecond)
				p := waitPath(t, a, b, "udp")
				require.Equal(t, "192.0.2.2:45002", p.Endpoint.String())
				reverse := waitPath(t, b, a, "udp")
				require.Equal(t, "192.0.2.1:45001", reverse.Endpoint.String())
				require.Positive(t, l.net.punches(flow{"wan", reverse.Endpoint, p.Endpoint, 17}))
				require.Positive(t, l.net.punches(flow{"wan", p.Endpoint, reverse.Endpoint, 17}))
			}
			c, d := tcpPair(t, l.business(a), l.business(b), b.ip.String(), ipv4.ProtocolNumber)
			roundTrip(t, c, d)
		})
	}
}

func TestGatewayLayouts(t *testing.T) {
	for _, layout := range []string{"single-udp", "single-tcp", "double-nat", "same-lan", "hairpin", "ipv6-udp", "ipv6-tcp"} {
		t.Run(layout, func(t *testing.T) {
			l := newLab(t)
			var a, b *host
			kind := "udp"
			want := ""
			switch layout {
			case "ipv6-udp", "ipv6-tcp":
				if layout == "ipv6-tcp" {
					kind = "tcp"
				}
				a = l.host("wan", "2001:db8::a", "", "both", true)
				b = l.host("wan", "2001:db8::b", "", "both", true)
				if kind == "tcp" {
					l.net.disturb(func(d datagram) disturbance { return disturbance{drop: d.protocol == 17} })
				}
				want = "[2001:db8::b]:4242"
			case "same-lan", "hairpin":
				g := edge("lan", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, openFilter)
				g.bindings = append(g.bindings, binding{inside: netip.MustParseAddrPort("10.1.0.3:4242"), port: 45002})
				g.hairpin = true
				g.install(t, l.net)
				a = l.host("lan", "10.1.0.2", "10.1.0.1", "udp", false)
				b = l.host("lan", "10.1.0.3", "10.1.0.1", "udp", layout == "same-lan")
				want = "10.1.0.3:4242"
				if layout == "hairpin" {
					want = "192.0.2.1:45002"
					l.top.Members[b.index].Endpoints = []nebula.Endpoint{{Network: "udp", Address: netip.MustParseAddrPort(want)}}
				}
			default:
				g := edge("lan", "10.1.0.1/24", "192.0.2.1/24", "10.1.0.2:4242", 45001, portFilter)
				if layout == "double-nat" {
					g.wan = "carrier"
					g.public = netip.MustParsePrefix("100.64.0.2/24")
					g.upstream = "100.64.0.1"
					outer := edge("carrier", "100.64.0.1/24", "192.0.2.1/24", "100.64.0.2:45001", 48000, portFilter)
					outer.install(t, l.net)
				}
				g.install(t, l.net)
				if layout == "single-tcp" {
					kind = "tcp"
				}
				a = l.host("lan", "10.1.0.2", "10.1.0.1", kind, false)
				b = l.host("wan", "192.0.2.10", "", kind, true)
				want = "192.0.2.10:4242"
			}
			l.start()
			path := l.connect(a, b, kind)
			require.Equal(t, want, path.Endpoint.String())
			reverse := waitPath(t, b, a, kind)
			switch layout {
			case "single-udp":
				require.Equal(t, "192.0.2.1:45001", reverse.Endpoint.String())
			case "single-tcp":
				require.Equal(t, "192.0.2.1", reverse.Endpoint.Addr().String())
			case "double-nat":
				require.Equal(t, "192.0.2.1:48000", reverse.Endpoint.String())
			case "hairpin":
				require.Equal(t, "10.1.0.1", reverse.Endpoint.Addr().String())
			}
			c, d := tcpPair(t, l.business(a), l.business(b), "fd42::2", ipv6.ProtocolNumber)
			roundTrip(t, c, d)
		})
	}
}
