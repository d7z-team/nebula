package e2e_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/nebulagvisor"
	"code.d7z.net/d7z-team/nebula/pki"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const meshPort = 4242

type lab struct {
	t      *testing.T
	net    *network
	top    nebula.Topology
	issuer pki.Issuer
	roots  *x509.CertPool
	hosts  []*host
}

type host struct {
	index   int
	ip      netip.Addr
	options nebula.Options
	node    *nebula.Node
}

func labPeer(ip netip.Addr) nebula.PeerID {
	id, err := pki.NewPeerID(ip, netip.MustParseAddr(fmt.Sprintf("fd42::%x", ip.As4()[3])))
	if err != nil {
		panic(err)
	}
	return id
}
func newLab(t *testing.T) *lab {
	t.Helper()
	key, err := pki.GenerateKey("ed25519")
	require.NoError(t, err)
	now := time.Now()
	root, err := pki.CreateRoot(key, pki.CAProfile{Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	require.NoError(t, err)
	l := &lab{
		t: t, net: newNetwork(), roots: x509.NewCertPool(), issuer: pki.Issuer{Chain: []*x509.Certificate{root}, Signer: key},
		top: nebula.Topology{
			Network:  "lab",
			Networks: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd42::/64")},
		},
	}
	l.roots.AddCert(root)
	return l
}

func (l *lab) credentials(ip netip.Addr, algorithm string, routes ...netip.Prefix) nebula.LocalCertificates {
	l.t.Helper()
	key, err := pki.GenerateKey(algorithm)
	require.NoError(l.t, err)
	req, err := pki.CreateCSR(key, pkix.Name{})
	require.NoError(l.t, err)
	leaf, err := l.issuer.IssueLeaf(req, pki.Enrollment{
		Scope: pki.Scope{Network: "lab", RoutedPrefixes: routes}, IPv4: ip, IPv6: labPeer(ip).IPv6(),
		Usages:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
		PublicKeyHash: sha256.Sum256(req.RawSubjectPublicKeyInfo),
		NotBefore:     time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute),
	})
	require.NoError(l.t, err)
	return nebula.LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}}
}

// Each host owns its underlay stack. All TCP dials, including failed dials,
// stay on this stack. Only explicitly published endpoints enter the topology.
func (l *lab) host(segment, physical, via, transport string, publish bool) *host {
	l.t.Helper()
	number := len(l.hosts) + 1
	ip := netip.MustParseAddr(fmt.Sprintf("10.13.0.%d", number))
	h := &host{index: len(l.hosts), ip: ip, options: nebula.Options{Roots: l.roots, Certificates: l.credentials(ip, "ed25519"), Interval: 140 * time.Millisecond, DialTimeout: 650 * time.Millisecond}}
	l.top.Members = append(l.top.Members, nebula.Member{IPv4: ip, IPv6: labPeer(ip).IPv6(), Topics: []string{"app/test"}})
	l.addUnderlay(h, segment, physical, via, transport, publish)
	l.hosts = append(l.hosts, h)
	return h
}
func (l *lab) addUnderlay(h *host, segment, physical, via, transport string, publish bool) {
	l.t.Helper()
	s := newStack(l.t)
	l.net.attach(l.t, s, 1, segment, physical, via)
	a := netip.MustParseAddr(physical)
	proto, defaultRoute := ipv4.ProtocolNumber, "0.0.0.0/0"
	if a.Is6() {
		proto, defaultRoute = ipv6.ProtocolNumber, "::/0"
	}
	s.SetRouteTable([]tcpip.Route{route(defaultRoute, via, 1)})
	m := &l.top.Members[h.index]
	bind := tcpip.FullAddress{Addr: addr(physical), Port: meshPort}
	if transport != "tcp" {
		pc, err := gonet.DialUDP(s, &bind, nil, proto)
		require.NoError(l.t, err)
		if a.Is4() {
			h.options.UDP4 = pc
		} else {
			h.options.UDP6 = pc
		}
		l.t.Cleanup(func() { pc.Close() })
		if publish {
			m.Endpoints = append(m.Endpoints, nebula.Endpoint{Network: "udp", Address: netip.AddrPortFrom(a, meshPort)})
		}
	}
	if transport != "udp" {
		listener, err := gonet.ListenTCP(s, bind, proto)
		require.NoError(l.t, err)
		if a.Is4() {
			h.options.TCP4 = listener
		} else {
			h.options.TCP6 = listener
		}
		l.t.Cleanup(func() { listener.Close() })
		if publish {
			m.Endpoints = append(m.Endpoints, nebula.Endpoint{Network: "tcp", Address: netip.AddrPortFrom(a, meshPort)})
		}
	}
	previousDial := h.options.DialTCP
	h.options.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		if ap.Addr().Is6() != a.Is6() && previousDial != nil {
			return previousDial(ctx, network, address)
		}
		if transport == "udp" || ap.Addr().Is6() != a.Is6() {
			return nil, errors.New("TCP unavailable on this host")
		}
		return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{Addr: gvisorAddr(ap.Addr()), Port: ap.Port()}, proto)
	}
}

func (l *lab) link(a, b *host) {
	left, right := &l.top.Members[a.index], &l.top.Members[b.index]
	left.Links = append(left.Links, labPeer(b.ip))
	right.Links = append(right.Links, labPeer(a.ip))
}

func (l *lab) start() {
	l.t.Helper()
	for _, h := range l.hosts {
		o := h.options
		o.Topology = l.top
		n, err := nebula.New(context.Background(), o)
		require.NoError(l.t, err)
		h.node = n
		l.t.Cleanup(func() { n.Close() })
	}
	for _, h := range l.hosts {
		require.NoError(l.t, h.node.Start())
	}
	l.t.Cleanup(func() {
		if l.t.Failed() {
			l.net.snapshot(l.t)
			for _, h := range l.hosts {
				l.t.Logf("%s: %+v; paths %+v", h.ip, h.node.ControlStatus(), h.node.Peers())
			}
		}
	})
}

func waitPath(t *testing.T, a, b *host, kind string) nebula.PeerStatus {
	t.Helper()
	var path nebula.PeerStatus
	require.Eventually(t, func() bool {
		for _, p := range a.node.Peers() {
			if p.Peer == labPeer(b.ip) && p.Active && p.Transport == kind {
				path = p
				return true
			}
		}
		return false
	}, 12*time.Second, 15*time.Millisecond, "%s -> %s: expected active %s", a.ip, b.ip, kind)
	t.Logf("path %s -> %s via %s endpoint=%s circuit=%v serial=%s localSerial=%s", a.ip, b.ip, kind, path.Endpoint, path.Circuit, path.Serial, path.LocalSerial)
	return path
}

func (l *lab) connect(a, b *host, kind string) nebula.PeerStatus {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(l.t.Context(), 10*time.Second)
	defer cancel()
	err := a.node.ConnectPeer(ctx, b.ip)
	require.NoError(l.t, err)
	return waitPath(l.t, a, b, kind)
}

func (l *lab) business(h *host) *stack.Stack {
	l.t.Helper()
	s := newStack(l.t)
	ep, err := nebulagvisor.NewEndpoint(h.node, nebulagvisor.Options{})
	require.NoError(l.t, err)
	l.t.Cleanup(func() {
		if l.t.Failed() {
			l.t.Logf("%s IP port: %+v", h.ip, ep.Stats())
		}
	})
	addNIC(l.t, s, 1, ep, h.ip.String(), labPeer(h.ip).IPv6().String())
	s.SetRouteTable([]tcpip.Route{route("10.13.0.0/24", "", 1), route("fd42::/64", "", 1)})
	return s
}

func forwardingPair(t *testing.T) (client, gateway *nebula.Node) {
	t.Helper()
	l := newLab(t)
	g := l.host("wan", "192.0.2.1", "", "both", true)
	c := l.host("wan", "192.0.2.2", "", "both", true)
	routes := []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("2001:db8:42::/64")}
	l.top.Members[g.index].RoutedPrefixes = routes
	g.options.Certificates = l.credentials(g.ip, "ed25519", routes...)
	l.net.disturb(func(d datagram) disturbance { return disturbance{drop: d.protocol == 17 && d.size > 1200} })
	l.start()
	l.connect(c, g, "udp")
	return c.node, g.node
}

func eventReceipt(t *testing.T, a, b *host, payload string) {
	t.Helper()
	sub, err := b.node.Subscribe("app/test")
	require.NoError(t, err)
	defer sub.Close()
	id, err := a.node.Publish(t.Context(), "app/test", []byte(payload))
	require.NoError(t, err)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case event := <-sub.Events():
			if event.ID == id {
				require.Equal(t, labPeer(a.ip), event.Origin)
				require.Equal(t, payload, string(event.Payload))
				return
			}
		case <-deadline:
			t.Fatalf("missing event %s from %s", id, a.ip)
		}
	}
}

func TestMixedTLSCredentials(t *testing.T) {
	for _, tc := range []struct{ transport, client, server string }{{"udp", "ed25519", "ml-dsa-44"}, {"tcp", "rsa", "p256"}} {
		t.Run(tc.transport, func(t *testing.T) {
			l := newLab(t)
			a := l.host("wan", "192.0.2.1", "", tc.transport, true)
			b := l.host("wan", "192.0.2.2", "", tc.transport, true)
			a.options.Certificates = l.credentials(a.ip, tc.client)
			b.options.Certificates = l.credentials(b.ip, tc.server)
			l.start()
			p := l.connect(a, b, tc.transport)
			require.EqualValues(t, tls.VersionTLS13, p.TLSVersion)
			require.Equal(t, nebula.ALPN, p.ALPN)
			require.Equal(t, tls.X25519MLKEM768.String(), p.Group)
			require.Equal(t, b.options.Certificates.Client.Leaf.SerialNumber.String(), p.Serial)
			require.Equal(t, a.options.Certificates.Client.Leaf.SerialNumber.String(), waitPath(t, b, a, tc.transport).Serial)
			eventReceipt(t, a, b, "client publication")
			eventReceipt(t, b, a, "server publication")
		})
	}
}

func TestDualUnderlayFamilyFailover(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t)
			a := l.host("wan4", "192.0.2.1", "", kind, true)
			b := l.host("wan4", "192.0.2.2", "", kind, true)
			l.addUnderlay(a, "wan6", "2001:db8::1", "", kind, true)
			l.addUnderlay(b, "wan6", "2001:db8::2", "", kind, true)
			l.start()
			require.NoError(t, a.node.ConnectPeer(t.Context(), labPeer(b.ip).IPv6()))
			first := waitPath(t, a, b, kind)
			require.True(t, first.Endpoint.Addr().Is4())
			left, right := l.business(a), l.business(b)
			c4, s4 := tcpPair(t, left, right, b.ip.String(), ipv4.ProtocolNumber)
			c6, s6 := tcpPair(t, left, right, b.node.ID().IPv6().String(), ipv6.ProtocolNumber)
			roundTrip(t, c4, s4)
			roundTrip(t, c6, s6)
			l.net.disturb(func(d datagram) disturbance { return disturbance{drop: d.segment == "wan4"} })
			require.Eventually(t, func() bool {
				for _, path := range a.node.Peers() {
					if path.Peer == b.node.ID() && path.Transport == kind && path.Active && path.Endpoint.Addr().Is6() {
						return true
					}
				}
				return false
			}, 12*time.Second, 20*time.Millisecond)
			roundTrip(t, c4, s4)
			roundTrip(t, c6, s6)
		})
	}
}
