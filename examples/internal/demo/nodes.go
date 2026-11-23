package demo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"net/netip"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/pki"
)

// Host holds the topology member and the route authority granted by the demo CA.
type Host struct {
	nebula.Member
	CertificateRoutes []netip.Prefix
}

func NewHost(number byte) Host {
	return Host{Member: nebula.Member{
		IPv4: netip.AddrFrom4([4]byte{10, 13, 0, number}),
		IPv6: netip.MustParseAddr(fmt.Sprintf("fd13::%x", number)),
	}}
}

// NewNodes binds ephemeral ports first so every node can use the complete topology.
// The caller starts the nodes after installing any initial path policy.
func NewNodes(ctx context.Context, transport string, hosts ...Host) (nodes []*nebula.Node, err error) {
	issuer, err := NewIssuer()
	if err != nil {
		return nil, fmt.Errorf("create demo CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Chain[0])
	topology := nebula.Topology{Network: "demo", Networks: []netip.Prefix{netip.MustParsePrefix("10.13.0.0/24"), netip.MustParsePrefix("fd13::/64")}}
	options := make([]nebula.Options, len(hosts))
	var owners []io.Closer
	defer func() {
		if err != nil {
			for _, owner := range owners {
				owner.Close()
			}
		}
	}()
	for i, host := range hosts {
		key, err := pki.GenerateKey("ed25519")
		if err != nil {
			return nil, err
		}
		enrollment, err := Enrollment(key.Public(), host.IPv4, host.IPv6, host.CertificateRoutes)
		if err != nil {
			return nil, err
		}
		csr, err := pki.CreateCSR(key, pkix.Name{})
		if err != nil {
			return nil, err
		}
		cert, err := issuer.IssueLeaf(csr, enrollment)
		if err != nil {
			return nil, fmt.Errorf("issue certificate for %s: %w", host.IPv4, err)
		}
		o := &options[i]
		o.Roots = roots
		o.Certificates.Client = tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
		var address netip.AddrPort
		switch transport {
		case "udp":
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			owners = append(owners, pc)
			o.UDP4 = pc
			address = pc.LocalAddr().(*net.UDPAddr).AddrPort()
		case "tcp":
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			owners = append(owners, listener)
			o.TCP4 = listener
			address = listener.Addr().(*net.TCPAddr).AddrPort()
		default:
			return nil, fmt.Errorf("unknown transport %q", transport)
		}
		host.Endpoints = []nebula.Endpoint{{Network: transport, Address: address}}
		topology.Members = append(topology.Members, host.Member)
	}
	nodes = make([]*nebula.Node, len(hosts))
	for i, o := range options {
		o.Topology = topology
		node, err := nebula.New(ctx, o)
		if err != nil {
			return nil, fmt.Errorf("create node %s: %w", hosts[i].IPv4, err)
		}
		owners[i] = node
		nodes[i] = node
	}
	return nodes, nil
}
