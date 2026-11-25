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
	"slices"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/pki"
)

// Host holds the topology member and the route authority granted by the demo CA.
type Host struct {
	nebula.Member
	CertificateRoutes []netip.Prefix
}

// NewHost assigns the numbered IPv4 and IPv6 addresses in the demo network.
func NewHost(number byte) Host {
	return Host{Member: nebula.Member{
		IPv4: netip.AddrFrom4([4]byte{10, 13, 0, number}),
		IPv6: netip.MustParseAddr(fmt.Sprintf("fd13::%x", number)),
	}}
}

// NodeOptions issues short-lived credentials and gives each host its own copy
// of the demo topology.
func NodeOptions(hosts ...Host) ([]nebula.Options, error) {
	issuer, err := NewIssuer()
	if err != nil {
		return nil, fmt.Errorf("create demo CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Chain[0])
	options := make([]nebula.Options, len(hosts))
	for i, host := range hosts {
		key, err := pki.GenerateKey("ed25519")
		if err != nil {
			return nil, err
		}
		enrollment, err := Enrollment(key.Public(), host.IPv4, host.IPv6, host.CertificateRoutes)
		if err != nil {
			return nil, err
		}
		enrollment.AnycastIPs = host.AnycastIPs
		csr, err := pki.CreateCSR(key, pkix.Name{})
		if err != nil {
			return nil, err
		}
		cert, err := issuer.IssueLeaf(csr, enrollment)
		if err != nil {
			return nil, fmt.Errorf("issue certificate for %s: %w", host.IPv4, err)
		}
		o := &options[i]
		o.Auth = nebula.AuthOptions{
			Roots: roots, ClusterCA: issuer.Chain[0],
			Certificates: nebula.LocalCertificates{Client: tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		}
		o.Topology = nebula.Topology{Network: "demo", Members: make([]nebula.Member, len(hosts))}
		for j, h := range hosts {
			o.Topology.Members[j] = h.Member.Clone()
		}
	}
	return options, nil
}

// NewNodes binds ephemeral ports first so every node can use the complete topology.
func NewNodes(ctx context.Context, transport string, hosts ...Host) ([]*nebula.Node, error) {
	options, err := NodeOptions(hosts...)
	if err != nil {
		return nil, err
	}
	return Listen(ctx, transport, options)
}

// Listen binds loopback sockets and constructs the nodes prepared by NodeOptions.
// On success it records the sockets in options. For each host with HideEndpoints
// unset, it adds its bound address to each topology that lists the host.
func Listen(ctx context.Context, transport string, options []nebula.Options) (nodes []*nebula.Node, err error) {
	var owners []io.Closer
	defer func() {
		if err != nil {
			for _, owner := range owners {
				owner.Close()
			}
		}
	}()
	prepared := slices.Clone(options)
	endpoints := make(map[nebula.PeerID]nebula.Endpoint, len(options))
	for i := range prepared {
		o := &prepared[i]
		chain, err := pki.ParseChain(o.Auth.Certificates.Client.Certificate)
		if err != nil {
			return nil, err
		}
		identity, err := pki.ReadIdentity(chain[0])
		if err != nil {
			return nil, err
		}
		if _, exists := endpoints[identity.ID]; exists {
			return nil, fmt.Errorf("duplicate local identity %s", identity.ID)
		}
		var address netip.AddrPort
		switch transport {
		case "udp":
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			owners = append(owners, pc)
			o.Transport.UDP4 = pc
			address = pc.LocalAddr().(*net.UDPAddr).AddrPort()
		case "tcp":
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			owners = append(owners, listener)
			o.Transport.TCP4 = listener
			address = listener.Addr().(*net.TCPAddr).AddrPort()
		default:
			return nil, fmt.Errorf("unknown transport %q", transport)
		}
		ep := nebula.Endpoint{}
		if !o.Transport.HideEndpoints {
			ep = nebula.Endpoint{Network: transport, Address: address}
		}
		endpoints[identity.ID] = ep
	}
	nodes = make([]*nebula.Node, len(options))
	for i := range prepared {
		o := &prepared[i]
		o.Topology.Members = slices.Clone(o.Topology.Members)
		for j := range o.Topology.Members {
			m := &o.Topology.Members[j]
			id, err := pki.NewPeerID(m.IPv4, m.IPv6)
			if err != nil {
				return nil, err
			}
			if ep := endpoints[id]; ep.Valid() && !slices.Contains(m.Endpoints, ep) {
				m.Endpoints = append([]nebula.Endpoint{ep}, m.Endpoints...)
			}
		}
		node, err := nebula.New(ctx, *o)
		if err != nil {
			return nil, fmt.Errorf("create demo node %d: %w", i, err)
		}
		owners[i] = node
		nodes[i] = node
	}
	copy(options, prepared)
	return nodes, nil
}
