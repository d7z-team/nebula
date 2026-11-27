package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"

	"gopkg.d7z.net/nebula"
	"gopkg.d7z.net/nebula/pki"
)

// Host holds the topology member and the route authority granted by the demo CA.
type Host struct {
	nebula.Member
	key               ed25519.PrivateKey
	CertificateRoutes []netip.Prefix
}

// NewHost assigns the numbered IPv4 and IPv6 addresses in the demo network.
func NewHost(number byte) Host {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	id, err := pki.NewPeerID(pub)
	if err != nil {
		panic(err)
	}
	return Host{key: key, Member: nebula.Member{
		ID:   id,
		IPv4: netip.AddrFrom4([4]byte{10, 13, 0, number}),
		IPv6: netip.MustParseAddr(fmt.Sprintf("fd13::%x", number)),
	}}
}

// NodeOptions issues short-lived credentials and gives each host its own copy
// of the demo topology.
func NodeOptions(hosts ...Host) ([]nebula.Options, error) {
	root, issuer, err := NewIssuers()
	if err != nil {
		return nil, fmt.Errorf("create demo CA: %w", err)
	}
	options := make([]nebula.Options, len(hosts))
	for i, host := range hosts {
		key := host.key
		enrollment, err := Enrollment(key.Public(), host.IPv4, host.IPv6, host.CertificateRoutes)
		if err != nil {
			return nil, err
		}
		enrollment.AnycastIPs = host.AnycastIPs
		csr, err := pki.CreateCSR(key, pkix.Name{})
		if err != nil {
			return nil, err
		}
		cert, err := issuer.IssueGrant(csr, enrollment)
		if err != nil {
			return nil, fmt.Errorf("issue certificate for %s: %w", host.IPv4, err)
		}
		node, err := root.IssueNode(csr, enrollment.PublicKeyHash, enrollment.NotBefore, enrollment.NotAfter)
		if err != nil {
			return nil, err
		}
		o := &options[i]
		o.Auth = nebula.AuthOptions{
			RootCA: root.Chain[0], ClusterCA: issuer.Chain[0],
			Certificates: nebula.LocalCertificates{Node: tls.Certificate{Certificate: [][]byte{node.Raw}, PrivateKey: key}, Grant: [][]byte{cert.Raw, issuer.Chain[0].Raw}},
		}
		o.Topology = nebula.Topology{Network: "demo", Members: make([]nebula.Member, len(hosts))}
		for j, h := range hosts {
			o.Topology.Members[j] = h.Clone()
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
				_ = owner.Close()
			}
		}
	}()
	prepared := slices.Clone(options)
	endpoints := make(map[nebula.PeerID]nebula.Endpoint, len(options))
	for i := range prepared {
		o := &prepared[i]
		chain, err := pki.ParseChain(o.Auth.Certificates.Grant)
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
			if ep := endpoints[m.ID]; ep.Valid() && !slices.Contains(m.Endpoints, ep) {
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
