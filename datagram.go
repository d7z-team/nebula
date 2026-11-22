package nebula

import (
	"fmt"
	"io"
	"net"
	"net/netip"
)

// DatagramTransport carries encrypted Nebula wire packets. Implementations
// must preserve datagram boundaries. New takes ownership after it returns a
// Node and closes the transport during shutdown. Close must unblock pending
// ReadFrom and WriteTo calls. Writes from multiple tunnels may be concurrent.
type DatagramTransport interface {
	ReadFrom([]byte) (int, netip.AddrPort, error)
	WriteTo([]byte, netip.AddrPort) error
	LocalAddr() (netip.AddrPort, error)
	Close() error
}

// RebindableTransport is an optional capability for transports which can move
// their underlay socket after a host network change.
type RebindableTransport interface {
	DatagramTransport
	Rebind() error
}

type packetConnTransport struct {
	net.PacketConn
}

// WrapPacketConn adapts a standard Go packet connection for Nebula. A Node
// takes ownership of pc when New returns successfully.
func WrapPacketConn(pc net.PacketConn) DatagramTransport {
	if pc == nil {
		return nil
	}
	return &packetConnTransport{PacketConn: pc}
}

func (p *packetConnTransport) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ap, err := addrPort(addr)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, ap, nil
}

func (p *packetConnTransport) WriteTo(b []byte, addr netip.AddrPort) error {
	n, err := p.PacketConn.WriteTo(b, net.UDPAddrFromAddrPort(addr))
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func (p *packetConnTransport) LocalAddr() (netip.AddrPort, error) {
	return addrPort(p.PacketConn.LocalAddr())
}

func addrPort(addr net.Addr) (netip.AddrPort, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), nil
	case interface{ AddrPort() netip.AddrPort }:
		return a.AddrPort(), nil
	default:
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("unsupported packet address %T: %w", addr, err)
		}
		return ap, nil
	}
}
