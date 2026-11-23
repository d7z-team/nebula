package nebula

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/slackhq/nebula/header"
)

// DatagramTransport carries complete outer datagrams, including any prefix
// configured with Options.DatagramMagic. ReadFrom and WriteTo preserve packet
// boundaries. Concurrent writes may borrow their input until WriteTo returns.
// New takes ownership on success. Close must unblock pending reads and writes.
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

type rxContext struct {
	scratch []byte
	nb      []byte
	h       header.H
	lhh     *lighthouseHandler
}

func (f *packetEngine) receiveDatagrams() error {
	rxc := &rxContext{
		scratch: make([]byte, mtu),
		nb:      make([]byte, 12),
		lhh:     f.lightHouse.NewRequestHandler(),
	}
	// One spare byte distinguishes an oversized UDP datagram truncated by ReadFrom.
	packet := make([]byte, len(f.datagramMagic)+mtu+header.MaxOverhead+1)
	for {
		n, from, err := f.outside.ReadFrom(packet)
		if err != nil {
			return err
		}
		if n <= len(f.datagramMagic) || n >= len(packet) {
			continue
		}
		if payload, ok := bytes.CutPrefix(packet[:n], f.datagramMagic); ok {
			f.dispatchDatagram(packetSender{UdpAddr: from}, payload, rxc)
		}
	}
}

func (f *packetEngine) writeDatagram(packet []byte, to netip.AddrPort) error {
	if c := f.control; c != nil && !c.policy().allowsEndpoint(to) {
		return errWritePolicy
	}
	if len(f.datagramMagic) == 0 {
		return f.outside.WriteTo(packet, to)
	}
	buf := f.datagramBuffers.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(f.datagramMagic) + len(packet))
	buf.Write(f.datagramMagic)
	buf.Write(packet)
	err := f.outside.WriteTo(buf.Bytes(), to)
	f.datagramBuffers.Put(buf)
	return err
}
