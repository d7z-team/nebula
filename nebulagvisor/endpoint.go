// Package nebulagvisor attaches Nebula as a layer-3 NIC to a caller-owned gVisor stack.
package nebulagvisor

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/slackhq/nebula"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// DefaultMTU is used when Options.MTU is zero.
	DefaultMTU = 1300
	// MinMTU is the smallest MTU supported by this dual-stack endpoint.
	MinMTU = 1280
)

// Options configures the L3 interface. A zero MTU selects DefaultMTU.
type Options struct {
	MTU uint32
}

type networkLink = stack.NetworkLinkEndpoint

// Endpoint implements stack.LinkEndpoint. Remove an attached NIC with
// Stack.RemoveNIC. Close an endpoint directly if CreateNIC failed.
type Endpoint struct {
	networkLink
	port *nebula.IPPort
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// NewEndpoint reserves the data port of node for one gVisor NIC.
func NewEndpoint(node *nebula.Node, opts Options) (*Endpoint, error) {
	if node == nil {
		return nil, errors.New("node is required")
	}
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	if opts.MTU < MinMTU || opts.MTU > nebula.MaxIPPacketSize {
		return nil, fmt.Errorf("MTU must be between %d and %d", MinMTU, nebula.MaxIPPacketSize)
	}
	// channel.Endpoint supplies a headerless dispatcher. TX uses the port's
	// bounded per-peer queues directly, so the channel needs no TX queue.
	link := channel.New(0, opts.MTU, "")
	port, err := node.OpenIPPort(func(ip []byte) {
		proto := ipv4.ProtocolNumber
		if ip[0]>>4 == 6 {
			proto = ipv6.ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)})
		link.InjectInbound(proto, pkt)
		pkt.DecRef()
	})
	if err != nil {
		link.Close()
		return nil, err
	}
	return &Endpoint{networkLink: link, port: port}, nil
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for i, pkt := range pkts.AsSlice() {
		if pkt.Size() > int(e.MTU()) {
			return i, &tcpip.ErrMessageTooLong{}
		}
		var via netip.Addr
		if hop := pkt.EgressRoute.NextHop; hop.BitLen() != 0 {
			var ok bool
			if via, ok = netip.AddrFromSlice(hop.AsSlice()); !ok {
				return i, &tcpip.ErrBadAddress{}
			}
		}
		view := pkt.ToView()
		err := e.port.WriteIP(via, view.AsSlice())
		view.Release()
		switch {
		case err == nil:
			continue
		case errors.Is(err, nebula.ErrQueueFull):
			return i, &tcpip.ErrNoBufferSpace{}
		case errors.Is(err, nebula.ErrPortClosed), errors.Is(err, nebula.ErrNodeClosed), errors.Is(err, nebula.ErrNodeNotStarted):
			return i, &tcpip.ErrClosedForSend{}
		case errors.Is(err, nebula.ErrMissingGateway), errors.Is(err, nebula.ErrPeerUnavailable):
			return i, &tcpip.ErrHostUnreachable{}
		case errors.Is(err, nebula.ErrAddressNotCertified):
			return i, &tcpip.ErrNotPermitted{}
		default:
			return i, &tcpip.ErrBadAddress{}
		}
	}
	return pkts.Len(), nil
}

// SetMTU clamps the value to the supported dual-stack tunnel limits.
func (e *Endpoint) SetMTU(mtu uint32) {
	e.networkLink.SetMTU(min(max(mtu, MinMTU), nebula.MaxIPPacketSize))
}

// ClearPending discards queued frames for the exact overlay next hop.
func (e *Endpoint) ClearPending(peer netip.Addr) int { return e.port.ClearPending(peer) }

// Stats returns a detached snapshot of the tunnel port.
func (e *Endpoint) Stats() nebula.PortStats { return e.port.Stats() }

func (e *Endpoint) Close() {
	e.port.Close()
	e.networkLink.Attach(nil)
	e.networkLink.Close()
}
