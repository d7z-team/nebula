// Package nebulagvisor exposes a mesh node as a layer 3 NIC in a caller-owned gVisor stack.
package nebulagvisor

import (
	"errors"
	"fmt"
	"net/netip"

	"code.d7z.net/d7z-team/nebula"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// DefaultMTU is the default link MTU, capped by the node's MaxIPSize.
	DefaultMTU = 1300
	// MinMTU is the minimum MTU for a dual-stack endpoint.
	MinMTU = 1280
)

// Options configures the dual-stack link MTU.
type Options struct {
	// A zero MTU selects the default.
	MTU uint32
}

type networkLink = stack.NetworkLinkEndpoint

// Endpoint implements stack.LinkEndpoint. Use Stack.RemoveNIC to detach a
// registered NIC. If CreateNIC fails, call Close to release the endpoint.
type Endpoint struct {
	networkLink
	port   *nebula.IPPort
	maxMTU uint32
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// NewEndpoint opens the node's IP port for exclusive use by a gVisor NIC.
func NewEndpoint(node *nebula.Node, opts Options) (*Endpoint, error) {
	if node == nil {
		return nil, errors.New("node is required")
	}
	maxMTU := uint32(node.MaxIPSize())
	if opts.MTU == 0 {
		opts.MTU = min(DefaultMTU, maxMTU)
	}
	if opts.MTU < MinMTU || opts.MTU > maxMTU {
		return nil, fmt.Errorf("MTU must be between %d and %d", MinMTU, maxMTU)
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
	return &Endpoint{networkLink: link, port: port, maxMTU: maxMTU}, nil
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
		packet := view.AsSlice()
		err := e.port.WriteIP(via, packet)
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
		case errors.Is(err, nebula.ErrAddressUnauthorized):
			return i, &tcpip.ErrNotPermitted{}
		default:
			return i, &tcpip.ErrBadAddress{}
		}
	}
	return pkts.Len(), nil
}

// SetMTU clamps the dual-stack link MTU to [MinMTU, MaxIPSize].
func (e *Endpoint) SetMTU(mtu uint32) {
	e.networkLink.SetMTU(min(max(mtu, MinMTU), e.maxMTU))
}

// ClearPending discards queued packets for peer and returns their count.
func (e *Endpoint) ClearPending(peer netip.Addr) int { return e.port.ClearPending(peer) }

// Stats returns a snapshot of the IP port's traffic, queue and drop counters.
func (e *Endpoint) Stats() nebula.PortStats { return e.port.Stats() }

func (e *Endpoint) Close() {
	e.port.Close()
	e.networkLink.Attach(nil)
	e.networkLink.Close()
}
