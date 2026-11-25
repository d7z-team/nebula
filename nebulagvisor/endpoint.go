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

// Options configures the link and its host-managed next hops.
type Options struct {
	// A zero MTU selects the default.
	MTU uint32
	// ResolveNextHop selects a peer when no gateway or mesh owner was supplied.
	ResolveNextHop func(netip.Addr, []byte) (nebula.PeerID, error)
	// ObserveReceive sees the authenticated sender and read-only packet before stack injection.
	// Calls may overlap. Copy packet bytes to retain them after return and
	// call Node.Close outside the callback.
	ObserveReceive func(nebula.PeerID, []byte)
	// ObserveTransmit reports dequeued mesh submissions as in nebula.IPPortOptions.
	ObserveTransmit func(nebula.TransmitResult)
}

type networkLink = stack.NetworkLinkEndpoint

// Endpoint implements stack.LinkEndpoint. Use Stack.RemoveNIC to detach a
// registered NIC. If CreateNIC fails, call Close to release the endpoint.
type Endpoint struct {
	networkLink
	node   *nebula.Node
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
	port, err := node.OpenIPPort(nebula.IPPortOptions{ResolveNextHop: opts.ResolveNextHop, ObserveTransmit: opts.ObserveTransmit, Deliver: func(from nebula.PeerID, ip []byte) {
		if opts.ObserveReceive != nil {
			opts.ObserveReceive(from, ip)
		}
		proto := ipv4.ProtocolNumber
		if ip[0]>>4 == 6 {
			proto = ipv6.ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)})
		link.InjectInbound(proto, pkt)
		pkt.DecRef()
	}})
	if err != nil {
		link.Close()
		return nil, err
	}
	return &Endpoint{networkLink: link, node: node, port: port, maxMTU: maxMTU}, nil
}

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for i, pkt := range pkts.AsSlice() {
		if pkt.Size() > int(e.MTU()) {
			return i, &tcpip.ErrMessageTooLong{}
		}
		var via nebula.PeerID
		if hop := pkt.EgressRoute.NextHop; hop.BitLen() != 0 {
			address, ok := netip.AddrFromSlice(hop.AsSlice())
			if !ok {
				return i, &tcpip.ErrBadAddress{}
			}
			if via, ok = e.node.LookupPeer(address); !ok {
				return i, &tcpip.ErrHostUnreachable{}
			}
		}
		view := pkt.ToView()
		packet := view.AsSlice()
		err := e.port.WriteIP(via, packet)
		view.Release()
		switch {
		case err == nil:
			continue
		case errors.Is(err, nebula.ErrPacketTooLarge):
			return i, &tcpip.ErrMessageTooLong{}
		case errors.Is(err, nebula.ErrQueueFull):
			return i, &tcpip.ErrNoBufferSpace{}
		case errors.Is(err, nebula.ErrPortClosed), errors.Is(err, nebula.ErrNodeClosed), errors.Is(err, nebula.ErrNodeNotStarted):
			return i, &tcpip.ErrClosedForSend{}
		case errors.Is(err, nebula.ErrNextHopRequired), errors.Is(err, nebula.ErrPeerUnavailable):
			return i, &tcpip.ErrHostUnreachable{}
		case errors.Is(err, nebula.ErrAddressUnauthorized), errors.Is(err, nebula.ErrPathPolicy), errors.Is(err, nebula.ErrInstanceConflict):
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
func (e *Endpoint) ClearPending(peer nebula.PeerID) int { return e.port.ClearPending(peer) }

// Stats returns a snapshot of the IP port's traffic, queue and drop counters.
func (e *Endpoint) Stats() nebula.PortStats { return e.port.Stats() }

func (e *Endpoint) Close() {
	e.port.Close()
	e.networkLink.Attach(nil)
	e.networkLink.Close()
}
