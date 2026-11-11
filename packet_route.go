package nebula

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
)

var (
	ErrNoRoute              = errors.New("no route to destination")
	ErrRouteUnauthorized    = errors.New("unsafe route is not authorized by the gateway certificate")
	ErrAddressNotLocal      = errors.New("address is not local to this node")
	ErrAddressNotCertified  = errors.New("virtual address is not authorized by this node certificate")
	ErrInvalidPacketAddress = errors.New("invalid inner IP packet")
)

// Route sends an inner IP prefix through the Nebula node identified by Via.
// Via is always an overlay address, never another unsafe address.
type Route struct {
	Prefix netip.Prefix
	Via    netip.Addr
}

type packetRouteTable struct {
	overlayNetworks []netip.Prefix
	overlayAddrs    *bart.Lite
	virtualAddrs    *bart.Lite
	unsafeRoutes    *bart.Table[netip.Addr]
}

func newPacketRouteTable(identity cert.Certificate, virtual []netip.Addr, routes []Route) (*packetRouteTable, error) {
	r := &packetRouteTable{
		overlayNetworks: slices.Clone(identity.Networks()),
		overlayAddrs:    new(bart.Lite),
		virtualAddrs:    new(bart.Lite),
		unsafeRoutes:    new(bart.Table[netip.Addr]),
	}
	for _, network := range identity.Networks() {
		r.overlayAddrs.Insert(netip.PrefixFrom(network.Addr(), network.Addr().BitLen()))
	}

	for _, addr := range virtual {
		addr = addr.Unmap()
		if !addr.IsValid() || r.overlayAddrs.Contains(addr) {
			return nil, fmt.Errorf("%w: %s", ErrAddressNotCertified, addr)
		}
		if !prefixesContain(identity.UnsafeNetworks(), addr) {
			return nil, fmt.Errorf("%w: %s", ErrAddressNotCertified, addr)
		}
		if overlapsAnyAddressNetwork(identity.Networks(), addr) {
			return nil, fmt.Errorf("virtual address %s overlaps an overlay network", addr)
		}
		r.virtualAddrs.Insert(netip.PrefixFrom(addr, addr.BitLen()))
	}

	seen := make(map[netip.Prefix]struct{}, len(routes))
	for _, route := range routes {
		prefix := route.Prefix.Masked()
		via := route.Via.Unmap()
		if !prefix.IsValid() || !via.IsValid() {
			return nil, fmt.Errorf("invalid unsafe route %s via %s", route.Prefix, route.Via)
		}
		if !containsOverlayAddressNetwork(identity.Networks(), via) {
			return nil, fmt.Errorf("unsafe route gateway %s is not in a local overlay network", via)
		}
		for _, overlay := range identity.Networks() {
			if prefixesOverlap(prefix, overlay) {
				return nil, fmt.Errorf("unsafe route %s overlaps overlay network %s", prefix, overlay)
			}
		}
		if _, ok := seen[prefix]; ok {
			return nil, fmt.Errorf("duplicate unsafe route %s", prefix)
		}
		seen[prefix] = struct{}{}
		r.unsafeRoutes.Insert(prefix, via)
	}
	return r, nil
}

func (r *packetRouteTable) isLocal(addr netip.Addr) bool {
	return r.overlayAddrs.Contains(addr) || r.virtualAddrs.Contains(addr)
}

func (r *packetRouteTable) resolve(destination netip.Addr) (netip.Addr, bool) {
	destination = destination.Unmap()
	for _, network := range r.overlayNetworks {
		if network.Contains(destination) {
			return destination, true
		}
	}
	via, ok := r.unsafeRoutes.Lookup(destination)
	return via, ok
}

func (r *packetRouteTable) unsafeGateway(addr netip.Addr) (netip.Addr, bool) {
	return r.unsafeRoutes.Lookup(addr.Unmap())
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func containsOverlayAddressNetwork(networks []netip.Prefix, addr netip.Addr) bool {
	for _, network := range networks {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

func overlapsAnyAddressNetwork(networks []netip.Prefix, addr netip.Addr) bool {
	for _, network := range networks {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

type innerPacket struct {
	source      netip.Addr
	destination netip.Addr
}

func parseInnerPacket(packet []byte) (innerPacket, error) {
	if len(packet) == 0 {
		return innerPacket{}, ErrInvalidPacketAddress
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < 20 || len(packet) < headerLen {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		source, _ := netip.AddrFromSlice(packet[12:16])
		destination, _ := netip.AddrFromSlice(packet[16:20])
		return innerPacket{source: source, destination: destination}, nil
	case 6:
		if len(packet) < 40 {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		source, _ := netip.AddrFromSlice(packet[8:24])
		destination, _ := netip.AddrFromSlice(packet[24:40])
		return innerPacket{source: source, destination: destination}, nil
	default:
		return innerPacket{}, ErrInvalidPacketAddress
	}
}

func (r *packetRouteTable) validateInbound(packet innerPacket, peer *hostInfo) error {
	if !r.isLocal(packet.destination) {
		return fmt.Errorf("%w: %s", ErrAddressNotLocal, packet.destination)
	}
	if slices.Contains(peer.vpnAddrs, packet.source) {
		return nil
	}
	if peerNetworkType(peer, packet.source) != networkTypeUnsafe {
		return fmt.Errorf("peer certificate does not authorize source %s", packet.source)
	}
	via, ok := r.unsafeGateway(packet.source)
	if !ok || !slices.Contains(peer.vpnAddrs, via) {
		return fmt.Errorf("%w: source %s via peer %v", ErrRouteUnauthorized, packet.source, peer.vpnAddrs)
	}
	return nil
}

func (r *packetRouteTable) validateOutbound(packet innerPacket, peer *hostInfo) error {
	if !r.isLocal(packet.source) {
		return fmt.Errorf("%w: %s", ErrAddressNotLocal, packet.source)
	}
	if slices.Contains(peer.vpnAddrs, packet.destination) {
		return nil
	}
	if peerNetworkType(peer, packet.destination) != networkTypeUnsafe {
		return fmt.Errorf("%w: destination %s", ErrRouteUnauthorized, packet.destination)
	}
	via, ok := r.unsafeGateway(packet.destination)
	if !ok || !slices.Contains(peer.vpnAddrs, via) {
		return fmt.Errorf("%w: destination %s via peer %v", ErrRouteUnauthorized, packet.destination, peer.vpnAddrs)
	}
	return nil
}

func peerNetworkType(peer *hostInfo, addr netip.Addr) networkType {
	if slices.Contains(peer.vpnAddrs, addr) {
		return networkTypeVPN
	}
	if peer.networks == nil {
		return networkTypeUnknown
	}
	networkType, _ := peer.networks.Lookup(addr)
	return networkType
}
