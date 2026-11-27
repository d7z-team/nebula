package nebula

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"gopkg.d7z.net/nebula/pki"
)

var ErrInvalidPacketAddress = errors.New("invalid inner IP packet")

type innerPacket struct {
	source      netip.Addr
	destination netip.Addr
}

func parseInnerPacket(packet []byte) (innerPacket, error) {
	if len(packet) == 0 || len(packet) > MaxIPPacketSize {
		return innerPacket{}, ErrInvalidPacketAddress
	}
	var ip innerPacket
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < 20 || len(packet) < headerLen || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		ip.source, _ = netip.AddrFromSlice(packet[12:16])
		ip.destination, _ = netip.AddrFromSlice(packet[16:20])
	case 6:
		if len(packet) < 40 || 40+int(binary.BigEndian.Uint16(packet[4:6])) != len(packet) {
			return innerPacket{}, ErrInvalidPacketAddress
		}
		ip.source, _ = netip.AddrFromSlice(packet[8:24])
		ip.destination, _ = netip.AddrFromSlice(packet[24:40])
	default:
		return innerPacket{}, ErrInvalidPacketAddress
	}
	if !isTunnelUnicast(ip.source) || (!isTunnelUnicast(ip.destination) && !validGroup(ip.destination) && ip.destination != limitedBroadcast) {
		return ip, ErrInvalidPacketAddress
	}
	return ip, nil
}

func isTunnelUnicast(addr netip.Addr) bool {
	return !addr.Is4In6() && (addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast())
}

func (n *Node) unicastNextHopLocked(via PeerID, dst netip.Addr) (PeerID, error) {
	s := n.policy.Load()
	if via != (PeerID{}) {
		_, configured := s.members[via]
		if owner := n.ownerLocked(dst); owner == via {
			return via, nil
		}
		if !configured && n.peers[via] == nil && !time.Now().Before(n.discovered[via].authorizedUntil) {
			return PeerID{}, ErrPeerUnavailable
		}
		if !s.allowsAddress(via, dst, nil) {
			return PeerID{}, ErrAddressUnauthorized
		}
		return via, nil
	}
	if owner := n.ownerLocked(dst); owner != (PeerID{}) {
		return owner, nil
	}
	if s.cluster.Subnet(dst).IsValid() && !s.cluster.InAnycastPool(dst) {
		return PeerID{}, ErrPeerUnavailable
	}
	return PeerID{}, ErrNextHopRequired
}

// allowsAddress intersects the member's topology grants with its handshake
// certificate when supplied. Admission to the session already binds the full ID.
func (s *topologyView) allowsAddress(peer PeerID, addr netip.Addr, cert *pki.Identity) bool {
	if owner, ok := s.owners[addr]; ok {
		return owner == peer && (cert == nil || addr == cert.IPv4 || addr == cert.IPv6)
	}
	if cert != nil && (addr == cert.IPv4 || addr == cert.IPv6) {
		return s.acceptsIdentity(*cert)
	}
	member := s.members[peer]
	if s.cluster.InAnycastPool(addr) {
		return slices.Contains(member.AnycastIPs, addr) && (cert == nil || slices.Contains(cert.AnycastIPs, addr))
	}
	if s.cluster.Subnet(addr).IsValid() || !isTunnelUnicast(addr) {
		return false
	}
	contains := func(p netip.Prefix) bool { return p.Contains(addr) }
	return slices.ContainsFunc(member.RoutedPrefixes, contains) && (cert == nil || slices.ContainsFunc(cert.RoutedPrefixes, contains))
}

func (s *topologyView) allowsDestination(from, to PeerID, dst netip.Addr, cert *pki.Identity) bool {
	if peers, group, err := s.groupRecipients(dst); group {
		_, subscribed := slices.BinarySearchFunc(peers, to, comparePeer)
		return err == nil && from != to && subscribed
	}
	return s.allowsAddress(to, dst, cert)
}

// authorizedBy checks a queued packet against the current topology.
func (ip innerPacket) authorizedBy(n *Node, from, to PeerID) bool {
	cfg := n.policy.Load()
	return cfg.allowsAddress(from, ip.source, nil) && (n.ownerLocked(ip.destination) == to || cfg.allowsDestination(from, to, ip.destination, nil))
}

// authorizedOn also checks the grants carried by the actual session credentials.
func (ip innerPacket) authorizedOn(cfg *topologyView, from, to pki.Identity) bool {
	return cfg.allowsAddress(from.ID, ip.source, &from) && cfg.allowsDestination(from.ID, to.ID, ip.destination, &to)
}
