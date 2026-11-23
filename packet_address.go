package nebula

import (
	"encoding/binary"
	"errors"
	"net/netip"
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
	if !isTunnelUnicast(ip.source) || !isTunnelUnicast(ip.destination) {
		return ip, ErrInvalidPacketAddress
	}
	return ip, nil
}

func isTunnelUnicast(addr netip.Addr) bool {
	return !addr.Is4In6() && (addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast())
}
