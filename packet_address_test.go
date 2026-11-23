package nebula

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInnerPacket(t *testing.T) {
	for _, tc := range []struct{ source, destination string }{
		{"10.0.0.1", "10.0.0.2"},
		{"2001:db8::1", "2001:db8::2"},
	} {
		source, destination := netip.MustParseAddr(tc.source), netip.MustParseAddr(tc.destination)
		var packet []byte
		if source.Is4() {
			packet = testIPv4(source, destination, "")
		} else {
			packet = testIPv6(source, destination, 40)
		}
		ip, err := parseInnerPacket(packet)
		require.NoError(t, err)
		require.Equal(t, source, ip.source)
		require.Equal(t, destination, ip.destination)
	}
}

func TestPacketRejectsMalformedLengthsAndMappedAddresses(t *testing.T) {
	good := testIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), "abc")
	shortHeader, longHeader := slices.Clone(good), slices.Clone(good)
	shortHeader[0], longHeader[0] = 0x44, 0x4f
	v6 := make([]byte, 40)
	v6[0] = 0x60
	copy(v6[8:24], netip.MustParseAddr("::ffff:10.0.0.1").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	for _, bad := range [][]byte{nil, {0x70}, good[:19], good[:20], shortHeader, longHeader, v6, v6[:39], make([]byte, MaxIPPacketSize+1)} {
		_, err := parseInnerPacket(bad)
		require.ErrorIs(t, err, ErrInvalidPacketAddress)
	}
}
