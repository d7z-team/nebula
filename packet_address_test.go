package nebula

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
)

func TestParseInnerPacket(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0], v4[3] = 0x45, 20
	copy(v4[12:16], netip.MustParseAddr("10.0.0.1").AsSlice())
	copy(v4[16:20], netip.MustParseAddr("10.0.0.2").AsSlice())
	p, err := parseInnerPacket(v4)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), p.source)
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), p.destination)

	v6 := make([]byte, 40)
	v6[0] = 0x60
	copy(v6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	p, err = parseInnerPacket(v6)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), p.source)
	require.Equal(t, netip.MustParseAddr("2001:db8::2"), p.destination)
	require.ErrorIs(t, func() error { _, err := parseInnerPacket([]byte{0x70}); return err }(), ErrInvalidPacketAddress)
}

func TestPacketRejectsMalformedLengthsAndMappedAddresses(t *testing.T) {
	good := testIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), "abc")
	short := slices.Clone(good)
	short[0] = 0x4f
	mismatched := slices.Clone(good)
	mismatched[3]--
	v6 := make([]byte, 40)
	v6[0] = 0x60
	copy(v6[8:24], netip.MustParseAddr("::ffff:10.0.0.1").AsSlice())
	copy(v6[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	for _, bad := range [][]byte{nil, good[:19], good[:20], short, mismatched, v6, v6[:39], make([]byte, MaxIPPacketSize+1)} {
		_, err := parseInnerPacket(bad)
		require.ErrorIs(t, err, ErrInvalidPacketAddress)
	}
}

func TestPacketCertificateOverlapWithDefaultRoute(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	overlay := netip.MustParsePrefix("10.42.0.0/24")
	vpn := netip.MustParsePrefix("10.42.0.2/24")
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	ca, key, err := cert.CreateCA(cert.CAOptions{Name: "ca", NotBefore: now, NotAfter: now.Add(time.Hour)})
	require.NoError(t, err)
	crt, _, err := cert.IssueCertificate(ca, key, cert.CertificateOptions{Name: "exit", Networks: []netip.Prefix{vpn}, UnsafeNetworks: []netip.Prefix{defaultRoute}, NotBefore: now, NotAfter: now.Add(time.Hour)})
	require.NoError(t, err)
	f := packetEngine{myVpnNetworksTable: new(bart.Lite), myVpnAddrsTable: new(bart.Lite)}
	f.myVpnNetworksTable.Insert(overlay)
	f.myVpnAddrsTable.Insert(netip.PrefixFrom(vpn.Addr(), 32))
	f.localUnsafe.Insert(defaultRoute)
	h := hostInfo{vpnAddrs: []netip.Addr{vpn.Addr()}}
	h.buildNetworks(f.myVpnNetworksTable, crt)
	for _, tc := range []struct {
		ip      string
		allowed bool
	}{{"10.42.0.2", true}, {"10.42.0.3", false}, {"192.0.2.33", true}} {
		ip := netip.MustParseAddr(tc.ip)
		require.Equal(t, tc.allowed, h.authorizes(ip))
		require.Equal(t, tc.allowed, f.authorizesLocal(ip))
	}
}
