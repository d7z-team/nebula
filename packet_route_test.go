package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
)

func routeTestCertificate(t *testing.T) cert.Certificate {
	t.Helper()
	ca, caKey, err := cert.CreateCA(cert.CAOptions{
		Name: "ca", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8:ffff::/48")},
		UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("2001:db8::/32")},
		NotBefore:      time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	host, _, err := cert.IssueCertificate(ca, caKey, cert.CertificateOptions{
		Name: "host", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("2001:db8:ffff::1/48")},
		UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("2001:db8::/32")},
		NotBefore:      time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute),
	})
	require.NoError(t, err)
	return host
}

func TestPacketRouteTable(t *testing.T) {
	crt := routeTestCertificate(t)
	routes, err := newPacketRouteTable(crt, []netip.Addr{netip.MustParseAddr("172.16.1.10")}, []Route{
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Via: netip.MustParseAddr("10.0.0.2")},
		{Prefix: netip.MustParsePrefix("172.20.1.0/24"), Via: netip.MustParseAddr("10.0.0.3")},
		{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), Via: netip.MustParseAddr("10.0.0.4")},
	})
	require.NoError(t, err)

	via, ok := routes.resolve(netip.MustParseAddr("10.0.0.9"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("10.0.0.9"), via)
	via, ok = routes.resolve(netip.MustParseAddr("172.20.1.8"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("10.0.0.3"), via)
	via, ok = routes.resolve(netip.MustParseAddr("2001:db8:1::8"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("10.0.0.4"), via, "an IPv6 unsafe prefix may use an IPv4 overlay gateway")
	require.True(t, routes.isLocal(netip.MustParseAddr("172.16.1.10")))

	_, err = newPacketRouteTable(crt, nil, []Route{
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Via: netip.MustParseAddr("10.0.0.2")},
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Via: netip.MustParseAddr("10.0.0.3")},
	})
	require.ErrorContains(t, err, "duplicate unsafe route")
	_, err = newPacketRouteTable(crt, nil, []Route{{Prefix: netip.MustParsePrefix("10.0.0.0/25"), Via: netip.MustParseAddr("10.0.0.2")}})
	require.ErrorContains(t, err, "overlaps overlay")
	_, err = newPacketRouteTable(crt, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil)
	require.ErrorIs(t, err, ErrAddressNotCertified)
}

func TestParseInnerPacket(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
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

func TestPacketIdentityAndRouteAuthorization(t *testing.T) {
	crt := routeTestCertificate(t)
	localVirtual := netip.MustParseAddr("172.16.1.10")
	routes, err := newPacketRouteTable(crt, []netip.Addr{localVirtual}, []Route{
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Via: netip.MustParseAddr("10.0.0.2")},
	})
	require.NoError(t, err)

	peer := &hostInfo{
		vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		networks: new(bart.Table[networkType]),
	}
	peer.networks.Insert(netip.MustParsePrefix("172.20.0.0/16"), networkTypeUnsafe)
	peer.networks.Insert(netip.MustParsePrefix("10.0.0.0/24"), networkTypeUnsafeVPNOverlap)

	require.NoError(t, routes.validateInbound(innerPacket{
		source: peer.vpnAddrs[0], destination: netip.MustParseAddr("10.0.0.1"),
	}, peer))
	require.NoError(t, routes.validateInbound(innerPacket{
		source: netip.MustParseAddr("172.20.1.8"), destination: localVirtual,
	}, peer))
	require.ErrorIs(t, routes.validateInbound(innerPacket{
		source: peer.vpnAddrs[0], destination: netip.MustParseAddr("10.0.0.9"),
	}, peer), ErrAddressNotLocal)
	require.ErrorContains(t, routes.validateInbound(innerPacket{
		source: netip.MustParseAddr("10.0.0.9"), destination: localVirtual,
	}, peer), "does not authorize source")
	require.ErrorContains(t, routes.validateInbound(innerPacket{
		source: netip.MustParseAddr("192.0.2.1"), destination: localVirtual,
	}, peer), "does not authorize source")

	require.NoError(t, routes.validateOutbound(innerPacket{
		source: localVirtual, destination: netip.MustParseAddr("172.20.1.8"),
	}, peer))
	require.NoError(t, routes.validateOutbound(innerPacket{
		source: netip.MustParseAddr("10.0.0.1"), destination: peer.vpnAddrs[0],
	}, peer))
	require.ErrorIs(t, routes.validateOutbound(innerPacket{
		source: netip.MustParseAddr("172.16.1.11"), destination: peer.vpnAddrs[0],
	}, peer), ErrAddressNotLocal)
	require.ErrorIs(t, routes.validateOutbound(innerPacket{
		source: localVirtual, destination: netip.MustParseAddr("192.0.2.1"),
	}, peer), ErrRouteUnauthorized)

	wrongVia, err := newPacketRouteTable(crt, []netip.Addr{localVirtual}, []Route{
		{Prefix: netip.MustParsePrefix("172.20.0.0/16"), Via: netip.MustParseAddr("10.0.0.3")},
	})
	require.NoError(t, err)
	require.ErrorIs(t, wrongVia.validateInbound(innerPacket{
		source: netip.MustParseAddr("172.20.1.8"), destination: localVirtual,
	}, peer), ErrRouteUnauthorized)
	require.ErrorIs(t, wrongVia.validateOutbound(innerPacket{
		source: localVirtual, destination: netip.MustParseAddr("172.20.1.8"),
	}, peer), ErrRouteUnauthorized)

	_, ok := routes.resolve(netip.MustParseAddr("192.0.2.1"))
	require.False(t, ok)
}
