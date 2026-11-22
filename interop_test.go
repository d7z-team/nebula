package nebula

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func interopSockets(t *testing.T, ids []nodeTestIdentity) ([]*net.UDPConn, map[netip.Addr][]netip.AddrPort) {
	t.Helper()
	var sockets []*net.UDPConn
	static := make(map[netip.Addr][]netip.AddrPort, len(ids))
	for _, id := range ids {
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sock.Close() })
		sockets = append(sockets, sock)
		static[id.addr] = []netip.AddrPort{sock.LocalAddr().(*net.UDPAddr).AddrPort()}
	}
	return sockets, static
}

// The upstream disabled TUN answers ICMP directly, without a privileged device.
func startStockNode(t *testing.T, binaryPath string, pool *cert.CAPool, id nodeTestIdentity, socket *net.UDPConn, static map[netip.Addr][]netip.AddrPort, lighthouses []netip.Addr, serve bool) {
	t.Helper()
	dir := t.TempDir()
	var bundle []byte
	for _, ca := range pool.CAs {
		pem, err := ca.Certificate.MarshalPEM()
		require.NoError(t, err)
		bundle = append(bundle, pem...)
	}
	pem, err := id.identity.Certificate.MarshalPEM()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), bundle, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "host.crt"), pem, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "host.key"), cert.MarshalPrivateKeyToPEM(id.identity.Certificate.Curve(), id.identity.PrivateKey), 0600))
	static = maps.Clone(static)
	delete(static, id.addr)
	hosts, err := json.Marshal(static)
	require.NoError(t, err)
	lhs, err := json.Marshal(lighthouses)
	require.NoError(t, err)
	config := fmt.Sprintf(`pki: {ca: ca.crt, cert: host.crt, key: host.key}
cipher: aes
listen: {host: 127.0.0.1, port: %d}
tun: {disabled: true}
static_host_map: %s
lighthouse: {hosts: %s, interval: 1}
relay: {am_relay: %t}
punchy: {respond: true, respond_delay: 50ms}
firewall:
  inbound: [{proto: any, host: any, port: any}]
  outbound: [{proto: any, host: any, port: any}]
`, socket.LocalAddr().(*net.UDPAddr).Port, hosts, lhs, serve)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(config), 0600))
	cmd := exec.Command(binaryPath, "-config", "config.yml")
	cmd.Dir = dir
	logFile, err := os.Create(filepath.Join(dir, "upstream.log"))
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, socket.Close())
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logFile.Name())
			t.Log(string(b))
		}
	})
}

func TestNodeUpstreamInterop(t *testing.T) {
	binaryPath := os.Getenv("NEBULA_INTEROP_BINARY")
	if binaryPath == "" {
		t.Skip("set NEBULA_INTEROP_BINARY to the upstream executable")
	}
	for _, version := range []cert.Version{cert.Version1, cert.Version2} {
		for _, stockRelay := range []bool{false, true} {
			for _, initiator := range []bool{true, false} {
				t.Run(fmt.Sprintf("v%d/stockRelay_%t/embeddedInitiator_%t", version, stockRelay, initiator), func(t *testing.T) {
					pool, ids := pathTestIdentities(t, version, 3)
					local, remote, relay := ids[0], ids[1], ids[2]
					sockets, static := interopSockets(t, ids)
					newLocal := func(id nodeTestIdentity, i int, serve bool) *Node {
						hosts := maps.Clone(static)
						delete(hosts, id.addr)
						n, err := New(t.Context(), Options{Identities: []Identity{id.identity}, CAPool: pool, Transport: WrapPacketConn(sockets[i]), InitiatingVersion: version, Relay: RelayOptions{Serve: serve}, Lighthouse: LighthouseOptions{AmLighthouse: !initiator && i == 0, StaticHosts: hosts}})
						require.NoError(t, err)
						require.NoError(t, n.Start())
						t.Cleanup(func() { _ = n.Close(); _ = n.Wait() })
						return n
					}
					if stockRelay {
						startStockNode(t, binaryPath, pool, relay, sockets[2], static, []netip.Addr{}, true)
					} else {
						newLocal(relay, 2, true)
					}
					n := newLocal(local, 0, false)
					lhs := []netip.Addr{}
					if !initiator {
						lhs = append(lhs, local.addr)
					}
					startStockNode(t, binaryPath, pool, remote, sockets[1], static, lhs, false)
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					if initiator {
						require.NoError(t, n.ConnectPeer(ctx, remote.addr))
					}
					require.Eventually(t, func() bool {
						s, ok := n.Peer(remote.addr)
						return ok && s.State == PeerStateEstablished && s.Initiator == initiator
					}, 8*time.Second, 10*time.Millisecond)
					via := TunnelPath{Relay: relay.addr}
					policy := PeerPathPolicy{Mode: Auto, Relays: []netip.Addr{relay.addr}}
					require.NoError(t, n.SetPeerPathPolicy(ctx, remote.addr, &policy))
					paired, err := n.CheckPeerPath(ctx, remote.addr, via)
					require.NoError(t, err)
					require.Equal(t, via.Relay, paired.Sent.Relay)
					require.False(t, paired.Received.Relay.IsValid())
					policy.Mode = RelayOnly
					require.NoError(t, n.SetPeerPathPolicy(ctx, remote.addr, &policy))
					require.Eventually(t, func() bool {
						check, e := n.CheckPeerPath(ctx, remote.addr, TunnelPath{})
						return e == nil && check.Sent.Relay == relay.addr && check.Received.Relay == relay.addr
					}, 8*time.Second, 20*time.Millisecond)
					p, rx := testIPPort(t, n)
					pkt := testIPv4(local.addr, remote.addr, "\x08\x00\x00\x00\x01\x02\x00\x01nebula")
					pkt[9] = 1
					binary.BigEndian.PutUint16(pkt[10:], ^checksum.Checksum(pkt[:20], 0))
					binary.BigEndian.PutUint16(pkt[22:], ^checksum.Checksum(pkt[20:], 0))
					require.NoError(t, p.WriteIP(netip.Addr{}, pkt))
					select {
					case reply := <-rx:
						require.Len(t, reply, len(pkt))
						require.Equal(t, remote.addr.AsSlice(), reply[12:16])
						require.Equal(t, local.addr.AsSlice(), reply[16:20])
						require.Zero(t, reply[20])
						require.Equal(t, pkt[24:], reply[24:])
					case <-ctx.Done():
						t.Fatal("upstream ICMP echo reply missing")
					}
					if version == cert.Version2 {
						v6 := make([]byte, 48)
						v6[0], v6[6], v6[7], v6[40] = 0x60, 58, 64, 128
						binary.BigEndian.PutUint16(v6[4:], 8)
						copy(v6[8:24], local.addr6.AsSlice())
						copy(v6[24:40], remote.addr6.AsSlice())
						sum := checksum.Checksum(v6[8:40], 0)
						binary.BigEndian.PutUint16(v6[42:], ^checksum.Checksum(v6[40:], sum+8+58))
						require.NoError(t, p.WriteIP(remote.addr, v6))
						select {
						case reply := <-rx:
							require.Len(t, reply, 48)
							require.EqualValues(t, 129, reply[40])
							require.Equal(t, remote.addr6.AsSlice(), reply[8:24])
						case <-ctx.Done():
							t.Fatal("missing ICMPv6 echo reply")
						}
					}
				})
			}
		}
	}
}

// A lighthouse query from the embedded node asks the stock endpoint to punch back.
// With no end-to-end session and direct handshakes denied, stock must discover R
// and originate the end-to-end handshake through the embedded forwarding node.
func TestNodeUpstreamRelayInitiator(t *testing.T) {
	binaryPath := os.Getenv("NEBULA_INTEROP_BINARY")
	if binaryPath == "" {
		t.Skip("set NEBULA_INTEROP_BINARY to the upstream executable")
	}
	for _, version := range []cert.Version{cert.Version1, cert.Version2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			pool, ids := pathTestIdentities(t, version, 3)
			a, b, r := ids[0], ids[1], ids[2]
			socks, static := interopSockets(t, ids)
			var endpoint, relay *Node
			for _, i := range []int{2, 0} {
				opts := Options{Identities: []Identity{ids[i].identity}, CAPool: pool, Transport: WrapPacketConn(socks[i]), InitiatingVersion: version}
				opts.Lighthouse.StaticHosts = maps.Clone(static)
				delete(opts.Lighthouse.StaticHosts, ids[i].addr)
				if i == 2 {
					opts.Relay.Serve = true
					opts.Lighthouse.AmLighthouse = true
				} else {
					opts.Lighthouse.Hosts = []netip.Addr{r.addr}
					opts.Lighthouse.AdvertiseEndpoints = static[a.addr]
					opts.Relay.AdvertiseVia = []netip.Addr{r.addr}
					opts.Paths.Peers = map[netip.Addr]PeerPathPolicy{b.addr: {Mode: RelayOnly, Relays: []netip.Addr{r.addr}}}
				}
				n, err := New(t.Context(), opts)
				require.NoError(t, err)
				require.NoError(t, n.Start())
				t.Cleanup(func() { _ = n.Close(); _ = n.Wait() })
				if i == 2 {
					relay = n
				} else {
					endpoint = n
				}
			}
			startStockNode(t, binaryPath, pool, b, socks[1], static, []netip.Addr{r.addr}, false)
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			require.Eventually(t, func() bool {
				one, ok := relay.PeerDiscovery(a.addr)
				other, exists := relay.Peer(b.addr)
				return ok && slices.Contains(one.Relays, r.addr) && exists && other.State == PeerStateEstablished
			}, 5*time.Second, 20*time.Millisecond)
			require.Eventually(t, func() bool {
				if h, ok := endpoint.Peer(b.addr); ok && h.State == PeerStateEstablished {
					return !h.Initiator && h.PathHealth.Active.Path.Relay == r.addr
				}
				require.NoError(t, endpoint.RefreshPeer(ctx, b.addr))
				return false
			}, 8*time.Second, 100*time.Millisecond)
			check, err := endpoint.CheckPeerPath(ctx, b.addr, TunnelPath{})
			require.NoError(t, err)
			require.True(t, check.SamePath)
			require.Equal(t, r.addr, check.Sent.Relay)
		})
	}
}
