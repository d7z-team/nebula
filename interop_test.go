package nebula

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// Run against an independently built upstream executable. Its disabled TUN
// replies to ICMP in-process, so neither network namespaces nor root are needed.
func TestNodeUpstreamInterop(t *testing.T) {
	binaryPath := os.Getenv("NEBULA_INTEROP_BINARY")
	if binaryPath == "" {
		t.Skip("set NEBULA_INTEROP_BINARY to the upstream nebula executable")
	}
	for _, initiator := range []bool{true, false} {
		t.Run(fmt.Sprintf("embedded_initiator_%t", initiator), func(t *testing.T) {
			pool, local, remote := newNodeTestIdentities(t)
			localSock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = localSock.Close() })
			reserved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			remoteUDP := reserved.LocalAddr().(*net.UDPAddr).AddrPort()
			require.NoError(t, reserved.Close())
			dir := t.TempDir()
			for _, ca := range pool.CAs {
				pem, err := ca.Certificate.MarshalPEM()
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), pem, 0600))
			}
			pem, err := remote.identity.Certificate.MarshalPEM()
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "host.crt"), pem, 0600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "host.key"), cert.MarshalPrivateKeyToPEM(remote.identity.Certificate.Curve(), remote.identity.PrivateKey), 0600))
			lighthouseHosts := "[]"
			if !initiator {
				lighthouseHosts = fmt.Sprintf("[%s]", local.addr)
			}
			cfg := fmt.Sprintf(`pki: {ca: ca.crt, cert: host.crt, key: host.key}
cipher: aes
listen: {host: 127.0.0.1, port: %d}
tun: {disabled: true}
static_host_map: {"%s": ["%s"]}
lighthouse: {hosts: %s, interval: 1}
firewall:
  inbound: [{proto: icmp, host: any, port: any}]
  outbound: [{proto: icmp, host: any, port: any}]
`, remoteUDP.Port(), local.addr, localSock.LocalAddr(), lighthouseHosts)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(cfg), 0600))
			n, err := New(t.Context(), Options{Identities: []Identity{local.identity}, CAPool: pool, Transport: WrapPacketConn(localSock),
				Lighthouse: LighthouseOptions{AmLighthouse: !initiator, StaticHosts: map[netip.Addr][]netip.AddrPort{remote.addr: {remoteUDP}}}})
			require.NoError(t, err)
			require.NoError(t, n.Start())
			t.Cleanup(func() { _ = n.Close(); _ = n.Wait() })
			p, rx := testIPPort(t, n)
			cmd := exec.Command(binaryPath, "-config", "config.yml")
			cmd.Dir = dir
			logFile, err := os.Create(filepath.Join(dir, "upstream.log"))
			require.NoError(t, err)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			require.NoError(t, cmd.Start())
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				_ = logFile.Close()
				if t.Failed() {
					logs, _ := os.ReadFile(logFile.Name())
					t.Log(string(logs))
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if initiator {
				require.NoError(t, n.ConnectPeer(ctx, remote.addr))
			}
			require.Eventually(t, func() bool {
				p, ok := n.Peer(remote.addr)
				return ok && p.State == PeerStateEstablished && p.Initiator == initiator
			}, 8*time.Second, 10*time.Millisecond)

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
		})
	}
}
