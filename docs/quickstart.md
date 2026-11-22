# 在 gVisor 栈上连接 Nebula peer

本例从客户端 `10.42.0.1` 通过 Nebula 隧道连接对端的 TCP 服务。外层 UDP 由操作系统收发，内层 TCP 连接由应用的 gVisor 栈建立。[安装说明](../README.md#安装)

运行示例需要以下条件。

- `s` 是已启用 `ipv4.NewProtocol` 和 `tcp.NewProtocol` 的 gVisor 栈，`nic` 是其中一个空闲 NIC ID。
- `identity` 是客户端证书及其原始私钥，证书地址为 `10.42.0.1/24`。`pool` 包含签发本机和对端证书的受信 CA。[加载或签发证书](../cert/README.md)
- `peerUDP` 是对端实际可达的 IPv4 地址和 UDP 监听端口。对端证书中的 overlay 地址为 `10.42.0.254`，其 TCP 服务监听 `10.42.0.254:8080`。

```go
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/nebulagvisor"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func CheckPeer(ctx context.Context, s *stack.Stack, nic tcpip.NICID,
	identity nebula.Identity, pool *cert.CAPool, peerUDP netip.AddrPort) (err error) {
	peer := netip.MustParseAddr("10.42.0.254")
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	node, err := nebula.New(ctx, nebula.Options{
		Identities: []nebula.Identity{identity},
		CAPool:     pool,
		Transport:  nebula.WrapPacketConn(pc),
		Lighthouse: nebula.LighthouseOptions{
			StaticHosts: map[netip.Addr][]netip.AddrPort{peer: {peerUDP}},
		},
	})
	if err != nil {
		_ = pc.Close()
		return err
	}
	defer func() { err = errors.Join(err, node.Close(), node.Wait()) }()

	ep, err := nebulagvisor.NewEndpoint(node, nebulagvisor.Options{})
	if err != nil {
		return err
	}
	if e := s.CreateNIC(nic, ep); e != nil {
		ep.Close()
		return fmt.Errorf("create NIC: %s", e)
	}
	defer s.RemoveNIC(nic)

	prefix := identity.Certificate.Networks()[0]
	local := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(prefix.Addr().AsSlice()),
		PrefixLen: prefix.Bits(),
	}
	if e := s.AddProtocolAddress(nic, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local,
	}, stack.AddressProperties{}); e != nil {
		return fmt.Errorf("assign address: %s", e)
	}
	s.AddRoute(tcpip.Route{Destination: local.Subnet(), NIC: nic})
	if err := node.Start(); err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(node.Context(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(dialCtx, s, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(peer.AsSlice()), Port: 8080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	return conn.Close()
}
```

此函数在 TCP 连接建立后关闭连接并卸载网卡。长期运行的服务可在多次拨号间复用节点和 NIC，在退出时统一清理。若拨号超时，可先核对 peer 的 UDP 候选地址和实际路径。[排错指南](nebula-nic.md#排错)
