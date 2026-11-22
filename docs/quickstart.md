# 在 gVisor 栈上连接 Nebula peer

本例从客户端 `10.42.0.1` 连接对端的 `10.42.0.254:8080`。调用方提供以下参数。

- `s` 是已启用 `ipv4.NewProtocol` 和 `tcp.NewProtocol` 的 gVisor 栈，`nic` 是其中一个空闲 NIC ID。
- `identity` 是客户端证书及其原始私钥，证书地址为 `10.42.0.1/24`。`pool` 包含签发本机和对端证书的受信 CA。[加载或签发证书](../cert/README.md)
- `peerUDP` 是对端可达的外层 IPv4 地址和 UDP 端口。对端已启动 Nebula，并在隧道地址 `10.42.0.254` 的 TCP 8080 端口提供服务。

在调用方模块中引入本分支后，即可使用下面的客户端函数。[安装说明](../README.md#安装)

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

	local := tcpip.AddressWithPrefix{
		Address: tcpip.AddrFrom4([4]byte{10, 42, 0, 1}), PrefixLen: 24,
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

第一次拨号会触发隧道握手。长期运行的服务可复用同一个节点和 NIC，在服务退出时卸载 NIC、关闭节点并等待退出。遇到连接超时或丢包时，可分别检查外层 UDP 候选、实际路径和端口拒绝原因。[排错指南](nebula-nic.md#排错)
