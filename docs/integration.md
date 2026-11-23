# 将节点嵌入 Go 应用

应用提供可信根、本机凭据、拓扑和物理套接字。每个 `Node` 持有独立的连接和路径状态。可以直接收发 IP，也可以把节点接到宿主创建的 gVisor 栈。[首次运行](quickstart.md) · [可运行的网关](../examples/gateway/main.go)

## 节点生命周期

下面的函数接收长期服务的 context、包含凭据和拓扑的 `opts` 以及对端任一虚拟地址。示例由函数内部创建唯一的物理套接字。`New` 成功时接管套接字和监听器；构造失败时由调用方关闭。节点启动后，取消服务 context 会触发关闭，显式调用 `Close` 可以等待后台任务退出。拨号 context 只控制本次等待，同一成员的建链尝试由节点共享。

```go
func serve(serviceCtx context.Context, opts nebula.Options, peer netip.Addr) error {
    socket, err := net.ListenPacket("udp4", "0.0.0.0:4242")
    if err != nil {
        return err
    }
    opts.UDP4 = socket
    node, err := nebula.New(serviceCtx, opts)
    if err != nil {
        socket.Close()
        return err
    }
    defer node.Close()
    if err := node.Start(); err != nil {
        return err
    }

    dialCtx, cancel := context.WithTimeout(serviceCtx, 5*time.Second)
    err = node.ConnectPeer(dialCtx, peer)
    cancel()
    if err != nil {
        return err
    }
    <-serviceCtx.Done()
    return serviceCtx.Err()
}
```

需要接收启动后的第一条消息或第一个包时，在 `Start` 前调用 `Subscribe` 或 `OpenIPPort`。初始路径策略也可在这时安装。`ConnectPeer`、`Publish`、`WriteIP` 需要节点已启动。重复启动返回 `ErrNodeAlreadyStarted`；关闭后的节点结束服务，重新启动服务时创建新实例。

## 跨机器连接

以 A、B 为例，在两端安装同一网络 `demo` 的成员视图，`Networks` 填 `10.13.0.0/24` 和 `fd13::/64`。以下物理地址为文档示例，替换为对端实际可达的地址。

| 成员 | 本机证书中的 IP SAN | 本机物理监听 | 双方拓扑中该成员的 `Endpoints` |
| --- | --- | --- | --- |
| A | `10.13.0.1`、`fd13::1` | `0.0.0.0:4242` UDP | `{Network: "udp", Address: netip.MustParseAddrPort("192.0.2.10:4242")}` |
| B | `10.13.0.2`、`fd13::2` | `0.0.0.0:4242` UDP | `{Network: "udp", Address: netip.MustParseAddrPort("192.0.2.20:4242")}` |

每台机器只加载自己的私钥、叶证书及中间链，`Options.Roots` 装入可信根。A 调用 `ConnectPeer(ctx, netip.MustParseAddr("fd13::2"))` 即可拨向 B。在两个成员的 `Links` 里互填完整 `PeerID` 可让节点主动维持邻接。启动前可用 `Topology.Validate()` 预检配置，运行中用 `ApplyTopology(ctx, topology)` 发布整份新视图。[拓扑模型](../topology.go) · [凭据装载](pki.md)

`UDP4/UDP6` 用于对应地址族的 QUIC 监听、拨号和打洞；`TCP4/TCP6` 接收入站 TCP 连接，出站 TCP 默认使用 `net.Dialer`，可通过 `DialTCP` 接入自有网络栈。有可达的 TCP 候选端点时，仅配置了 UDP 监听的本机也可以向其拨号。UDP 和 TCP 可以监听同一端口号。经过 NAT 时可在 `AdvertiseEndpoints` 公布映射后的本机地址。用任一虚拟地址查找成员，签名端点介绍负责补充物理候选地址。[端点发现](mesh.md#发现选路与中继)

## 选择直连或中继

`SetPeerPathPolicy(peer, mode)` 中的 `peer` 可以是对端任一虚拟地址。`Auto` 允许在合规路径间选路，`DirectOnly` 只许直连，`RelayOnly` 只许经中继，`Blocked` 封锁到该成员的路径。两端任一成员启用 `Restricted` 后，只有列在双向 `Links` 的邻居才能直连。电路每个中间成员还须启用 `Transit`。节点维护间隔 `Interval` 默认 2 秒，单次拨号和控制交换使用的 `DialTimeout` 默认 4 秒。`MaxCircuits` 默认 128。[三节点配置和 IP 回执](../examples/relay/main.go)

```go
if err := node.SetPeerPathPolicy(peer, nebula.RelayOnly); err != nil {
    return err
}
if err := node.ConnectPeer(ctx, peer); err != nil {
    return err
}
for _, path := range node.Paths() {
    if path.Active && (path.Peer.IPv4() == peer || path.Peer.IPv6() == peer) {
        log.Printf("peer=%s transport=%s circuit=%v tls_group=%s",
            path.Peer, path.Transport, path.Circuit, path.TLSGroup)
    }
}
```

## IP 收发与网关

每个节点同时可附加一个 IP 端口。`OpenIPPort` 接收完整 IP 包，回调可能并发执行；在回调外关闭节点。`WriteIP(netip.Addr{}, packet)` 按目标虚拟地址选择成员，访问下游地址时传入网关的虚拟地址作为下一跳。返回成功表示已复制并入队。应用可用 `errors.Is` 区分立即拒绝的原因，再结合实际收包和异步计数排障。

```go
err := port.WriteIP(gateway, packet)
switch {
case errors.Is(err, nebula.ErrQueueFull):
    log.Printf("send queue full: %+v", port.Stats())
case errors.Is(err, nebula.ErrPathPolicy), errors.Is(err, nebula.ErrAddressUnauthorized):
    log.Printf("check path and address authorization via %v", gateway)
case errors.Is(err, nebula.ErrMissingGateway):
    log.Printf("check the overlay next hop for this destination")
}
return err
```

`Stats().Queued` 表示仍在队列中等待的包，`RejectedOutbound` 和 `LastDrop` 可以帮助发现入队后的建链、授权或传输出错。`ClearPending(peer)` 清理积压并取消当前等待，返回仍在队列中的包数。节点运行中单独关闭端口后，写入返回 `ErrPortClosed`。在本机拓扑成员上设置 `BytesPerSecond` 并应用拓扑，可以限制本机提交的 IP、事件及中继应用字节总量，单位为字节每秒，零表示不限速。

网关示例采用外层 TLS/TCP，通过 `nebulagvisor.NewEndpoint` 独占节点 IP 端口，再用 `CreateNIC` 加入用户态网络栈。注册失败调用 `Endpoint.Close`，成功后用 `RemoveNIC` 拆卸。双栈 NIC 的默认 MTU 为 1300 字节，受节点 `MaxIPSize` 限制，最低 1280 字节。逐路由设置 MTU 时，例如 `node.RecommendedMTU(gateway, destination.Is6(), int(ep.MTU()))`，第二个参数表示内层目的地址族。查询在没有活动路径时也可返回给定上限。[适配器](../nebulagvisor/endpoint.go)

访问下游失败时，沿报文方向逐项检查。[双栈网关源码](../examples/gateway/main.go)

1. 签发网关证书时，通过 `Enrollment.Scope.RoutedPrefixes` 或 CLI `-routes` 批准下游 IPv4、IPv6 前缀。
2. 两端拓扑通过网关成员的 `RoutedPrefixes` 启用相应前缀，客户端把去往这些前缀的路由指向网关虚拟地址。
3. 网关的 mesh NIC 和 LAN NIC 都有地址，两个 NIC 对相应地址族均启用 `SetNICForwarding`。
4. 下游主机把去往 mesh 网段的路由指向网关 LAN 地址。示例中的回显服务会核对它看到的客户端源地址。

`Options.InboundPolicy` 在会话、拓扑和证书地址授权通过后执行。比如接收端仅允许某个网关转发来自获准 LAN 的流量时，可以在构造节点前设置以下附加过滤。回调使用的策略数据应支持并发读取。

```go
opts.InboundPolicy = func(peer nebula.PeerID, src, dst netip.Addr) bool {
    return peer == gatewayID && allowedLAN.Contains(src) && dst == serviceIP
}
```

## 事件与运行状态

发布方的 `Member.Topics` 可授予 `app/demo` 及其子树；订阅方按完整主题 `app/demo/hello` 调用 `Subscribe`。先注册订阅并消费 `sub.Events()`，再触发业务。`Publish` 返回的 ID 表示本机已接纳，可以用它关联接收端回执。邻居在有效期内补发缺失事件；本机新建的订阅从之后接纳的事件开始交付。缓冲上限为 32 条，`sub.Missed()` 记录本订阅因缓冲满而丢弃的数量。`sub.Close()` 或关闭节点都会关闭交付 channel。[事件收发示例](../examples/quickstart/main.go)

- 检查服务启动和本机资格用 `ControlStatus().Started` 与 `Ready`。本机证书和成员视图有效时，启动前 `Ready` 也可以为真。
- 检查对端连通性先用 `ConnectPeer`，再用 `Paths()` 看每条已建立路径的 `Active`、`Transport`、`Circuit` 和 `AuthorizedUntil`。同一成员可能有多行。`TLSGroup` 为握手使用的密钥交换组。
- 检查数据交付用 `IPPort.Stats()` 或 `nebulagvisor.Endpoint.Stats()`，最后核对接收端业务回执。证书热加载和宿主授权复查另见 PKI 指南。[证书管理](pki.md#热加载与宿主授权)

## gVisor 的 IPv4 网关构建

本项目使用 gVisor 的 `go` 分支。当前固定版本 `83df8eae069e` 在 IPv4 单播转发复制报文后，仍从先前取得的原包头读取 TTL。使用该版本构建 IPv4 转发网关时，可应用仓库补丁，在复制前保存 TTL。在宿主应用的模块根目录执行以下命令，将 `/path/to/gvisor-ipv4-ttl.patch` 换成补丁的实际路径。[上游转发实现](https://github.com/google/gvisor/blob/83df8eae069e6c607672f779f63f3538815cc037/pkg/tcpip/network/ipv4/ipv4.go#L788-L835) · [IPv4 转发补丁](../patches/gvisor-ipv4-ttl.patch)

```sh
go mod vendor
git apply --directory=vendor/gvisor.dev/gvisor /path/to/gvisor-ipv4-ttl.patch
go test -mod=vendor -race ./...
```
