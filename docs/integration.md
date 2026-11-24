# 将节点嵌入 Go 应用

每个 `Node` 持有独立的连接和路径状态。实际接入可从双进程示例开始：用 `pki.ParseCertificatesPEM` 装入可信根集合和固定的单张集群 CA，用 `tls.LoadX509KeyPair` 装入本机叶链和私钥，再将宿主批准的 JSON 解码到 `nebula.Topology`。节点可以直接收发 IP，也可接到宿主创建的 gVisor 栈。[可运行的磁盘凭据示例](quickstart.md#使用磁盘凭据启动两个进程) · [双栈网关](../examples/gateway/main.go)

## 节点生命周期

物理端口已用于 HTTPS 或 HTTP/3 时，可以让节点和网站使用同一分流器的不同分支。多个域名仍可使用同一网站监听器。[端口复用接入与关闭](portshare.md#接入与关闭)

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

需要接收启动后的第一条消息或第一个包时，在 `Start` 前调用 `Subscribe` 或 `OpenIPPort`。初始路径策略也可在这时安装。`ConnectPeer`、`Publish`、`WriteIP` 需要节点已启动。已取消的调用不会启动新的拨号。重复启动返回 `ErrNodeAlreadyStarted`。后台收发或认证回调可以通知宿主退出，由外层 goroutine 调用 `Close` 并等待任务结束。

## 运行中更新

| 宿主操作 | 入口与生效范围 | 如何判断结果 |
| --- | --- | --- |
| 更新本机的成员、邻接、地址或发布权限 | `ApplyTopology(ctx, view)` 校验并安装整份视图，清理失权路径与积压。无效视图返回错误并保留现状。 | 返回 nil 表示视图已安装。撤回本机资格后 `ControlStatus().Ready` 为 false。 |
| 为同一个成员换证 | `ReloadCertificates(ctx, set)` 校验完整凭据后原子替换；失败保留原凭据。之后的握手和对象签名使用新凭据。 | `ControlStatus().Serial` 是当前客户端证书序列号。`Paths()` 每行的 `LocalSerial` 是该会话实际使用的本机证书序列号。 |
| 宿主改变了授权钩子的判定 | 更新宿主策略，再调用 `Revalidate(ctx)` 复查本机凭据、会话和缓存事件。 | 返回 nil 表示复查完成。用 `ControlStatus().Ready` 看本机资格，用 `Paths()` 看复查后的路径。 |

`New` 和 `ApplyTopology` 各自保存一份私有拓扑。如果宿主也要为不同节点准备可独立修改的视图，为每份视图创建自己的 `Members` 切片，用 `member.Clone()` 复制要放入的成员。这样可以在一份视图中修改邻接、端点或主题，其他视图继续使用各自的值。[多节点示例](../examples/demo/nodes.go)

信任根和集群 CA 在创建节点时固定。[凭据示例与授权钩子](pki.md#热加载与宿主授权)

## 跨机器连接

以 A、B 为例，在两端安装同一网络 `demo` 的成员视图，并在集群 CA 的 IP Name Constraints 中声明 `10.13.0.0/24` 和 `fd13::/64`。以下物理地址为文档示例，替换为对端实际可达的地址。

| 成员 | 本机证书中的 IP SAN | 本机物理监听 | 双方拓扑中该成员的 `Endpoints` |
| --- | --- | --- | --- |
| A | `10.13.0.1`、`fd13::1` | `0.0.0.0:4242` UDP | `{Network: "udp", Address: netip.MustParseAddrPort("192.0.2.10:4242")}` |
| B | `10.13.0.2`、`fd13::2` | `0.0.0.0:4242` UDP | `{Network: "udp", Address: netip.MustParseAddrPort("192.0.2.20:4242")}` |

每台机器只加载自己的私钥、叶证书及中间链，`Options.Roots` 装入可信根，`Options.ClusterCA` 指向定义此集群的证书。A 调用 `ConnectPeer(ctx, netip.MustParseAddr("fd13::2"))` 即可拨向 B。在两个成员的 `Links` 里互填完整 `PeerID` 可让节点主动维持邻接。启动前可用 `Topology.Validate(cluster)` 预检配置，运行中用 `ApplyTopology(ctx, topology)` 发布整份新视图。[拓扑模型](../topology.go) · [凭据装载](pki.md)

`UDP4/UDP6` 用于对应地址族的 QUIC 监听、拨号和打洞。`TCP4/TCP6` 接收入站 TCP，出站 TCP 默认使用 `net.Dialer`，可通过 `DialTCP` 接入自有网络栈。UDP 和 TCP 可以监听同一端口号。

| 部署需要 | 由谁填写 | 使用方式 |
| --- | --- | --- |
| 启动时已知的物理入口 | 宿主在本机拓扑的目标 `Member.Endpoints` 填入可达 UDP 或 TCP 端点 | 用目标虚拟主地址调用 `ConnectPeer`。 |
| 公布宿主已知的 NAT 映射 | 位于 NAT 内的节点在 `Options.AdvertiseEndpoints` 填入自己的映射地址 | 节点将这些候选地址写入签名介绍，邻居可从中发现直连入口。 |
| 经共同邻居会合 | 宿主在相应成员视图中填写双向 `Links`，让双方能到达该邻居 | 邻居协助交换端点，双方在各自实际 UDP 套接字上打洞。 |
| 允许直连失败后走中继 | 宿主在路径各跳的拓扑中给中间成员设置 `Transit` 并配置双向邻接 | 默认 `Auto` 可建立电路，`RelayOnly` 指定经中继。检查 `Paths()` 的 `Transport`、`Circuit` 和业务回执。 |

两个成员共用外层 NAT，而其中一个成员还在内层网关之后时，中间网段上的成员可能无法经公网地址回连。如果宿主知道内层网关面向中间网段的映射，例如 UDP `100.64.0.2:45001`，可以将它加入内层成员的 `Options.AdvertiseEndpoints`。中间网段的成员便可从签名介绍取得该地址并尝试直连。[NAT 场景重放](testing.md#运行测试) · [发现与选路机制](mesh.md#发现选路与中继)

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

每个节点可附加一个 IP 端口。`OpenIPPort(nebula.IPPortOptions{Deliver: receive})` 将完整 IP 包和经过认证的端到端发送方 ID 交给 `receive(from, packet)`。端口回调可并发，在节点和端口锁外运行。在回调外关闭节点。`WriteIP(nebula.PeerID{}, packet)` 能解析主地址和组地址；访问远端 VIP 或下游地址时，传入选定实例或网关的完整 ID，也可在端口选项中提供 `ResolveNextHop`。[下一跳与回程](addressing.md#下一跳与回程)

```go
gateway, ok := node.LookupPeer(gatewayPrimary)
if !ok {
    return nebula.ErrPeerUnavailable
}
err := port.WriteIP(gateway, packet)
switch {
case errors.Is(err, nebula.ErrQueueFull):
    log.Printf("send queue full: %+v", port.Stats())
case errors.Is(err, nebula.ErrPathPolicy), errors.Is(err, nebula.ErrAddressUnauthorized):
    log.Printf("check path and address authorization via %v", gateway)
case errors.Is(err, nebula.ErrPeerUnavailable):
    log.Printf("check membership of %s", gateway)
}
return err
```

| 需要确认的结果 | 查看位置 | 能确认的事实 |
| --- | --- | --- |
| 本机是否接纳写入 | `WriteIP` 的返回值 | 单播成功表示已复制入队。组投递可能只有部分接收者入队，合法空组也可返回 nil。本机收包上限同样约束写入大小。 |
| 包在发送队列中发生了什么 | `Stats()`、`ClearPending(peerID)` | `Queued` 只计等待包；清空操作返回移除的等待包数，并尝试取消在途包。等待期间因撤权或拥塞的丢弃可查拒绝计数。 |
| 已出队的这次提交是否成功 | `ObserveTransmit(result)` | 拨号失败时 `Transport` 为空。选好路径后发现包超过对端上限时，结果带有所选传输，且 `errors.Is(result.Err, nebula.ErrPacketTooLarge)` 为真。回调可能并发，应及时返回。 |
| 远端业务是否处理了请求 | 对端应用回执 | 用请求 ID 和预期成员关联回执。传输接受一个包后，远端仍可能丢弃它。 |

异步上限示例可用 `go test -v -run '^ExampleIPPort_WriteIP$' .` 运行。[可执行示例](../example_test.go) · [双进程应用回执](quickstart.md#使用磁盘凭据启动两个进程)

在本机拓扑成员上设置 `BytesPerSecond` 并应用拓扑，可以限制本机提交的 IP、事件及中继应用字节总量，单位为字节每秒，零表示不限速。

网关示例采用外层 TLS/TCP，通过 `nebulagvisor.NewEndpoint` 独占节点 IP 端口，再用 `CreateNIC` 加入用户态网络栈。注册失败调用 `Endpoint.Close`，成功后用 `RemoveNIC` 拆卸。双栈 NIC 的默认 MTU 为 1300 字节，受节点 `MaxIPSize` 限制，最低 1280 字节。逐路由设置 MTU 时，例如 `node.RecommendedMTU(gateway, destination.Is6(), int(ep.MTU()))`，第二个参数表示内层目的地址族。查询在没有活动路径时也可返回给定上限。[适配器](../nebulagvisor/endpoint.go)

访问下游失败时，沿报文方向逐项检查。[双栈网关源码](../examples/gateway/main.go)

1. 在集群 CA 设置下游路由委派上限。签发网关证书时，通过 `Enrollment.Scope.RoutedPrefixes` 或 CLI `-routes` 批准下游 IPv4、IPv6 前缀。
2. 两端拓扑通过网关成员的 `RoutedPrefixes` 启用相应前缀，客户端把去往这些前缀的路由指向网关虚拟地址。
3. 网关的 mesh NIC 和 LAN NIC 都有地址，两个 NIC 对相应地址族均启用 `SetNICForwarding`。
4. 下游主机把去往 mesh 网段的路由指向网关 LAN 地址。示例中的回显服务会核对它看到的客户端源地址。

网关回包进入 gVisor 栈之前，`nebulagvisor.Options.ObserveReceive(from, packet)` 会提供端到端认证的发送方和完整只读 IP 包。宿主可在这里记录业务流对应的入站网关，再在 `ResolveNextHop` 中使用该绑定。回调可能并发，需在返回后使用包内容时应先复制。[网关示例](../examples/gateway/main.go)

`Options.InboundPolicy` 在会话、拓扑和证书地址授权通过后执行。比如接收端仅允许某个网关转发来自获准 LAN 的流量时，可以在构造节点前设置以下附加过滤。回调使用的策略数据应支持并发读取。

```go
opts.InboundPolicy = func(peer nebula.PeerID, src, dst netip.Addr) bool {
    return peer == gatewayID && allowedLAN.Contains(src) && dst == serviceIP
}
```

## 事件与运行状态

发布方的 `Member.Topics` 可授予 `app/demo` 及其子树；订阅方按完整主题 `app/demo/hello` 调用 `Subscribe`。先注册订阅并消费 `sub.Events()`，再触发业务。`Publish` 返回的 ID 表示本机已接纳，可以用它关联接收端回执。邻居在有效期内补发缺失事件；本机新建的订阅从之后接纳的事件开始交付。缓冲上限为 32 条，`sub.Missed()` 记录本订阅因缓冲满而丢弃的数量。`sub.Close()` 或关闭节点都会关闭交付 channel。[事件收发示例](../examples/quickstart/main.go)

- TCP 监听遇到暂时性错误会退避重试。永久错误可从 `ControlStatus().ListenerErrors["tcp4"]` 或 `["tcp6"]` 读取，用于定位退出的入口。
- 检查服务启动和本机资格用 `ControlStatus().Started` 与 `Ready`。本机证书和成员视图有效时，启动前 `Ready` 也可以为真。
- 检查对端连通性先用 `ConnectPeer`，再用 `Paths()` 看每条已建立路径的 `Active`、`Transport`、`Circuit` 和 `AuthorizedUntil`。同一成员可能有多行。`TLSGroup` 为握手使用的密钥交换组。
- 对照一般流量的首选路径与单个包实际选择的路径，使用 `Paths()` 各行的 `Active` 和端口或 gVisor 的 `ObserveTransmit`。[发送诊断](#ip-收发与网关)

## gVisor 的 IPv4 网关构建

本项目使用 gVisor 的 `go` 分支。当前固定版本 `83df8eae069e` 在 IPv4 单播转发复制报文后，仍从先前取得的原包头读取 TTL。使用该版本构建 IPv4 转发网关时，可应用仓库补丁，在复制前保存 TTL。在宿主应用的模块根目录执行以下命令，将 `/path/to/gvisor-ipv4-ttl.patch` 换成补丁的实际路径。[上游转发实现](https://github.com/google/gvisor/blob/83df8eae069e6c607672f779f63f3538815cc037/pkg/tcpip/network/ipv4/ipv4.go#L788-L835) · [IPv4 转发补丁](../patches/gvisor-ipv4-ttl.patch)

```sh
go mod vendor
git apply --directory=vendor/gvisor.dev/gvisor /path/to/gvisor-ipv4-ttl.patch
go test -mod=vendor -race ./...
```

广播、组播和任播服务的 NIC 掩码、订阅和服务 socket 配置见[集群地址与 IP 交付](addressing.md#gvisor-接入)。
