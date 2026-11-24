# 将节点嵌入 Go 应用

每个 `Node` 独立持有凭据、拓扑和会话。用 `pki.ParseCertificatesPEM` 读取可信根和集群 CA，用 `tls.LoadX509KeyPair` 装入本机叶链和私钥，再把宿主批准的成员视图传给 `Options.Topology`。只知道一个已有成员的物理地址时，初始视图可以只列本机。节点可以直接收发 IP，也可接到宿主创建的 gVisor 栈。[双进程接入](quickstart.md#使用磁盘凭据启动两个进程) · [双栈网关](../examples/gateway/main.go)

## 节点生命周期

下面的函数以已有成员的物理 UDP 端点接入网络。`New` 成功时接管套接字和监听器，构造失败时由调用方关闭。取消服务 context 会触发已启动节点的关闭，显式调用 `Close` 会等待后台任务退出。

```go
func serve(serviceCtx context.Context, opts nebula.Options, ep nebula.Endpoint) error {
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
    _, err = node.ConnectEndpoint(dialCtx, ep)
    cancel()
    if err != nil {
        return err
    }
    <-serviceCtx.Done()
    return serviceCtx.Err()
}
```

需要接收启动后的第一条消息或第一个包时，在 `Start` 前调用 `Subscribe` 或 `OpenIPPort`。初始路径策略也可在这时安装。连接、网络查询、发布和写包都需要节点已启动。已取消的调用不会启动新的拨号。重复启动返回 `ErrNodeAlreadyStarted`。后台收发或认证回调可以通知宿主退出，由外层 goroutine 调用 `Close` 并等待任务结束。

## 运行中更新

| 宿主操作 | 入口与生效范围 | 如何判断结果 |
| --- | --- | --- |
| 更新本机的成员、邻接、地址或发布权限 | `ApplyTopology(ctx, view)` 校验并安装整份视图，清理失权路径与积压。无效视图返回错误并保留现状。 | 返回 nil 表示视图已安装。撤回本机资格后 `ControlStatus().Ready` 为 false。 |
| 为同一个成员换证 | `ReloadCertificates(ctx, set)` 校验完整凭据后原子替换；失败保留原凭据。之后的握手和对象签名使用新凭据。 | `ControlStatus().Serial` 是当前客户端证书序列号。`Paths()` 每行的 `LocalSerial` 是该会话实际使用的本机证书序列号。 |
| 宿主改变了授权钩子的判定 | 更新宿主策略，再调用 `Revalidate(ctx)` 复查本机凭据、会话和缓存主题消息，并清空发现缓存。 | 返回 nil 表示复查完成。用 `ControlStatus().Ready` 看本机资格，用 `Paths()` 看复查后的路径。 |

`New` 和 `ApplyTopology` 各自保存一份私有拓扑。如果宿主也要为不同节点准备可独立修改的视图，为每份视图创建自己的 `Members` 切片，用 `member.Clone()` 复制要放入的成员。这样可以在一份视图中修改邻接、端点或主题，其他视图继续使用各自的值。[多节点示例](../examples/demo/nodes.go)

信任根和集群 CA 在创建节点时固定。[凭据示例与授权钩子](pki.md#热加载与宿主授权)

## 跨机器连接

`Options.UDP4`、`UDP6` 用于对应地址族的 QUIC 监听、拨号和打洞。`TCP4`、`TCP6` 接收入站 TCP，出站 TCP 默认使用 `net.Dialer`，也可用 `DialTCP` 接入自有网络栈。UDP 和 TCP 可以绑定相同端口号。如果还需在这些端口提供 HTTPS 或 HTTP/3，可把 `portshare` 的 mesh 分支交给节点。[与网站共享监听端口](portshare.md#接入与关闭)

| 已知信息 | 连接方式 |
| --- | --- |
| 一个物理地址和端口 | 用 `ConnectEndpoint(ctx, ep)` 拨号，`ep.Network` 填 `udp` 或 `tcp`。成功后返回在该端点通过认证和路径策略检查的成员 ID。 |
| 对端的一个虚拟主地址 | 如果 `LookupPeer(primary)` 能在本机找到归属，用 `ConnectPeer(ctx, primary)` 连接其所有者。预配置时，在对端的 `Member.Endpoints` 填入可达物理端点。 |
| 对端完整的双栈身份 | 用 `ConnectPeerID(ctx, id)` 等待与该身份的获准路径。要持续维护该邻居，在拓扑中为两端配置双向 `Links`。 |

同一物理端点的并发 `ConnectEndpoint` 共享拨号。取消调用方的 context 会结束该调用的等待，已启动的拨号受节点生命周期和 `DialTimeout` 约束。错误包含传输、地址和底层原因，宿主决定何时重试或换用其他端点。

### 按地址发现成员和下游网关

`LookupPeer(primary)` 只查本机的静态成员、有效签名介绍和已认证会话。如果只知道一个陌生的成员主地址或下游单播地址，使用 `ResolveIP` 查询签名介绍。

```go
matches, err := node.ResolveIP(ctx, netip.MustParseAddr("172.30.0.42"))
if err != nil {
    return err
}
for _, m := range matches {
    log.Printf("gateway %v serves %v, valid until %v", m.Peer, m.Prefix, m.ValidUntil)
}
```

`ResolveIP` 在已认证的邻居之间查询。输入普通集群主地址会精确匹配证书中的任一 IP SAN；输入下游地址会返回本次取得的网关及其最具体的匹配前缀。先按前缀长度、再按成员身份排序。结果可来自尚在有效期内的缓存，表示签名归属信息，业务可达性需通过实际连接确认。调用可取消，冷查询有跳数和时间预算。缓存命中或邻居提前结束查询时，返回的网关可以只是候选的一部分。未找到时可在邻接变化后重试。[可运行示例](../examples/discovery/main.go)

选中结果后调用 `ConnectPeerID(ctx, m.Peer)`，握手绑定完整地址对。向该网关转发下游 IP 包之前，宿主须核准网关及其前缀，并用 `ApplyTopology` 安装相应授权。再调用 `port.WriteIP(m.Peer, packet)`，收发双方根据各自拓扑和实际会话证书校验数据。[网关实例](../examples/gateway/main.go) · [组地址与任播交付](addressing.md)

两个成员共用外层 NAT，而其中一个成员还在内层网关之后时，中间网段上的成员可能无法经公网地址回连。如果宿主知道内层网关面向中间网段的映射，例如 UDP `100.64.0.2:45001`，可以将它加入内层成员的 `Options.AdvertiseEndpoints`。采用默认通告策略时，中间网段的成员便可从签名介绍取得该地址并尝试直连。[NAT 场景重放](testing.md#运行测试) · [发现与选路机制](mesh.md#发现选路与中继)

## 选择直连或中继

`SetPeerPathPolicy(peer, mode)` 中的 `peer` 可以是对端任一虚拟地址。`Auto` 允许在合规路径间选路，`DirectOnly` 只许直连，`RelayOnly` 只许经中继，`Blocked` 封锁到该成员的路径。两端任一成员启用 `Restricted` 后，只有列在双向 `Links` 的邻居才能直连。电路每个中间成员还须启用 `Transit`。节点维护间隔 `Interval` 默认 2 秒，单次拨号和控制交换使用的 `DialTimeout` 默认 4 秒。`MaxCircuits` 默认 128。[三节点配置和 IP 回执](../examples/relay/main.go)

```go
if err := node.SetPeerPathPolicy(peerID.IPv4(), nebula.RelayOnly); err != nil {
    return err
}
if err := node.ConnectPeerID(ctx, peerID); err != nil {
    return err
}
if path, ok := node.PreferredPath(peerID); ok {
    next := path.Peer
    if len(path.Circuit) > 0 {
        next = path.Circuit[1]
    }
    log.Printf("next=%s transport=%s circuit=%v", next, path.Transport, path.Circuit)
}
```

`PreferredPath` 只读取本机已建立且获准承载一般流量的会话并返回独立快照。尚未建链或已失去全部路径时返回 `false`。直连的下一跳就是对端，`Endpoint` 为当前连接地址。中继的 `Circuit` 从本机到对端按顺序列出成员，`Endpoint` 为零值。要查某个下游 IP，可先用 `ResolveIP` 找到网关，再查到该网关的路径。某个包实际采用的电路以 `ObserveTransmit` 为准。

### 让节点通过已连接的邻居提供中继

在 `A — R1 — H — R2 — B` 中，H 可以只与 R1、R2 建立物理连接，同时为 A、B 转发流量。

1. 在 H 调用 `New` 前设置 `Options.HideEndpoints = true`。分发给其他节点的拓扑保留 H 的双栈主地址和邻接，留空 H 的 `Member.Endpoints`。按主地址或获授权的下游地址查询 H，仍会返回 H 的签名身份、匹配前缀和有效期。
2. 各跳宿主在自己的拓扑中批准电路的双向 `Links`，并为 R1、H、R2 设置 `Transit`。将 H 标为 `Restricted`，它的 `Links` 只列 R1、R2。在 H 的本地视图填入这两个邻居的可达物理端点。接收入站的邻居也必须允许 H 的连接。如果邻居本身受限，需要在它的私有视图批准 H 的物理来源。
3. H 启动后会维护这两个邻居，也可调用 `ConnectPeerID` 等待邻接就绪。其他成员可以复用 H 主动建立的双向会话。期望 A 到 B 始终使用中继时，在 A、B 对彼此设置 `RelayOnly`。撤回 H 的 `Transit` 会拆除经 H 的电路，获准以 H 为终点的连接仍可建立。

启用 `HideEndpoints` 的 H 收到会合请求时只回复签名介绍。H 自己发起的拨号、打洞和备线路径探测仍遵循路径策略，`Restricted` 与双向 `Links` 将这些操作限定到获准邻居。直接邻居能从套接字看到 H 的物理地址，此前已分发的签名记录也可能缓存至有效期结束。[三节点可运行示例](../examples/relay/main.go) · [五节点故障重放](testing.md#运行测试)

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

在本机拓扑成员上设置 `BytesPerSecond` 并应用拓扑，可以限制本机提交的 IP、主题消息及中继应用字节总量，单位为字节每秒，零表示不限速。

网关示例先按物理 TCP 地址接入，再分别按 IPv4、IPv6 下游地址查询。它将签名结果与宿主批准的网关身份和前缀核对，以 `ApplyTopology` 安装业务授权，并通过下游 UDP 回显验证往返。示例采用外层 TLS/TCP，通过 `nebulagvisor.NewEndpoint` 独占节点 IP 端口，再用 `CreateNIC` 加入用户态网络栈。注册失败调用 `Endpoint.Close`，成功后用 `RemoveNIC` 拆卸。双栈 NIC 的默认 MTU 为 1300 字节，受节点 `MaxIPSize` 限制，最低 1280 字节。逐路由设置 MTU 时，例如 `node.RecommendedMTU(gateway, destination.Is6(), int(ep.MTU()))`，第二个参数表示内层目的地址族。查询在没有活动路径时也可返回给定上限。[适配器](../nebulagvisor/endpoint.go)

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

## 主题消息与运行状态

发布方的 `Member.Topics` 可授予 `app/demo` 及其子树；订阅方按完整主题 `app/demo/hello` 调用 `Subscribe`。先注册订阅并从 `sub.Publications()` 读取 `nebula.DeliveredPublication`，再触发业务。`Publish` 返回的 ID 表示本机已接纳，可以用它关联接收端回执。邻居在有效期内补发缺失主题消息；本机新建的订阅从之后接纳的主题消息开始交付。缓冲上限为 32 条，`sub.Missed()` 记录本订阅因缓冲满而丢弃的数量。`sub.Close()` 或关闭节点都会关闭交付 channel。[主题消息收发示例](../examples/quickstart/main.go)

- TCP 监听遇到暂时性错误会退避重试。永久错误可从 `ControlStatus().ListenerErrors["tcp4"]` 或 `["tcp6"]` 读取，用于定位退出的入口。
- 检查服务启动和本机资格用 `ControlStatus().Started` 与 `Ready`。本机证书和成员视图有效时，启动前 `Ready` 也可以为真。
- 检查对端连通性先用 `ConnectPeer`，再用 `Paths()` 看每条已建立路径的 `Active`、`Transport`、`Circuit` 和 `AuthorizedUntil`。同一成员可能有多行。`TLSGroup` 为握手使用的密钥交换组。
- 对照一般流量的首选路径与单个包实际选择的路径，使用 `PreferredPath(peerID)` 和端口或 gVisor 的 `ObserveTransmit`。[发送诊断](#ip-收发与网关)

## gVisor 的 IPv4 网关构建

本项目使用 gVisor 的 `go` 分支。当前固定版本 `83df8eae069e` 在 IPv4 单播转发复制报文后，仍从先前取得的原包头读取 TTL。使用该版本构建 IPv4 转发网关时，可应用仓库补丁，在复制前保存 TTL。在宿主应用的模块根目录执行以下命令，将 `/path/to/gvisor-ipv4-ttl.patch` 换成补丁的实际路径。[上游转发实现](https://github.com/google/gvisor/blob/83df8eae069e6c607672f779f63f3538815cc037/pkg/tcpip/network/ipv4/ipv4.go#L788-L835) · [IPv4 转发补丁](../patches/gvisor-ipv4-ttl.patch)

```sh
go mod vendor
git apply --directory=vendor/gvisor.dev/gvisor /path/to/gvisor-ipv4-ttl.patch
go test -mod=vendor -race ./...
```

广播、组播和任播服务的 NIC 掩码、订阅和服务 socket 配置见[集群地址与 IP 交付](addressing.md#gvisor-接入)。
