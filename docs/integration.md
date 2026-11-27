# 将节点嵌入 Go 应用

每个 `Node` 独立持有凭据、拓扑和会话。在 `Options.Auth` 配置根 CA、固定的集群 CA、节点证书和同钥授权链，在 `Options.Topology` 填入宿主批准的成员。节点可直接收发 IP，也可接入宿主的 gVisor 栈。[凭据加载](pki.md#热加载与宿主授权) · [双进程接入](quickstart.md#使用磁盘凭据启动两个进程) · [双栈网关](../examples/gateway/main.go)

## 节点生命周期

下面的函数以已有成员的物理 UDP 端点接入网络。`New` 成功时接管套接字和监听器，构造失败时由调用方关闭。取消服务 context 会触发已启动节点的关闭，显式调用 `Close` 会等待后台任务退出。

```go
func serve(serviceCtx context.Context, opts nebula.Options, ep nebula.Endpoint) error {
    socket, err := net.ListenPacket("udp4", "0.0.0.0:4242")
    if err != nil {
        return err
    }
    opts.Transport.UDP4 = socket
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

## 选择本机安全策略

| 宿主目的 | 配置或操作 | 对现有连接和消息的影响 |
| --- | --- | --- |
| 为同一成员换证 | `ReloadCertificates(ctx, set)` 校验并替换整组本机凭据。 | 新握手和签名使用新凭据。已建立的会话仍按其实际握手证书授权，每条路径的 `PathStatus.LocalNodeSerial` 和 `LocalGrantSerial` 可用于核对。 |
| 撤回对证书或公钥的信任 | 更新 `Options.Auth.CheckChain` 读取的宿主策略，再调用 `Revalidate(ctx)`。 | 本机复查凭据、会话、实例冲突和缓存主题消息，清空发现缓存，关闭失权路径。可用 `ControlStatus()` 和 `Paths()` 核对结果。[按公钥撤权示例](pki.md#热加载与宿主授权) |
| 调整网关、VIP、邻接或中继权限 | 用 `ApplyTopology(ctx, view)` 安装完整的本地视图。 | 失去授权的路径、电路和排队包会被清理。移除一个远端的成员条目会收回其静态授权，有效集群凭据仍可在路径允许时使用该成员自己的主地址。 |
| 限制本机到一个成员的路径 | 用 `SetPeerPathPolicy(peerID, RelayOnly)` 限定中继路径，或用 `Blocked` 封锁到该成员的路径。 | 本机关闭与新模式冲突的已有路径。各节点独立决定是否信任同一张证书或接纳其签名消息。 |
| 限制哪些网关可代表某个源网段 | 网关的集群授权和本机拓扑共同限定地址收发范围。在 `Options.InboundPolicy` 按认证成员与包地址进一步筛选。 | 策略在合规入站 IP 包交付前逐包执行，适用于已有会话。[下一跳与回程](addressing.md#下一跳与回程) |
| 控制物理地址披露 | 创建节点时设置 `Options.Transport.HideEndpoints`；以 `Member.Restricted` 和双向 `Links` 限定直连邻居。 | 本机的签名介绍省略端点，响应会合查询时只回复记录。直连邻居仍可看到实际套接字地址。 |
| 选择可传播的物理地址 | 用 `Options.Transport.AllowAdvertiseEndpoint` 按候选来源、地址和观测者筛选本机签名介绍。 | 获准地址可以随签名介绍继续转发。已经发布的记录按原有效期过期。 |
| 限制主动联系的物理地址 | 用 `Options.Transport.AllowOutboundEndpoint` 筛选 TCP、QUIC 拨号、备用路径探测和 UDP 打洞目的地。 | `ConnectEndpoint` 遇到拒绝返回 `ErrPathPolicy`，自动拨号继续选择候选或获准中继。已有会话由成员路径策略控制。 |
| 调整主题发布权 | 在 `Member.PublishTopics` 指定允许发布的主题或子树，调用 `ApplyTopology`。 | 本机会复核缓存中原发布者的主题授权。`Subscribe` 决定本机投递，转发邻居可以读取正文。机密载荷由应用加密给目标接收者。 |

`Revalidate` 和 `ApplyTopology` 在提交前遇到上下文取消时返回错误，宿主可重新发起调用。提交后，即使上下文取消，也会等到提交时已登记的握手授权帧写完或写入失败，再返回成功。各节点分别生效，已交给传输层的字节仍可能稍后到达。[握手与撤权边界](mesh.md#证书生命周期与宿主授权)

`New` 和 `ApplyTopology` 各自保存一份私有拓扑。如果宿主也要为不同节点准备可独立修改的视图，为每份视图创建自己的 `Members` 切片，用 `member.Clone()` 复制要放入的成员。这样可以在一份视图中修改邻接、端点或主题，其他视图继续使用各自的值。[多节点示例](../examples/demo/nodes.go)

信任根和集群 CA 在创建节点时固定。无效拓扑或换证失败会保留当前配置。有效视图也可以撤回本机成员资格，此时 `ControlStatus().Ready` 为 false。[凭据示例与授权钩子](pki.md#热加载与宿主授权)

### 只发布指定入口

例如网关绑定了管理网监听器，同时为其他成员提供固定的公网入口。将入口加入 `AdvertiseEndpoints`，只授权显式通告来源即可。

```go
opts.Transport.AdvertiseEndpoints = []nebula.Endpoint{publicEndpoint}
opts.Transport.AllowAdvertiseEndpoint = func(c nebula.EndpointCandidate) bool {
    return c.Source == nebula.EndpointFromConfig
}
```

若还接受可信邻居报告的 NAT 映射，可额外允许 `c.Source == nebula.EndpointFromObservation && c.Observer == trustedPeer`。默认候选来自显式通告、拓扑、具体监听地址和已认证 QUIC 邻居的有效观测。每个邻居可按地址族各提供一个观测。获准端点写入同一份可转发的签名介绍，所有收到介绍的成员都能读取。发布和出站端点回调都应支持并发并及时返回。[端点过滤示例](../examples/discovery/main.go) · [限定直连邻居](#让节点通过已连接的邻居提供中继)

## 跨机器连接

`Options.Transport.UDP4`、`UDP6` 用于对应地址族的 QUIC 监听、拨号和打洞。`TCP4`、`TCP6` 接收入站 TCP。只需出站 TCP 时可将传输配置留空，节点使用 `net.Dialer`；自有网络栈可提供 `DialTCP`。UDP 和 TCP 可绑定相同端口号，与网站共用这些端口时，将 `portshare` 的 mesh 分支交给节点。[与网站共享监听端口](portshare.md#接入与关闭)

| 已知信息 | 连接方式 |
| --- | --- |
| 入口的物理地址和端口 | 用 `ConnectEndpoint(ctx, ep)` 连接，`ep.Network` 填 `udp` 或 `tcp`。成功后返回该端点通过认证的成员 ID。 |
| 对端的一个虚拟主地址 | `ConnectPeer(ctx, primary)` 按本机已知的地址归属建链。归属未知时先用 `ResolveIP` 查询邻居，再用结果的 `Peer` 调用 `ConnectPeerID`。 |
| 对端的公钥指纹 | 用 `ConnectPeerID(ctx, id)` 等待与该身份的获准路径。要持续维护该邻居，在拓扑中为两端配置双向 `Links`。 |

首次接入时，若本机只配置了自己的拓扑条目，在 `New` 前将入口的公钥指纹加入 `Auth.TrustedEntrypoints`。本机也可通过拓扑中的 `Member.ID` 或已验证且有效的签名介绍认可对端。

`Member.Endpoints`、`Options.Transport.AdvertiseEndpoints` 和 `ConnectEndpoint` 使用集群成员网段和 VIP 池之外的物理单播地址，端口须非零。监听器可绑定通配地址，通告时填写对端可达的具体地址。

并发的 `ConnectEndpoint` 按物理端点共享拨号，`ConnectPeer` 和 `ConnectPeerID` 按完整成员身份共享拨号。任一调用方取消 context 只结束自己的等待。`ConnectEndpoint` 成功表示本机已注册直连。邻居也完成注册后，其他成员才能通过这条邻接查询新节点。期间遇到 `ErrPeerUnavailable` 可在调用方的截止时间内重试。[按地址发现的示例](../examples/discovery/main.go)

按需连接失去最后一条路径后，可以再次调用连接 API，也可以向已知成员写包来触发建链。

### 按地址发现成员和下游网关

`LookupPeer(primary)` 返回本机记录的主地址归属。已确认的实例冲突可以在路径断开、介绍过期后继续保留这项绑定。要确认有可用路径，调用 `PreferredPath(peerID)`。只知道陌生的主地址或下游单播地址时，用 `ResolveIP` 查询签名介绍。

```go
matches, err := node.ResolveIP(ctx, netip.MustParseAddr("172.30.0.42"))
if err != nil {
    return err
}
for _, m := range matches {
    log.Printf("gateway %v serves %v, valid until %v", m.Peer, m.Prefix, m.ValidUntil)
}
```

| 查询目的 | API | 返回哪些成员 |
| --- | --- | --- |
| 找到主地址所有者或已知网关 | `ResolveIP(ctx, dst)` | 命中本机有效的签名介绍时直接返回，否则查询邻居。主地址精确匹配；下游地址返回每个网关最具体的匹配前缀。 |
| 已有默认出口，寻找新加入的站点网关 | `RefreshIP(ctx, dst)` | 对成员网段和 VIP 池外的下游单播地址发起或加入一轮查询，返回本机匹配的介绍及本轮收到且仍有效的候选。邻居可以转交签名缓存。 |

两者都按前缀长度降序、再按成员身份排序。某网关本轮缺席，其有效缓存仍可供 `ResolveIP` 使用。对同一目的地址的并发网络查询共享请求，各调用方可以独立取消等待。[可运行示例](../examples/discovery/main.go)

`IPMatch.Addresses` 给出签名授权中的两个主地址。选中结果后调用 `ConnectPeerID(ctx, m.Peer)`，握手验证该公钥持有者及其在本集群的双栈地址授权。向该网关转发下游 IP 包之前，宿主须核准网关及其前缀，并用 `ApplyTopology` 安装相应授权。再调用 `port.WriteIP(m.Peer, packet)`，收发双方根据各自拓扑和会话使用的集群授权校验数据。[网关实例](../examples/gateway/main.go) · [组地址与任播交付](addressing.md)

两个成员共用外层 NAT，而其中一个成员还在内层网关之后时，中间网段上的成员可能无法经公网地址回连。如果宿主知道内层网关面向中间网段的映射，例如 UDP `100.64.0.2:45001`，可以将它加入内层成员的 `Options.Transport.AdvertiseEndpoints`。采用默认通告策略时，中间网段的成员便可从签名介绍取得该地址并尝试直连。[NAT 场景重放](testing.md#运行测试) · [发现与选路机制](mesh.md#发现选路与中继)

## 排查重复地址与实例

同一 IPv4 或 IPv6 出现在两条静态成员配置中时，`Topology.Validate` 和 `ApplyTopology` 会报告重复地址及两个完整的 `PeerID`。安装失败时当前拓扑继续生效。运行中遇到来自其他公钥的竞争地址声明，可以按该主地址查看本机证据。

两个运行实例使用同一节点公钥时，用 `node.InstanceConflicts()` 枚举本机已确认的冲突，包括已经失去最后一条路径的成员。`Retained` 是保留的实例，`ConfirmedAt` 是探活确认时间。`Selected` 表示已选定实例、正在等待准入，`EvidenceTruncated` 表示证据已超出容量，需要人工复核。选定实例获得路径后，此项从快照消失。

在实际转发业务的节点调用 `node.InspectIP(ip)`，按公钥标识、双栈地址、实例及 `NodeSHA256`、`GrantSHA256` 核对实际出示的两张证书。查询 VIP 时按本机拓扑关联成员；查询下游地址时，签名介绍按通告的最长匹配前缀返回，路径和拓扑记录按本机配置的最长匹配前缀返回。实际发包时还要检查该会话的集群授权。结果只涵盖本机见过的信息，可与其他观察节点及签发台账对照。[可运行示例](../examples/discovery/main.go)

| 来源 | 含义 |
| --- | --- |
| `topology` | 本机批准的主地址、任播实例或下游网关。 |
| `introduction` | 签名成员披露的端点和下游前缀。`discovered` 表示已缓存。相同签名记录的重放保留原接收时间。 |
| `session` | `accepted` 表示可用的认证路径。`incumbent at collision` 记录冲突发生时的首选路径，`instance conflict` 记录被拒绝的竞争实例。直连记录包含本机观察到的远端地址，中继记录列出成员路径。 |
| `conflict` | 竞争握手之后原实例仍成功应答探活。`retained` 是保留方，`held out` 是被隔离方；`selected` 表示本机已经选定、等待接入。此行的两个时间分别是整起争议的首次观测和探活确认时间；单次握手的观测时间见 `session` 行。 |

近期观测合并保留十分钟、最多 256 条，已确认的本机约束另行保存。每个冲突保留最多 16 组实例、握手证书及用途，超出后仍隔离竞争路径，由管理员明确选择保留方。新建节点会生成新的本机实例标识，冲突观测和处置决定仅保存在原节点内存中。分区期间不同观察节点可能接纳不同实例。持有相同私钥且主动伪装相同实例标识的运行方需要管理员从密钥和签发记录排查。

确定需要撤回的节点证书或集群授权后，更新宿主 `Options.Auth.CheckChain` 读取的策略，然后调用 `node.Revalidate(ctx)`。节点按握手实际出示的证书链和用途复查。原实例曾以客户端和服务端两种角色建立路径时，只撤回一种用途仍可能留下有效凭据。复查后仅剩一个获准实例时，可向该实例恢复交付。如果已选实例在重连前失去授权，且仍有多个获准实例，该成员的发送队列暂停接收新包，`WriteIP` 返回 `ErrInstanceConflict`。宿主可从 `InspectIP` 列出的有效候选中重新选择。

同一凭据误部署两次时，先停止错误副本，核实正确设备的 `ControlStatus().Instance`，再在观察节点调用 `node.ResolveInstanceConflict(peer, keep)`。用 `PreferredPath(peer)` 返回的 `PathStatus.Instance` 核对恢复后的路径。若私钥已经泄露，宿主应按公钥撤权并换钥。[按公钥撤权示例](pki.md#热加载与宿主授权)

## 选择直连或中继

`SetPeerPathPolicy(peerID, mode)` 绑定节点公钥指纹，可在建链和发现前预设。只有一个主地址时，可先用 `LookupPeer(ip)` 确认当前归属。调用 `configured, effective := node.PeerPathPolicy(peerID)` 可读取配置值和叠加拓扑限制后的有效模式。`Auto` 清除本机覆盖并允许在合规路径间选路，`DirectOnly` 只许直连，`RelayOnly` 只许经中继，`Blocked` 封锁到该成员的路径。两端任一成员启用 `Restricted` 后，只有列在双向 `Links` 的邻居才能直连。电路每个中间成员还须启用 `Transit`。

`Options` 中以下参数取零时使用默认值。

| 参数 | 默认值 | 作用范围 |
| --- | --- | --- |
| `MaxInboundHandshakes` | 256 | 本节点所有地址族的 TCP 和 QUIC 共用的入站建链名额。建链结束即释放，已注册的直连会话不占名额。[共享端口容量](portshare.md#容量和部署边界) |
| `MaxCircuits` | 512 | 本机发起、终止和转发的电路合计占用，含正在建立的电路。用 `ControlStatus().Circuits` 读取当前占用。 |
| `MaintenanceInterval` | 2 秒 | 邻居维护及已建路径探活的调度间隔。 |
| `DialTimeout` | 4 秒 | 拨号、握手、控制交换和传输写入的基础超时。中继建链按剩余跳数计算预算。 |

```go
if err := node.SetPeerPathPolicy(peerID, nebula.RelayOnly); err != nil {
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

1. 在 H 调用 `New` 前设置 `Options.Transport.HideEndpoints = true`。分发给其他节点的拓扑保留 H 的双栈主地址和邻接，留空 H 的 `Member.Endpoints`。按主地址或获授权的下游地址查询 H，仍会返回 H 的签名身份、匹配前缀和有效期。
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
| 已出队的这次提交是否成功 | `ObserveTransmit(result)` | 拨号失败或等待带宽时被取消，`Transport` 可以为空。包超过所选路径的对端收包上限时，结果带有所选传输和 `ErrPacketTooLarge`。回调可能并发，应及时返回。 |
| 远端业务是否处理了请求 | 对端应用回执 | 用请求 ID 和预期成员关联回执。传输接受一个包后，远端仍可能丢弃它。 |

异步上限示例可用 `go test -v -run '^ExampleIPPort_WriteIP$' .` 运行。[可执行示例](../example_test.go) · [双进程应用回执](quickstart.md#使用磁盘凭据启动两个进程)

在本机拓扑成员上设置 `BytesPerSecond` 并应用拓扑，可以限制本机提交的 IP、主题消息及中继应用字节总量，单位为字节每秒，零表示不限速。

网关示例在外层使用 TLS/TCP。客户端用 `RefreshIP` 发现网关、用 `ApplyTopology` 批准下游前缀，在 gVisor 中为站点前缀和默认出口安装路由。两个下游的 IPv4 和 IPv6 UDP 回显可核对实际出口。[双栈网关源码](../examples/gateway/main.go)

通过 `nebulagvisor.NewEndpoint` 独占节点 IP 端口，再用 `CreateNIC` 加入用户态网络栈。注册失败调用 `Endpoint.Close`，成功后用 `RemoveNIC` 拆卸。节点的 `Options.MaxIPSize` 默认 65535 字节，可设为 1280～65535。双栈 NIC 的默认 MTU 取 1300 字节与该上限的较小值。逐路由设置 MTU 可调用 `node.RecommendedMTU(gateway, destination.Is6(), int(ep.MTU()))`，无可用路径时只按本机上限计算。[适配器](../nebulagvisor/endpoint.go) · [路径 MTU](mesh.md#路由-mtu)

访问下游失败时，沿报文方向检查以下设置。

1. 在集群 CA 设置下游路由委派上限。为网关签发集群授权时，通过 `Enrollment.Scope.RoutedPrefixes` 或 CLI `-routes` 批准下游 IPv4、IPv6 前缀。
2. 两端拓扑通过网关成员的 `RoutedPrefixes` 启用相应前缀，客户端把去往这些前缀的路由指向网关虚拟地址。
3. 网关的 mesh NIC 和 LAN NIC 都有地址，两个 NIC 对相应地址族均启用 `SetNICForwarding`。
4. 下游主机把去往 mesh 网段的路由指向网关 LAN 地址。示例中的回显服务会核对它看到的客户端源地址。

接管 Linux 宿主默认路由时，将外层 TCP/UDP 端点留在可达的物理路由上，避免隧道递归。公网出口应具备返回客户端地址的上游路由，或由宿主按需配置 SNAT。

网关回包进入 gVisor 栈之前，`nebulagvisor.Options.ObserveReceive(from, packet)` 会提供端到端认证的发送方和完整只读 IP 包。宿主可在这里记录业务流对应的入站网关，再在 `ResolveNextHop` 中使用该绑定。回调可能并发，需在返回后使用包内容时应先复制。[网关示例](../examples/gateway/main.go)

`Options.InboundPolicy` 在会话、拓扑和证书地址授权通过后执行。比如接收端仅允许某个网关转发来自获准 LAN 的流量时，可以在构造节点前设置以下附加过滤。回调使用的策略数据应支持并发读取。

```go
opts.InboundPolicy = func(peer nebula.PeerID, src, dst netip.Addr) bool {
    return peer == gatewayID && allowedLAN.Contains(src) && dst == serviceIP
}
```

## 主题消息与运行状态

例如，给发布成员的 `PublishTopics` 配置 `app/demo`，接收方在发布前调用 `Subscribe("app/demo/hello")`，即可从 `sub.Publications()` 读取之后在本机接纳的该主题消息。每个订阅缓冲 32 条，满时的丢弃数见 `sub.Missed()`。关闭订阅或节点会关闭接收通道。`Publish` 返回本机接纳的消息 ID，需要确认远端处理结果时用该 ID 关联业务回执。[收发示例](../examples/quickstart/main.go) · [缓存与补发](mesh.md#签名主题消息)

| 排查的问题 | 查看位置 |
| --- | --- |
| 节点是否已经启动、具备本机成员资格 | `ControlStatus().Started` 表示已启动收发。`Ready` 表示本机凭据和成员视图有效，启动前也可以为真。`AuthorizedUntil` 给出本机三个用途、证书链和宿主授权共同限定的截止时刻；`GrantExpires` 是本机集群授权的到期时刻。 |
| 哪个入口停止接收连接 | `ControlStatus().ListenerErrors` 按 `udp4`、`udp6`、`tcp4`、`tcp6` 记录异常退出的入口。TCP 遇到暂时性错误会退避重试。共享 UDP 的物理套接字读取遇到永久错误时，两个打开的分支都能取得底层错误。 |
| 是否因入站建链名额耗尽而拒连 | 比较两次 `ControlStatus().RejectedInboundHandshakes` 的差值，可得这段时间因本节点名额已满而拒绝的连接数。共享端口丢包和 QUIC 传输层拒绝连接发生在节点接入之前。 |
| 拨号为何失败 | 先看本次连接返回的错误。`ControlStatus().LastError` 保留最近的建链错误，`DialFailures` 累计失败的端点拨号。 |
| 到成员有哪些可用路径 | `Paths()` 列出每条已建路径的传输、双方节点证书和授权叶的序列号、授权截止时间及探测数据。`PreferredPath(peerID)` 返回一般流量当前会选的路径。 |
| 某个包是否发出 | `IPPort.Stats()` 提供排队和丢包计数，`ObserveTransmit` 给出已出队包的本地提交结果。远端处理情况由应用回执确认。[发送诊断](#ip-收发与网关) |

## gVisor 的 IPv4 网关构建

本项目使用 gVisor 的 `go` 分支。当前固定版本 `83df8eae069e` 在 IPv4 单播转发复制报文后，仍从先前取得的原包头读取 TTL。使用该版本构建 IPv4 转发网关时，可应用仓库补丁，在复制前保存 TTL。在宿主应用的模块根目录执行以下命令，将 `/path/to/gvisor-ipv4-ttl.patch` 换成补丁的实际路径。[上游转发实现](https://github.com/google/gvisor/blob/83df8eae069e6c607672f779f63f3538815cc037/pkg/tcpip/network/ipv4/ipv4.go#L788-L835) · [IPv4 转发补丁](../patches/gvisor-ipv4-ttl.patch)

```sh
go mod vendor
git apply --directory=vendor/gvisor.dev/gvisor /path/to/gvisor-ipv4-ttl.patch
go test -mod=vendor -race ./...
```

广播、组播和任播服务的 NIC 掩码、订阅和服务 socket 配置见[集群地址与 IP 交付](addressing.md#gvisor-接入)。
