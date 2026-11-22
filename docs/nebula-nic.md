# Nebula 网关转发与网卡管理

应用把 `nebulagvisor.Endpoint` 注册为 gVisor 栈中的三层网卡。gVisor 决定下一跳并处理 IP 转发。Nebula 验证内层 IP 地址，通过直连或中转把包送到下一跳对应的 peer。[直连示例](quickstart.md)

## 经网关访问下游子网

以客户端 `10.42.0.1`、网关 `10.42.0.254` 和下游主机 `192.168.50.20` 为例。网关的 LAN 地址为 `192.168.50.1`，两台 Nebula 节点都属于 overlay 网段 `10.42.0.0/24`。

| 位置 | 配置 |
| --- | --- |
| 网关证书 | `Networks` 包含 `10.42.0.254/24`，`UnsafeNetworks` 包含 `192.168.50.0/24`。这授权网关承载该 LAN 的流量。[签发示例](../cert/README.md) |
| 客户端 | 保留 overlay 直达路由。为 `192.168.50.0/24` 添加一条路由，出口为 Nebula NIC，网关为 `10.42.0.254`。 |
| 网关 | overlay 路由指向 Nebula NIC，LAN 路由指向 LAN NIC。在这两个接收接口上为 IPv4 启用转发。 |
| 下游主机或其路由器 | 将 `10.42.0.0/24` 的回程指向 `192.168.50.1`。使用源 NAT 的部署由网关宿主配置地址转换。 |

客户端在直连示例的 `s.AddRoute` 后添加下游路由。

```go
lan := tcpip.AddressWithPrefix{
	Address: tcpip.AddrFrom4([4]byte{192, 168, 50, 0}), PrefixLen: 24,
}
s.AddRoute(tcpip.Route{
	Destination: lan.Subnet(),
	Gateway:     tcpip.AddrFromSlice(peer.AsSlice()),
	NIC:         nic,
})
```

应用拨号时使用下游地址 `192.168.50.20`。gVisor 选出的下一跳是 `10.42.0.254`，Nebula 通过静态配置或 lighthouse 找到该网关的外层地址。要强制经中转到达网关，或检查这段链路的抖动，在网关的 overlay 地址上配置路径策略。[直连、中转与链路健康](paths.md)

在网关上，为 Nebula 和 LAN 两张网卡启用转发。`vpnNIC` 和 `lanNIC` 是它们在网关栈中的 NIC ID。

```go
for _, id := range []tcpip.NICID{vpnNIC, lanNIC} {
	if _, e := s.SetNICForwarding(id, ipv4.ProtocolNumber, true); e != nil {
		return fmt.Errorf("enable forwarding on NIC %d: %s", id, e)
	}
}
```

双栈部署还要分配 IPv6 地址、添加 IPv6 路由，并为 `ipv6.ProtocolNumber` 启用转发。IPv6 下游网段也可使用 IPv4 overlay 下一跳。使用默认出口时，将 `0.0.0.0/0` 或 `::/0` 指向相应网关，保留更具体的 overlay 直达路由，网关证书须覆盖预期承载的下游地址。[三端 TCP、UDP 和回程示例](../forwarding_test.go)

### 双向证书授权

发送端检查本机证书对源地址的授权，并检查下一跳 peer 的证书是否允许目的地址。握手前入队的包在认证完成后复核。接收端检查已认证 peer 的源地址和本机证书对目的地址的授权，再将包交给 gVisor。overlay 内的地址要匹配节点的确切证书身份，`UnsafeNetworks` 授权的是下游前缀。

多个网关的证书可以覆盖同一子网，允许去程和回程通过不同的网关。要指定哪些网关可以送入某类流量，设置 `Options.InboundPolicy(peer, source, destination) bool`。该回调在证书检查通过后运行，`peer` 为对方证书的首个 overlay 地址，返回 `false` 会拒绝该包。

## 网卡与端口生命周期

同一进程可以运行多个 `nebula.Node`。为每个节点提供可独立收包和关闭的 `DatagramTransport`。多个节点可以共享证书对象和预先配置好的 `cert.CAPool`，在使用期间将两者视为只读。信任策略不同的节点应分别建池。

| 操作 | 调用方的职责 |
| --- | --- |
| 提供传输 | 普通 UDP 使用 `nebula.WrapPacketConn`。`nebula.New` 成功后节点接管传输，失败时调用方关闭它。自定义 `DatagramTransport` 须保留数据报边界、支持并发写，并在 `Close` 时唤醒阻塞的读写。`WriteTo` 在调用期间借用输入缓冲，异步发送须在返回前复制。 |
| 挂载和卸载 | 一个节点同时持有一个数据端口。`NewEndpoint` 预留端口，`CreateNIC` 失败时调用 `ep.Close()`。挂载成功后用 `s.RemoveNIC(id)` 删除该 NIC 及其路由并释放端口，之后可挂载新端点。 |
| 选择 MTU | 用 `nebulagvisor.Options.MTU` 设置，默认 `nebulagvisor.DefaultMTU`（1300）。构造时接受 1280 至 9001，运行时 `SetMTU` 将值限制在该范围。外层传输还要容纳 Nebula 封装开销。 |
| 停止服务 | 宿主管理 socket 的关闭或 deadline。`node.Close()` 取消数据端口并关闭外层传输，`node.Wait()` 等待节点任务退出并报告致命传输错误。其他 NIC 和整个栈继续由宿主管理。 |

### 自定义 UDP 数据报前缀

与上游互通时，将 `Options.DatagramMagic` 留空。上游握手包以 `10` 开头，普通数据包以 `11` 开头（十六进制，高四位为版本，低四位为消息类型）。打洞包只有一个字节 `00` 或 `01`。

在 `nebula.New` 前设置 `opts.DatagramMagic = []byte{0x4e, 0x42}` 后，握手包以 `4e 42 10` 开头，打洞包 `00` 变为 `4e 42 00`。每跳只添加一次前缀，接收端匹配后将其剥离。所有参与节点（包括 lighthouse 和中转）须使用相同字节，规划底层 MTU 时额外预留 `len(opts.DatagramMagic)` 字节。前缀明文传输，身份认证由 Nebula 握手完成。

### 接入其他三层设备

通过 `node.OpenIPPort(deliver)`，应用可以将隧道接入自己的三层设备。例如，应用可以使用 `IFF_TUN | IFF_NO_PI` 创建 Linux TUN 接口，配置接口地址和系统路由，再按以下方向收发原始 IP 包。

- 系统发往隧道时，从 TUN 读取完整的单播 IP 包，调用 `port.WriteIP(nextHop, packet)`。直达 overlay 地址时，下一跳可传 `netip.Addr{}`。访问下游子网时，传网关的 overlay 地址。成功返回表示包副本已入队。
- 隧道发往系统时，`deliver` 收到已通过证书授权的 IP 包。回调在节点接收协程上借用包数据，交给异步写 TUN 的协程前须复制。

退出时由应用关闭 TUN 并调用 `port.Close()` 释放节点的数据端口。

## 发现与运行时管理

已知 UDP 端点时，在 `Lighthouse.StaticHosts` 中将 peer 的 overlay 地址映射到该端点。使用 lighthouse 发现 UDP 路径时，服务端设置 `Lighthouse.AmLighthouse = true`，客户端将其 overlay 地址加入 `Lighthouse.Hosts` 并配置静态 UDP 端点。

本机通过 `AdvertiseEndpoints` 通告固定地址，通过 `EndpointProvider` 提供动态地址。节点串行调用 provider。回调应响应 context 取消，在回调返回后再发起新的通告或重绑。

| 操作 | API 与结果 |
| --- | --- |
| 查找或刷新 peer | `PeerDiscovery(addr)` 读取缓存。客户端用 `RefreshPeer(ctx, addr)` 将查询排队，同一地址共享在途请求，队列满时可用 context 取消等待。要等待可用隧道，调用 `ConnectPeer`。 |
| 更新静态候选 | `SetPeerEndpoints(addr, endpoints)` 替换该 peer 的静态 UDP 地址，已学习的地址和已建立的隧道继续可用。 |
| 通告本机地址 | `AdvertiseNow(ctx)` 获取动态地址并向 lighthouse 发送更新。底层传输实现 `RebindableTransport` 时，`node.Rebind()` 重绑 UDP 并重新通告。 |
| 建立或关闭连接 | `ConnectPeer(ctx, addr)` 等待经过认证且具有可用出口的隧道。取消 context 结束本次等待，共享握手可继续。`DisconnectPeer` 和 `DisconnectAll` 撤销所选 peer 的在途握手并关闭隧道，后续流量可重新触发握手。 |

接收端按 `Lighthouse.MaxReported` 分别限制每个来源的 IPv4 endpoint、IPv6 endpoint 和 relay 数量。主动通告、查询回复和打洞通知超出单包容量时，发送端按相同的条数上限裁剪各类候选，保留各列表的原始顺序。UDP 直连握手先尝试 `Options.PreferredRanges` 中的地址，组内依次优先 IPv6、非私有 IPv4 和私有 IPv4。

## 调整节点容量

在调用 `nebula.New` 前设置 `Options`。下表各字段独立取值，零值或负值沿用该字段的默认值。直接使用 `IPPort` 和通过 gVisor 挂载的端点共用相同的 IP 队列设置。例如，只增加端口总容量可以写 `opts.IPPort.QueueSize = 1024`。

| 字段 | 默认值 | 作用 |
| --- | --- | --- |
| `IPPort.QueueSize`、`IPPort.PerPeerQueueSize` | 512、100 个包 | 端口总队列和单个下一跳的队列，两项都要有空位才能入队。 |
| `Handshake.ControlQueueSize`、`Handshake.RefreshAttempt` | 100 个包、第 5 次尝试 | 等待握手的每个 peer 可缓存的控制包数，以及再次向 lighthouse 查询的尝试序号。 |
| `Lighthouse.QueryBuffer`、`Lighthouse.MaxReported` | 1024 个查询、每类 10 项 | 待发现查询的队列容量，以及每个报告来源的候选上限。 |
| `Punchy.QueueSize` | 64 个任务 | 等待发送的打洞任务总数。 |
| `Relay.MaxMappings`、`Relay.PendingTimeout`、`Relay.RequestInterval` | 8192、1 分钟、100 毫秒 | 节点持有的中转映射总数、半开映射的保留时间、同一映射两次建立请求的最小间隔。到期映射在下一次巡检时回收。 |
| `Connections.MaxTunnelsPerAddress`、`Connections.RoamSuppressInterval` | 5 条、2 秒 | 同一 overlay 地址可保留的隧道数，以及收到同一漫游候选地址的流量后，再次触发探测的最短间隔。 |

## 监控节点和流量

按实例轮询快照，通过 `node.Context().Done()` 监听停止。节点处于 `NodeStateRunning` 且 `node.Peer(addr)` 找到该 peer 时，用 `peer.PathHealth.Active.Path.Endpoint.IsValid()` 判断当前是否有可用出口。验证往返可达性可调用 `CheckPeerPath`。[路径策略与主动探测](paths.md)

**端口流量**通过 `port.Stats()` 或 gVisor 的 `ep.Stats()` 读取。`Queued` 是等待发送的包数。`SentPackets`、`SentBytes` 在业务包成功提交给本地传输时累计，排队重试的包在最终提交时计一次。`ReceivedPackets`、`ReceivedBytes` 在入站包通过授权、交给端口回调时累计。字节数按完整内层 IP 包计算。对同一端口两次采样的字节差除以时间差，即为平均吞吐率。新打开的端口从零累计。

**中转负载**通过 `node.RelayStats()` 读取。`UsedMappings` 和 `MaxMappings` 分别是本地中转索引的当前占用和生效上限。半开映射和端点映射都占用索引，一条端到端线路可占多个索引。`ForwardedDatagrams` 按节点生命周期累计，每次替其他节点向下一跳成功提交握手、探测或业务数据报时加一。

## 排错

| 现象 | 检查方法 |
| --- | --- |
| 节点启动后连不上 peer | 用 `node.Snapshot()` 核对本机状态、证书地址和外层监听地址，用 `node.Discovery()` 核对 lighthouse 配置。`node.PeerDiscovery(addr)` 返回缓存中已知的 endpoint 与 relay，供核对 UDP 可达性。`node.Err()` 可读取导致节点停机的传输错误。 |
| 想知道 IP 包实际走了哪条路 | 在 `node.Peer(addr)` 返回的快照中，`CurrentEndpoint` 是该会话已知的直连 UDP 地址，`LastDataPath` 记录最近一次成功提交给外层传输的 IP 包路径。其中 `Endpoint` 是外层 UDP 端点，`Relay` 为空表示直连。 |
| peer 能连通，下游主机不通 | 核对下游路由的 `Gateway`、网关证书、两侧 NIC 转发开关和回程路由。直接使用 IPPort 时，缺少网关会返回 `ErrMissingGateway`，证书拒绝可通过 `errors.Is(err, nebula.ErrAddressNotCertified)` 判断。 |
| 包已入队，稍后发送失败 | 查看 `ep.Stats()` 或 `port.Stats()` 的 `Queued`、`RejectedInbound`、`RejectedOutbound` 和 `LastDrop`。最后一项记录最近一次端口拒绝的原因和可取得的地址。适配器自身的 MTU 检查直接返回 gVisor 的 `ErrMessageTooLong`。 |
| 队列满或正在更换网关 | `ErrQueueFull` 对应 gVisor 的 `ErrNoBufferSpace`。检查端口总容量与下一跳容量。更换网关后可用 `ClearPending(oldPeer)` 撤销旧下一跳的积压包，返回值为撤销数量。已交给传输的包仍可能完成发送。 |
