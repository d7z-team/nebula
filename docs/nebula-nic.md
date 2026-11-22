# Nebula 网关转发与网卡管理

宿主把 `nebulagvisor.Endpoint` 注册为原生三层 NIC。gVisor 负责选路、分片、校验和及转发时的 TTL 或 Hop Limit。Nebula 根据选定的下一跳查找 peer，用证书核验内层 IP 地址，并通过直连或 relay 传送原始 IP 包。[直连示例](quickstart.md)

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

此时应用拨号的目的地址为 `192.168.50.20`。`PacketBuffer.EgressRoute.NextHop` 提供网关的 overlay 地址，`StaticHosts` 或 lighthouse 提供该网关的外层 UDP 地址。内层 IP 目的地址一直是下游主机。网关侧通过以下调用启用双向转发，`vpnNIC` 和 `lanNIC` 为其宿主栈中的接口 ID。

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

| 操作 | 调用方的职责 |
| --- | --- |
| 提供传输 | 普通 UDP 使用 `nebula.WrapPacketConn`。`nebula.New` 成功后节点接管传输，失败时调用方关闭它。自定义 `DatagramTransport` 须保留数据报边界，支持并发写，并在 `Close` 时唤醒阻塞的读写。 |
| 挂载和卸载 | 一个节点同时持有一个数据端口。`NewEndpoint` 预留端口，`CreateNIC` 失败时调用 `ep.Close()`。挂载成功后用 `s.RemoveNIC(id)` 删除该 NIC 及其路由并释放端口，之后可挂载新端点。 |
| 选择 MTU | 默认 1300，构造时接受 1280 至 9001，运行时 `SetMTU` 将值限制在该范围。外层传输还要容纳 Nebula 封装开销。 |
| 停止服务 | 宿主管理 socket 的关闭或 deadline。`node.Close()` 取消数据端口并关闭外层传输，`node.Wait()` 等待节点任务退出并报告致命传输错误。其他 NIC 和整个栈继续由宿主管理。 |

直接集成其他三层设备时，使用 `node.OpenIPPort(deliver)`。回调在接收线程上借用只读 IP 包，异步处理应先复制并尽快返回。发送完整的单播 IP 包使用 `port.WriteIP(nextHop, packet)`，直达 overlay 时可传零值 `netip.Addr{}`，发往下游子网时传网关的 overlay 地址。返回成功表示端口已接收包副本并安排发送。用完后调用 `port.Close()`。

## 发现与运行时管理

- **配置发现。** 已知 peer 可直接填入 `Lighthouse.StaticHosts`。提供发现服务的节点设置 `Lighthouse.AmLighthouse`。客户端在 `Lighthouse.Hosts` 填入其 overlay 地址，并为每个 lighthouse 提供静态外层 endpoint。通过 `AdvertiseEndpoints` 或 `EndpointProvider` 提供本机可通告的地址。动态回调串行执行，应响应 context 取消，重新通告或重绑安排在回调返回后。
- **选择路径。** 每个报告来源分别保留最多 10 个 IPv4 endpoint、10 个 IPv6 endpoint 和 10 个 relay。overlay 地址先从报告的外层 endpoint 中滤除。每次握手向去重后的直连候选发送请求，先使用 `Options.PreferredRanges` 内的地址，各组内按 IPv6、非私有 IPv4、私有 IPv4 排序，同级按地址和端口排序。收到错误身份的地址会被暂时跳过，成功握手后可重新参与选路。
- **使用 relay。** 中继节点设置 `Relay.AmRelay`，目标节点在 `Relay.Relays` 填入可用中继的 overlay 地址并向 lighthouse 通告，拨号端启用 `Relay.UseRelays`。经过中继时，gVisor 路由的下一跳仍指向承载内层流量的目标 peer。
- **更新地址。** `SetPeerEndpoints` 替换指定 peer 的静态候选，已学习的地址和现有隧道各自独立。`RefreshPeer` 向 lighthouse 排队查询，`AdvertiseNow` 立即通告本机地址。实现 `RebindableTransport` 的传输可以调用 `node.Rebind()` 切换底层地址并重新通告。
- **管理连接。** `ConnectPeer(ctx, addr)` 等待隧道建立，取消 context 结束本次等待，共享握手可继续。`DisconnectPeer` 和 `DisconnectAll` 拆除隧道，后续流量可以重新触发握手。

## 排错

| 现象 | 检查方法 |
| --- | --- |
| 节点启动后连不上 peer | 用 `node.Snapshot()` 核对本机状态、证书地址和外层监听地址，用 `node.Discovery()` 核对 lighthouse 配置。`node.PeerDiscovery(addr)` 返回缓存中已知的 endpoint 与 relay，供核对 UDP 可达性。`node.Err()` 可读取导致节点停机的传输错误。 |
| 想知道 IP 包实际走了哪条路 | 在 `node.Peer(addr)` 返回的快照中，`CurrentEndpoint` 是当前直连地址，`LastDataPath` 记录最近一次成功提交给外层传输的 IP 包路径。其中 `Relay` 为空表示直连。 |
| peer 能连通，下游主机不通 | 核对下游路由的 `Gateway`、网关证书、两侧 NIC 转发开关和回程路由。直接使用 IPPort 时，缺少网关会返回 `ErrMissingGateway`，证书拒绝可通过 `errors.Is(err, nebula.ErrAddressNotCertified)` 判断。 |
| 包已入队，稍后发送失败 | 查看 `ep.Stats()` 或 `port.Stats()` 的 `Queued`、`RejectedInbound`、`RejectedOutbound` 和 `LastDrop`。最后一项记录最近一次端口拒绝的原因和可取得的地址。适配器自身的 MTU 检查直接返回 gVisor 的 `ErrMessageTooLong`。 |
| 队列满或正在更换网关 | 每个下一跳最多排队 100 个包，每个端口合计 512 个。端口满时返回 `ErrQueueFull`，对应 gVisor 的 `ErrNoBufferSpace`。更新路由后，如需丢弃仍发往旧网关的积压包，调用 `ClearPending(oldPeer)`，返回值为撤销数量。已交给传输的包仍可能完成发送。 |
