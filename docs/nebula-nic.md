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

应用拨号时使用下游地址 `192.168.50.20`。gVisor 在 `PacketBuffer.EgressRoute.NextHop` 中传入网关地址 `10.42.0.254`，Nebula 通过静态配置或 lighthouse 找到网关的外层地址。

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

| 操作 | 调用方的职责 |
| --- | --- |
| 提供传输 | 普通 UDP 使用 `nebula.WrapPacketConn`。`nebula.New` 成功后节点接管传输，失败时调用方关闭它。自定义 `DatagramTransport` 须保留数据报边界，支持并发写，并在 `Close` 时唤醒阻塞的读写。 |
| 挂载和卸载 | 一个节点同时持有一个数据端口。`NewEndpoint` 预留端口，`CreateNIC` 失败时调用 `ep.Close()`。挂载成功后用 `s.RemoveNIC(id)` 删除该 NIC 及其路由并释放端口，之后可挂载新端点。 |
| 选择 MTU | 默认 1300，构造时接受 1280 至 9001，运行时 `SetMTU` 将值限制在该范围。外层传输还要容纳 Nebula 封装开销。 |
| 停止服务 | 宿主管理 socket 的关闭或 deadline。`node.Close()` 取消数据端口并关闭外层传输，`node.Wait()` 等待节点任务退出并报告致命传输错误。其他 NIC 和整个栈继续由宿主管理。 |

### 接入其他三层设备

调用 `node.OpenIPPort(deliver)` 取得端口。回调在接收线程上借用只读 IP 包，异步处理时先复制再返回。用 `port.WriteIP(nextHop, packet)` 提交完整的单播 IP 包。直达 overlay 地址时，下一跳可传零值 `netip.Addr{}`。访问下游子网时，传网关的 overlay 地址。返回成功表示包副本已入队，用完端口后调用 `port.Close()`。

## 发现与运行时管理

已知外层地址时，在 `Lighthouse.StaticHosts` 中将 peer 的 overlay 地址映射到 UDP endpoint。使用 lighthouse 时，服务端设置 `Lighthouse.AmLighthouse`，客户端把服务端的 overlay 地址加入 `Lighthouse.Hosts`，并为每个 lighthouse 配置静态 endpoint。

本机通过 `AdvertiseEndpoints` 通告固定地址，通过 `EndpointProvider` 提供动态地址。节点串行调用 provider。回调应响应 context 取消，在回调返回后再发起新的通告或重绑。

| 操作 | API 与结果 |
| --- | --- |
| 查找或刷新 peer | `PeerDiscovery(addr)` 返回已缓存的地址和中转。`RefreshPeer(ctx, addr)` 向 lighthouse 排队查询，同一地址共享在途请求。队列满时可通过 context 取消等待。配置的 lighthouse 地址和无需发现的节点会直接返回。 |
| 更新静态候选 | `SetPeerEndpoints(addr, endpoints)` 替换该 peer 的静态地址，已学习的地址和已建立的隧道继续可用。 |
| 通告本机地址 | `AdvertiseNow(ctx)` 获取动态地址并向 lighthouse 发送更新。底层传输实现 `RebindableTransport` 时，可用 `node.Rebind()` 重绑并重新通告。 |
| 建立或关闭连接 | `ConnectPeer(ctx, addr)` 等待经过认证且具有可用出口的隧道。取消 context 结束本次等待，共享握手可继续。`DisconnectPeer` 和 `DisconnectAll` 拆除隧道，后续流量可重新触发握手。 |

每个报告来源最多保留 10 个 IPv4 endpoint、10 个 IPv6 endpoint 和 10 个 relay。直连握手轮换候选，先尝试 `Options.PreferredRanges` 中的地址，组内依次优先 IPv6、非私有 IPv4 和私有 IPv4。

## 直连、中转与链路健康

客户端访问下游子网时，gVisor 的路由选定网关，Nebula 的路径策略决定如何到达该网关。要指定中转或调查线路抖动，按网关的 overlay 地址配置策略并检查探测的去程和回程。[路径配置与健康检查](paths.md)

## 排错

| 现象 | 检查方法 |
| --- | --- |
| 节点启动后连不上 peer | 用 `node.Snapshot()` 核对本机状态、证书地址和外层监听地址，用 `node.Discovery()` 核对 lighthouse 配置。`node.PeerDiscovery(addr)` 返回缓存中已知的 endpoint 与 relay，供核对 UDP 可达性。`node.Err()` 可读取导致节点停机的传输错误。 |
| 想知道 IP 包实际走了哪条路 | 在 `node.Peer(addr)` 返回的快照中，`CurrentEndpoint` 是当前直连地址，`LastDataPath` 记录最近一次成功提交给外层传输的 IP 包路径。其中 `Relay` 为空表示直连。 |
| peer 能连通，下游主机不通 | 核对下游路由的 `Gateway`、网关证书、两侧 NIC 转发开关和回程路由。直接使用 IPPort 时，缺少网关会返回 `ErrMissingGateway`，证书拒绝可通过 `errors.Is(err, nebula.ErrAddressNotCertified)` 判断。 |
| 包已入队，稍后发送失败 | 查看 `ep.Stats()` 或 `port.Stats()` 的 `Queued`、`RejectedInbound`、`RejectedOutbound` 和 `LastDrop`。最后一项记录最近一次端口拒绝的原因和可取得的地址。适配器自身的 MTU 检查直接返回 gVisor 的 `ErrMessageTooLong`。 |
| 队列满或正在更换网关 | 每个下一跳最多排队 100 个包，每个端口合计 512 个。端口满时返回 `ErrQueueFull`，对应 gVisor 的 `ErrNoBufferSpace`。更新路由后，如需丢弃仍发往旧网关的积压包，调用 `ClearPending(oldPeer)`，返回值为撤销数量。已交给传输的包仍可能完成发送。 |
