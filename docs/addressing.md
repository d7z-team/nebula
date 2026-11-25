# 集群地址与 IP 交付

集群 CA 声明成员子网、下游路由上限和服务地址池。每个成员以叶证书中的一对主地址认证。节点可通过已有邻居发现其他成员的主地址，宿主在本机拓扑中另行批准网关前缀、服务 VIP 和组投递。下面的示例用三个节点验证广播、组播和任播交付。[示例源码](../examples/addressing/main.go)

```sh
go run ./examples/addressing
```

## 签发和分配

1. 在集群 CA 的 `CAProfile.PermittedIPs` 设置一个 IPv4 和一个 IPv6 成员网段，例如 `10.13.0.0/24` 和 `fd13::/64`。这些 CIDR 写入标准 X.509 IP Name Constraints，共同定义一条逻辑链路。站点 CA 在上级委派的双栈范围内签发地址。
2. 在 `Scope.RoutedPrefixes` 设置可下放的业务路由，在 `Scope.AnycastPools` 预留服务池。服务池可在成员网段内，也可独立分配。站点 CA 省略 mesh 扩展时继承上述授权上限。
3. 每个节点的两个独占主地址共同构成 `PeerID`。叶证书用 `Scope.AnycastIPs` 授权精确 VIP，用 `Scope.RoutedPrefixes` 授权下游前缀。客户端、服务端使用不同凭据时，各方向要分别授权。
4. 将信任根和固定的集群 CA 填入 `Options.Auth.Roots` 和 `Options.Auth.ClusterCA`。启动前可用 `pki.ReadClusterCA(cert)` 和 `topology.Validate(cluster)` 预检地址规划，运行中用 `node.Cluster()` 读取同一规划。[CA 签发参数与证书字段](pki.md#证书配置)

`v4, v6 := cluster.MemberPrefixes()` 返回集群前缀，`cluster.AnycastPools()` 返回服务池副本。分配器可用 `cluster.MemberAddresses(within)` 枚举集群内任意规范子范围，按集群前缀判断网络边界，用 `cluster.ValidateMember(id)` 检查一对指定地址。宿主在自己的持久化分配表中分别为 IPv4 和 IPv6 建唯一约束，在同一事务中预留这对地址，再签发证书。IPv4 普通子网保留网络地址和定向广播地址，/31 和 /32 可使用所有地址。IPv6 普通子网保留全零接口标识，/127 和 /128 可使用所有地址。成员分配会跳过 VIP 池和排除范围。下级 CA 进一步收窄的 SAN 范围只影响签发权限，逻辑链路边界始终取集群 CA 的子网。[分配 API](../pki/cluster.go) · [RFC 3021](https://www.rfc-editor.org/rfc/rfc3021) · [RFC 6164](https://www.rfc-editor.org/rfc/rfc6164)

多个成员可以共同承载同一 VIP 或下游前缀。核对运行中观察到的主地址、VIP 或网关声明时，在相关节点调用 `InspectIP(ip)`。[排查与恢复](integration.md#排查重复地址与实例)

## 广播与组播

`Topology.EnableBroadcast` 控制广播收发，`EnableMulticast` 控制组播收发，两者默认关闭。用 `node.ApplyTopology(ctx, topology)` 更新本机视图。在接收成员的 `MulticastGroups` 中列出要订阅的组地址。发送方按自己拓扑的 `Members` 展开接收名单，接收方按自己的视图校验交付资格。不同站点 CA 签发的成员共享一条逻辑链路。[拓扑字段](../topology.go)

| 目的地址 | 远端接收者 |
| --- | --- |
| `255.255.255.255` 或本子网 IPv4 定向广播 | 本机拓扑中的其他成员 |
| `224.0.0.1`、`ff02::1` | 本机拓扑中的其他成员 |
| IPv6 接口作用域组，如 `ff01::1` | 由宿主栈在本机处理 |
| 其余可用组播地址（含链路作用域） | 当前拓扑中订阅该地址的成员 |

每个合格远端各有一份排队记录，共用原始报文，各自等待带宽。中继沿认证电路转发，宿主栈处理本地回环。接收端核对源地址、会话、组流量开关和接收资格，再调用宿主的 `InboundPolicy`。

每个成员最多等待 64 份，每个端口最多等待 512 份，并限制为 512 个成员队列。只要有合格队列能接纳，写入即可成功。全部已满时返回 `ErrQueueFull`。广播、组播和 VIP 在每个节点共用 8 个冷拨名额，同一成员共享在途拨号。等待名额时，对端主动连入也能让包获得路径。清空队列会结束这些包的等待，拨号完成时释放名额。

## 下一跳与回程

| 目的地址 | 宿主如何写入原始 IP 端口 |
| --- | --- |
| 成员主地址 | `port.WriteIP(nebula.PeerID{}, packet)` 根据本机拓扑、有效签名介绍或认证会话确定地址归属。`node.LookupPeer(primary)` 可从这些本地信息中取得完整 ID。 |
| 广播、组播 | 传入零 ID，由端口按上表确定远端接收者。 |
| 服务 VIP | `node.AnycastMembers(vip)` 返回本机拓扑许可的成员副本，其中可以包含本机。选定远端后调用 `port.WriteIP(peerID, packet)`。本机服务由宿主栈交付。 |
| 下游地址 | 传入有相应路由授权的网关 ID。两个网关承载同一前缀时，原始端口的 `Deliver(from, packet)` 提供入站网关的认证 ID，宿主可以将回包写给该 ID。 |

VIP 或下游地址使用零 ID 时，端口在入队前调用一次可选的 `ResolveNextHop(dst, packet)`。回调收到只读包，可以查询节点或应用的流绑定表。回调结束后，端口用最新拓扑重新检查所选成员；回调返回的错误直接交给写入方。显式下一跳、已归属的主地址和组流量均跳过回调。调用方未配置解析器或解析器返回零 ID 时，写入返回 `ErrNextHopRequired`。目的为本机尚未知的普通主地址时，先显式调用 `ResolveIP(ctx, dst)`，选中结果后可调用 `ConnectPeerID(ctx, match.Peer)`，向该身份写包。

查询下游地址得到多个候选时，应用可按流选定网关。宿主核准网关及其下游前缀后，用 `ApplyTopology` 安装本机视图。实际收发时还会校验会话证书中的地址授权。[地址查询与缓存](integration.md#按地址发现成员和下游网关) · [IP 端口](../ip_port.go)

网关的 `RoutedPrefixes` 同时批准发往该范围的目的地址以及网关代表的源地址，支持下游主动发起的连接。已有默认出口时，调用 `RefreshIP(ctx, dst)` 可查询新加入的站点网关。给两个网关分别批准 `0.0.0.0/0` 与站点 `/24` 后，宿主可优先经站点网关发包；入站时两者都可以代表该站点。宿主可用 `InboundPolicy` 收窄入站来源。双栈默认出口另外需要批准 `::/0`。成员网段中的未分配地址和已保留的服务池始终按各自规则交付。[双出口示例](../examples/gateway/main.go)

实例冲突导致交付暂停时，原始端口的 `WriteIP` 返回 `ErrInstanceConflict`，gVisor 网卡写入返回 `tcpip.ErrNotPermitted`。

通过 `ObserveTransmit` 读取已出队包的结果，用 `errors.Is` 区分路径不可达（`ErrPeerUnavailable`）、路径策略拒绝（`ErrPathPolicy`）和地址未获授权（`ErrAddressUnauthorized`）。

- 冷拨失败时，端口丢弃该成员的剩余积压，并计入 `RejectedOutbound`。
- 建链后失去可用路径时，当前包报告失败，下一包可向同一成员重新建链。切换到 `RelayOnly` 会使等待旧直连带宽的包收到 `ErrPathPolicy`。其余获准的包按顺序在新会话上复核证书权限后发送。[发送队列](../ip_transmit.go)

## 任播服务

例如成员 `10.13.0.2` 和 `10.13.0.3` 均提供 `10.13.0.200`。给两张叶证书各授权这个精确 VIP，在这两个 `Member.AnycastIPs` 中分别启用它。两台机器仍使用各自唯一的双栈主地址建立 TLS 会话。实例返回的业务包可以用该 VIP 作源，接收端对回包执行同样的拓扑和证书检查。网关拥有的默认路由也须遵守成员地址和 VIP 的专属授权。

**有状态服务的排空。** 宿主在建立 TCP 连接时绑定实例的完整 `PeerID`。定向探测向这个实例的 VIP 和业务端口发起请求，检查应用响应。计划摘流时，将新连接交给其他实例，保留旧绑定和 VIP 授权直至连接结束。紧急撤权时，从本机拓扑撤回该成员的 VIP，端口会清理失权的等待包。已选实例拨号失败或失权时，宿主决定后续连接的去向。[可运行的 TCP 排空示例](../examples/anycast/main.go)

```sh
go run ./examples/anycast
```

示例的宿主只发起一种 IPv4 TCP 服务，拨号前已知源端口。做透明转发时，宿主需要让同一 IP 数据报的分片获得一致的下一跳，或拒绝无法归属的分片。处理内层 QUIC 时，连接迁移可改变五元组，终止 QUIC 的应用可按真实连接生命周期绑定实例。[QUIC 连接迁移](https://www.rfc-editor.org/rfc/rfc9000#section-9)

探活阈值、接流名单、排空期限及配置发布均由应用决定。拓扑更新只在应用它的节点生效，已交给底层传输的包仍可能随后到达，接收端按本机视图验权。库只在所选成员的获准路径之间评分和切换。中继按端到端电路转发，服务实例直接接收发给自己的 VIP 包。[线路策略](mesh.md#发现选路与中继)

## gVisor 接入

- 用成员主地址和 `cluster.Subnet(ip).Bits()` 为 NIC 设置掩码，并添加相应的直连路由。IPv4 定向广播依赖 NIC 的实际前缀长度。
- 将广播、组播及服务地址的路由指向 mesh NIC。独立 VIP 池可单独配置直连路由。广播发送端设置 `SO_BROADCAST`；组播接收端在业务栈加入相应组，并在拓扑声明接收成员。应用选择与该成员匹配的源地址。
- 在每个服务实例的 NIC 上另行配置 VIP，通常使用 /32 或 /128，并将服务 socket 绑定到 VIP。gVisor 可用 `stack.NeverPrimaryEndpoint` 保留主地址作为普通出站源。已有的本机 VIP 或接口作用域组流量按宿主栈的本地交付规则处理。[网关示例](../examples/gateway/main.go) · [真实 UDP 业务测试](../e2e/addressing_test.go)
- 路由表显式指定的网关优先，以网关主地址查找完整成员身份。访问远端 VIP 时，直连路由配合 `nebulagvisor.Options.ResolveNextHop` 可按业务连接指定实例。使用宿主机路由表、策略路由或 NAT 的接入程序自行配置这些规则。按指定成员估算路由 MTU 可用 `node.RecommendedMTU(peerID, dst.Is6(), int(ep.MTU()))`。gVisor 可基于实际路由 MTU 选择 TCP 段大小。多网关回程可以用 `ObserveReceive` 在协议栈接收前记录实际网关，用 `ResolveNextHop` 为对应业务选择回程。[接入指南](integration.md#ip-收发与网关)
