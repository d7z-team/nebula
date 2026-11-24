# 集群地址与 IP 交付

集群 CA 决定可分配的主地址、下游路由上限和服务地址池。拓扑决定哪些成员、网关、服务实例和组订阅在本机生效。传输层对每个实际收发的包核对拓扑与端到端会话证书。以三个节点在本机验证各类目的地址，可以运行下面的示例。[示例源码](../examples/addressing/main.go)

```sh
go run ./examples/addressing
```

## 签发和分配

1. 使用 `Scope{Network: "demo", Cluster: true}` 声明集群 CA，在 `CAProfile.PermittedIPs` 设置同族互不重叠的成员子网，IPv4 和 IPv6 各至少一个。例如 `10.13.0.0/24`、`fd13::/64`。这些 CIDR 写入标准 X.509 IP Name Constraints。集群 CA 可以是信任根，也可以由企业根签发。
2. 在 CA 的 `Scope.RoutedPrefixes` 设置可下放的业务路由，在 `Scope.AnycastPools` 预留服务地址，例如 `10.13.0.192/27`。服务地址池可以位于成员子网内部，也可以独立部署。下级 CA 省略 mesh 扩展时继承上级授权，提供扩展时按其中的范围收窄。签发者的 `Issuer.Chain` 按顺序提供签发 CA、集群 CA 和已有的上级链。
3. 每个成员获得一个独占 IPv4 和一个独占 IPv6。两者是叶证书的 IP SAN，共同构成 `PeerID`。需要承载服务时，将每个获批 VIP 写入叶证书的 `Scope.AnycastIPs`。下游路由和 VIP 分别签发。客户端、服务端使用不同凭据时，两种方向的会话均需各自具备相应授权。
4. 为节点提供 `Options.Roots` 和 `Options.ClusterCA`。用 `pki.ReadClusterCA(cert)` 读取规划并调用 `topology.Validate(cluster)` 预检，运行中通过 `node.Cluster()` 读取同一规划。PKIX 验证、集群 CA 固定、mesh 委派和宿主授权作用于同一条证书路径。[签发命令与编码](pki.md)

`cluster.Subnets()` 和 `cluster.AnycastPools()` 返回副本。分配器可用 `cluster.MemberAddresses(prefix)` 按需遍历候选主地址，用 `cluster.ValidateMember(id)` 检查一对指定地址。宿主在自己的持久化分配表中分别为 IPv4 和 IPv6 建唯一约束，在同一事务中预留这对地址，再签发证书。IPv4 普通子网保留网络地址和定向广播地址，/31 和 /32 可使用所有地址。IPv6 普通子网保留全零接口标识，/127 和 /128 可使用所有地址。成员分配会跳过 VIP 池和排除范围。下级 CA 进一步收窄的 SAN 范围只影响签发权限，逻辑链路边界始终取集群 CA 的子网。[分配 API](../pki/cluster.go) · [RFC 3021](https://www.rfc-editor.org/rfc/rfc3021) · [RFC 6164](https://www.rfc-editor.org/rfc/rfc6164)

## 广播与组播

`Topology.EnableBroadcast` 与 `EnableMulticast` 分别控制本机的发送和接收，默认关闭。发布整份新拓扑时调用 `node.ApplyTopology(ctx, topology)`。发送者和接收者按各自的当前视图执行策略。对于组播，在接收成员的 `MulticastGroups` 中列出精确 IP；成员可以订阅多个组。下表的“同子网”指两端成员在相应地址族的主地址位于同一个 CA 子网。[拓扑字段](../topology.go)

| 目的地址 | 远端接收者 |
| --- | --- |
| `255.255.255.255` 或本子网 IPv4 定向广播 | 同一 IPv4 子网的成员 |
| `224.0.0.1`、`ff02::1` | 同族同子网的全部成员 |
| 其余 `224.0.0.0/24`、IPv6 链路作用域组 | 同族同子网且订阅该组的成员 |
| IPv6 接口作用域组，如 `ff01::1` | 由宿主栈在本机处理 |
| 其余可用组播地址 | 当前拓扑中订阅该地址的成员 |

发送节点为每个合格远端排队一份，共用原始报文内容，每份独立整形。中继沿已认证电路转发，宿主栈处理本地回环。接收端校验源地址、会话、开关和接收资格后调用宿主的 `InboundPolicy`。每个成员队列最多等待 64 份，每个端口最多等待 512 份，同时最多有 512 个成员队列。广播、组播和 VIP 流量在每个节点最多同时发起 8 次冷拨。同一成员复用在途拨号。清空队列会结束对应包的等待，拨号任务结束时释放名额。部分队列满时，写入仍可在其余合格队列成功。全部可用队列均满时返回 `ErrQueueFull`。

## 下一跳与回程

| 目的地址 | 宿主如何写入原始 IP 端口 |
| --- | --- |
| 成员主地址 | `port.WriteIP(nebula.PeerID{}, packet)` 按当前拓扑交给该地址的唯一成员。已知主地址可用 `node.LookupPeer(primary)` 取得完整 ID。 |
| 广播、组播 | 传入零 ID，由端口按上表确定远端接收者。 |
| 服务 VIP | `node.AnycastMembers(vip)` 返回本机拓扑许可的成员副本，其中可以包含本机。选定远端后调用 `port.WriteIP(peerID, packet)`。本机服务由宿主栈交付。 |
| 下游地址 | 传入有相应路由授权的网关 ID。两个网关承载同一前缀时，原始端口的 `Deliver(from, packet)` 提供入站网关的认证 ID，宿主可以将回包写给该 ID。 |

VIP 或下游地址使用零 ID 时，端口在入队前调用一次可选的 `ResolveNextHop(dst, packet)`。回调收到只读包，可以查询节点或应用的流绑定表。回调结束后，端口用最新拓扑重新检查所选成员；回调返回的错误直接交给写入方。显式下一跳、已归属的主地址和组流量均跳过回调。调用方未配置解析器或解析器返回零 ID 时，写入返回 `ErrNextHopRequired`。成员子网内未分配的普通地址返回 `ErrPeerUnavailable`。[IP 端口](../ip_port.go)

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
