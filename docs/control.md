# 受管网络

受管节点先用标准 Nebula UDP 握手验证对端证书，再通过隧道内的 UDP 套接字同步配置、发现其他节点和交换应用事件。新节点可从一个可达的控制节点加入。它需要自己的有效身份、受信的主机 CA、固定的配置 CA，以及引导节点的 overlay 地址和外层端点。引导节点提供已经安装的签名配置，网络中至少有一个节点要先取得首份配置。加入拓扑后，普通成员即可协助邻居发现其他成员。

| 部署方式 | 支持的通信 |
| --- | --- |
| 普通节点，`Options.Control == nil` | 标准 Nebula 直连、lighthouse 发现和单跳中继。 |
| 受管端点之间使用上游单跳中继 | 中继转发端到端加密流量，两端可同步配置、发现节点和交换应用事件。 |
| 路径两端及所有中转均启用控制服务 | 在签名拓扑上建立多跳路径、探测主备路线，并按节点整形。 |

与上游节点混部时，将 `Options.DatagramMagic` 留空，并为普通 peer、lighthouse 和单跳中继提供标准可达路径。三种部署共用 Nebula 包头、Noise 握手和 `MessageRelay` 格式。

## 签发配置

管理员为网络选择一个名称和固定的配置 CA 公共证书。网络名称最多 128 个 ASCII 字符，支持字母、数字、点、下划线和连字符。每次签发完整配置，递增 `revision`。下面连接两个子网叶节点和两个网关，叶节点的 UDP 出口各只有一个。

```json
{
  "format": 1,
  "network": "office",
  "revision": 12,
  "revoked": [],
  "settings": {"app/service": {"logLevel": "info"}},
  "members": {
    "10.42.0.1": {"restricted": true, "links": ["10.42.0.2"], "endpoints": ["192.0.2.1:4242"]},
    "10.42.0.2": {"transit": true, "links": ["10.42.0.1", "10.42.0.3"], "endpoints": ["192.0.2.2:4242"], "bytesPerSecond": 1048576},
    "10.42.0.3": {"transit": true, "links": ["10.42.0.2", "10.42.0.4"], "endpoints": ["192.0.2.3:4242"]},
    "10.42.0.4": {"restricted": true, "links": ["10.42.0.3"], "endpoints": ["192.0.2.4:4242"]}
  }
}
```

把示例保存为 `office.json`，将成员地址和外层端点替换为实际地址。在持有配置 CA 签名私钥的机器上，从仓库根目录执行以下命令。`ca.crt`、`ca.key` 分别为该 CA 的 Nebula PEM 证书和签名私钥。工具填写 `authority` 并输出含正文和签名的 JSON。Go 调用方也可通过 `control.Sign` 传入 `crypto.Signer`。

```sh
go run ./cmd/nebula-config -ca ca.crt -key ca.key < office.json > office.signed.json
```

将签名文件交给一个启用了 `Options.Control` 的节点。在该节点上通过 Go API 安装，随后在线邻居会逐跳同步。版本比较以同一网络的签名正文为准，管理员每次更改配置都应签发更高的版本。

```go
wire, err := os.ReadFile("office.signed.json")
if err != nil {
	return err
}
return node.ApplyNetworkConfig(ctx, wire)
```

| 成员字段 | 用途 |
| --- | --- |
| `links` | 以证书主 overlay 地址标识的邻居，双方都要列出这条边。边上的邻居直接建立 Nebula 会话。 |
| `endpoints` | 该成员可供握手的外层 UDP 端点。受限叶节点只能向其授权邻居的签名端点或本机静态记录发送。 |
| `restricted` | 允许与指定邻居直连，其他目的节点经具备中转资格的邻居访问。若叶节点还需直接访问 lighthouse，将它也列为邻居并提供端点。 |
| `transit` | 授权该成员转发。中转节点还须在本地设置 `Relay.Serve = true`。多跳路径沿双向 `links` 建立。标准单跳转发在本机配置了 `links` 时也会检查入邻居和出邻居。 |
| `bytesPerSecond` | 此节点所有外层 Nebula UDP 负载的总出口速率，单位为字节/秒。零表示使用传输本身的速率。 |
| `publisher`、`topics` | 独立的 Ed25519 发布公钥（32 字节，JSON 中为标准 Base64）及授权主题前缀。节点用对应私钥签名自身端点介绍和应用事件。 |
| `certificate` | 可选的主机证书指纹，约束该成员签名介绍中声明的证书。将该指纹列入 `revoked` 也会暂停对应的发布授权。 |

`revoked` 为当前完整的主机证书指纹列表，使用小写十六进制。安装时立即退役本实例中匹配的会话，适用于 P-256 证书的等价签名编码。握手发布会话前再次检查当前列表。管理员可以签发更高版本的完整配置来恢复某张证书、替换发布密钥或修改主题授权。每个实例独立验证和保存状态。

管理员可以在顶层 `settings` 放置应用定义的 JSON 配置。它与拓扑和吊销列表共享同一签名、版本和替换语义。接入方调用 `node.SignedNetworkConfig()` 获取当前文档的独立副本，以 `control.Verify(wire, "office", configCA)` 取得已验证的 `Config.Settings`、版本和摘要，再按应用自己的结构解码。配置同步可以传递应用自定义数据，具体操作由读取该配置的应用执行。

## 接入 Go 节点

以示例的叶节点 `10.42.0.1` 为例，在快速入门的 `stack.Options.TransportProtocols` 中加入 `udp.NewProtocol`，在 `nebula.New` 前配置引导网关。网关自身使用自己的引导邻居和状态文件，并设置 `opts.Relay.Serve = true`。[gVisor 接入示例](quickstart.md)

```go
gateway := netip.MustParseAddr("10.42.0.2")
opts.Lighthouse.StaticHosts = map[netip.Addr][]netip.AddrPort{
	gateway: {netip.MustParseAddrPort("192.0.2.2:4242")},
}
opts.Control = &nebula.ControlOptions{
	Authority:       configCA,
	Network:         "office",
	StateFile:       "/var/lib/myapp/office.signed.json",
	Bootstrap:       []netip.Addr{gateway},
	MinimumRevision: 12,
}
```

`configCA` 是部署时固定的配置 CA 公共证书。`opts.CAPool` 负责验证 Nebula 节点身份。为每个实例准备独立的 `StateFile` 和可写的父目录。`New` 会验证已有文件的签名、网络名和最低版本。文件缺失时可从 `Bootstrap` 同步。在当前配置包含本机证书的主 overlay 地址前，节点仅向引导邻居建链并交换配置。

在调用 `node.Start()` 前，将套接字绑定到本机证书的主 overlay 地址。下例使用 IPv4，IPv6 主地址使用 `ipv6.ProtocolNumber`。同一网络的节点使用相同的控制端口，默认值为 42842。

```go
local := identity.Certificate.Networks()[0].Addr()
socket, err := gonet.DialUDP(s, &tcpip.FullAddress{
	NIC: nic, Addr: tcpip.AddrFromSlice(local.AsSlice()), Port: nebula.DefaultControlPort,
}, nil, ipv4.ProtocolNumber)
if err != nil {
	return err
}
if err := node.AttachControl(socket); err != nil {
	socket.Close()
	return err
}
if err := node.Start(); err != nil {
	return err
}
```

成功附加后，`Node.Close` 会关闭套接字和订阅。使用操作系统 TUN 的调用方可传入绑定在该 overlay 地址上的 UDP `net.PacketConn`。外层传输监听地址由 `Options.Transport` 决定，控制端口由 `ControlOptions.Port` 决定。自定义控制端口时，绑定套接字也要使用该端口。如果配置了 `InboundPolicy`，请允许控制邻居向本机主 overlay 地址送入流量。控制服务将收到的报文与 IPPort 记录的已认证会话对应后再处理。

## 配置同步与发现

邻居默认每两秒用 hello 通报网络名、版本、配置正文的 SHA-256 摘要、文档长度和中转能力。接收方按偏移拉取 640 字节分块，验证整份配置后原子替换状态文件。签名文档上限为 1 MiB。同版同摘要可以重复安装，同版不同正文会报冲突。分区恢复后直接同步最新版本。备份或重建状态文件时，可用 `MinimumRevision` 指定信任的最低版本。

已知邻居的签名端点或本地静态端点即可握手。需要动态发现时，在发起端和目标端分别为 `ControlOptions.Publisher` 配置与各自成员记录匹配的私钥。

1. 发起端签名介绍自己的候选。普通成员可通告签名端点、`Lighthouse.AdvertiseEndpoints`、`EndpointProvider` 返回的地址，以及直连邻居或引导节点观察到的 NAT 映射。受限成员介绍可用的中转邻居。
2. 控制节点按请求号去重，每次最多转给四个邻居，最多传播 16 跳。目标通过反向路径返回自己的签名介绍。
3. 两端在各自路径策略允许时向候选端点打洞，用 Nebula 证书握手验证最终对端。介绍有效期为 30 秒。

## 发布与接收应用事件

前面的四节点示例可直接用于签名拓扑和多跳转发。要发布事件，在发布节点设置 `ControlOptions.Publisher` 私钥，并在下一个签名版本中为该成员填写匹配的 `publisher` 公钥和 `topics`。例如，`"topics": ["app/service"]` 授权发布该主题及其子主题，订阅按完整主题匹配。以下示例在接收端订阅，发布后用返回的 ID 识别这条消息。为 `ctx` 设置截止时间可以限制等待时长。

```go
const topic = "app/service/reload"
sub, err := receiver.Subscribe(topic)
if err != nil {
	return err
}
defer sub.Close()

id, err := publisher.Publish(ctx, topic, []byte("api"))
if err != nil {
	return err
}
for {
	select {
	case event, ok := <-sub.Events():
		if !ok {
			return nebula.ErrNodeClosed
		}
		if event.ID == id {
			log.Printf("reload from %s: %s", event.Origin, event.Payload)
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

`Publish` 返回的 ID 表示本地已接受该签名事件。每条负载最多 384 字节。邻居交换摘要并补取缺失消息，同一事件在缓存窗口内只投递一次。每节点最多缓存 512 条，最长五分钟。分区超出窗口的节点可能错过消息。每个订阅有 32 个投递槽，`Missed()` 统计本订阅因消费过慢丢弃的投递。需要跨重启或长期分区生效的操作写入 CA 签名配置。

## 多跳、故障切换与整形

发起端在签名图上按最少跳数选择路径，每个第一跳保留一条主选路线，并在存在时试探一条绕过主路某条边的备选。每条路线最多 16 个节点且节点互异。单跳使用标准 Nebula 中转建立流程。多跳的每对邻居先直接认证，中转逐跳验证并替换外层认证封装，端点间使用标准 Noise 会话。

`Relay.MaxMappings` 限制每节点可用的本地中继索引数，默认 8192，标准单跳和受管多跳共享这个额度。一条双向多跳路径在每个端点占用一个索引，在每个中转占用两个。规划网关容量时，主路和备路要分别计入，即使两条路线共用同一个网关。

节点按既有路径探测策略评估备用路线。两条路径即使共用第一跳，也有独立的 `TunnelPath.Circuit`，端到端探测可区分整条线路。活跃路径受使用或监测驱动，确认超时、邻接消失和拓扑撤权会释放映射。叶节点的端点白名单还在最终写 UDP 前检查。调用 `SetPeerEndpoints` 替换网关的静态端点也会立即更新白名单，签名端点继续有效。子网前缀转发另由 gVisor 路由和证书 `UnsafeNetworks` 授权。[探测与切换参数](paths.md) · [子网路由示例](nebula-nic.md)

启用整形时，按外层 Nebula 数据报字节（包括可选前缀）计费。数据预算为速率的 90%，控制预留 10%，控制报文可借用闲置的数据额度。令牌桶允许短时突发。数据按来源分队列，每来源队列上限 64 KiB，总待发上限 256 KiB。在发送端，配置同步和路径探测可使用控制额度，应用事件使用数据额度。中转只能看到端到端报文的 Nebula 头，可优先转发握手和短探测报文。多跳中转按路径标识的来源调度，标准单跳中转按入邻居调度。宿主机出口可用 Linux `tc` 计入底层 IP、UDP 及设备上的其他流量。

## 排查受管网络

| 排查目标 | API 和观察项 |
| --- | --- |
| 配置是否一致 | 对比各节点的 `ControlStatus().Revision` 和 `Digest`。同版本应具有相同摘要。`LastError` 记录最近一次本地或同步安装配置的错误。 |
| 引导或同步卡住 | `Neighbors` 列出最近交换 hello 的邻居，`LastSync` 是最近收到 hello 的时间。先核对引导端点和两端控制端口，再检查网络名、CA、最低版本和状态目录。配置是否追齐用 `Revision` 和 `Digest` 判断。 |
| 多跳路线及转发 | `ControlStatus().Circuits` 返回本地路径的 ID、完整地址序列和就绪状态。用 `node.Peer(addr)` 返回的快照查看 `PathHealth`，再用 `RelayStats().ForwardedDatagrams` 查看转发量。 |
| 拥塞与投递 | `ControlStatus().Egress` 显示启用整形期间累计提交的字节、其中的控制字节、整形丢弃字节、当前待发字节和上次数据排队延迟。`MissedEvents` 汇总本地订阅溢出。 |
