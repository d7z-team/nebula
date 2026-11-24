# 测试与故障重放

从仓库根目录运行。端到端测试在进程内创建独立的 gVisor 主机、网段和 NAT 网关。外层网络承载实际的 QUIC 或 TCP 会话；内层网络通过节点的虚拟网卡收发业务。测试同时检查物理端点、认证路径和业务回执。[虚拟网络](../e2e/network_test.go) · [节点与业务栈](../e2e/mesh_test.go)

## 运行测试

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -race -count=1 -timeout=5m ./e2e -args -extended
go test -race -count=1 -timeout=5m ./e2e -args -extended -portshare
```

常规 CI 在 Linux、macOS 和 Windows 运行自带凭据的示例，双进程示例由 `TestPeerProcesses` 验证。Linux 另用 `-portshare` 重跑 gVisor 场景，让实验节点的 UDP 和 TCP 入口使用端口分流器。[示例入口](../README.md#getting-started) · [共享 443 端口](portshare.md)

可按故障类型单独重放。前两条命令分别验证物理端点断网后的重新接入，以及两种 NAT 映射或过滤条件下的选路。

```sh
go test -race -count=1 -run '^TestConnectEndpointRecoveryAfterUDPBlackout$' .
go test -v -count=1 -run '^TestNATPaths$/^(port|destination-specific)$' ./e2e
go test -race -v -count=1 -run '^TestChaosMobileHandover$' ./e2e -args -extended
go test -race -v -count=1 -run '^TestChaosCanaryAfterNATRebind$' ./e2e -args -extended
go test -race -v -count=1 -run '^TestChaosHiddenTransit$' ./e2e -args -extended
go test -v -count=1 -run '^TestSeededChaos$' ./e2e -args -extended -seed 7
```

种子决定八步故障操作的顺序。使用 `-v` 查看每一步的操作、路径和业务回执。排查失败时记录提交号、种子和首次失败步骤。定时与手动 CI 还会在竞态检测下运行固定故障场景，并重放种子 1 至 10。[混沌场景](../e2e/chaos_test.go) · [CI 配置](../.github/workflows/test.yml)

双进程示例用磁盘凭据验证接入、地址查询和签名回执。并发用例检查多个调用方共享拨号或查询时，一个调用方超时后其他调用方能否继续。[双进程测试](../examples/peer/main_test.go) · [拨号测试](../dial_test.go) · [发现测试](../lookup_test.go)

```sh
go test -count=1 -run '^TestPeerProcesses$' ./examples/peer
go test -v -run '^ExampleNode_ResolveIP$' .
go test -race -count=10 -run '^TestConnectEndpointSharesDial$|^TestConcurrentResolveCancellation$' .
go test -race -count=10 -run '^TestTCPFallbackOnInitialDial$' .
```

## 按问题选择测试

| 问题 | 测试与观测点 |
| --- | --- |
| 线协议互通 | `TestWireStreams` 通过认证会话核对固定 Ping、双 IP 包流和电路确认字节；推送的空确认与原始 CMS 补发由 `TestMaximumPublicationAndInventoryFrames` 验证。`TestWireJSON` 核对字段、编码和纳秒整数精度。[协议格式](mesh.md#操作码和流边界) · [固定线格式](../wire_test.go) |
| 集群分配、组交付与服务 VIP | `TestGroupDatagrams` 通过中继送达广播和组播。`TestAnycastService` 让宿主分别指定 A、B，核对双栈 UDP 的 VIP 回包。`TestAnycastTCPPathChange` 在同一 TCP 连接上从直连切到中继，核对提交记录中的成员和电路。[业务测试](../e2e/addressing_test.go) · [证书与地址边界](../pki/cluster_test.go) |
| 有状态业务排空、撤权及回程 | `go run ./examples/anycast` 在一个 VIP 上定向探测 A，同时核对仍由 A 服务的旧连接、新建到 B 的连接和撤权结果。根包测试覆盖冷拨失败、授权热更新与解析回调并发、等待带宽时撤回 VIP，以及双归下游按入站网关回包。[排空示例](../examples/anycast/main.go) · [收发测试](../addressing_test.go) |
| 网站与 mesh 共享端口 | `TestShareSitesAndPolicy` 检查三个 SNI 站点、HTTP/1.1、HTTP/2、HTTP/3、mesh 认证和同源撤权；`portshare` 包覆盖原始字节、分片重传、CID 轮换、迁移、对端重启和分支生命周期。[集成测试](../portshare_test.go) · [QUIC 场景](../portshare/quic_test.go) |
| NAT 映射或过滤影响直连 | `TestNATCalibration` 核对公网端实际看到的源地址和端口。`TestNATPaths` 检查打洞报文、认证直连，以及目的地相关映射下的中继回退。`TestGatewayLayouts` 覆盖单 NAT、双 NAT、同网段与 NAT 回环。[NAT 测试](../e2e/nat_test.go) |
| 隐藏端点与多跳转发 | `TestHiddenIntroduction` 检查 NAT 地址反馈、真实会合和离线缓存返回的签名介绍，以及会合时的物理发包记录。`TestChaosHiddenTransit` 让 NAT 后的 H 主动建立两侧邻接，通过五节点电路交付双栈流量，再只在 H 撤回中继授权。加 `-extended` 会切断再恢复一侧邻接，要求原有内层 TCP 连接收到新的回执，并核对 H 全程发包的物理目的地址。[发现测试](../lookup_test.go) · [五节点测试](../e2e/chaos_test.go) |
| 入站先连通、UDP 黑洞或中继恢复直连 | `TestConnectPeerAcceptsInboundDuringDial` 在 VIP 出站拨号阻塞时清空队列，验证新包能使用反向建立的 TLS 会话，并核对冷拨名额的释放时机。`TestTCPFallbackOnInitialDial` 在多个 UDP 地址静默丢包时通过 TCP 建链。`TestChaosCanaryAfterNATRebind` 在第一次探测旧端口时切换 NAT 映射，核对观察者看到的新端口、本轮打洞与认证直连，以及原内层 TCP 连接上的业务回执。[建链测试](../mesh_test.go) · [换址测试](../e2e/chaos_test.go) |
| 移动网络连续换出口 | `TestChaosMobileHandover` 模拟移动端保留本地 UDP 套接字、与固定公网节点通信。连续四次同时更换 NAT 公网 IPv4 和端口，每次切断旧出口，新映射上的首包触发 400 ms 双向断流，恢复后单向逐包延迟在 20–80 ms 之间变化。每轮要求原内层 TCP 连接在 12 秒内收到本轮数据的摘要回执，并核对固定端看到的认证成员和新端点。日志记录从开始切换到收到回执的耗时；12 秒用于限制测试等待。[移动切换场景](../e2e/chaos_test.go) |
| 丢包、时延或窄路径 | `TestLossAndNarrowPath` 将外层 UDP 载荷限制为 1200 字节，检查 1280 字节内层 IPv6 包的交付与可靠流回退计数。`TestChaosFailoverAndRenewal` 在同一内层连接上检查切路、换证和恢复。[链路故障测试](../e2e/chaos_test.go) |
| 双栈选路或网关转发 | `TestDualUnderlayFamilyFailover` 切断外层 IPv4 后继续传输内层双栈业务。`TestNodeGVisorForwardingAndDetach` 核对下游源地址、TTL、Hop Limit 及卸载虚拟 NIC 后的 LAN 连接。[外层双栈](../e2e/mesh_test.go) · [网关转发](../e2e/forwarding_test.go) |
| 选路与端点发现 | `TestCanaryAndTransmitHysteresis` 通过两个真实 TCP 端点核对状态查询、连接确认、VIP 临时改道和普通包最终使用的端点。`TestRelaySearchContinuesAcrossDials` 让同一首跳的前八条候选失败，检查下次拨号建立的电路。其余互联用例覆盖双方收包上限、签名介绍与授权到期、邻居调度和监听恢复。[互联回归](../interconnect_test.go) |
| 多路径邻居与消息补发 | `TestPublicationRepairAndPolicyWithdrawal` 在同一邻居的两条 TCP 会话上检查推送字节数，随后让迟到的成员从清单补取。[主题消息测试](../publication_test.go) |
| 故障恢复与关闭 | 扩展场景切断中继、撤回发布者授权，或在整形积压且拨号目标失联时取消首个等待者并关闭节点。分别核对恢复路径、补发主题消息、其余等待者退出和队列清空。[混沌测试](../e2e/chaos_test.go) |
| 证书签发、热加载或授权期限 | 检查 CSR 公钥审批、双栈 SAN、逐链 CIDR 委派、CA 允许的每个 EKU 与有效期。会话测试核对握手期间换证前后的实际序列号，主题消息测试覆盖最大 CMS 对象和分页清单的交付。[签发边界](../pki/boundaries_test.go) · [路径授权](../identity_boundaries_test.go) · [握手](../authentication_test.go) · [主题消息](../publication_test.go) |

NAT 网关由 gVisor 执行转发、SNAT 和 DNAT。测试固定 UDP 公网映射并按出站报文记录允许的回包来源，从而分别控制映射与过滤。IPv4 转发测试在 FORWARD 钩子中保留包头引用。CI 的 `gateway` 作业还会在 vendor 中应用 gVisor 补丁，验证实际部署使用的双栈转发路径。[IPv4 网关构建](integration.md#gvisor-的-ipv4-网关构建)

## 性能对照

在同一台机器上用相同的 Go 版本和并行度比较两个工作树。以下基准将准备拓扑或建立会话的时间排除在计时之外。

```sh
go test -run '^$' -bench '^BenchmarkPacketAuthorization$' -benchtime=200ms -benchmem -count=5 -cpu=1 .
go test -run '^$' -bench '^BenchmarkMeshIP$' -benchtime=500x -benchmem -count=5 -cpu=2 .
go test -run '^$' -bench '^BenchmarkPathStatus$' -benchmem .
```

`BenchmarkMeshIP` 分别经独占 UDP、两端共享 UDP 和 TCP 逐包发送 1 KiB 的内层 IPv4 包，每次等对端收到后再发下一个。可比较每包分配次数、字节数以及交付延迟的 p95、p99。`BenchmarkPathStatus` 分别在连接 16 和 128 个 TCP 对端后读取完整路径状态。[基准代码](../mesh_test.go)

`BenchmarkPacketAuthorization` 测量一次已认证会话对内层包的地址授权，分别覆盖成员主地址、VIP、下游地址，以及在 128 名订阅者中查找最后一名成员。比较查询实现时使用相同拓扑和目的成员，再用 `BenchmarkMeshIP` 测量完整收发路径。[地址授权基准](../addressing_test.go)
