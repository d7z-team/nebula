# 测试与故障重放

从仓库根目录运行。端到端测试在进程内创建独立的 gVisor 主机、网段和 NAT 网关。外层网络承载实际的 QUIC 或 TCP 会话；内层网络通过节点的虚拟网卡收发业务。测试同时检查物理端点、认证路径和业务回执。[虚拟网络](../e2e/network_test.go) · [节点与业务栈](../e2e/mesh_test.go)

## 运行测试

```sh
make fmt
make lint
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
```

常规 CI 在 Linux、macOS 和 Windows 上运行测试及八个自带凭据的示例，Linux 另测竞态、共享端口与打过补丁的 gVisor 网关。磁盘凭据双进程示例的签名回执由 `TestPeerProcesses` 验证。[示例入口](../README.md#examples) · [双进程测试](../examples/peer/main_test.go) · [CI 配置](../.github/workflows/test.yml)

quic-go 的 `failed to sufficiently increase receive buffer size` 表示物理套接字的缓冲区小于期望值，QUIC 会按实际大小运行。Linux 上可用 `sysctl net.core.rmem_max net.core.wmem_max` 查看内核上限。使用 gVisor 等虚拟套接字时，也可能看到 `connection doesn't allow setting of receive buffer size`。诊断测试失败时，先定位 `--- FAIL` 对应的断言。[quic-go 缓冲区说明](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)

## 按问题选择测试

| 现象 | 从哪里开始 |
| --- | --- |
| 有端点但连不上 | 用 `TestTCPFallbackOnInitialDial` 检查 UDP 黑洞后的 TCP 回退，用 `TestOutboundEndpointPolicyWithRelay` 核对出站策略和中继路径。[传输回退](../mesh_test.go) · [端点拨号](../dial_test.go) |
| 共享端口集中接入时拒连或丢包 | `TestSharedListenersInboundHandshakes` 检查 TCP 与 QUIC 共用名额时的拒绝计数和后续重连。`TestUDPBranchCloseWithBacklog` 检查分支满时的报文保留顺序、关闭时释放积压，以及另一分支的收发。[节点接入](../portshare_test.go) · [分支收发](../portshare/raw_test.go) |
| 大量邻居探活滞后或 TCP 路径翻倍 | `TestMaintenanceProbesWholeHub` 验证四个探活名额在同一轮持续处理邻居。`TestInboundTCPCanaryAndExplicitDial` 核对唯一 TCP 候选的后台探测和显式拨号。[邻接测试](../interconnect_test.go) |
| 调长探活间隔后发现记录过期、断线或误摘路径 | `TestSlowProbeRenewsIntroductionAndReconnects` 检查签名介绍提前续期和常驻邻居重连。`TestProbeFailureThresholdAfterRecovery` 在 QUIC 上先恢复短暂丢包，再验证连续失败达到阈值时摘除路径。[探活测试](../interconnect_test.go) |
| 换址或切换地址族后断流 | `TestNATPaths` 和 `TestGatewayLayouts` 覆盖不同的映射、过滤及多层 NAT。`TestChaosMobileHandover` 和 `TestDualUnderlayFamilyFailover` 在既有业务连接上检查回执。[NAT](../e2e/nat_test.go) · [移动换址](../e2e/chaos_test.go) · [双栈切换](../e2e/mesh_test.go) |
| 整形期间切路或建邻失败 | `TestChaosRelayOnlyWhileShaping` 检查在途包和后续包的路径；`TestColdCircuitAcrossSlowHops` 在延迟中继上交付首包。[发送队列](../addressing_test.go) · [中继与邻接](../interconnect_test.go) |
| 撤回中继路径或关闭流时阻塞 | `TestCircuitWithdrawalWhileOpening` 在下游握手停顿时撤回路径，核对拨号返回、名额释放和邻接复用。`TestQUICStreamCloseDuringWrite` 检查关闭流能唤醒阻塞写入，同一连接的其他流仍可读到完整响应和 EOF。[电路生命周期](../circuit_capacity_test.go) · [QUIC 流关闭](../wire_test.go) |
| 查询缺少端点或网关前缀 | `TestAdvertRetainsUsableNATMapping` 检查 NAT 观测的筛选和保留；`TestRefreshIPWithCachedDefault` 比较本轮应答和有效缓存。[地址发现](../lookup_test.go) |
| TLS 密钥交换组不符或无法建链 | `TestTLSAdmissionAndPeerIdentity` 检查无共同组时的握手拒绝，`TestMixedTLSCredentials` 核对 TCP 和 QUIC 两端的协商结果，`TestChaosRelayPartition` 在中继分区恢复前后核对端到端组。[握手准入](../policy_integration_test.go) · [直连](../e2e/mesh_test.go) · [中继恢复](../e2e/chaos_test.go) |
| 握手、换证或撤权异常 | `TestGrantDisclosure` 检查 TCP 和 QUIC 的授权交换。`TestGrantWriteRechecksPolicy` 和 `TestRevalidateDuringGrantWrite` 分别覆盖校验中和写入中提交新策略。`TestNodeAndGrantProof` 验证同钥续证。[握手](../authentication_test.go) · [证书](../pki/boundaries_test.go) |
| 撤权后仍有业务或查询应答 | `TestMemberWithdrawalIsolation` 在三个节点间核对业务回执、主题投递、双向重连及重启后的入口认证。`TestLookupReplyAfterRequesterWithdrawal` 检查下游晚到的有效介绍在转发处停止。`TestRevalidateConcurrentPublication` 覆盖复查与消息准入并发。[端到端隔离](../e2e/chaos_test.go) · [查询](../lookup_test.go) · [主题准入](../policy_integration_test.go) |
| 主地址重复或同一密钥出现多个实例 | `TestInspectAddressClaims` 核对竞争声明。`TestInstanceConflictWhileProbesBusy` 和 `TestInstanceConflictRecovery` 分别覆盖满载时的冲突复核和选定实例后的交付。`TestRelayTCPWithDuplicateInstance` 检查既有 TCP 连接。[实例诊断](../instance_test.go) · [中继长连接](../e2e/addressing_test.go) |
| VIP 或下游地址交付失败 | 任播示例验证排空期间的新旧连接，网关测试核对双栈回包、IPv4 TTL 和 IPv6 Hop Limit。[任播](../examples/anycast/main.go) · [网关](../e2e/forwarding_test.go) · [gVisor 构建](integration.md#gvisor-的-ipv4-网关构建) |
| 协议互通或消息补发异常 | 查看帧的预期字节、共享端口的 mesh 与网站分流，以及消息推送与缓存补取。[线协议](../wire_test.go) · [端口复用](../portshare_test.go) · [主题消息](../publication_test.go) |

## 重放故障

完整运行扩展端到端测试时，先用独占套接字，再用共享端口。`-extended` 启用较长的网络故障场景，`-portshare` 让虚拟节点通过共享分支收发 TCP 和 UDP。

```sh
go test -race -count=1 -timeout=5m ./e2e -args -extended
go test -race -count=1 -timeout=5m ./e2e -args -extended -portshare
```

复现单个问题时，可按拨号、NAT 或中继拓扑选择用例。

```sh
go test -race -count=10 -run '^(TestConnectEndpointSharesDial|TestPeerPolicyChangeDuringDirectDial|TestGroupSendUsesInboundPathWhileWaitingForDialSlot)$' .
go test -race -count=5 -run '^(TestColdCircuitAcrossSlowHops|TestChaosRelayOnlyWhileShaping|TestChaosDefaultExitWithdrawal|TestNeighborDialWhilePublicationsArePaced)$' .
go test -v -count=1 -run '^TestNATPaths$/^(port|destination-specific)$' ./e2e
go test -race -v -count=1 -run '^TestChaos(HiddenTransit|RelayPartition)$' ./e2e -args -extended
```

`TestSeededChaos` 每个种子生成八步故障序列，每步在既有 TCP 连接上核对业务回执。以下命令覆盖定时和手动 CI 使用的十个种子。复现失败时只运行对应的种子，`-v` 会显示步号和动作。[混沌场景](../e2e/chaos_test.go)

```sh
(
  set -e
  for seed in 1 2 3 4 5 6 7 8 9 10; do
    go test -v -count=1 -run '^TestSeededChaos$' ./e2e -args -extended -seed "$seed"
  done
)
```

## 中继容量验收

`TestRelayCapacity` 在两台中继之间建立唯一的物理邻接，常规测试由 8 个源节点连接 9 个目的节点，共 72 条端到端认证电路。以下命令使用 16 个源和 32 个目的，分别在 TCP 和 QUIC 邻接上达到默认的 512 条上限。满载时检查探活、未缓存的 IP 查询和双向 IP 交付，再撤回一台中继的转发权并等待所有节点释放电路。日志中的堆占用是全部 50 个节点同进程运行时一次 GC 后的采样。[容量用例](../circuit_capacity_test.go)

```sh
go test -v -count=1 -run '^TestRelayCapacity$' . -args -full-relay-capacity
```

`TestRelayFairness` 比较两个邻居分别通过八条和一条电路发包时的交付份额。等权用例覆盖 TCP 和 QUIC，加权用例验证 3:1 配置，并在竞争结束后核对独占吞吐。`TestRelaySlowExit` 使一个出口阻塞，核对其他入向或出向邻居的进展及撤权后的资源释放。[公平转发测试](../relay_fairness_test.go)

按需规模测试启用默认维护与探活，连接 208 个源和 4 个服务，共 832 条电路。单骨干和双骨干分别经 TCP、QUIC 运行。接入中继为回程骨干配置权重 8，每个源最多同时提交一个 8 KiB 包。该配置下检查每个源有业务交付、64 次短请求均在期限内完成、原电路持续存活。可追加 `-backbone-weight 1` 对照等权部署，或用 `-relay-flight 8` 测量发送方深积压。日志报告短请求完成数和 p95（含超时样本）、每个源交付字节的分布、意外关闭数、观测到的最大探活间隔和负载期采样的进程堆峰值。堆采样包含整套测试节点。[规模用例](../relay_fairness_test.go)

```sh
go test -v -count=1 -run '^TestRelayScale$' . -args -relay-scale
```

## 性能对照

在同一台机器上用相同的 Go 版本和并行度比较两个工作树。以下基准将准备拓扑或建立会话的时间排除在计时之外。

```sh
go test -run '^$' -bench '^BenchmarkPacketAuthorization$' -benchtime=200ms -benchmem -count=5 -cpu=1 .
go test -run '^$' -bench '^BenchmarkMeshIP$' -benchtime=500x -benchmem -count=5 -cpu=2 .
go test -run '^$' -bench '^BenchmarkPathStatus$' -benchmem .
```

`BenchmarkMeshIP` 分别经独占 UDP、两端共享 UDP 和 TCP 逐包发送 1 KiB 的内层 IPv4 包，每次等对端收到后再发下一个。可比较每包分配次数、字节数以及交付延迟的 p95、p99。`BenchmarkPathStatus` 分别在连接 16 和 128 个 TCP 对端后读取完整路径状态。[基准代码](../mesh_test.go)

`BenchmarkPacketAuthorization` 使用收发双方的公钥 ID、双栈主地址和业务授权，测量内层包的地址检查，分别覆盖成员主地址、VIP、下游地址，以及在 128 名组播订阅者中查找目的成员。比较查询实现时使用相同拓扑和目的成员，再用 `BenchmarkMeshIP` 测量完整收发路径。[地址授权基准](../addressing_test.go)
