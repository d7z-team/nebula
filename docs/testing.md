# 测试与故障重放

从仓库根目录运行。端到端测试在进程内创建独立的 gVisor 主机、网段和 NAT 网关。外层网络承载实际的 QUIC 或 TCP 会话；内层网络通过节点的虚拟网卡收发业务。测试同时检查物理端点、认证路径和业务回执。[虚拟网络](../e2e/network_test.go) · [节点与业务栈](../e2e/mesh_test.go)

## 运行测试

```sh
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
go test -race -count=1 -timeout=5m ./e2e -args -extended
go test -race -count=1 -timeout=5m ./e2e -args -extended -portshare
```

`-extended` 启用较长的网络故障场景，`-portshare` 让测试节点通过共享分支收发 TCP 和 UDP。常规 CI 在 Linux、macOS 和 Windows 上运行测试及八个自带凭据的示例，Linux 另测竞态、共享端口与打过补丁的 gVisor 网关。磁盘凭据双进程示例的签名回执由 `TestPeerProcesses` 验证。[示例入口](../README.md#examples) · [CI 配置](../.github/workflows/test.yml)

quic-go 的 `failed to sufficiently increase receive buffer size` 表示物理套接字的缓冲区小于期望值，QUIC 会按实际大小运行。Linux 上可用 `sysctl net.core.rmem_max net.core.wmem_max` 查看内核上限。使用 gVisor 等虚拟套接字时，也可能看到 `connection doesn't allow setting of receive buffer size`。诊断测试失败时，先定位 `--- FAIL` 对应的断言。[quic-go 缓冲区说明](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)

## 按问题选择测试

| 现象 | 从哪里开始 |
| --- | --- |
| 有端点但连不上 | 用 `TestTCPFallbackOnInitialDial` 检查 UDP 黑洞后的 TCP 回退，用 `TestOutboundEndpointPolicyWithRelay` 核对出站策略和中继路径。[传输回退](../mesh_test.go) · [端点拨号](../dial_test.go) |
| 换址或切换地址族后断流 | `TestNATPaths` 和 `TestGatewayLayouts` 覆盖不同的映射、过滤及多层 NAT。`TestChaosMobileHandover` 和 `TestDualUnderlayFamilyFailover` 在既有业务连接上检查回执。[NAT](../e2e/nat_test.go) · [移动换址](../e2e/chaos_test.go) · [双栈切换](../e2e/mesh_test.go) |
| 整形期间切路或建邻失败 | `TestChaosRelayOnlyWhileShaping` 检查在途包和后续包的路径；`TestColdCircuitAcrossSlowHops` 在延迟中继上交付首包。[发送队列](../addressing_test.go) · [中继与邻接](../interconnect_test.go) |
| 查询缺少端点或网关前缀 | `TestAdvertRetainsUsableNATMapping` 检查 NAT 观测的筛选和保留；`TestRefreshIPWithCachedDefault` 比较本轮应答和有效缓存。[地址发现](../lookup_test.go) |
| 握手、换证或撤权异常 | `TestGrantDisclosure` 检查 TCP 和 QUIC 的授权交换。`TestGrantWriteRechecksPolicy` 和 `TestRevalidateDuringGrantWrite` 分别覆盖校验中和写入中提交新策略。`TestNodeAndGrantProof` 验证同钥续证。[握手](../authentication_test.go) · [证书](../pki/boundaries_test.go) |
| 撤权后仍有业务或查询应答 | `TestMemberWithdrawalIsolation` 在三个节点间核对业务回执、主题投递、双向重连及重启后的入口认证。`TestLookupReplyAfterRequesterWithdrawal` 检查下游晚到的有效介绍在转发处停止。`TestRevalidateConcurrentPublication` 覆盖复查与消息准入并发。[端到端隔离](../e2e/chaos_test.go) · [查询](../lookup_test.go) · [主题准入](../policy_integration_test.go) |
| 主地址重复或同一密钥出现多个实例 | `TestInspectAddressClaims` 检查竞争声明，`TestRelayTCPWithDuplicateInstance` 检查既有 TCP 连接，`TestInstanceConflictRecovery` 验证选定实例后的交付。[实例诊断](../instance_test.go) · [中继长连接](../e2e/addressing_test.go) |
| VIP 或下游地址交付失败 | 任播示例验证排空期间的新旧连接，网关测试核对双栈回包、IPv4 TTL 和 IPv6 Hop Limit。[任播](../examples/anycast/main.go) · [网关](../e2e/forwarding_test.go) · [gVisor 构建](integration.md#gvisor-的-ipv4-网关构建) |
| 协议互通或消息补发异常 | 查看帧的预期字节、共享端口的 mesh 与网站分流，以及消息推送与缓存补取。[线协议](../wire_test.go) · [端口复用](../portshare_test.go) · [主题消息](../publication_test.go) |

## 重放故障

根包的拨号、队列和中继回归可直接重复运行。端到端 NAT 场景可按映射、过滤类型选择子用例。

```sh
go test -race -count=10 -run '^(TestConnectEndpointSharesDial|TestPeerPolicyChangeDuringDirectDial|TestGroupSendUsesInboundPathWhileWaitingForDialSlot)$' .
go test -race -count=5 -run '^(TestColdCircuitAcrossSlowHops|TestChaosRelayOnlyWhileShaping|TestChaosDefaultExitWithdrawal|TestNeighborDialWhilePublicationsArePaced)$' .
go test -v -count=1 -run '^TestNATPaths$/^(port|destination-specific)$' ./e2e
```

用 `-extended` 启用较长的故障场景。`TestSeededChaos` 用 `-seed` 生成八步故障序列，续签动作按步号单独更新节点证书或集群授权，`-v` 显示操作和业务回执。记录提交号、种子和首次失败步骤，可在同一版本重放操作顺序。定时和手动 CI 会重放种子 1 至 10。[混沌场景](../e2e/chaos_test.go)

```sh
go test -race -v -count=1 -run '^TestChaos(MobileHandover|CanaryAfterNATRebind)$' ./e2e -args -extended
go test -v -count=1 -run '^TestSeededChaos$' ./e2e -args -extended -seed 7
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
