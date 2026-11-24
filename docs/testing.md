# 测试与故障重放

从仓库根目录运行。端到端测试在进程内创建独立的 gVisor 主机、网段和 NAT 网关。外层网络承载实际的 QUIC 或 TCP 会话；内层网络通过节点的虚拟网卡收发业务。测试同时检查物理端点、认证路径和业务回执。[虚拟网络](../e2e/network_test.go) · [节点与业务栈](../e2e/mesh_test.go)

## 运行测试

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -race -count=1 -timeout=5m ./e2e -args -extended
go test -race -count=1 -timeout=5m ./e2e -args -extended -portshare
```

常规 CI 在 Linux、macOS 和 Windows 上运行单元测试和自带凭据的示例。Linux 另以共享端口重跑端到端场景。双进程示例由 `TestPeerProcesses` 使用磁盘凭据验证。[示例入口](../README.md#examples) · [CI 配置](../.github/workflows/test.yml)

quic-go 的 `failed to sufficiently increase receive buffer size` 表示物理套接字的缓冲区小于期望值，QUIC 会按实际大小运行。Linux 上可用 `sysctl net.core.rmem_max net.core.wmem_max` 查看内核上限。使用 gVisor 等虚拟套接字时，也可能看到 `connection doesn't allow setting of receive buffer size`。诊断测试失败时，先定位 `--- FAIL` 对应的断言。[quic-go 缓冲区说明](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)

## 按问题选择测试

| 现象 | 重放入口与判断依据 |
| --- | --- |
| 有端点但连不上 | `TestTCPFallbackOnInitialDial` 模拟 UDP 黑洞，检查 TCP 回退。`TestConnectEndpointRecoveryAfterUDPBlackout` 检查通信恢复后的显式重拨。[传输回退](../mesh_test.go) · [端点重拨](../dial_test.go) |
| 限速后切路或建邻失败 | `TestChaosPathLossWhileShaping` 和 `TestChaosRelayOnlyWhileShaping` 核对在途包的错误、后续包的顺序及实际路径。`TestNeighborDialWhilePublicationsArePaced` 在发布持续等待带宽时新增邻居。[发送队列](../addressing_test.go) · [邻居维护](../interconnect_test.go) |
| 中继首次建链失败 | `TestColdCircuitAcrossSlowHops` 延迟下游两跳，在第一条电路上验收实际 IP 包。`TestRelaySearchContinuesAcrossDials` 检查后续拨号能否继续搜索候选。[中继测试](../interconnect_test.go) |
| NAT、移动换址或双栈切换 | `TestNATPaths` 检查打洞报文和最终认证路径，`TestGatewayLayouts` 覆盖多层 NAT 及回环。`TestChaosMobileHandover` 连续四次更换公网 IPv4 和端口。`TestDualUnderlayFamilyFailover` 切断外层 IPv4，两者都在原有业务连接上核对回执。[NAT 场景](../e2e/nat_test.go) · [移动换址](../e2e/chaos_test.go) · [双栈切换](../e2e/mesh_test.go) |
| 查询结果缺少预期端点或前缀 | `TestAdvertRetainsUsableNATMapping` 核对邻居再次上报后返回的有效端点。`TestGatewayIntroductionBudget` 签发接近尺寸上限的网关介绍，核对路由和可容纳的观测。`TestHiddenIntroduction` 检查会合应答和离线缓存。[发现测试](../lookup_test.go) |
| 地址授权或网关转发异常 | 任播示例检查排空期间新旧连接的去向。网关测试检查下游看到的源地址、IPv4 TTL 和 IPv6 Hop Limit。CI 的 `gateway` 作业另外验证应用 gVisor 转发补丁后的构建。[任播示例](../examples/anycast/main.go) · [组播与任播](../e2e/addressing_test.go) · [网关测试](../e2e/forwarding_test.go) · [网关构建](integration.md#gvisor-的-ipv4-网关构建) |
| 握手、换证或签名失败 | 签发测试覆盖双栈 SAN、委派和有效期。CMS 测试比较不同签名算法的尺寸预检与实际签名。握手测试记录换证前后会话使用的证书序列号。[证书边界](../pki/boundaries_test.go) · [CMS](../pki/pki_test.go) · [握手](../authentication_test.go) |
| 协议互通、端口复用或消息补发异常 | 线协议测试检查帧字节、字段及纳秒精度。共享端口测试验证同一端口的 mesh 和多站点 HTTPS、HTTP/3。主题消息测试核对推送和缓存补取。[线协议](../wire_test.go) · [共享端口](../portshare_test.go) · [主题消息](../publication_test.go) |

## 重放故障

根包的拨号、队列和中继回归可直接重复运行。端到端 NAT 场景可按映射、过滤类型选择子用例。

```sh
go test -race -count=10 -run '^(TestConnectEndpointSharesDial|TestPeerPolicyChangeDuringDirectDial|TestGroupSendUsesInboundPathWhileWaitingForDialSlot)$' .
go test -race -count=5 -run '^(TestColdCircuitAcrossSlowHops|TestChaosRelayOnlyWhileShaping|TestNeighborDialWhilePublicationsArePaced)$' .
go test -v -count=1 -run '^TestNATPaths$/^(port|destination-specific)$' ./e2e
```

端到端测试的 `-extended` 开关启用较长的故障场景或追加故障步骤。`-seed` 指定八步故障序列，`-v` 输出每一步的操作、路径和业务回执。记录提交号、种子和首次失败步骤即可在同一版本重放该序列。定时和手动 CI 会重放种子 1 至 10。[混沌场景](../e2e/chaos_test.go)

```sh
go test -race -v -count=1 -run '^TestChaosMobileHandover$' ./e2e -args -extended
go test -race -v -count=1 -run '^TestChaosCanaryAfterNATRebind$' ./e2e -args -extended
go test -race -v -count=1 -run '^TestChaosHiddenTransit$' ./e2e -args -extended
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

`BenchmarkPacketAuthorization` 测量一次已认证会话对内层包的地址授权，分别覆盖成员主地址、VIP、下游地址，以及在 128 名订阅者中查找最后一名成员。比较查询实现时使用相同拓扑和目的成员，再用 `BenchmarkMeshIP` 测量完整收发路径。[地址授权基准](../addressing_test.go)
