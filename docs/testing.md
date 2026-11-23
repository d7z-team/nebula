# 测试与故障重放

从仓库根目录运行。端到端测试在进程内创建独立的 gVisor 主机、网段和 NAT 网关。外层网络承载实际的 QUIC 或 TCP 会话；内层网络通过节点的虚拟网卡收发业务。测试同时检查物理端点、认证路径和业务回执。[虚拟网络](../e2e/network_test.go) · [节点与业务栈](../e2e/mesh_test.go)

## 运行测试

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -race -count=1 -timeout=5m ./e2e -args -extended
```

复查端口受限 NAT 的直连行为，或重放指定混沌种子，可以单独运行相应场景。

```sh
go test -v -count=1 -run '^TestNATPaths$/^port$' ./e2e
go test -v -count=1 -run '^TestSeededChaos$' ./e2e -args -extended -seed 7
```

种子决定八步故障操作的顺序。使用 `-v` 查看每一步的操作、路径和业务回执。排查失败时记录提交号、种子和首次失败步骤。定时与手动 CI 还会在竞态检测下运行固定故障场景，并重放种子 1 至 10。[混沌场景](../e2e/chaos_test.go) · [CI 配置](../.github/workflows/test.yml)

## 按问题选择测试

| 问题 | 测试与观测点 |
| --- | --- |
| NAT 映射或过滤影响直连 | `TestNATCalibration` 核对公网端实际看到的源地址和端口。`TestNATPaths` 检查打洞报文、认证直连，以及目的地相关映射下的中继回退。`TestGatewayLayouts` 覆盖单 NAT、双 NAT、同网段与 NAT 回环。[NAT 测试](../e2e/nat_test.go) |
| 丢包、时延或窄路径 | `TestLossAndNarrowPath` 将外层 UDP 载荷限制为 1200 字节，检查 1280 字节内层 IPv6 包的交付与可靠流回退计数。`TestChaosFailoverAndRenewal` 在同一内层连接上检查切路、换证和恢复。[链路故障测试](../e2e/chaos_test.go) |
| 双栈选路或网关转发 | `TestDualUnderlayFamilyFailover` 切断外层 IPv4 后继续传输内层双栈业务。`TestNodeGVisorForwardingAndDetach` 核对下游源地址、TTL、Hop Limit 及卸载虚拟 NIC 后的 LAN 连接。[外层双栈](../e2e/mesh_test.go) · [网关转发](../e2e/forwarding_test.go) |
| 中继分区、事件补发或关闭积压队列 | 扩展场景切断中继、撤回发布者授权，或在整形与拨号期间关闭节点。分别核对恢复路径、晚加入订阅者收到的事件和关闭后的队列状态。[混沌测试](../e2e/chaos_test.go) |
| 证书签发、热加载或授权期限 | 检查 CSR 公钥审批、双栈 SAN、逐链 CIDR 委派与有效期。会话测试核对握手期间换证前后的实际序列号，事件测试覆盖最大 CMS 对象和分页清单的交付。[签发边界](../pki/boundaries_test.go) · [路径授权](../identity_boundaries_test.go) · [握手与帧](../authentication_test.go) |

NAT 网关由 gVisor 执行转发、SNAT 和 DNAT。测试固定 UDP 公网映射并按已发送的报文记录允许的回包来源，从而分别控制映射与过滤。IPv4 转发测试在 FORWARD 钩子中保留包头引用。使用项目固定依赖构建网关时，参见部署步骤。[IPv4 网关构建](quickstart.md#gvisor-的-ipv4-网关构建)

## 性能对照

在同一台机器上用相同的 Go 版本和并行度比较两个工作树。以下基准从建链后开始计时。

```sh
go test -run '^$' -bench '^BenchmarkMeshIP$' -benchtime=500x -benchmem -count=5 -cpu=2 .
go test -run '^$' -bench '^BenchmarkPeerStatus$' -benchmem .
```

`BenchmarkMeshIP` 经 UDP 和 TCP 逐包发送 1 KiB 的内层 IPv4 包，每次等对端收到后再发下一个。可比较每包分配次数、字节数以及交付延迟的 p95、p99。`BenchmarkPeerStatus` 分别在连接 16 和 128 个 TCP 对端后读取完整路径状态。[基准代码](../mesh_test.go)
