# 用于 gVisor 的 Nebula 三层网卡

这是一个可嵌入 Go 应用的 Nebula 模块。`nebulagvisor` 将加密隧道挂载为应用内 gVisor 栈的三层虚拟网卡。Nebula 负责节点发现、证书认证和加密传输，应用管理 IP 地址、路由、转发和 socket。

- 支持 IPv4、IPv6 和跨地址族下一跳。网关可以转发其证书中 `UnsafeNetworks` 授权的下游流量。
- 通过静态地址或 lighthouse 发现节点。每个 peer 可选择自动选路、仅直连或仅中转。自动模式根据认证探测测量的时延、抖动和超时切换路径。
- 默认 UDP 格式与上游 Nebula 互通。可通过 `DatagramTransport` 自定义外层传输，也可通过 `IPPort` 向其他三层设备收发 IP 包。

## 安装

需要 Go 1.27.3 或更高版本。在应用模块根目录克隆仓库，并让 Go 使用这个本地副本。

```sh
git clone --single-branch https://code.d7z.net/d7z-team/nebula.git ../nebula
go mod edit -require=github.com/slackhq/nebula@v0.0.0 -replace=github.com/slackhq/nebula=../nebula
```

已有本地副本时，可将 `-replace` 的目标改为实际路径。在应用中导入 `github.com/slackhq/nebula` 和 `github.com/slackhq/nebula/nebulagvisor` 后运行 `go mod tidy`。使用的 gVisor 版本见 [go.mod](go.mod)。

## 快速开始

直连示例在已有 gVisor 栈上创建网卡，为它分配证书中的 overlay 地址，然后通过隧道拨号到 `10.42.0.254:8080`。首次拨号会触发 Nebula 握手。[完整 TCP 客户端示例](docs/quickstart.md)

| 使用场景 | 指南 |
| --- | --- |
| 从 PEM 加载身份，签发客户端或网关证书 | [证书与信任池](cert/README.md) |
| 通过网关访问下游子网，设置转发和回程 | [网关转发](docs/nebula-nic.md#经网关访问下游子网) |
| 指定中转，检查链路质量和切换原因 | [直连、中转与链路健康](docs/paths.md) |
| 监控端口吞吐量和中转容量 | [节点和流量监控](docs/nebula-nic.md#监控节点和流量) |
| 与上游 UDP 互通，或为节点配置统一标识 | [数据报前缀](docs/nebula-nic.md#自定义-udp-数据报前缀) |
| 接入其他三层设备，或调整发送队列 | [IP 数据端口](docs/nebula-nic.md#接入其他三层设备) · [容量参数](docs/nebula-nic.md#调整节点容量) |
| 刷新节点地址或定位丢包 | [发现与连接](docs/nebula-nic.md#发现与运行时管理) · [排错](docs/nebula-nic.md#排错) |

## 测试

在本仓库根目录运行 `make check` 执行 `go vet` 和全仓测试，运行 `make race` 检查竞态。指定上游 Nebula 可执行文件的绝对路径，可以验证 v1/v2 证书、双向发起握手和两端担任中转的互通组合。

```sh
NEBULA_INTEROP_BINARY=/path/to/upstream/nebula go test . -run '^TestNodeUpstream(Interop|RelayInitiator)$' -count=1
```

<details>
<summary>转发测试、链路消融实验与基准测试</summary>

```sh
# 三端双栈网关转发
go test . -run '^TestNodeGVisorForwardingAndDetach$' -count=1

# 同一轨迹下比较选路策略，并测量重绑后 1,000 个逻辑会话的恢复时间
go test . -run '^(TestPathQualitySelection|TestPathRebindAtScale)$' -v -count=1

# 同一 peer 已有待发查询时，再次请求发现的开销
go test . -run '^$' -bench '^BenchmarkPendingLighthouseQuery$' -benchmem

# 比较默认格式和两字节前缀对 1300 字节数据报的封装开销
go test . -run '^$' -bench '^BenchmarkDatagramFraming$' -benchmem -cpu=1
```

</details>

## 许可证

[MIT License](LICENSE)
