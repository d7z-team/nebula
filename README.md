# Nebula 三层网卡

将 Nebula 加密隧道挂载为 gVisor 的三层网卡。Nebula 负责节点发现、证书认证和加密传输，应用在自己的 gVisor 栈中管理 IP 地址、路由、转发和 socket。

- 支持 IPv4、IPv6 和跨地址族下一跳。网关可以转发其证书中 `UnsafeNetworks` 授权的下游流量。
- 通过静态地址或 lighthouse 发现节点。每个 peer 可选择自动选路、仅直连或仅中转。自动模式根据认证探测测量的时延、抖动和超时切换路径。
- 使用 `DatagramTransport` 接入自定义外层传输，使用 `IPPort` 接入其他三层设备。

## 安装

需要 Go 1.27.3 或更高版本。在应用模块根目录执行以下命令，将库检出到相邻的 `../nebula` 目录。已有该分支的本地副本时，直接使用其路径设置 `-replace`。

```sh
git clone --branch tools --single-branch https://code.d7z.net/d7z-team/nebula.git ../nebula
go mod edit -require=github.com/slackhq/nebula@v0.0.0 -replace=github.com/slackhq/nebula=../nebula
```

在应用中导入 `github.com/slackhq/nebula` 和 `github.com/slackhq/nebula/nebulagvisor` 后运行 `go mod tidy`。该分支使用的 gVisor 版本见 [go.mod](go.mod)。

## 快速开始

用本机身份、CA 池和 UDP 传输创建 `nebula.Node`。用 `nebulagvisor.NewEndpoint` 取得端点，通过 `s.CreateNIC` 将其挂载到已有的 gVisor 栈。给 NIC 分配证书中的 overlay 地址，添加直达路由并调用 `node.Start()`。第一次向 peer 拨号会触发握手。[完整 TCP 客户端示例](docs/quickstart.md)

| 使用场景 | 指南 |
| --- | --- |
| 从 PEM 加载身份，签发客户端或网关证书 | [证书与信任池](cert/README.md) |
| 通过网关访问下游子网，设置转发和回程 | [网关转发](docs/nebula-nic.md#经网关访问下游子网) |
| 指定中转，检查链路质量和切换原因 | [直连、中转与链路健康](docs/paths.md) |
| 管理网卡、刷新节点地址、定位丢包 | [网卡与端口](docs/nebula-nic.md#网卡与端口生命周期) · [发现与连接](docs/nebula-nic.md#发现与运行时管理) · [排错](docs/nebula-nic.md#排错) |

## 测试

在本仓库根目录运行 `make check` 执行 `go vet` 和全仓测试，运行 `make race` 检查竞态。指定上游 Nebula 可执行文件的绝对路径，可以验证 v1/v2 证书、双向发起握手和两端担任中转的互通组合。

```sh
NEBULA_INTEROP_BINARY=/path/to/upstream/nebula go test . -run '^TestNodeUpstream(Interop|RelayInitiator)$' -count=1
```

<details>
<summary>转发测试、链路消融实验与发现查询基准</summary>

```sh
# 三端双栈网关转发
go test . -run '^TestNodeGVisorForwardingAndDetach$' -count=1

# 同一轨迹下比较选路策略，并测量重绑后 1,000 个逻辑会话的恢复时间
go test . -run '^(TestPathQualitySelection|TestPathRebindAtScale)$' -v -count=1

# 同一 peer 已有待发查询时，再次请求发现的开销
go test . -run '^$' -bench '^BenchmarkPendingLighthouseQuery$' -benchmem
```

</details>

## 许可证

[MIT License](LICENSE)
