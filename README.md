# Nebula 三层网卡

将 Nebula 加密隧道作为三层网卡接入已有的 gVisor TCP/IP 栈。Nebula 负责节点认证、握手和加密传输，应用通过 gVisor 管理 IP 地址、路由、转发和 socket。

## 主要功能

- 支持 IPv4、IPv6 和跨地址族下一跳。网关可转发其证书中 `UnsafeNetworks` 授权的下游流量。
- 通过静态地址或 lighthouse 查找 peer，支持 UDP 打洞与 relay 中继。
- `DatagramTransport` 可替换外层传输，`IPPort` 可对接其他三层设备。

## 安装

需要 Go 1.27.3 或更高版本。假设本仓库检出在应用模块旁的 `../nebula`，在应用模块中运行以下命令。

```sh
go mod edit -require=github.com/slackhq/nebula@v0.0.0 -replace=github.com/slackhq/nebula=../nebula
```

在代码中导入 `github.com/slackhq/nebula` 和 `github.com/slackhq/nebula/nebulagvisor`，然后运行 `go mod tidy`。已有 gVisor 依赖的项目可用 `go list -m gvisor.dev/gvisor` 核对版本。[模块依赖](go.mod)

## 快速开始

用本机证书、受信 CA 池和 UDP 传输创建 `node` 后，将端点挂载到已有的 `s *stack.Stack`。其中 `nic` 是应用选取的空闲 NIC ID。

```go
ep, err := nebulagvisor.NewEndpoint(node, nebulagvisor.Options{})
if err != nil {
	return err
}
if e := s.CreateNIC(nic, ep); e != nil {
	ep.Close()
	return fmt.Errorf("create NIC: %s", e)
}
defer s.RemoveNIC(nic)
```

给 NIC 分配证书中的 overlay 地址，添加路由并调用 `node.Start()`。随后即可通过 `gonet.DialContextTCP` 拨号，首个发往 peer 的包会触发握手。[完整 TCP 连接示例](docs/quickstart.md)

## 文档

- [证书与信任池](cert/README.md) — 加载已有 PEM，签发客户端与网关身份。
- [网关转发与网卡管理](docs/nebula-nic.md) — 配置 unsafe route、下游回程和 relay，管理网卡与队列。
- [连接与丢包排查](docs/nebula-nic.md#排错) — 检查候选地址、实际传输路径和端口拒绝原因。

## 测试

```sh
make check  # go vet 和全仓测试
make race   # 竞态检测
```

单独运行三端双栈转发测试，或指定上游 Nebula 可执行文件验证握手与 ICMP 互通。

```sh
go test . -run '^TestNodeGVisorForwardingAndDetach$' -count=1
NEBULA_INTEROP_BINARY=/path/to/upstream/nebula go test . -run '^TestNodeUpstreamInterop$' -count=1
```

## 许可证

[MIT License](LICENSE)
