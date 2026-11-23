# 在本机连接两个节点

在仓库根目录使用 Go 1.27.3 或更高版本运行以下命令。程序在内存中签发 Alice 和 Bob 的双栈证书，分别绑定 IPv4 回环上的临时 UDP 端口，并在同一进程启动两个节点。

```sh
go run ./examples/quickstart
```

在 `examples` 目录中使用 `go run ./quickstart`，在 `examples/quickstart` 中使用 `go run .`。成功时标准输出为

```text
hello from 10.13.0.2@fd13::2
IPv6 fd13::2 -> fd13::1 (40 bytes)
```

1. Bob 的拓扑成员拥有 `app/demo` 子树的发布权。Alice 订阅完整主题 `app/demo/hello`，Bob 用 Alice 的虚拟 IPv6 地址调用 `ConnectPeer`。
2. Bob 调用 `Publish`。Alice 核对事件 ID、发布者和正文后打印第一行。
3. 两端各打开一个 `IPPort`。Bob 写入完整的 IPv6 包，Alice 收到后核对内容并打印第二行。包头中的 IPv6 地址属于 mesh 成员，承载它的 QUIC 连接使用两个回环 UDP 端点。

业务流程在示例入口中，临时凭据、套接字和 `nebula.New` 的调用在共享准备代码中。[双节点通信](../examples/quickstart/main.go) · [节点创建](../examples/internal/demo/nodes.go)

运行长期服务、跨机器部署或接入自己的 gVisor 栈时，参见接入指南。需要导出证书文件时，按 PKI 指南运行离线签发命令。[应用接入](integration.md) · [签发证书](pki.md#签发证书)
