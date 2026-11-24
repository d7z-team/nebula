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

业务流程在示例入口中，临时凭据、套接字和 `nebula.New` 的调用在共享准备代码中。[双节点通信](../examples/quickstart/main.go) · [节点创建](../examples/demo/nodes.go)

## 使用磁盘凭据启动两个进程

先在仓库根目录按 PKI 指南的命令签发 Alice 和 Bob 的 PEM 文件。以下命令沿用同一 shell 的 `$lab` 临时目录。实际部署时，每台机器只需自己的叶证书链、私钥、可信根、固定的集群 CA 和宿主批准的拓扑。[签发证书](pki.md#签发证书) · [示例源码](../examples/peer/main.go)

将以下拓扑保存到凭据目录，并记下输出的目录路径。Bob 向 Alice 的物理 UDP 端点建链，Alice 通过同一会话发送回执。两端分别拥有请求或回执主题的发布权。

```sh
cat > "$lab/topology.json" <<'JSON'
{
  "network": "demo",
  "members": [
    {"ipv4":"10.13.0.1", "ipv6":"fd13::1", "topics":["app/peer/receipt"],
     "endpoints":[{"network":"udp","address":"127.0.0.1:4242"}]},
    {"ipv4":"10.13.0.2", "ipv6":"fd13::2", "topics":["app/peer/request"]}
  ]
}
JSON
echo "$lab"
```

在第一个终端从仓库根目录启动 Alice，等待输出 `listening on 127.0.0.1:4242`。

```sh
go run ./examples/peer -listen 127.0.0.1:4242 -peer fd13::2 \
  -roots "$lab/ca.pem" -cluster-ca "$lab/ca.pem" -cert "$lab/alice.pem" \
  -key "$lab/alice.key" -topology "$lab/topology.json"
```

在第二个终端进入同一仓库根目录，将 `lab` 设为前面输出的目录，再运行 Bob。

```sh
go run ./examples/peer -peer 10.13.0.1 -send hello \
  -roots "$lab/ca.pem" -cluster-ca "$lab/ca.pem" -cert "$lab/bob.pem" \
  -key "$lab/bob.key" -topology "$lab/topology.json"
```

Alice 输出 `request from 10.13.0.2@fd13::2: "hello"`。Bob 核对回执的发布者和原请求 ID，输出 `receipt from 10.13.0.1@fd13::1 for …` 后退出。用 Ctrl-C 停止 Alice。这两个主题上的事件可传播给已连接的邻居，示例在业务层按预期发送者筛选请求和回执。

跨机器运行时，将拓扑中 Alice 的端点和她的监听地址换成实际可达的物理地址，`-peer` 仍填对端证书中的任一虚拟主地址。企业根与集群 CA 分开部署时，`-roots` 指向可信根集合，`-cluster-ca` 指向单张集群 CA，`-cert` 按叶证书在前的顺序包含所需中间证书。[应用接入](integration.md)
