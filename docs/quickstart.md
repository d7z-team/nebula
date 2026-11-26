# 在本机连接两个节点

在仓库根目录运行以下命令。示例为 Alice 和 Bob 各生成一份节点证书和同钥集群授权，通过 IPv4 回环上的 QUIC 连接传送消息和 IPv6 包。

```sh
go run ./examples/quickstart
```

成功时会看到一条签名主题消息和一个内层 IPv6 包。

```text
hello from <Bob 的 PeerID>
IPv6 fd13::2 -> fd13::1 (40 bytes)
```

Bob 的拓扑条目授予 `app/demo` 子树的发布权。Alice 订阅完整主题 `app/demo/hello`，核对收到的消息 ID、发布者和正文。随后 Bob 通过 `IPPort.WriteIP` 写入一个完整的 IPv6 包，Alice 核对收到的字节。[双节点通信](../examples/quickstart/main.go) · [凭据与节点创建](../examples/demo/nodes.go)

## 使用磁盘凭据启动两个进程

先在仓库根目录按 PKI 指南的命令签发 Alice 和 Bob 的 PEM 文件。以下命令沿用同一 shell 的 `$lab` 临时目录。实际部署时，每台机器只需自己的节点证书、集群授权链、私钥、可信根、固定的集群 CA 和宿主批准的拓扑。[签发证书](pki.md#签发证书) · [示例源码](../examples/peer/main.go)

将以下拓扑保存到凭据目录，并记下输出的目录路径。示例只接受一个完整的拓扑 JSON 对象，遇到未知字段会在绑定端口前报告文件名和字段名。Bob 在启动后按命令行提供的物理 UDP 端点连接 Alice，Alice 通过同一会话发送回执。两端分别拥有请求或回执主题的发布权。

```sh
alice_id=$("$lab/nebula-pki" inspect -fingerprint -in "$lab/alice.pem")
bob_id=$("$lab/nebula-pki" inspect -fingerprint -in "$lab/bob.pem")
cat > "$lab/topology.json" <<JSON
{
  "network": "demo",
  "members": [
    {"id":"$alice_id", "ipv4":"10.13.0.1", "ipv6":"fd13::1", "publishTopics":["app/peer/receipt"]},
    {"id":"$bob_id", "ipv4":"10.13.0.2", "ipv6":"fd13::2", "publishTopics":["app/peer/request"]}
  ]
}
JSON
echo "$lab"
```

在第一个终端从仓库根目录启动 Alice，等待输出 `listening on 127.0.0.1:4242`。

```sh
go run ./examples/peer -listen 127.0.0.1:4242 -peer fd13::2 \
  -root "$lab/root.pem" -cluster-ca "$lab/ca.pem" -cert "$lab/alice.pem" -grant "$lab/alice.grant" \
  -key "$lab/alice.key" -topology "$lab/topology.json"
```

在第二个终端进入同一仓库根目录，将 `lab` 设为前面输出的目录。用 Bob 的凭据接入并查询 Alice 的 IPv6 地址，成功时会输出 `fd13::1 via <Alice 的 PeerID> (fd13::1/128)`。

```sh
go run ./examples/peer -connect 127.0.0.1:4242 -resolve fd13::1 \
  -root "$lab/root.pem" -cluster-ca "$lab/ca.pem" -cert "$lab/bob.pem" -grant "$lab/bob.grant" \
  -key "$lab/bob.key" -topology "$lab/topology.json"
```

随后发送请求并等待回执。

```sh
go run ./examples/peer -connect 127.0.0.1:4242 -peer 10.13.0.1 -send hello \
  -root "$lab/root.pem" -cluster-ca "$lab/ca.pem" -cert "$lab/bob.pem" -grant "$lab/bob.grant" \
  -key "$lab/bob.key" -topology "$lab/topology.json"
```

Alice 输出 `request from <Bob 的 PeerID>: "hello"`。Bob 核对回执的发布者和原请求 ID，输出 `receipt from <Alice 的 PeerID> for …` 后退出。用 Ctrl-C 停止 Alice。请求和回执都可传播给已连接的邻居。示例只处理预期成员签发的消息。

跨机器运行时，将 Alice 的监听地址和 Bob 的 `-connect` 换成实际可达的物理端点，Bob 的 `-listen` 绑定本机相应地址族的接口，`-peer` 填拓扑中对端的 IPv4 或 IPv6 主地址，该地址须与对端的集群授权一致。[应用接入](integration.md)
