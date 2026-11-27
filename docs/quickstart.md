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

在仓库根目录按 PKI 指南签发 Alice 和 Bob 的 PEM 文件，保留同一终端的 `$lab` 变量。两个进程共用可信根、固定的集群 CA 和拓扑，各自加载自己的私钥、节点证书及集群授权。[签发证书](pki.md#签发证书) · [示例源码](../examples/peer/main.go)

编译示例并进入凭据目录。拓扑用节点公钥指纹标识成员，分别授予 Bob 发布请求、Alice 发布回执的权限。记下 `pwd` 输出的目录，第二个终端会用到。

```sh
go build -o "$lab/peer" ./examples/peer
cd "$lab"
pwd
alice_id=$(./nebula-pki inspect -fingerprint -in alice.pem)
bob_id=$(./nebula-pki inspect -fingerprint -in bob.pem)
cat > topology.json <<JSON
{
  "network": "demo",
  "members": [
    {"id":"$alice_id", "ipv4":"10.13.0.1", "ipv6":"fd13::1", "publishTopics":["app/peer/receipt"]},
    {"id":"$bob_id", "ipv4":"10.13.0.2", "ipv6":"fd13::2", "publishTopics":["app/peer/request"]}
  ]
}
JSON
```

在这个目录启动 Alice，等待输出 `listening on 127.0.0.1:4242`。程序默认从当前目录读取 `root.pem`、`ca.pem` 和 `topology.json`。

```sh
./peer -listen 127.0.0.1:4242 -peer fd13::2 -cert alice.pem -grant alice.grant -key alice.key
```

在第二个终端进入前面输出的凭据目录。用 Bob 的凭据连接 Alice 的物理 UDP 端点，再查询她的虚拟 IPv6 地址。成功时会输出 `fd13::1 via <Alice 的 PeerID> (fd13::1/128)`。

```sh
./peer -connect 127.0.0.1:4242 -resolve fd13::1 -cert bob.pem -grant bob.grant -key bob.key
```

随后发送请求并等待回执。

```sh
./peer -connect 127.0.0.1:4242 -peer 10.13.0.1 -send hello -cert bob.pem -grant bob.grant -key bob.key
```

Alice 输出 `request from <Bob 的 PeerID>: "hello"`。Bob 核对回执的发布者和原请求 ID，输出 `receipt from <Alice 的 PeerID> for …` 后退出。用 Ctrl-C 停止 Alice。请求和回执都可传播给已连接的邻居。示例只处理预期成员签发的消息。

跨机器运行时，将 Alice 的监听地址和 Bob 的 `-connect` 换成实际可达的物理端点，Bob 的 `-listen` 绑定本机相应地址族的接口，`-peer` 填拓扑中对端的 IPv4 或 IPv6 主地址，该地址须与对端的集群授权一致。[应用接入](integration.md)
