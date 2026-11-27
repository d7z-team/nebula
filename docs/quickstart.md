# 在本机连接两个节点

在仓库根目录运行以下命令。示例为 Alice 和 Bob 各生成一份节点证书和同钥集群授权，通过 IPv4 回环上的 QUIC 连接传送 IPv6 包。

```sh
go run ./examples/quickstart
```

Bob 按 Alice 的 `PeerID` 预连接并确认首选路径为 UDP 直连。首行显示 Go 实际协商的密钥交换组。运行 `go run ./examples/quickstart -hybrid` 时，两端都要求 `X25519MLKEM768`，输出如下。[预连接用法](integration.md#在首个业务包前预连接)

```text
connected to Alice over udp with X25519MLKEM768
IPv6 fd13::2 -> fd13::1 (40 bytes)
```

Bob 在自己的 IP 端口上调用 `tx.WriteIP(nebula.PeerID{}, packet)`，由节点根据包的目的地址 `fd13::1` 选择 Alice。Alice 通过 `Deliver` 收到整包并核对字节。[双节点通信](../examples/quickstart/main.go) · [凭据与节点创建](../examples/demo/nodes.go)

## 使用磁盘凭据启动两个进程

在仓库根目录按 PKI 指南签发 Alice 和 Bob 的 PEM 文件，保留同一终端的 `$lab` 变量。两个进程共用可信根、固定的集群 CA 和拓扑，各自加载自己的私钥、节点证书及集群授权。[签发证书](pki.md#签发证书) · [示例源码](../examples/peer/main.go)

编译示例并进入凭据目录。拓扑用节点公钥指纹标识成员，并列出各自的双栈主地址。记下 `pwd` 输出的目录，第二个终端会用到。

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
    {"id":"$alice_id", "ipv4":"10.13.0.1", "ipv6":"fd13::1"},
    {"id":"$bob_id", "ipv4":"10.13.0.2", "ipv6":"fd13::2"}
  ]
}
JSON
```

在这个目录启动 Alice，等待输出 `listening on 127.0.0.1:4242`。程序默认从当前目录读取 `root.pem`、`ca.pem` 和 `topology.json`。

```sh
./peer -listen 127.0.0.1:4242 -cert alice.pem -grant alice.grant -key alice.key
```

在第二个终端进入同一凭据目录。`-connect` 指定 Alice 的物理 UDP 端点，`-resolve` 指定要查询的虚拟地址。两者一起使用时，Bob 先完成握手，再输出 `fd13::1 via <Alice 的 PeerID> (fd13::1/128)` 并退出。仅使用 `-connect` 可以核对端点的认证身份。

```sh
./peer -connect 127.0.0.1:4242 -resolve fd13::1 -cert bob.pem -grant bob.grant -key bob.key
```

跨机器运行时，将 Alice 的监听地址和 Bob 的 `-connect` 换成实际可达的物理端点，Bob 的 `-listen` 绑定本机相应地址族的接口。用 Ctrl-C 停止 Alice。[应用接入](integration.md)
