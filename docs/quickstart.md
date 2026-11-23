# 在本机连接两个节点

使用 Go 1.27.3 或更高版本，在仓库根目录打开一个 POSIX shell。示例在本机运行两个节点，Bob 经 IPv4 回环上的 QUIC 连接 Alice，发送 `app/demo/hello` 签名事件和一个 40 字节的 IPv6 包。实验只需要普通 UDP 套接字。[示例源码](../examples/quickstart/main.go)

## 签发证书

以下命令创建临时目录和测试 CA。每个节点各生成一把私钥，证书中同时写入它的虚拟 IPv4、IPv6 和网络名。示例用本机生成的 CSR 指纹作为签发输入。部署时，签发者应通过独立可信的渠道取得获批公钥的 SHA-256 指纹，再传给 `-approved-key`。

```sh
lab=$(mktemp -d)
go build -o "$lab/nebula-pki" ./cmd/nebula-pki
(
  set -eu
  cd "$lab"
  ./nebula-pki keygen -algorithm p256 -out ca.key
  ./nebula-pki root -key ca.key -name "Demo CA" -days 30 -out ca.pem
  n=0
  for name in alice bob; do
    n=$((n + 1))
    ./nebula-pki keygen -out "$name.key"
    ./nebula-pki request -key "$name.key" -name "$name" -out "$name.csr"
    hash=$(./nebula-pki inspect -in "$name.csr" -fingerprint)
    ./nebula-pki issue -ca ca.pem -ca-key ca.key -in "$name.csr" \
      -approved-key "$hash" -network demo -ipv4 "10.13.0.$n" -ipv6 "fd13::$n" -name "$name" -days 7 -out "$name.pem"
    ./nebula-pki verify -in "$name.pem" -network demo -ipv4 "10.13.0.$n" -ipv6 "fd13::$n" -roots ca.pem
  done
)
```

## 运行示例

在同一个 shell 中运行以下命令。

```sh
go run ./examples/quickstart "$lab"
```

Alice 收到的数据会打印为两行。

```text
hello from 10.13.0.2@fd13::2
IPv6 fd13::2 -> fd13::1 (40 bytes)
```

示例先用 `nebula.New`、`Start` 启动节点，再让 Alice 调用 `Subscribe`，让 Bob 调用 `ConnectPeer` 和 `Publish`。Bob 的拓扑成员被授予 `app/demo` 子树的发布权，Alice 按完整主题名订阅。两个节点各通过 `OpenIPPort` 接入数据面。实验结束后可以删除 `$lab` 中的示例程序、私钥和证书。

## 跨机器部署

| 配置 | 填写内容 |
| --- | --- |
| 身份 | 每台机器只加载本机私钥、叶证书和中间 CA 链，`Options.Roots` 装入信任的根证书。 |
| 虚拟地址 | 在 `Topology.Networks` 中声明网段，每个成员在 `Members` 中各占用一个唯一的 IPv4 和 IPv6。地址对和网络名须与证书匹配。调用 `ConnectPeer` 时可传对端的任一虚拟地址。 |
| 物理端点 | 让 `UDP4`、`UDP6` 或 TCP 监听器绑定本机地址和端口。在对应成员的 `Endpoints` 填入对端实际可达的 IP 和端口。经过 NAT 时可填映射后的公网端点，或由本机通过 `AdvertiseEndpoints` 发布。 |
| 自动建链 | 在两个成员的 `Links` 中互填对方的完整 `PeerID`，节点会主动维持该邻接。已有认证邻居可协助发现其他拓扑成员的物理端点。 |

宿主取得新的本机证书后，调用 `ReloadCertificates(ctx, set)` 安装完整凭据。拓扑和访问规则用 `ApplyTopology` 更新。外部吊销数据变化时，先更新 `Options.CheckChain` 读取的数据，再调用 `Revalidate` 复查活动会话和缓存事件。[PKI 接口](pki.md) · [认证与选路](mesh.md)

## 接入原始 IP 或 gVisor

一个节点可打开一个 `IPPort`。直接收发时，用 `WriteIP(netip.Addr{}, packet)` 按目的虚拟地址查找成员；访问下游子网时，用 `WriteIP(gateway, packet)` 指定网关的虚拟地址。返回成功表示包已入队。用 `IPPort.Stats()` 检查收发和丢包计数。接收回调可能并发执行，关闭节点应在回调之外进行。[数据面实现](../ip_port.go)

使用 gVisor 时，由 `nebulagvisor.NewEndpoint` 打开节点的 IP 端口，随后在宿主的 gVisor 栈调用 `CreateNIC`，配置虚拟地址和路由。注册失败时调用 `Endpoint.Close`，成功后通过 `RemoveNIC` 卸载。要转发下游子网流量，签发网关证书时用 `-routes` 批准下游前缀，在对应拓扑成员的 `RoutedPrefixes` 启用该前缀，配置下一跳、回程路由，并在网关的两个 NIC 上启用对应地址族的转发。[双栈网关示例](../e2e/forwarding_test.go)

### gVisor 的 IPv4 网关构建

本项目使用 gVisor 的 `go` 分支。当前固定版本 `83df8eae069e` 在 IPv4 单播转发复制报文后，仍从先前取得的原包头读取 TTL。使用该版本构建 IPv4 转发网关时，可应用仓库补丁，在复制前保存 TTL。在宿主应用的模块根目录执行以下命令，将 `/path/to/gvisor-ipv4-ttl.patch` 换成补丁的实际路径。[上游转发实现](https://github.com/google/gvisor/blob/83df8eae069e6c607672f779f63f3538815cc037/pkg/tcpip/network/ipv4/ipv4.go#L788-L835) · [IPv4 转发补丁](../patches/gvisor-ipv4-ttl.patch)

```sh
go mod vendor
git apply --directory=vendor/gvisor.dev/gvisor /path/to/gvisor-ipv4-ttl.patch
go test -mod=vendor -race ./...
```
