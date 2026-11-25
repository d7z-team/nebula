# 与网站共享 TCP 和 UDP 端口

同一进程可以在同一地址的 TCP/443 上接收 HTTPS 和 mesh TLS，在 UDP/443 上接收 HTTP/3 和 mesh QUIC。宿主各绑定一次物理端口，将两个 `Mesh()` 分支交给节点，把 `Other()` 交给原有服务。网站仍可按 SNI 选证书、按 HTTP Host 或 `:authority` 路由到多个站点。[可运行示例](../examples/portshare/main.go)

```sh
go run ./examples/portshare
# 本机的两个 443 端口可绑定时
go run ./examples/portshare -port 443
```

示例先完成 mesh 对端认证，再分别从两个虚拟主机取回 HTTP/2 和 HTTP/3 响应，并核对响应协议和正文。

## 接入与关闭

以下代码假定宿主已在同一地址和端口绑定 `listener`、`socket`，并准备好节点的 `opts`、网站证书和处理器。

```go
tcp := portshare.NewTCP(listener)
udp := portshare.NewUDP(socket)
defer tcp.Close()
defer udp.Close()

opts.Transport.TCP4, opts.Transport.UDP4 = tcp.Mesh(), udp.Mesh()
node, err := nebula.New(ctx, opts)
if err != nil {
    return err
}
defer node.Close()
if err := node.Start(); err != nil {
    return err
}

https := &http.Server{Handler: sites, TLSConfig: websiteTLS.Clone()}
h3 := &http3.Server{Handler: sites, TLSConfig: websiteTLS.Clone()}
defer https.Close()
defer h3.Close()
serveErr := make(chan error, 2)
go func() { serveErr <- https.ServeTLS(tcp.Other(), "", "") }()
go func() { serveErr <- h3.Serve(udp.Other()) }()
select {
case err := <-serveErr:
    return err
case <-ctx.Done():
    return ctx.Err()
}
```

- 物理 TCP 监听遇到暂时性错误时退避重试。TCP 监听或 UDP 读取循环因错误退出时，两个仍打开的分支都会报告该错误。主动关闭的分支返回 `net.ErrClosed`。
- TCP 和 UDP 可以分别启用。双栈部署为每个物理地址族分别创建分流器，IPv6 分支传给 `TCP6`、`UDP6`。将可达的公网地址和端口按通常方式放入拓扑端点或签名通告。
- `udp.Mesh()` 返回公开的 `meshwire.SharedSocket`，可以直接传入节点的 UDP 选项。宿主若只需统计 mesh 流量，可以在包装类型中嵌入该接口并覆盖 `ReadFrom` 或 `WriteTo`。节点会通过包装后的套接字调用 `ConfigureMeshQUIC`。统计整个物理端口的流量时，在调用 `NewUDP` 前包装原始套接字。[接口定义](../meshwire/transport.go)
- 分流器接管传入的物理套接字。关闭某个逻辑分支只结束该分支的监听或数据报 I/O，另一分支可以继续工作。已经交出的 TCP 连接由接收方关闭。每个逻辑 UDP 分支有独立的读写截止时间；节点关闭时为 QUIC 的最后一次写入留出最多一个 `DialTimeout`。整个服务退出时先关闭节点和网站，再关闭分流器以释放物理端口。[TCP 实现](../portshare/tcp.go) · [UDP 分支](../portshare/packet_conn.go)

## 数据归属

宿主自行创建 mesh QUIC transport 时，可直接在监听或拨号前调用配置方法。它设置 `transport.ConnectionIDGenerator` 和 `config.Tracer`，供分流器识别连接 ID 和无状态复位。监听和拨号使用同一份 QUIC 配置，TLS 的 `NextProtos` 使用 `[]string{meshwire.ALPN}`。使用 `nebula.Node` 时这些设置由节点完成。

```go
socket := udp.Mesh()
transport := &quic.Transport{Conn: socket}
config := &quic.Config{Versions: []quic.Version{quic.Version1}, EnableDatagrams: true}
socket.ConfigureMeshQUIC(transport, config)
```

| 到达的流量 | 处理 |
| --- | --- |
| TCP 客户端发来 TLS ClientHello | 跨 TLS record 读取首个 ClientHello。ALPN 列表恰为单项 `nebula-mesh` 时交给 mesh。其他列表、缺少 ALPN 和可识别的明文交给宿主。接收方读取从第一个字节开始的原始流，保留连接地址并自行握手。 |
| 新 QUIC v1 客户端 Initial | 用 RFC 9001 的公开 Initial 密钥提取 CRYPTO 帧，按源地址及初始目标 CID 重组乱序或重传的 ClientHello，按同一 ALPN 规则选分支。按抵达顺序重放暂存的完整原始数据报及源地址，包括同一报内合并的 QUIC 包。 |
| 已知 mesh CID 或活动复位 token | 直接投递 mesh 分支。带有本机密钥校验标记的随机 CID 用于识别轮换、Retry 及迁移后的包。quic-go 的公开连接事件在内存中登记对端提供并已使用的复位 token，连接结束时清理。最终的包解密、复位验证与握手认证均由接收方完成。 |
| 单字节 UDP 数据报 `00` | 保留给 mesh 单向 NAT 打洞。入站时消费，发送仍从同一物理套接字出站。 |
| 其他 UDP 流量 | 交给 `Other()`，包括普通数据报、HTTP/3 的 QUIC v2 和宿主自己连接的后续数据报。零长度数据报也保留边界和源地址。 |

分流只决定由谁读取，节点仍执行原有的双向 TLS、成员和逐包路径校验。即使网站与 mesh 客户端使用完全相同的 UDP 源和目标端口，切换 `RelayOnly`、`Blocked` 或拓扑邻接限制也只约束 mesh 流量。宿主可以给网站配置独立的 TLS、QUIC 版本和客户端认证。[同源策略与三站点测试](../portshare_test.go) · [TLS ALPN](https://www.rfc-editor.org/rfc/rfc7301) · [QUIC Initial 保护](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)

## 容量和部署边界

TCP 分流适用于客户端先发数据的服务。每个 TCP 监听器最多同时等待 128 个连接，分类及交给分支的时限为 2 秒。TCP 和 UDP 都接受最多 64 KiB 的 ClientHello；TCP 预留额外 4 KiB 容纳 TLS record 封装。每个 UDP 套接字同时暂存最多 128 个待识别握手，每个最多保留 48 个数据报、96 KiB 的原始数据。待识别状态在 2 秒后过期，已分类的初始 CID 归属最多缓存 4096 条、各 5 秒。每个 UDP 分支独立排队 128 个数据报。超限、超时或分支排满会关闭待分类的 TCP 连接或丢弃对应的 UDP 数据报；QUIC 的可靠数据由端点重传。

UDP 分支提供标准 `net.PacketConn` 的载荷、报文边界和源地址接口。内核收发缓冲区在物理套接字上设置。需要按入站目的 IP 选择回包源地址的多地址主机，应分别绑定相应的本地 IP；通配绑定的逐包目的地址、ECN 和批量收发等辅助信息不经逻辑接口传递。共享模式还需复制数据报、校验 CID 并处理 QUIC 连接事件，可按测试指南在目标环境测量。[性能对照](testing.md#性能对照) · [QUIC CID 和复位](https://www.rfc-editor.org/rfc/rfc9000#section-10.3)
