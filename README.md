## Nebula Fork

> 这是 Nebula 的 Fork 项目 做自用用途

本分支是一个仅供 Go 程序嵌入的 Nebula 节点库。它保留 Nebula 的证书、Noise
握手、lighthouse、NAT punch、relay 和 wire protocol，数据面则使用 gVisor
userspace netstack。它不会创建 TUN/TAP/Wintun、修改系统路由、扫描网卡或自行
绑定宿主端口，也不提供 CLI、YAML 配置、ctl/local API、DNS、SSH、metrics、
端口转发或 firewall policy。

## 创建节点

应用负责创建外层数据报传输。普通 UDP socket 可直接通过 `WrapPacketConn`
注入；测试、移动端或已有网络框架也可以实现最小的 `DatagramTransport` 接口。

```go
packetConn, err := net.ListenPacket("udp", ":4242")
if err != nil {
	return err
}

hostCertificate, _, err := cert.UnmarshalCertificateFromPEM(hostCertificatePEM)
if err != nil {
	return err
}
hostKey, _, _, err := cert.UnmarshalPrivateKeyFromPEM(hostKeyPEM)
if err != nil {
	return err
}
caPool, err := cert.NewCAPoolFromPEM(caPEM)
if err != nil {
	return err
}

node, err := nebula.New(ctx, nebula.Options{
	Identities: []nebula.Identity{{
		Certificate: hostCertificate,
		PrivateKey:  hostKey,
	}},
	CAPool:    caPool,
	Transport: nebula.WrapPacketConn(packetConn),
	Lighthouse: nebula.LighthouseOptions{
		StaticHosts: map[netip.Addr][]netip.AddrPort{
			netip.MustParseAddr("10.42.0.1"): {
				netip.MustParseAddrPort("203.0.113.10:4242"),
			},
		},
	},
})
if err != nil {
	return err
}
if err := node.Start(); err != nil {
	return err
}
defer func() {
	_ = node.Close()
	_ = node.Wait()
}()
```

`Node` 在构造成功后拥有 transport，并在关闭时关闭它以中断读取。transport
的 `Close` 必须能中断 `ReadFrom`。`Close` 可重复调用，`Wait` 等待全部内部 worker；
transport 发生 fatal read error 时，`Wait` 返回原始错误。实现了
`RebindableTransport` 的传输可通过 `Node.Rebind` 切换底层网络并触发
lighthouse update 和 punch。

## 进程内管理 API

公共管理能力是 `Node` 上的 typed Go API：`Snapshot` 和 `Err` 查询节点生命周期、
地址、证书、transport 与 fatal error；`Peers` 和 `Peer` 查询握手中或已建立的
peer；`Discovery` 和 `PeerDiscovery` 查询 lighthouse、advertised endpoint、relay
及 peer discovery 状态。所有查询结果都是与内部状态脱离的深拷贝，可由调用方安全
保留或修改；节点关闭后查询返回关闭前最后观测到的状态，不表示连接仍然可用。

`ConnectPeer` 主动建立并等待 peer tunnel；`DisconnectPeer` 和 `DisconnectAll`
取消握手并关闭选定 tunnel；`RefreshPeer` 主动发起 lighthouse 查询；
`AdvertiseNow` 重新读取动态 endpoint 并发送 lighthouse update；`Rebind` 切换支持
rebind 的 transport 后重新广播 endpoint。这些会改变状态或产生网络流量的方法要求
节点已通过 `Start` 运行，并支持相应的 `context.Context` 取消语义。

本节点是 lighthouse、目标就是 lighthouse，或没有配置 lighthouse 时，相应的
`RefreshPeer`/`AdvertiseNow` 是成功的 no-op。`EndpointProvider` 调用会被串行化，
必须遵守传入的 context，且不能同步回调同一节点的 `AdvertiseNow` 或 `Rebind`。
provider 返回错误时，已配置的固定 endpoint 仍会发送，之后该错误返回给调用方。

管理能力仅供宿主在同一进程内调用，不提供 ctl、HTTP Info API、metrics 或字符串
命令注册表。identity、CA、virtual/unsafe route 和协议参数不支持运行时替换；需要
变更时应关闭旧 `Node` 并用新 `Options` 创建节点。

## TCP、UDP 和 HTTP

`Dial` 和 `DialContext` 支持 `tcp`/`tcp4`/`tcp6` 与
`udp`/`udp4`/`udp6`；`Listen` 仅创建 TCP listener，`ListenPacket` 仅创建 UDP
packet connection。监听地址必须是本节点证书地址、已注册虚拟地址或通配地址；
端口 `0` 会由 gVisor 分配动态端口。`tcp`/`udp` 通配监听使用单个双栈 endpoint，
`tcp6`/`udp6` 通配监听严格限制为 IPv6。地址只接受 IP literal；名称解析由宿主
应用负责。listener 和 connection 的具体 gVisor 类型属于内部实现，公共契约仅为
标准库的 `net.Listener`、`net.PacketConn` 和 `net.Conn`。

```go
listener, err := node.Listen("tcp", "10.42.0.2:8080")
if err != nil {
	return err
}
go http.Serve(listener, handler)

client := &http.Client{Transport: &http.Transport{
	DialContext: node.DialContext,
}}

packetConn, err := node.ListenPacket("udp", ":5353")
```

本库没有端口级 firewall。应用必须决定创建哪些 listener，并在 HTTP、RPC 或
其他应用协议层完成认证和授权。

`LighthouseOptions`、`PunchyOptions` 和 `RelayOptions` 分别控制动态地址发现、
NAT 打洞与中继。静态部署只需 `StaticHosts`；动态部署应配置 lighthouse 的静态
入口，并通过 `AdvertiseEndpoints` 或 `EndpointProvider` 提供宿主实际可达地址。

## 虚拟地址和 unsafe route

虚拟地址可用于在证书 overlay 地址以外监听或作为主动连接的源地址。每个虚拟
地址都必须由本节点每张 identity 的 `UnsafeNetworks` 覆盖。unsafe route 使用
最长前缀匹配，`Via` 必须是本地 overlay 网段内的 Nebula peer 地址。

```go
node, err := nebula.New(ctx, nebula.Options{
	// Identities、CAPool、Transport 等略
	VirtualAddresses: []netip.Addr{
		netip.MustParseAddr("172.30.0.10"),
	},
	UnsafeRoutes: []nebula.Route{{
		Prefix: netip.MustParsePrefix("172.31.0.0/16"),
		Via:    netip.MustParseAddr("10.42.0.254"),
	}},
})

dialer := node.Dialer(nebula.DialerOptions{
	LocalAddr: netip.MustParseAddr("172.30.0.10"),
})
conn, err := dialer.DialContext(ctx, "tcp", "10.42.0.3:443")
```

入站和出站仍强制校验 certificate address、`UnsafeNetworks`、实际 tunnel peer
和配置的 `Via`，并禁止 unsafe route 覆盖 overlay 身份。嵌入式节点只接收以
自身 overlay/virtual address 为目的的数据，不充当收到流量的通用 IP 转发器。

## 证书 API

`cert.CreateCA`、`cert.IssueCertificate`、`cert.GenerateSigningKey` 和
`cert.GenerateKeyAgreementKey` 提供 v1/v2、Curve25519 和 P256 的纯 Go 证书
生成接口。原有 PEM、CA pool、签名验证及私钥加密解密 API 保持可用；FIPS
140-only 模式下默认生成 P256，Curve25519 和 ChaChaPoly 会被明确拒绝。

## 与上游节点互通

与未修改的 Nebula 节点通信时，需要使用相同 CA、可协商的证书版本/curve/
cipher，并通过 UDP `DatagramTransport` 提供双方可达的 underlay endpoint；地址
发现可使用 lighthouse 或 `StaticHosts`。若上游节点作为 unsafe gateway，还必须
在其证书中授权对应 `UnsafeNetworks`，且上游 firewall/路由允许这些流量。反向
访问本库的 virtual address 时，上游需要把该前缀路由到本节点。协议兼容不表示
保留上游的命令行、配置文件、系统网卡或防火墙行为。
