# 直连、中转与链路健康

路径策略按 peer 的 overlay 地址配置。访问下游子网时，gVisor 路由中的网关就是要配置的 peer。[网关转发示例](nebula-nic.md#经网关访问下游子网)

## 选择路径模式

| 模式 | 行为 |
| --- | --- |
| `Auto`（默认） | 初次连接优先尝试直连。业务使用一条活动路径，探测可验证一条备用路径。显式设置 `Relays` 可限制允许的中转。 |
| `DirectOnly` | 握手和业务只走直连。可探测并切换同一 peer 的不同外层地址。 |
| `RelayOnly` | 握手、业务、探测和关闭通知均须经过允许的单跳中转，并停用对该 peer 的直连打洞。可用中转来自显式的 `Relays`，留空时使用发现记录。 |

例如，客户端可以强制通过中转访问网关，并在空闲时每隔约 30 秒检查活动路径。`gateway` 和 `relay` 分别是网关和中转的 overlay 地址。将以下配置传给 `nebula.New`。

```go
opts.Paths.Peers = map[netip.Addr]nebula.PeerPathPolicy{
	gateway: {
		Mode:            nebula.RelayOnly,
		Relays:          []netip.Addr{relay},
		MonitorInterval: 30 * time.Second,
	},
}
```

中转节点设置 `Relay.Serve = true` 并与两端直连。它也可以为自己的连接选择其他中转。端点通过 `Relay.AdvertiseVia` 向 lighthouse 发布可以到达自己的中转。使用纯静态配置时，在两端设置对方的中转名单，并为中转提供静态外层地址。

`Paths.Default` 适用于没有单独配置的 peer。运行中调用 `node.SetPeerPathPolicy(ctx, gateway, &policy)` 替换指定地址的策略，传入 `nil` 撤销该地址的覆盖。更新成功后，新提交给传输的数据报使用新策略。同一证书的多个地址在认证后共享路径，各地址的显式限制取交集。如果没有共同路径，快照显示 `PathBlocked`。首次握手也须强制中转时，为应用可能拨号的每个地址设置策略。

## 手动检查去程与回程

`CheckPeerPath` 发送认证探测并等待回显。传入零值检查当前出口，传入 `TunnelPath{Relay: relay}` 检查指定中转，传入 `TunnelPath{Endpoint: ep}` 检查已知直连地址。

```go
check, err := node.CheckPeerPath(ctx, gateway, nebula.TunnelPath{})
if err != nil {
	return err
}
log.Printf("sent=%v received=%v rtt=%v", check.Sent, check.Received, check.RTT)
```

上游 Nebula 能回显标准的加密 Test 消息。它可以沿另一条路径返回。`Sent` 和 `Received` 分别记录去程和回程，只有 `SamePath` 为真的样本用于比较 RTT 和抖动。探测回显和业务包也可能采用不同路径。

单端收紧策略后，如果本机已有验证成功的中转，却收到违反策略的直连业务包，本机会丢弃该包并沿中转重新握手。需要从发送端约束两个方向的业务时，在两端都配置 `RelayOnly`。

| 检查错误 | 含义 |
| --- | --- |
| `ErrPathPolicy` | 请求路径或探测回程违反本机策略。 |
| `ErrPathTimeout` | 已发出探测，等待期限内未收到认证回显。 |
| `ErrPathChanged` | 检查期间发生了 Rebind、会话退役或相关策略更新，可以重新检查指定路径。 |

## 自动巡检与切换

活跃 peer 的主路约每 10 秒检查一次，备用路径约每 30 秒检查一次。节点共享控制包预算（每秒 100 个，突发 40 个），其中后台探测最多每秒 20 个，突发 10 个。实际间隔随负载和随机错峰变化。普通空闲连接暂停质量巡检。给指定 peer 设置 `MonitorInterval` 可在空闲时继续检查，并在断连后重建。巡检流量单独计量。

- **性能换路**需要备用路径连续三次明显优于主路，且主路已保持至少 30 秒。
- **故障接管**发生在主路连续三次探测超时且备用路径近期验证成功时。故障线路从 30 秒开始退避重试。
- **查看切换原因**时，读取 `node.Peer(addr)` 返回的快照。`PathHealth.Active` 和 `Standby` 包含采样间隔、抖动及近期超时数。`LastCheck` 记录最近探测，`Reason` 记录最近一次选路原因。`LastDataPath` 记录最近一次成功提交的业务包路径。
