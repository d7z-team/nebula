# 直连、中转与链路健康

路径策略按 peer 的 overlay 地址配置。访问下游子网时，gVisor 路由中的网关就是要配置的 peer。[网关转发示例](nebula-nic.md#经网关访问下游子网)

## 选择路径模式

| 模式 | 行为 |
| --- | --- |
| `Auto`（默认） | 初次连接优先尝试直连。业务使用一条活动路径，探测可验证一条备用路径。显式设置 `Relays` 可限制允许的中转。 |
| `DirectOnly` | 握手和业务只走直连。可探测并切换同一 peer 的不同外层地址。 |
| `RelayOnly` | 握手、业务、探测和关闭通知均须经过允许的中转，并停用对该 peer 的直连打洞。可用中转来自显式的 `Relays`，留空时使用发现记录。 |

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

标准单跳中转节点设置 `Relay.Serve = true` 并与两端直连。它也可以为自己的连接选择其他中转。端点通过 `Relay.AdvertiseVia` 向 lighthouse 发布可以到达自己的中转。使用纯静态配置时，在两端设置对方的中转名单，并为中转提供静态外层地址。启用受管控制服务后，也可以在签名拓扑上通过多个网关转发。[多跳部署与整形](control.md)

`node.SetPeerPathPolicy(ctx, gateway, &policy)` 替换指定地址的策略，传入 `nil` 撤销该地址的覆盖。更新成功后，新提交给传输的数据报使用新策略。

- 拨号前用 `policy, ok := node.PeerPathPolicy(gateway)` 查询该地址的显式策略。显式设置为 `Auto` 时也返回 `true`，返回的中转列表可由调用方修改。`ok` 为 `false` 表示该地址没有覆盖，节点默认策略见 `node.Discovery().DefaultPathPolicy`。
- 认证后用 `node.Peer(gateway)` 返回的快照查看 `PathHealth.Policy`。同一证书的多个地址共享路径，各地址的显式限制取交集。要让首次握手也强制中转，为应用可能拨号的每个地址设置策略。

受管节点还会把本地策略与当前签名拓扑取交集。例如，受限叶节点与签名 `links` 中的网关直连，访问远端 peer 则须经获准的中转。给远端配置本地 `DirectOnly` 会得到 `PathBlocked`。它是有效策略的诊断结果，可配置的模式为表中的三种。[成员与拓扑配置](control.md#签发配置)

## 手动检查去程与回程

`node.CheckPeerPath(ctx, peer, path)` 向指定路径发送认证探测并等待回显。

| 要检查的路径 | `path` |
| --- | --- |
| 当前业务出口 | `nebula.TunnelPath{}` |
| 已知 UDP 直连端点 | `nebula.TunnelPath{Endpoint: ep}` |
| 指定第一跳 | `nebula.TunnelPath{Relay: relay}` |
| 指定一条已建立的多跳路线 | `nebula.TunnelPath{Relay: relay, Circuit: id}`。可直接传入该 peer 的 `PathHealth.Active.Path` 或 `Standby.Path`。完整路线见本机 `ControlStatus().Circuits` 中的同一 ID。 |

```go
check, err := node.CheckPeerPath(ctx, gateway, nebula.TunnelPath{})
if err != nil {
	return err
}
log.Printf("sent=%v received=%v rtt=%v", check.Sent, check.Received, check.RTT)
```

上游 Nebula 能回显标准的加密 Test 消息。`Sent` 和 `Received` 分别记录本机发送和收到回显的路径，只有 `SamePath` 为真的样本参与 RTT 和抖动比较。两条多跳路线可使用同一第一跳和 UDP 端点，`Circuit` 区分具体路线。重建后应从新快照取 ID。`LastDataPath` 记录本机最近一次成功提交的 IP 包，包含受管服务的隧道内 UDP 流量。

单端收紧策略后，如果本机已有验证成功的中转，却收到违反策略的直连业务包，本机会丢弃该包并沿中转重新握手。需要从发送端约束两个方向的业务时，在两端都配置 `RelayOnly`。

| 检查错误 | 含义 |
| --- | --- |
| `ErrPathPolicy` | 请求路径或探测回程违反本机策略。 |
| `ErrPathTimeout` | 已发出探测，等待期限内未收到认证回显。 |
| `ErrPathChanged` | 检查期间发生了 Rebind、会话退役或相关策略更新，可以重新检查指定路径。 |
| `ErrPeerUnavailable` | peer 或指定路径不可用，或在 `CheckTimeout` 内未取得路径检查结果。 |

## 自动巡检与切换

活跃 peer 定期采样主路和备路，实际间隔随节点共享预算和随机错峰变化。普通空闲连接暂停巡检。给指定 peer 设置 `MonitorInterval` 可在空闲时继续检查，并在断连后重建。

- **性能换路**默认需要备用路径连续三次明显优于主路，且主路已保持至少 30 秒。
- **故障接管**默认发生在主路连续三次探测超时且备用路径近期验证成功时。故障线路从 30 秒开始退避重试。
- **查看切换原因**时，读取 peer 快照的 `PathHealth.Reason` 和 `PathHealth.LastCheck`。用 `PathHealth.Active`、`PathHealth.Standby` 对比主备路径的采样间隔、抖动和近期超时数。

## 调整探测与选路

在 `nebula.New` 前设置 `opts.Paths.Probes` 和 `opts.Paths.Selection`。下面的配置将主路采样周期改为 5 秒，并在主路连续两次超时后允许近期验证成功的备路接管。

```go
opts.Paths.Probes.ActiveInterval = 5 * time.Second
opts.Paths.Selection.FailureThreshold = 2
```

| `Paths.Probes` 字段 | 默认值 | 用途 |
| --- | --- | --- |
| `ActiveInterval`、`StandbyInterval`、`IdleTimeout` | 10 秒、30 秒、1 分钟 | 活跃连接的主备采样周期和进入空闲状态的时间。空闲时设置了 `MonitorInterval` 的 peer 使用该周期，备路约为其三倍。 |
| `TickInterval`、`SweepInterval` | 125 毫秒、10 秒 | 调度时钟精度，以及清理半开中转和检查需重连 peer 的周期。 |
| `InitialTimeout`、`MinTimeout`、`MaxTimeout` | 1 秒、300 毫秒、5 秒 | 首次探测的回显等待时间和自适应等待时间的上下界，首次等待也受上下界约束。 |
| `CheckTimeout` | 10 秒 | 连接建立后，手动 `CheckPeerPath` 等待路径和探测结果的期限。调用方仍可用 context 提前结束等待。 |
| `ControlBudget`、`ProbeBudget` | 突发 40、每 10 毫秒补 1 个；突发 10、每 50 毫秒补 1 个 | 使用 `nebula.PacketBudget{Burst: ..., Every: ...}` 配置。定期采样和手动 `CheckPeerPath` 共用探测预算，发送时还受控制包总预算约束。中转邻接故障复核只使用控制包预算。 |

| `Paths.Selection` 字段 | 默认值 | 用途 |
| --- | --- | --- |
| `FailureThreshold`、`RetryInterval` | 3 次、250 毫秒 | 主路连续超时达到阈值时触发故障处理，未达阈值时提前重试。 |
| `SwitchThreshold`、`HoldTime` | 3 次、30 秒 | 性能换路所需的连续优势次数与同路往返样本数，以及主路的最短保持时间。 |
| `Freshness`、`MeasurementTTL` | 45 秒、90 秒 | 备路接管或主路对比所用样本的有效期，以及 RTT 估计器的重置间隔。 |
| `SampleWindow` | 16 次 | 近期超时统计窗口，可设 1 至 64。 |
| `MinImprovement`、`ImprovementPercent` | 15 毫秒、20% | 与主路评分比较，绝对改善量与相对改善量取较大者作为换路门槛。 |
| `JitterThreshold`、`JitterPercent` | 15 毫秒、20% | 对比绝对抖动和相对于平滑 RTT 的阈值，取较大者判定抖动降级。 |
| `MinBackoff`、`MaxBackoff`、`RecoveryInterval` | 30 秒、5 分钟、30 秒 | 故障线路的初始和最大退避时间，以及恢复握手的最小间隔。 |

零值或负值采用默认值。超时和退避的下界须小于或等于上界，百分比按整数填写（例如 `20` 表示 20%），最大为 100。节点创建时会检查这些约束。
