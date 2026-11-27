# 仓库约定

Nebula 是嵌入 Go 应用的三层网络库。节点负责认证、发现、选路与数据传输。宿主应用提供拓扑和信任策略，通过库的 API 与钩子应用变更。[接入指南](docs/integration.md)

## 开发约定

- 节点行为和 IP 收发在根包 `nebula`。与宿主服务共用监听端口时，`portshare` 负责分流，`meshwire` 定义共享套接字接口。gVisor 网络栈的适配放在 `nebulagvisor`。
- TLS 使用节点证书认证身份，握手后另行验证集群授权。证书签发与解析在 `pki`，离线命令在 `cmd/nebula-pki`。修改握手或授权交换时，对照[协议说明](docs/mesh.md)。
- Go 注释（含 Go doc）和 `README.md` 使用英文，其余项目文档使用中文。
- 公开 API 的用法变更时，同步更新对应指南和 `examples/` 下的示例，并运行受影响的示例。[示例入口](README.md#examples)

## 验证

- 从仓库根目录运行 `make fmt`、`make lint` 和 `make check`。涉及并发、节点生命周期或网络收发路径时，加跑 `make race`。
- 改动 NAT 穿透、中继或共享端口时，从 `e2e/` 选择对应场景。故障种子重放见[测试指南](docs/testing.md)，gVisor 网关的补丁验证见 [CI 的 gateway 作业](.github/workflows/test.yml)。
