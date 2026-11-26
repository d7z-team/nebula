# AGENTS.md

本指南适用于整个仓库。开发环境使用 [go.mod](go.mod) 指定的 Go 版本。

## 代码位置

- 根包 `nebula` 管理节点、路径选择和原始 IP 收发。[handshake.go](handshake.go) 负责 TLS 身份认证和集群授权交换，[session.go](session.go) 负责会话注册与流分派，[publication.go](publication.go) 管理签名主题消息的发布、订阅和补发。
- `portshare/` 负责与宿主服务共享 TCP、UDP 监听端口。`meshwire/` 定义 mesh ALPN 和共享 UDP 套接字接口。[接入示例](examples/portshare/main.go)
- `pki/` 负责 X.509 证书与签名对象，`cmd/nebula-pki/` 提供离线命令行工具。
- `nebulagvisor/` 将节点接入调用方的 gVisor 栈。双栈网关用法见[接入指南](docs/integration.md)。

## 开发约定

- 从仓库根目录运行 `make fmt`，用 gci 整理导入分组、用 gofumpt 格式化 Go 代码。Go 注释、Go doc 和 README 使用英文，其余项目文档使用中文。
- 变更公共 API 时，同步更新调用方、Go doc、相关指南和可运行示例。针对行为变化，优先从公开入口验证。

## 验证

从仓库根目录运行 `go test ./...` 和 `go vet ./...`。涉及并发、节点生命周期或收发路径时，运行 `go test -race ./...`。

改动示例后直接运行对应命令，例如 `go run ./examples/relay`。其他示例入口见 [README](README.md)，NAT 场景与混沌种子重放命令见[测试指南](docs/testing.md)。
