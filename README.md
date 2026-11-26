# Nebula mesh for Go

Nebula connects Go applications over an encrypted Layer 3 mesh. Each node has a certified IPv4 and IPv6 address and exposes a raw IP port. You can handle packets directly or attach the port as a NIC to your own gVisor stack.

## Getting started

With Go 1.27.3 or later, run the two-node example from the repository root.

```sh
go run ./examples/quickstart
```

Bob sends Alice a signed publication and an IPv6 packet over a loopback QUIC connection. The example generates its own credentials. [Walkthrough](docs/quickstart.md)

## Use from a Go module

Add the module to your application.

```sh
go get code.d7z.net/d7z-team/nebula
```

To develop against a local checkout, point your module at that directory.

```sh
go mod edit -replace=code.d7z.net/d7z-team/nebula=/absolute/path/to/nebula
go get code.d7z.net/d7z-team/nebula@v0.0.0
```

1. Give `nebula.New` the root CA, pinned cluster CA, node certificate and same-key cluster grant in `Options.Auth`. The local topology can start with just your own member.
2. For QUIC, supply a UDP socket for each underlay address family you use. An outbound-only TCP node can use the default dialer. Register any IP receiver or subscription that needs to receive the first delivery, then call `Start`.
3. Call `ConnectEndpoint(ctx, ep)` with a known entry's physical address. For a first contact outside your topology, configure its public-key fingerprint in `Auth.TrustedEntrypoints` before creating the node. Use reciprocal `Member.Links` for neighbors that should stay connected while idle. [Integration guide](docs/integration.md) · [Discovery example](examples/discovery/main.go)

## Examples

The self-contained examples generate short-lived credentials in memory. Their network traffic uses ephemeral loopback ports and runs as an ordinary user. The public `examples/demo` package supplies fixtures for local experiments and tests.

| Command | What the example verifies |
| --- | --- |
| `go run ./examples/quickstart` | A signed publication and an IPv6 packet arrive over IPv4 QUIC. [Source](examples/quickstart/main.go) |
| `go run ./examples/discovery` | Connect to one physical UDP endpoint, resolve a downstream address through a neighbor, and exchange IPv6 packets with the discovered gateway. [Source](examples/discovery/main.go) |
| `go run ./examples/relay` | R connects to A and B while keeping its physical endpoints out of discovery. A inspects its next hop and exchanges IP packets with B through R. [Source](examples/relay/main.go) |
| `go run ./examples/gateway` | Route dual-stack traffic through a site gateway and a default exit. Each downstream service sees the client's address. [Source](examples/gateway/main.go) |
| `go run ./examples/addressing` | Two peers receive a directed broadcast, one subscriber receives a multicast packet, and one service instance receives an anycast packet. [Source](examples/addressing/main.go) |
| `go run ./examples/anycast` | Drain one of two TCP services on the same VIP, probe it directly, keep its established connection alive, then withdraw its VIP authorization. [Source](examples/anycast/main.go) |
| `go run ./examples/pki` | Delegate IPv4 and IPv6 ranges to a site CA, verify a root-issued node identity, and validate its same-key site-issued grant. [Source](examples/pki/main.go) |
| `go run ./examples/portshare` | A mesh peer, an HTTP/2 site and an HTTP/3 site share one loopback port. [Source](examples/portshare/main.go) |

For deployment with existing certificates, run `go run ./examples/peer` with the listener, credential and topology arguments in the walkthrough. It runs the same program in two terminals and checks a signed receipt from the expected member. [Commands](docs/quickstart.md#使用磁盘凭据启动两个进程) · [Source](examples/peer/main.go)

## Features

- **Authenticated transport.** QUIC and TCP use mutual TLS 1.3 with X25519MLKEM768. TLS presents a root-issued node certificate. After TLS, peers confirm the cluster and exchange grants carrying their overlay addresses and permissions. Mesh and web services can share TCP and UDP ports via ALPN. [Handshake](docs/mesh.md#tls-与成员身份) · [Port sharing](docs/portshare.md)
- **Discovery and relays.** Look up primary addresses and downstream gateways through authenticated neighbors. Connect to a selected public-key identity and inspect its direct or relayed path. Hosts can filter advertised endpoints, limit outbound dials and designate transit neighbors. [Discovery](docs/integration.md#按地址发现成员和下游网关) · [Relay setup](docs/integration.md#让节点通过已连接的邻居提供中继)
- **IP routing.** Each cluster has one IPv4 and one IPv6 member prefix. The host can enable broadcast and multicast, choose an anycast instance per flow, or route through a gateway authorized for downstream prefixes, including default routes. [Addressing](docs/addressing.md)
- **Credentials and diagnostics.** Issue credentials with the Go API or offline CLI, reload them and apply host certificate policy. Inspect address claims and confirmed conflicts between instances sharing a node key. [PKI](docs/pki.md) · [Conflict diagnosis](docs/integration.md#排查重复地址与实例)
- **Signed publications.** Publish to authorized topics and subscribe by exact topic name. Neighbors can forward and fetch signed messages while they remain valid. [Publication delivery](docs/mesh.md#签名主题消息)

## Documentation

The guides are in Chinese.

| Guide | Contents |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Connect two local nodes or use PEM credentials to exchange a request and receipt between two processes. |
| [Integration guide](docs/integration.md) | Embed a node, configure physical endpoints and policies, route a subnet and diagnose delivery. |
| [Addressing](docs/addressing.md) | Allocate member addresses, configure group delivery and deploy anycast services. |
| [Port sharing](docs/portshare.md) | Run mesh, HTTPS and HTTP/3 together, manage socket ownership and understand classification limits. |
| [Mesh protocol](docs/mesh.md) | Peer identity, path selection, packet authorization, publication delivery and runtime status. |
| [PKI reference](docs/pki.md) | X.509 certificate profile, certificate roles, delegation and signed objects. |
| [Testing guide](docs/testing.md) | NAT scenarios, fault replay and benchmarks. |

## Development

```sh
make fmt
go test ./...
go test -race ./...
go vet ./...
```

## Origin and license

This project originated from Slack's Nebula and now implements its own TLS-based mesh protocol. [Upstream project](https://github.com/slackhq/nebula) · [MIT License](LICENSE)
