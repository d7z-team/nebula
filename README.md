# Nebula mesh for Go

Nebula connects Go applications over an encrypted Layer 3 mesh. Each member has one certified IPv4 address and one certified IPv6 address. Applications can exchange signed publications, open a raw IP port, or attach that port to a gVisor stack.

## Getting started

With Go 1.27.3 or later, run the two-node example from the repository root.

```sh
go run ./examples/quickstart
```

The example generates credentials, connects Bob to Alice over QUIC, and delivers a signed publication and an IPv6 packet. [Walkthrough](docs/quickstart.md)

## Use from a Go module

Add the module to your application.

```sh
go get gopkg.d7z.net/nebula
```

1. Give `nebula.New` the root CA, pinned cluster CA, node certificate and same-key cluster grant in `Options.Auth`. The local topology can start with just your own member.
2. For QUIC, supply a UDP socket for each underlay address family you use. An outbound-only TCP node can use the default dialer. Register any IP receiver or subscription that needs to receive the first delivery, then call `Start`.
3. Call `ConnectEndpoint(ctx, ep)` with a member's physical endpoint. If your initial topology contains only your own member, add the entry's public-key fingerprint to `Auth.TrustedEntrypoints` before calling `New`. Use `ResolveIP` to discover an overlay address through connected neighbors. Configure reciprocal `Member.Links` to reconnect designated neighbors after a disconnect. [Integration guide](docs/integration.md) · [Discovery example](examples/discovery/main.go)

## Examples

These examples run as an ordinary user and generate short-lived credentials in memory. Networking examples use ephemeral loopback ports for the underlay. The public `examples/demo` package supplies their fixtures.

| Command | What the example verifies |
| --- | --- |
| `go run ./examples/quickstart` | A signed publication and an IPv6 packet arrive over IPv4 QUIC. [Source](examples/quickstart/main.go) |
| `go run ./examples/discovery` | Connect to one physical UDP endpoint, resolve a downstream address through a neighbor, and exchange IPv6 packets with the discovered gateway. [Source](examples/discovery/main.go) |
| `go run ./examples/relay` | R connects to A and B with its endpoints hidden. After R stops accepting new transit circuits, A and B exchange IP packets over their existing circuit. [Source](examples/relay/main.go) |
| `go run ./examples/gateway` | Route dual-stack traffic through a site gateway and a default exit. Each downstream service sees the client's address. [Source](examples/gateway/main.go) |
| `go run ./examples/addressing` | Two peers receive a directed broadcast, one subscriber receives a multicast packet, and one service instance receives an anycast packet. [Source](examples/addressing/main.go) |
| `go run ./examples/anycast` | Drain one of two TCP services on the same VIP, probe it directly, keep its established connection alive, then withdraw its VIP authorization. [Source](examples/anycast/main.go) |
| `go run ./examples/pki` | Delegate IPv4 and IPv6 ranges to a site CA, verify a root-issued node identity, and validate its same-key site-issued grant. [Source](examples/pki/main.go) |
| `go run ./examples/portshare -alpn acme-mesh` | A mesh peer negotiates a custom ALPN while HTTP/2 and HTTP/3 sites share its loopback port. [Source](examples/portshare/main.go) |

The two-process example reads PEM credentials from disk and verifies a signed receipt from the expected peer. [Setup and commands](docs/quickstart.md#使用磁盘凭据启动两个进程) · [Source](examples/peer/main.go)

## Documentation

The guides are in Chinese.

| Guide | Contents |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Connect two local nodes or use PEM credentials to exchange a request and receipt between two processes. |
| [Integration guide](docs/integration.md) | Discover members and gateways, configure relays and connection limits, and diagnose address or instance conflicts. |
| [Addressing](docs/addressing.md) | Allocate dual-stack addresses, enable broadcast and multicast, select anycast instances and use subnet or default gateways. |
| [Port sharing](docs/portshare.md) | Share TCP with HTTPS and UDP with HTTP/3, configure the listeners and size the mesh handshake limit. |
| [Mesh protocol](docs/mesh.md) | Mutual TLS 1.3 over QUIC or TCP, configurable key exchange groups, end-to-end relay circuits, and delivery of IP packets and signed publications. |
| [PKI reference](docs/pki.md) | Issue and verify node certificates and same-key cluster grants with the Go API or offline CLI, and reload credentials. |
| [Testing guide](docs/testing.md) | Replay NAT and network faults, verify relay capacity and run benchmarks. |

## Development

```sh
make fmt
go test ./...
go test -race ./...
go vet ./...
```

## Origin and license

This project originated from Slack's Nebula and now implements its own TLS-based mesh protocol. [Upstream project](https://github.com/slackhq/nebula) · [MIT License](LICENSE)
