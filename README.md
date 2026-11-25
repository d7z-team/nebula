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

Set the trust roots, pinned cluster CA and member credentials in `Options.Auth`. Pass the local member view in `Options.Topology`. It can initially contain just your own member. For QUIC, supply a UDP socket for each physical address family you use in `Options.Transport`. An outbound-only TCP node can use the default dialer with no listener. Pass these options to `nebula.New`. [Integration guide](docs/integration.md)

Register an IP receiver or topic subscription before `Start` if you need the first delivery. Once the node is running, call `ConnectEndpoint(ctx, ep)` with an existing member’s physical address to learn its authenticated `PeerID`. Configure reciprocal `Member.Links` for neighbors that should stay connected while idle. [Discovery example](examples/discovery/main.go)

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
| `go run ./examples/pki` | Delegate IPv4 and IPv6 ranges to a site CA, issue a member certificate, and verify its identity and server usage. [Source](examples/pki/main.go) |
| `go run ./examples/portshare` | A mesh peer, an HTTP/2 site and an HTTP/3 site share one loopback port. [Source](examples/portshare/main.go) |

For deployment with existing certificates, run `go run ./examples/peer` with the listener, credential and topology arguments in the walkthrough. It runs the same program in two terminals and checks a signed receipt from the expected member. [Commands](docs/quickstart.md#使用磁盘凭据启动两个进程) · [Source](examples/peer/main.go)

## Features

- **Authenticated transports.** QUIC over UDP and TLS over TCP use mutual TLS 1.3 with X25519MLKEM768 key exchange. A node can listen on the same port number for both transports. Peers exchange their IP receive limits and per-run instance IDs before carrying traffic. QUIC sends IP packets as datagrams and falls back to a reliable stream for larger packets within the negotiated limit.
- **Shared website ports.** `portshare` routes a TLS or QUIC v1 handshake to the mesh when the client offers only `nebula-mesh` via ALPN. Websites receive their original traffic and handle their own certificates and virtual hosts. On UDP, the splitter also recognizes mesh connection IDs and consumes the one-byte NAT punch. [Port sharing guide](docs/portshare.md)
- **Discovery and routing.** `ResolveIP(ctx, ip)` returns signed matches from the local cache or queries authenticated neighbors on a miss. Call `RefreshIP(ctx, dst)` to look for downstream gateways even when a default route is cached. Use `ConnectPeerID(ctx, match.Peer)` to connect to a selected member or gateway, and `PreferredPath(match.Peer)` to inspect its transport and relay hops. [Integration guide](docs/integration.md#按地址发现成员和下游网关)
- **Address and instance diagnostics.** Topology validation reports duplicate primary addresses and both member IDs. At runtime, use `InspectIP` for local address claims and `InstanceConflicts()` for confirmed cases of two instances using the same address pair. [Diagnosis and recovery](docs/integration.md#排查重复地址与实例)
- **Private endpoints and relays.** Set `Options.Transport.HideEndpoints` to omit physical addresses from signed introductions. A member can dial its neighbors and relay encrypted traffic over those connections. Configure `Restricted` and reciprocal `Links` to limit its direct connections and probes. Grant `Transit` to let it relay for others. [Relay setup](docs/integration.md#让节点通过已连接的邻居提供中继)
- **Cluster addressing.** A pinned cluster CA defines one IPv4 and one IPv6 member prefix. Site issuers can sign addresses in delegated ranges on this shared link. Service VIPs can use independent pools. Enable broadcast and multicast in the topology or authorize multiple instances for one VIP. The application chooses the instance for each flow. The mesh selects an authorized path to that member and can report each local packet submission. [Addressing guide](docs/addressing.md)
- **Gateway authorization.** A gateway can advertise downstream prefixes, including IPv4 and IPv6 default routes, within its certificate and local topology grants. To route through it, approve the gateway and prefixes in your own topology and configure forwarding in your network stack. [Gateway example](examples/gateway/main.go)
- **Identity and publications.** Issue certificates with the Go PKI API, the offline CLI or an enterprise CA. Applications can reload credentials and supply a certificate-chain authorization hook. Use `Publish` to send a signed message and `Subscribe` to receive messages for an exact topic.

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
