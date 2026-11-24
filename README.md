# Nebula mesh for Go

Nebula connects Go applications over an encrypted Layer 3 mesh. Each node has a certified IPv4 and IPv6 address and exposes a raw IP port. You can handle packets directly or attach the port as a NIC to your own gVisor stack.

## Use from a Go module

Use Go 1.27.3 or later. To use a published revision, run this in your application's module:

```sh
go get code.d7z.net/d7z-team/nebula
```

To try the source in a local checkout, point your module at that directory:

```sh
go mod edit -replace=code.d7z.net/d7z-team/nebula=/absolute/path/to/nebula
go get code.d7z.net/d7z-team/nebula@v0.0.0
```

Pass your trust roots, pinned cluster CA, member credentials and local topology to `nebula.New`. The initial topology can contain just your own member. For QUIC, supply a UDP socket for the physical address family you plan to use. An outbound TCP client can use the default dialer. [Integration guide](docs/integration.md)

Register an IP receiver or topic subscription before `Start` if you need the first delivery. Once the node is running, call `ConnectEndpoint(ctx, ep)` with an existing member’s physical address. It returns the authenticated member’s `PeerID`. You can then query other addresses through that neighbor. [Discovery example](examples/discovery/main.go)

## Getting started

Run the two-node example from the repository root.

```sh
go run ./examples/quickstart
```

The self-contained examples generate short-lived credentials in memory. Their network traffic uses ephemeral loopback ports and runs as an ordinary user. The public `examples/demo` package supplies fixtures for local experiments and tests.

| Command | What the example verifies |
| --- | --- |
| `go run ./examples/quickstart` | A signed publication and an IPv6 packet arrive over IPv4 QUIC. [Source](examples/quickstart/main.go) |
| `go run ./examples/discovery` | Connect to one physical UDP endpoint, resolve a downstream address through a neighbor, and exchange IPv6 packets with the discovered gateway. [Source](examples/discovery/main.go) |
| `go run ./examples/relay` | R connects to A and B while keeping its physical endpoints out of discovery. A inspects its next hop and exchanges IP packets with B through R. [Source](examples/relay/main.go) |
| `go run ./examples/gateway` | Discover a gateway, apply the host’s approved LAN prefixes, and route through gVisor over TLS/TCP. The downstream service sees the client's address. [Source](examples/gateway/main.go) |
| `go run ./examples/addressing` | Two peers receive a directed broadcast, one subscriber receives a multicast packet, and one service instance receives an anycast packet. [Source](examples/addressing/main.go) |
| `go run ./examples/anycast` | Drain one of two TCP services on the same VIP, probe it directly, keep its established connection alive, then withdraw its VIP authorization. [Source](examples/anycast/main.go) |
| `go run ./examples/pki` | A root issues a dual-stack member certificate and the application verifies its identity and server usage. [Source](examples/pki/main.go) |
| `go run ./examples/portshare` | A mesh peer, an HTTP/2 site and an HTTP/3 site share one loopback port. [Source](examples/portshare/main.go) |

For deployment with existing certificates, run `go run ./examples/peer` with the listener, credential and topology arguments in the walkthrough. It runs the same program in two terminals and checks a signed receipt from the expected member. [Commands](docs/quickstart.md#使用磁盘凭据启动两个进程) · [Source](examples/peer/main.go)

## Features

- **Authenticated transports.** QUIC over UDP and TLS over TCP use mutual TLS 1.3 with X25519MLKEM768 key exchange. A node can listen on the same port number for both transports. Peers exchange their IP receive limits before carrying traffic. QUIC sends IP packets as datagrams and falls back to a reliable stream for larger packets within the negotiated limit.
- **Shared website ports.** The optional `portshare` package routes connections offering `meshwire.ALPN` as their sole protocol to the node and hands other traffic to your existing TCP or UDP service. Your HTTP servers retain control of certificates and virtual hosts. Custom UDP adapters can implement `meshwire.SharedSocket` to configure the node's QUIC transport. [Port sharing guide](docs/portshare.md)
- **Discovery and routing.** Use `ResolveIP(ctx, ip)` to find a member or downstream gateway through authenticated neighbors. Pass the selected `IPMatch.Peer` to `ConnectPeerID` to connect to that exact address pair. Use `PreferredPath(peer)` to inspect its current transport and relay hops.
- **Private endpoints and relays.** Set `Options.HideEndpoints` to omit physical addresses from signed introductions. A member can dial its neighbors and relay encrypted traffic over those connections. Configure `Restricted` and reciprocal `Links` to limit its direct connections and probes. Grant `Transit` to let it relay for others. [Relay setup](docs/integration.md#让节点通过已连接的邻居提供中继)
- **Cluster addressing.** A pinned CA defines dual-stack member subnets and service address pools. Enable broadcast and multicast in the topology or authorize multiple instances for one VIP. The application chooses the instance for each flow. The mesh selects an authorized path to that member and can report each local packet submission. [Addressing guide](docs/addressing.md)
- **Gateway authorization.** A gateway can advertise downstream prefixes covered by its certificate and local topology. To route through it, approve the gateway and prefixes in your own topology and configure forwarding in your network stack. [Gateway example](examples/gateway/main.go)
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
