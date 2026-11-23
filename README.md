# Nebula mesh for Go

Nebula connects Go applications over an encrypted Layer 3 mesh. Each node has a certified IPv4 and IPv6 address and exposes a raw IP port. You can handle packets directly or attach the port as a NIC to your own gVisor stack.

## Getting started

From your application's Go module, install the library with Go 1.27.3 or later.

```sh
go get code.d7z.net/d7z-team/nebula
```

To try it locally, follow the quickstart to issue credentials for two nodes, then run the example from this repository. It sends a signed application event and an IPv6 packet over an IPv4 loopback connection. [Quickstart](docs/quickstart.md) · [Runnable example](examples/quickstart/main.go)

## Features

- **Authenticated transports.** QUIC over UDP and TLS over TCP use mutual TLS 1.3 with X25519MLKEM768 key exchange. A node can listen on the same port number for both transports. QUIC sends IP packets as datagrams and falls back to a reliable stream for larger packets.
- **Discovery and routing.** Authenticated neighbors share signed endpoint introductions for UDP hole punching. Nodes probe direct and relayed paths, apply per-peer path policies and support end-to-end encrypted multi-hop circuits.
- **Gateway authorization.** The topology assigns addresses to members and enables routed subnets within the gateway certificate's authority. Applications configure forwarding and routes in their own network stack.
- **Identity and events.** Use the Go PKI API, the offline CLI or an enterprise CA to issue mesh certificates. Applications can reload credentials, supply a certificate-chain authorization hook and publish or subscribe to signed events.

## Documentation

The guides are in Chinese.

| Guide | Contents |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Issue credentials, connect nodes, deploy on separate hosts and attach a gVisor NIC. |
| [Mesh protocol](docs/mesh.md) | Peer identity, path selection, packet authorization, event delivery and runtime status. |
| [PKI reference](docs/pki.md) | X.509 certificate profile, certificate roles, delegation and signed objects. |
| [Testing guide](docs/testing.md) | NAT scenarios, fault replay and benchmarks. |

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

## Origin and license

This project originated from Slack's Nebula and now implements its own TLS-based mesh protocol. [Upstream project](https://github.com/slackhq/nebula) · [MIT License](LICENSE)
