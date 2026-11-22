# Nebula for gVisor

Embed [Nebula](https://github.com/slackhq/nebula) in a Go application and attach its encrypted overlay as a Layer 3 interface in a [gVisor](https://github.com/google/gvisor) network stack. Nebula handles peer discovery, certificate authentication, and encrypted tunnels. The application manages IP addresses, routes, forwarding, and sockets through gVisor.

## Features

- IPv4 and IPv6 tunnels, including cross-family next hops and gateway forwarding for networks authorized by `UnsafeNetworks` in the gateway's certificate.
- Peer discovery through static endpoints or lighthouses. Per-peer policies support direct-only, relay-only, and automatic path selection based on latency, jitter, and timeouts observed by authenticated probes.
- Independent nodes in the same process, with Go APIs for connection management, path checks, port traffic counters, and relay usage.
- A gVisor link endpoint for the overlay, an `IPPort` for other Layer 3 devices, and a `DatagramTransport` interface for custom underlay transports.

## Relationship to upstream Nebula

This project is an independent fork of [`slackhq/nebula`](https://github.com/slackhq/nebula), based on upstream commit [`a136e25`](https://github.com/slackhq/nebula/commit/a136e25a0602ed4f2ada15d0f160e52a2517d9e0). The latest recorded upstream review covers changes through [`7876efa`](https://github.com/slackhq/nebula/commit/7876efaaf499061109ca888f6ad4f197140087b8), with selected fixes backported to this fork.

This fork is distributed as an embeddable Go library with its own `Node` API. Use the upstream project for the standalone Nebula daemon and its YAML configuration.

The default UDP framing interoperates with upstream Nebula. Leave `Options.DatagramMagic` empty when communicating with upstream peers, lighthouses, or relays. Interoperability tests cover v1 and v2 certificates, handshakes initiated by either implementation, and relays running either implementation. The Go management APIs, health-aware path selection, and custom datagram prefixes are features of this fork. [Run the interoperability tests](#testing).

## Installation

Requires Go 1.27.3 or later. From the root of your application's Go module, clone this fork and point a local module replacement at it.

```sh
git clone https://code.d7z.net/d7z-team/nebula.git ../nebula
go mod edit -require=github.com/slackhq/nebula@v0.0.0
go mod edit -replace=github.com/slackhq/nebula=../nebula
```

The fork retains the upstream module path. Import `github.com/slackhq/nebula` and `github.com/slackhq/nebula/nebulagvisor` in your Go code, then run `go mod tidy`. The gVisor revision used by this fork is declared in [`go.mod`](go.mod).

## Quick start

1. Load a Nebula identity and trusted CA pool, then create a node with `nebula.New`.
2. Create a `nebulagvisor.Endpoint` for the node and register it as a NIC in your gVisor stack. Assign the overlay address from the certificate and add a route to the peer.
3. Start the node and dial the peer's overlay address through gVisor. The first connection triggers the Nebula handshake.

The [complete TCP client example](docs/quickstart.md) shows setup and cleanup for a connection to `10.42.0.254:8080`.

## Documentation

The guides are written in Chinese and include Go examples.

| Guide | Topics |
| --- | --- |
| [Certificates and trust pools](cert/README.md) | Load PEM identities and issue client or gateway certificates |
| [Direct and relayed paths](docs/paths.md) | Configure per-peer policies, probe paths, and inspect failover |
| [Gateway forwarding and NIC management](docs/nebula-nic.md) | Set up downstream routes, attach other Layer 3 devices, and manage discovery |
| [Monitoring and troubleshooting](docs/nebula-nic.md#监控节点和流量) | Inspect peer reachability, port traffic, relay capacity, and packet drops |

## Testing

```sh
make check  # go vet and the full Go test suite
make race   # Run the suite with the race detector
```

To run the interoperability suite, point `NEBULA_INTEROP_BINARY` at an upstream Nebula executable.

```sh
NEBULA_INTEROP_BINARY=/path/to/upstream/nebula go test . -run '^TestNodeUpstream(Interop|RelayInitiator)$' -count=1
```

<details>
<summary>Forwarding tests and benchmarks</summary>

```sh
# Dual-stack gateway forwarding through gVisor
go test . -run '^TestNodeGVisorForwardingAndDetach$' -count=1

# Path selection and recovery after rebinding 1,000 logical sessions
go test . -run '^(TestPathQualitySelection|TestPathRebindAtScale)$' -v -count=1

# Discovery query coalescing
go test . -run '^$' -bench '^BenchmarkPendingLighthouseQuery$' -benchmem

# Datagram framing with the default format and a two-byte prefix
go test . -run '^$' -bench '^BenchmarkDatagramFraming$' -benchmem -cpu=1
```

</details>

## License

[MIT](LICENSE)
