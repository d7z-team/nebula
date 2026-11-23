# Nebula for gVisor

Embed Nebula in a Go application and attach its encrypted overlay as a Layer 3 interface in a gVisor network stack. Nebula discovers and authenticates peers and carries IP packets over UDP. Your application owns the IP addresses, routes, forwarding rules, and sockets in gVisor.

## Features

- IPv4 and IPv6 tunnels, including cross-family next hops and gateway forwarding for networks authorized by `UnsafeNetworks` in the gateway's certificate.
- Peer discovery through static endpoints or lighthouses. Per-peer policies support direct-only, relay-only, and automatic path selection based on latency, jitter, and timeouts observed by authenticated probes.
- Optional managed networking with CA-signed configuration snapshots, peer introductions, multi-hop relays, per-node egress shaping, and signed application events.
- Independent nodes in the same process, with Go APIs for connection management, path checks, port traffic counters, and relay usage.
- A gVisor link endpoint for the overlay, an `IPPort` for other Layer 3 devices, and a `DatagramTransport` interface for custom underlay transports.

## Relationship to upstream Nebula

This project is an independent fork of `slackhq/nebula`. It branched from upstream at `d4e6b16`. The latest recorded upstream review covers changes through `7876efa`, with selected fixes backported to this fork. [Upstream base](https://github.com/slackhq/nebula/commit/d4e6b160916c848c3a52f5cc0c1255990481ffb5) · [Reviewed revision](https://github.com/slackhq/nebula/commit/7876efaaf499061109ca888f6ad4f197140087b8) · [Backport record](https://code.d7z.net/d7z-team/nebula/commit/7428fd5a63c5ae25351b9121c90565bf2c28ba64)

This fork provides the embeddable `Node` API and the offline `nebula-config` signer. Upstream provides the standalone daemon and its YAML configuration.

With the default UDP framing (empty `Options.DatagramMagic`), nodes can use upstream peers, lighthouses, and single-hop relays. Two managed endpoints can synchronize through an upstream relay because their control traffic travels inside the encrypted IP tunnel. A managed multi-hop route requires participating endpoints and relays along the entire route. [Deployment guide](docs/control.md) · [Interoperability tests](#testing)

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
3. Start the node and dial the peer's overlay address through gVisor. The first packet can trigger the handshake. If you enable `Options.Control`, bind the overlay UDP socket and call `AttachControl` before `Start`.

The [overlay TCP client example](docs/quickstart.md) shows setup and cleanup for a connection to `10.42.0.254:8080`.

## Documentation

The guides are written in Chinese and include Go examples.

| Guide | Topics |
| --- | --- |
| [Certificates and trust pools](cert/README.md) | Load PEM identities and issue client or gateway certificates |
| [Direct and relayed paths](docs/paths.md) | Configure per-peer policies, probe paths, and inspect failover |
| [Managed networks](docs/control.md) | Bootstrap through a peer, sign configuration, publish events, and operate multi-hop relays |
| [Gateway forwarding and NIC management](docs/nebula-nic.md) | Set up downstream routes, attach other Layer 3 devices, and manage discovery |
| [Monitoring and troubleshooting](docs/nebula-nic.md#监控节点和流量) | Inspect peer reachability, port traffic, relay capacity, and packet drops |
| [Protocol design reference](DESIGN.md) | Trace the UDP handshake, NAT traversal, relay forwarding, and failover to their implementations and upstream design discussions |

## Testing

```sh
make check  # go vet and the full Go test suite
make race   # Run the suite with the race detector
```

To run the interoperability suite, point `NEBULA_INTEROP_BINARY` at an upstream Nebula executable.

```sh
NEBULA_INTEROP_BINARY=/path/to/upstream/nebula go test . -run '^(TestNodeUpstream(Interop|RelayInitiator)|TestManagedUpstreamRelay)$' -count=1
```

## License

[MIT](LICENSE)
