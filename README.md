# Nebula

Nebula is a Go library for connecting applications over a private IPv4/IPv6 network. Each node runs inside your process and has one certified address in each family. Peers communicate over QUIC or TLS 1.3 over TCP. They can use UDP hole punching to connect directly across NATs or reach each other through authorized relays.

Use an IP port to handle packets in Go, or attach the node to a gVisor stack to use TCP and UDP sockets on the mesh.

## Installation

Requires Go 1.27.3 or later.

```sh
go get gopkg.d7z.net/nebula
```

To try the library, run two nodes on loopback. The example generates its own credentials and delivers an IPv6 packet over an IPv4 QUIC connection.

```sh
go run gopkg.d7z.net/nebula/examples/quickstart@latest
```

## Usage

The receiver below connects to a known member by its mesh IP and logs incoming packets. Supply the local node's credentials, approved topology, and transport in `nebula.Options`. A UDP socket enables QUIC. [Loading credentials and configuring a node](docs/integration.md)

```go
package meshapp

import (
	"context"
	"log"
	"net/netip"

	"gopkg.d7z.net/nebula"
)

func Receive(ctx context.Context, opts nebula.Options, peer netip.Addr) error {
	node, err := nebula.New(ctx, opts)
	if err != nil {
		return err
	}
	defer node.Close()

	_, err = node.OpenIPPort(nebula.IPPortOptions{
		Deliver: func(from nebula.PeerID, packet []byte) {
			log.Printf("received %d bytes from %s", len(packet), from)
		},
	})
	if err != nil {
		return err
	}
	if err := node.Start(); err != nil {
		return err
	}
	if err := node.ConnectPeer(ctx, peer); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}
```

To send packets as well, keep the port returned by `OpenIPPort` and call `port.WriteIP(nebula.PeerID{}, packet)`. For a known member's primary address, the node selects the peer from the packet's destination IP. A successful call queues the packet for transmission. [Two-node send and receive example](examples/quickstart/main.go)

## Examples

From the repository root, run an example with a command such as `go run ./examples/relay`.

- Discover the gateway for a downstream IP or connect two peers through a relay. [Discovery](examples/discovery) · [Relay](examples/relay)
- Attach a gVisor stack, route a subnet through a gateway, or drain an anycast service while existing TCP connections finish. [Gateway](examples/gateway) · [Addressing](examples/addressing) · [Anycast](examples/anycast)
- Serve HTTPS, HTTP/3, and mesh traffic on the same port. [Port sharing](examples/portshare)
- Issue credentials or run peers in separate processes using PEM files. [PKI](examples/pki) · [Two-process walkthrough](docs/quickstart.md#使用磁盘凭据启动两个进程)

## Documentation

Run `go doc gopkg.d7z.net/nebula` for the Go API. The project guides are in Chinese.

- [Getting started](docs/quickstart.md) · [Embedding a node](docs/integration.md)
- [Addressing and routing](docs/addressing.md) · [Sharing a listener](docs/portshare.md)
- [Certificates and authorization](docs/pki.md) · [Mesh protocol](docs/mesh.md)

For development, run `make fmt`, `make lint`, and `make check` from the repository root. The testing guide covers race detection, NAT scenarios, and replaying network faults. [Testing guide](docs/testing.md)

## License

Nebula originated from Slack's Nebula project and is distributed under the MIT license. [Upstream Nebula](https://github.com/slackhq/nebula) · [MIT license](LICENSE)
