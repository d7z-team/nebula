// Package meshwire defines the TLS protocol identifier and the shared UDP socket contract for mesh transports.
package meshwire

import (
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ALPN is the default TLS application protocol identifier for mesh connections.
const ALPN = "nebula-mesh"

// ResolveALPN returns ALPN for an empty identifier. A custom identifier may
// contain up to 255 bytes, as specified by RFC 7301.
func ResolveALPN(id string) (string, error) {
	if id == "" {
		return ALPN, nil
	}
	if len(id) > 255 {
		return "", errors.New("ALPN identifier exceeds 255 bytes")
	}
	return id, nil
}

// SharedSocket is the mesh branch of a shared UDP socket.
type SharedSocket interface {
	net.PacketConn
	// ConfigureMeshQUIC sets up packet routing for the transport and config.
	// The node calls it before using either for listening or dialing.
	ConfigureMeshQUIC(*quic.Transport, *quic.Config)
}

// AcceptTCP retries transient listener failures with bounded backoff. Closing
// done interrupts backoff; close the listener to interrupt a blocked Accept.
func AcceptTCP(l net.Listener, done <-chan struct{}) (net.Conn, error) {
	for delay := 5 * time.Millisecond; ; delay = min(2*delay, time.Second) {
		conn, err := l.Accept()
		if err == nil {
			return conn, nil
		}
		netErr, ok := errors.AsType[net.Error](err)
		if !ok || (!netErr.Timeout() && !netErr.Temporary()) {
			return nil, err
		}
		select {
		case <-done:
			return nil, net.ErrClosed
		case <-time.After(delay):
		}
	}
}
