package nebula

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUserNetstackDestroyCancelsDialAndClosesCreationGate(t *testing.T) {
	_, a, b := newNodeTestIdentities(t)
	routes, err := newPacketRouteTable(a.identity.Certificate, nil, nil)
	require.NoError(t, err)
	netstack, err := newUserNetstack(routes, a.identity.Certificate.Networks(), nil, 1300)
	require.NoError(t, err)
	t.Cleanup(netstack.destroy)

	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		conn, err := netstack.dialContext(context.Background(), "tcp4", net.JoinHostPort(b.addr.String(), "19000"), a.addr)
		if conn != nil {
			_ = conn.Close()
		}
		dialed <- dialResult{conn: conn, err: err}
	}()

	packetContext, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	packet, err := netstack.readPacket(packetContext)
	require.NoError(t, err, "the dial must enter gVisor before the stack is destroyed")
	packet.Release()

	destroyed := make(chan struct{})
	go func() {
		netstack.destroy()
		close(destroyed)
	}()
	select {
	case result := <-dialed:
		require.Nil(t, result.conn)
		require.Error(t, result.err)
	case <-time.After(time.Second):
		t.Fatal("destroy did not cancel the in-flight TCP dial")
	}
	select {
	case <-destroyed:
	case <-time.After(time.Second):
		t.Fatal("destroy remained blocked after canceling the TCP dial")
	}

	_, err = netstack.listen("tcp4", ":0")
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = netstack.listenPacket("udp4", ":0")
	require.ErrorIs(t, err, net.ErrClosed)
}
