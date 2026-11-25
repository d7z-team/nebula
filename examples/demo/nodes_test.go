package demo_test

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"

	"github.com/stretchr/testify/require"
)

func TestListenWithIndependentViews(t *testing.T) {
	a, b, c := demo.NewHost(1), demo.NewHost(2), demo.NewHost(3)
	a.PublishTopics = []string{"app/alice"}
	opts, err := demo.NodeOptions(a, b, c)
	require.NoError(t, err)
	// The first member sees only B. C sees all members in reverse order.
	opts[0].Topology.Members = opts[0].Topology.Members[:2]
	slices.Reverse(opts[2].Topology.Members)
	opts[1].Topology.Members[0].PublishTopics[0] = "app/other"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	nodes, err := demo.Listen(ctx, "tcp", opts)
	require.NoError(t, err)
	for _, n := range nodes {
		t.Cleanup(func() { n.Close() })
		require.NoError(t, n.Start())
	}
	require.NoError(t, nodes[0].ConnectPeer(ctx, b.IPv6))
	require.NoError(t, nodes[2].ConnectPeer(ctx, b.IPv4))
	_, err = nodes[0].Publish(ctx, "app/alice", []byte("hello"))
	require.NoError(t, err)
	for i, o := range opts {
		for _, m := range o.Topology.Members {
			target := slices.IndexFunc(nodes, func(n *nebula.Node) bool { return n.ID().IPv6() == m.IPv6 })
			require.NotEqual(t, -1, target)
			require.Len(t, m.Endpoints, 1)
			require.Equal(t, opts[target].Transport.TCP4.Addr().String(), m.Endpoints[0].Address.String(), "view %d", i)
		}
	}
	_, known := nodes[0].LookupPeer(c.IPv4)
	require.False(t, known)
}

func TestListenClosesNodesOnConstructionError(t *testing.T) {
	opts, err := demo.NodeOptions(demo.NewHost(1), demo.NewHost(2))
	require.NoError(t, err)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()
	opts[0].Transport.TCP4 = listener
	opts[1].Topology.Network = "different"
	_, err = demo.Listen(t.Context(), "udp", opts)
	require.Error(t, err)
	require.Nil(t, opts[0].Transport.UDP4)
	require.ErrorIs(t, listener.SetDeadline(time.Now()), net.ErrClosed)
}
