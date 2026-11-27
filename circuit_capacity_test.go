package nebula

import (
	"context"
	"flag"
	"net"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/require"
)

var fullRelayCapacity = flag.Bool("full-relay-capacity", false, "exercise 512 authenticated circuits across one physical adjacency")

func TestCircuitLeaseInterruptsRead(t *testing.T) {
	a, b := net.Pipe()
	client, err := yamux.Client(a, nil)
	require.NoError(t, err)
	defer client.Close()
	server, err := yamux.Server(b, nil)
	require.NoError(t, err)
	defer server.Close()
	leg, err := client.OpenStream()
	require.NoError(t, err)
	remote, err := server.AcceptStream()
	require.NoError(t, err)
	defer remote.Close()
	ctx, cancel := context.WithCancel(t.Context())
	l := circuitLease{n: &Node{}, ctx: ctx, cancel: cancel, ends: []net.Conn{leg}}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := leg.Read(b[:])
		done <- err
	}()
	l.close()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("relay read still waiting for the remote FIN")
	}
}

func TestRelayCapacity(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			sources, targets := 8, 9 // Cross the 64 inbound request slots in ordinary CI.
			if *fullRelayCapacity {
				sources, targets = 16, 32
			}
			f := newFixture(t, slices.Repeat([]string{network}, 2+sources+targets)...)
			for i := range f.opts {
				f.opts[i].MaintenanceInterval = time.Hour
				f.opts[i].DialTimeout = 4 * time.Second
			}
			f.start()
			left, right := f.nodes[0], f.nodes[1]
			// Install the links after connecting them in one direction, so every
			// circuit must share exactly the same physical backbone connection.
			for i := 1; i < len(f.nodes); i++ {
				parent := 0
				if i >= 2+sources {
					parent = 1
				}
				_, err := f.nodes[parent].ConnectEndpoint(t.Context(), f.cfg.Members[i].Endpoints[0])
				require.NoError(t, err)
				f.link(parent, i)
				f.cfg.Members[i].Restricted = true
			}
			f.cfg.Members[0].Transit, f.cfg.Members[1].Transit = true, true
			for _, n := range f.nodes {
				require.NoError(t, n.ApplyTopology(t.Context(), f.cfg))
			}
			for i, source := range f.nodes[2 : 2+sources] {
				for j, target := range f.nodes[2+sources:] {
					require.NoError(t, source.ConnectPeerID(t.Context(), target.id), "circuit %d of %d", i*targets+j+1, sources*targets)
				}
			}
			require.Equal(t, sources*targets, left.ControlStatus().Circuits)
			require.Equal(t, sources*targets, right.ControlStatus().Circuits)
			paths := slices.DeleteFunc(left.Paths(), func(p PathStatus) bool { return p.Peer != right.id })
			require.Len(t, paths, 1)
			require.Equal(t, network, paths[0].Transport)
			if *fullRelayCapacity {
				runtime.GC()
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				t.Logf("all %d nodes at capacity: %.1f MiB live Go heap", len(f.nodes), float64(m.HeapAlloc)/(1<<20))
			}
			s := left.preferredSession(right.id, true)
			at := time.Now()
			reply, err := s.request(t.Context(), opPing, []byte("ping"), 4)
			require.NoError(t, err)
			require.Equal(t, []byte("ping"), reply)
			t.Log("backbone ping", time.Since(at))
			// Ask across the backbone for a target that has sent no introduction.
			a, b := f.nodes[2], f.nodes[len(f.nodes)-1]
			require.Empty(t, left.ipMatches(b.Addresses().IPv4, nil))
			at = time.Now()
			hits, err := left.ResolveIP(t.Context(), b.Addresses().IPv4)
			require.NoError(t, err)
			require.Len(t, hits, 1)
			require.Equal(t, b.id, hits[0].Peer)
			t.Log("uncached lookup", time.Since(at))
			ends := [2]*Node{a, b}
			in := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
			var ports [2]*IPPort
			for i, n := range ends {
				ports[i], err = n.OpenIPPort(IPPortOptions{Deliver: func(_ PeerID, packet []byte) { in[i] <- packet }})
				require.NoError(t, err)
			}
			for i, src := range ends {
				dst := ends[1-i]
				packet := testIPv4(src.Addresses().IPv4, dst.Addresses().IPv4, "round trip")
				require.NoError(t, ports[i].WriteIP(dst.id, packet))
				select {
				case got := <-in[1-i]:
					require.Equal(t, packet, got)
				case <-time.After(4 * time.Second):
					t.Fatal("IP delivery timed out")
				}
			}
			f.cfg.Members[1].Transit = false
			require.NoError(t, right.ApplyTopology(t.Context(), f.cfg))
			require.Eventually(t, func() bool {
				for _, n := range f.nodes {
					if n.ControlStatus().Circuits != 0 {
						return false
					}
				}
				return true
			}, 5*time.Second, 10*time.Millisecond)
			require.True(t, left.usable(s))
		})
	}
}
