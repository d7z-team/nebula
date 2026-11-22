package nebula

import (
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/require"
)

func TestDatagramMagicWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic []byte
	}{
		{"upstream", nil},
		{"custom", []byte{0xa5, 0, 0x73}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pool, local, remote := newNodeTestIdentities(t)
				tr := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:34001"), netip.MustParseAddrPort("127.0.0.1:34002"))
				magic := slices.Clone(tc.magic)
				n, err := New(t.Context(), Options{
					Identities: []Identity{local.identity}, CAPool: pool, Transport: tr[0],
					DatagramMagic: magic, Punchy: PunchyOptions{Delay: time.Millisecond},
				})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, n.Close()); require.NoError(t, n.Wait()) })
				clear(magic) // The caller can reuse its options after New.
				require.NoError(t, n.Start())

				// An unknown tunnel index elicits a RecvError with the same index.
				request := header.Encode(make([]byte, header.Len), header.Version, header.Message, header.MessageNone, 73, 1)
				if len(tc.magic) > 0 {
					other := slices.Clone(tc.magic)
					other[len(other)-1]++
					for _, wire := range [][]byte{request, tc.magic[:1], tc.magic, slices.Concat(other, request)} {
						require.NoError(t, tr[1].WriteTo(wire, tr[0].addr))
					}
					synctest.Wait()
					require.Empty(t, tr[1].packets)
				}
				require.NoError(t, tr[1].WriteTo(slices.Concat(tc.magic, request), tr[0].addr))
				synctest.Wait()
				require.Len(t, tr[1].packets, 1)
				reply := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, 73, 0)
				require.Equal(t, slices.Concat(tc.magic, reply), (<-tr[1].packets).packet)

				n.punchy.Schedule(tr[1].addr, remote.addr)
				time.Sleep(time.Millisecond)
				synctest.Wait()
				require.Len(t, tr[1].packets, 1)
				require.Equal(t, slices.Concat(tc.magic, []byte{0}), (<-tr[1].packets).packet)
			})
		})
	}
}

func TestDatagramMagicConcurrentWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool, local, _ := newNodeTestIdentities(t)
		tr := newMemoryDatagramNetwork(netip.MustParseAddrPort("127.0.0.1:34001"), netip.MustParseAddrPort("127.0.0.1:34002"))
		gate := &gatedWriteTransport{base: tr[0], entered: make(chan struct{}), release: make(chan struct{})}
		n, err := New(t.Context(), Options{Identities: []Identity{local.identity}, CAPool: pool, Transport: gate, DatagramMagic: []byte("NB")})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, n.Close()); require.NoError(t, n.Wait()) })
		gate.enabled.Store(true)
		first := make(chan error, 1)
		go func() { first <- n.engine.writeDatagram([]byte("first"), tr[1].addr) }()
		<-gate.entered
		gate.enabled.Store(false)
		require.NoError(t, n.engine.writeDatagram([]byte("other"), tr[1].addr))
		gate.unblock()
		require.NoError(t, <-first)
		require.Equal(t, "NBother", string((<-tr[1].packets).packet))
		require.Equal(t, "NBfirst", string((<-tr[1].packets).packet))
	})
}

// Count bytes at the transport boundary to measure framing without socket I/O.
type countingDatagramTransport struct {
	DatagramTransport
	written int64
}

func (t *countingDatagramTransport) WriteTo(packet []byte, _ netip.AddrPort) error {
	t.written += int64(len(packet))
	return nil
}

func BenchmarkDatagramFraming(b *testing.B) {
	pool, local, _ := newNodeTestIdentities(b)
	to := netip.MustParseAddrPort("127.0.0.1:34001")
	for _, tc := range []struct {
		name  string
		magic []byte
	}{{"upstream", nil}, {"prefix", []byte("NB")}} {
		b.Run(tc.name, func(b *testing.B) {
			tr := &countingDatagramTransport{DatagramTransport: newMemoryDatagramNetwork(to)[0]}
			n, err := New(b.Context(), Options{Identities: []Identity{local.identity}, CAPool: pool, Transport: tr, DatagramMagic: tc.magic})
			require.NoError(b, err)
			b.Cleanup(func() { require.NoError(b, n.Close()); require.NoError(b, n.Wait()) })
			packet := make([]byte, 1300)
			b.ReportAllocs()
			for b.Loop() {
				if err := n.engine.writeDatagram(packet, to); err != nil {
					b.Fatal(err)
				}
			}
			require.Equal(b, int64(b.N)*int64(len(packet)+len(tc.magic)), tr.written)
		})
	}
}
