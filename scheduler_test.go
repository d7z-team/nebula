package nebula

import (
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSchedulerDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		s := newScheduler[int](16)
		delivered := make(chan int, 64)
		go s.Run(ctx, func(val int) { delivered <- val })

		canceled, cancel := context.WithCancel(ctx)
		s.Schedule(canceled, -1, time.Second)
		cancel()
		for batch := range 2 {
			var want []int
			for i := range 32 {
				val := batch*32 + i
				s.Schedule(ctx, val, time.Second)
				want = append(want, val)
			}
			synctest.Wait()
			require.Empty(t, delivered)
			time.Sleep(time.Second)
			synctest.Wait()
			require.Len(t, delivered, len(want))
			got := make([]int, len(want))
			for i := range got {
				got[i] = <-delivered
			}
			slices.Sort(got)
			require.Equal(t, want, got)
		}
	})
}

// Drain each batch so the bound on outstanding timers is independent of b.N.
func BenchmarkScheduler(b *testing.B) {
	const batch = 64
	ctx := b.Context()
	s := newScheduler[int](batch)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; {
		n := min(batch, b.N-i)
		for j := range n {
			s.Schedule(ctx, j, 0)
		}
		for range n {
			<-s.queue
		}
		i += n
	}
}
