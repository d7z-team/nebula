package nebula

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimerWheelDelivery(t *testing.T) {
	const tick = 10 * time.Millisecond
	wheel := newTimerWheel[string](tick, 4*tick)
	start := time.Time{}
	wheel.Advance(start)
	wheel.Add("short", tick/2)
	wheel.Add("same tick", tick)
	wheel.Add("rounded", tick+1)
	wheel.Add("capped", 100*tick)
	wheel.Advance(start.Add(tick + tick/2))
	_, ok := wheel.Purge()
	require.False(t, ok)

	// Advancing again keeps the fractional tick and delivers the bucket in order.
	wheel.Advance(start.Add(2 * tick))
	for _, want := range []string{"short", "same tick"} {
		got, ok := wheel.Purge()
		require.True(t, ok)
		require.Equal(t, want, got)
	}
	wheel.Advance(start.Add(3 * tick))
	got, ok := wheel.Purge()
	require.True(t, ok)
	require.Equal(t, "rounded", got)
	wheel.Add("next rotation", 3*tick)
	wheel.Advance(start.Add(50 * tick))
	for _, want := range []string{"capped", "next rotation"} {
		got, ok := wheel.Purge()
		require.True(t, ok)
		require.Equal(t, want, got)
	}
	_, ok = wheel.Purge()
	require.False(t, ok)
}
