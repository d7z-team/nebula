package nebula

import (
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// snapshot returns the bitmap as a []bool of length b.length, for readable
// test assertions against the now-packed []uint64 storage.
func (b *replayWindowBits) snapshot() []bool {
	out := make([]bool, b.length)
	for i := uint64(0); i < b.length; i++ {
		out[i] = b.get(i)
	}
	return out
}

func TestBitsRequiresPowerOfTwo(t *testing.T) {
	assert.Panics(t, func() { newReplayWindow(10) })
	assert.Panics(t, func() { newReplayWindow(0) })
	assert.NotPanics(t, func() { newReplayWindow(1) })
	assert.NotPanics(t, func() { newReplayWindow(16) })
	assert.NotPanics(t, func() { newReplayWindow(1024) })
	assert.NotPanics(t, func() { newReplayWindow(16384) })
}

func TestBits(t *testing.T) {
	l := test.NewLogger()
	b := newReplayWindow(16)
	assert.EqualValues(t, 16, b.length)

	// This is initialized to zero - receive one. This should work.
	assert.True(t, b.Check(l, 1))
	assert.True(t, b.Update(l, 1))
	assert.EqualValues(t, 1, b.current)
	g := []bool{true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Receive two
	assert.True(t, b.Check(l, 2))
	assert.True(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)
	g = []bool{true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Receive two again - it will fail
	assert.False(t, b.Check(l, 2))
	assert.False(t, b.Update(l, 2))
	assert.EqualValues(t, 2, b.current)

	// Jump ahead to 25, which clears the window and sets slot 25%16 = 9.
	assert.True(t, b.Check(l, 25))
	assert.True(t, b.Update(l, 25))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Mark 24, which is in window (current 25, length 16, window covers [10,25]).
	assert.True(t, b.Check(l, 24))
	assert.True(t, b.Update(l, 24))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Mark 5, not allowed because 5 <= current-length (25-16=9).
	assert.False(t, b.Check(l, 5))
	assert.False(t, b.Update(l, 5))
	assert.EqualValues(t, 25, b.current)
	g = []bool{false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false}
	assert.Equal(t, g, b.snapshot())

	// Make sure we handle wrapping around once to the same slot. With
	// length=16, packets 1 and 17 share slot 1.
	b = newReplayWindow(16)
	assert.True(t, b.Update(l, 1))
	assert.True(t, b.Update(l, 17))
	assert.Equal(t, []bool{false, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false}, b.snapshot())

	// Walk through a few windows in order
	b = newReplayWindow(16)
	for i := uint64(1); i <= 100; i++ {
		assert.True(t, b.Check(l, i), "Error while checking %v", i)
		assert.True(t, b.Update(l, i), "Error while updating %v", i)
	}

	assert.False(t, b.Check(l, 1), "Out of window check")
}

// TestBitsCheckAcrossWarmupBoundary pins the underflow trick in Check's
// in-window clause. While in warmup, b.current-b.length underflows uint64
// to a huge value so the first OR-clause is always false; the second
// clause (i < length && current < length) carries the in-window check.
// Once current >= length the regimes flip cleanly.
func TestBitsCheckAcrossWarmupBoundary(t *testing.T) {
	l := test.NewLogger()
	b := newReplayWindow(16)

	// Warmup: current=0. Check(0) must read the marker (set) and return false.
	assert.False(t, b.Check(l, 0), "marker slot should look already-received")
	// Warmup: any 0 < i < length is in-window and unset → accepted.
	for i := uint64(1); i < 16; i++ {
		assert.True(t, b.Check(l, i), "warmup in-window i=%d should be accepted", i)
	}
	// Warmup: i >= length but > current is "next number" so accepted.
	assert.True(t, b.Check(l, 16))
	assert.True(t, b.Check(l, 1_000_000))

	// Cross into steady state.
	assert.True(t, b.Update(l, 100))
	// Now current=100, length=16. In-window range is [85..100].
	// 84 is just outside: the underflow clause activates; 84 > 100-16=84 is false.
	// And the warmup clause is false (current >= length). So out of window.
	assert.False(t, b.Check(l, 84))
	// 85 sits at the boundary. 85 > 84 is true → in window, unset → accept.
	assert.True(t, b.Check(l, 85))
	// 100 is current itself; not strictly greater, in-window, but already set.
	assert.False(t, b.Check(l, 100))
	// Way out: clearly out of window.
	assert.False(t, b.Check(l, 50))
}

// TestBitsMarkerInvariant verifies the seeded bits[0]=1 marker behaves
// correctly across warmup and beyond.
func TestBitsMarkerInvariant(t *testing.T) {
	l := test.NewLogger()
	b := newReplayWindow(8)

	// Counter 0 is the seeded marker; Check sees it as already received.
	assert.False(t, b.Check(l, 0))
	// Update(0) at current=0 hits the duplicate branch.
	assert.False(t, b.Update(l, 0))

	// Walk forward through warmup; the marker must remain set.
	for n := uint64(1); n <= 7; n++ {
		assert.True(t, b.Update(l, n))
	}
	// Position 0 (the marker) should still read as set because we never
	// cleared it; Update(0) still looks like a duplicate.
	assert.False(t, b.Check(l, 0))

	// Cross into steady state with a unit advance to 8: pos=0 now represents
	// counter 8 rather than the marker.
	assert.True(t, b.Update(l, 8))
	// The slot at pos 0 is now occupied by counter 8.
	assert.False(t, b.Check(l, 8))
}

// BenchmarkBitsUpdateInOrder is the steady-state hot path: each call is
// i == current+1.
func BenchmarkBitsUpdateInOrder(b *testing.B) {
	l := test.NewLogger()
	z := newReplayWindow(16384)
	for n := 0; n < b.N; n++ {
		z.Update(l, uint64(n)+1)
	}
}

// BenchmarkBitsUpdateReorder simulates light reorder within the window:
// every other packet arrives one slot behind its predecessor (forces the
// in-window backfill branch).
func BenchmarkBitsUpdateReorder(b *testing.B) {
	l := test.NewLogger()
	z := newReplayWindow(16384)
	for n := 0; n < b.N; n++ {
		base := uint64(n) * 2
		z.Update(l, base+2)
		z.Update(l, base+1)
	}
}

// BenchmarkBitsUpdateLargeJumps stresses the clearRange word-level path.
func BenchmarkBitsUpdateLargeJumps(b *testing.B) {
	l := test.NewLogger()
	z := newReplayWindow(16384)
	for n := 0; n < b.N; n++ {
		z.Update(l, uint64(n+1)*1000)
	}
}
