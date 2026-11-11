package nebula

import (
	"context"
	"fmt"
	"log/slog"
	"math"
)

const bitsPerWord = 64

// replayWindowBits is a sliding-window anti-replay tracker. The window is stored as a
// circular bitmap packed into uint64 words (8x denser than a []bool), so a
// length-N window costs N/8 bytes. length must be a power of two.
type replayWindowBits struct {
	length     uint64
	lengthMask uint64
	current    uint64
	bits       []uint64
}

func newReplayWindow(length uint64) *replayWindowBits {
	if length == 0 || length&(length-1) != 0 {
		panic(fmt.Sprintf("replayWindowBits length must be a power of two, got %d", length))
	}

	nWords := length / bitsPerWord
	if nWords == 0 {
		nWords = 1
	}
	b := &replayWindowBits{
		length:     length,
		lengthMask: length - 1,
		bits:       make([]uint64, nWords),
	}

	// There is no valid packet counter 0, so mark it as already seen.
	b.bits[0] = 1
	return b
}

func (b *replayWindowBits) get(i uint64) bool {
	pos := i & b.lengthMask
	//bit-shifting by 6 because i is a bit index, not a u64 index, and we need to find the u64 without bit in it
	return b.bits[pos>>6]&(uint64(1)<<(pos&63)) != 0
}

func (b *replayWindowBits) set(i uint64) {
	pos := i & b.lengthMask
	b.bits[pos>>6] |= uint64(1) << (pos & 63)
}

// clearRange clears count bits starting at circular position startPos.
// count must be in [1, length].
func (b *replayWindowBits) clearRange(startPos, count uint64) {
	if count >= b.length {
		clear(b.bits)
		return
	}

	pos := startPos
	remaining := count

	// handle the potential partial word before pos becomes u64 aligned
	word := pos >> 6
	bit := pos & 63
	take := min(min(uint64(64)-bit, remaining), b.length-pos)
	var mask uint64
	if take == 64 {
		mask = math.MaxUint64
	} else {
		mask = ((uint64(1) << take) - 1) << bit
	}
	b.bits[word] &^= mask
	remaining -= take
	pos = (pos + take) & b.lengthMask

	// Clear whole words.
	for remaining >= 64 {
		word = pos >> 6
		b.bits[word] = 0
		remaining -= 64
		pos = (pos + 64) & b.lengthMask
	}

	// Clear the remaining partial word
	if remaining > 0 {
		word = pos >> 6
		mask = (uint64(1) << remaining) - 1
		b.bits[word] &^= mask
	}
}

func (b *replayWindowBits) strictlyWithinWindow(i uint64) bool {
	// Handle the case where the window hasn't slid yet. This avoids u64 underflow.
	inWarmup := b.current < b.length
	if i < b.length && inWarmup {
		return true
	}

	// Next, if the packet is in-window, see if we've seen it before
	if i > b.current-b.length {
		return true
	}
	return false //not within window!
}

// Check returns true if i is within (or way out in front of) the window, and not a replay
func (b *replayWindowBits) Check(l *slog.Logger, i uint64) bool {
	// If i is the next number, return true.
	if i > b.current {
		return true
	}

	if b.strictlyWithinWindow(i) {
		return !b.get(i)
	}

	// Not within the window
	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("rejected a packet (top)", "current", b.current, "incoming", i)
	}
	return false
}

// Update has three branches:
//   - i == b.current+1: fast path; advance the cursor by one.
//   - i  >  b.current+1: jump path; clear all slots between current and i
//     (or up to a full window's worth, whichever is smaller) via clearRange,
//     then mark i.
//   - i  <= b.current: in-window check for duplicates; out-of-window otherwise.
//
// newReplayWindow seeds bits[0]=1 so counter 0 looks "received" — Update never
// clears that marker during warmup (clearRange skips position 0 when
// startPos=1), and once b.current >= b.length the marker is no longer
// consulted.
func (b *replayWindowBits) Update(l *slog.Logger, i uint64) bool {
	// Fast path: i is the next expected counter. Split out so the function
	// stays small and avoids paying for the slow paths' slog argument-build
	// stack frame on every call. The bit read/test/write is inlined to
	// touch the backing word once.
	if i == b.current+1 {
		pos := i & b.lengthMask
		word := pos >> 6
		mask := uint64(1) << (pos & 63)
		w := b.bits[word]
		b.bits[word] = w | mask
		b.current = i
		return true
	}
	return b.updateSlow(l, i)
}

// updateSlow handles jumps, in-window backfill, dupes, and out-of-window.
func (b *replayWindowBits) updateSlow(l *slog.Logger, i uint64) bool {
	// If i is a jump, adjust the window, update current, and return true.
	if i > b.current {
		end := min(i, b.current+b.length)
		count := end - b.current
		startPos := (b.current + 1) & b.lengthMask
		b.clearRange(startPos, count)

		b.set(i)
		b.current = i
		return true
	}

	// If i is within the current window but below the current counter, check to see if it's a duplicate
	if b.strictlyWithinWindow(i) {
		pos := i & b.lengthMask
		word := pos >> 6
		mask := uint64(1) << (pos & 63)
		w := b.bits[word]
		if b.current == i || w&mask != 0 {
			if l.Enabled(context.Background(), slog.LevelDebug) {
				l.Debug("Receive window",
					"accepted", false,
					"currentCounter", b.current,
					"incomingCounter", i,
					"reason", "duplicate",
				)
			}
			return false
		}

		b.bits[word] = w | mask
		return true
	}

	// In all other cases, fail and don't change current.
	if l.Enabled(context.Background(), slog.LevelDebug) {
		l.Debug("Receive window",
			"accepted", false,
			"currentCounter", b.current,
			"incomingCounter", i,
			"reason", "nonsense",
		)
	}
	return false
}
