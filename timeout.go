package nebula

import (
	"sync"
	"time"
)

const timerCacheMax = 50000

// timerWheel batches handshake retries and traffic checks at tick boundaries.
// Each bucket and the expired queue preserve insertion order.
type timerWheel[T any] struct {
	mu                          sync.Mutex
	tickDuration, wheelDuration time.Duration
	started                     bool
	lastTick                    time.Time
	current                     int
	wheel                       []timeoutList[T]
	expired                     timeoutList[T]
	itemCache                   *timeoutItem[T]
	itemsCached                 int
}

type timeoutList[T any] struct {
	head, tail *timeoutItem[T]
}

type timeoutItem[T any] struct {
	item T
	next *timeoutItem[T]
}

func newTimerWheel[T any](tick, duration time.Duration) *timerWheel[T] {
	// Allow a full-duration delay even when the current tick is almost over.
	return &timerWheel[T]{tickDuration: tick, wheelDuration: duration, wheel: make([]timeoutList[T], duration/tick+2)}
}

func (tw *timerWheel[T]) Add(v T, delay time.Duration) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	delay = min(max(delay, tw.tickDuration), tw.wheelDuration)
	ticks := int((delay-1)/tw.tickDuration) + 1
	bucket := &tw.wheel[(tw.current+1+ticks)%len(tw.wheel)]
	item := tw.itemCache
	if item == nil {
		item = &timeoutItem[T]{}
	} else {
		tw.itemCache = item.next
		tw.itemsCached--
		item.next = nil
	}
	item.item = v
	if bucket.tail == nil {
		bucket.head = item
	} else {
		bucket.tail.next = item
	}
	bucket.tail = item
}

// Purge returns the oldest item made ready by Advance.
func (tw *timerWheel[T]) Purge() (T, bool) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	var zero T
	item := tw.expired.head
	if item == nil {
		return zero, false
	}
	tw.expired.head = item.next
	if tw.expired.head == nil {
		tw.expired.tail = nil
	}
	val := item.item
	if tw.itemsCached < timerCacheMax {
		item.item = zero
		item.next = tw.itemCache
		tw.itemCache = item
		tw.itemsCached++
	}
	return val, true
}

// Advance preserves the fractional tick when moving buckets to the ready queue.
func (tw *timerWheel[T]) Advance(now time.Time) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if !tw.started {
		tw.lastTick = now
		tw.started = true
		return
	}
	elapsed := int64(now.Sub(tw.lastTick) / tw.tickDuration)
	for range min(elapsed, int64(len(tw.wheel))) {
		tw.current = (tw.current + 1) % len(tw.wheel)
		bucket := &tw.wheel[tw.current]
		if bucket.head == nil {
			continue
		}
		if tw.expired.tail == nil {
			tw.expired.head = bucket.head
		} else {
			tw.expired.tail.next = bucket.head
		}
		tw.expired.tail = bucket.tail
		*bucket = timeoutList[T]{}
	}
	tw.lastTick = tw.lastTick.Add(time.Duration(elapsed) * tw.tickDuration)
}
