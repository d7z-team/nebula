package nebula

import (
	"context"
	"math"
	"sync"
	"time"
)

// scheduler delivers delayed jobs to a single worker and reuses their timers.
type scheduler[T any] struct {
	queue chan T
	pool  sync.Pool
}

type schedItem[T any] struct {
	val   T
	ctx   context.Context
	timer *time.Timer
}

func newScheduler[T any](queueSize int) *scheduler[T] {
	s := &scheduler[T]{queue: make(chan T, queueSize)}
	s.pool.New = func() any {
		item := &schedItem[T]{}
		// Initialize the timer before Reset can fire and recycle the item on another goroutine.
		item.timer = time.AfterFunc(math.MaxInt64, func() {
			if item.ctx.Err() == nil {
				select {
				case s.queue <- item.val:
				case <-item.ctx.Done():
				}
			}
			var zero T
			item.val = zero
			item.ctx = nil
			s.pool.Put(item)
		})
		item.timer.Stop()
		return item
	}
	return s
}

func (s *scheduler[T]) Schedule(ctx context.Context, val T, delay time.Duration) {
	item := s.pool.Get().(*schedItem[T])
	item.val = val
	item.ctx = ctx
	item.timer.Reset(delay)
}

func (s *scheduler[T]) Run(ctx context.Context, fn func(T)) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.queue:
			fn(item)
		}
	}
}
