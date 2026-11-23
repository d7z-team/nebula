package nebula

import (
	"context"

	"golang.org/x/time/rate"
)

// setShapingRate runs during construction or under n.mu.
func (n *Node) setShapingRate(bytesPerSecond int) {
	limit := rate.Inf
	if bytesPerSecond > 0 {
		limit = rate.Limit(bytesPerSecond)
	}
	if n.limiter == nil || limit != n.limiter.Limit() {
		if n.rateCancel != nil {
			n.rateCancel()
		}
		n.rateCtx, n.rateCancel = context.WithCancel(n.ctx)
		n.limiter = rate.NewLimiter(limit, MaxIPPacketSize+1)
	}
}

func (n *Node) shape(ctx context.Context, size int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n.mu.Lock()
		limiter, generation := n.limiter, n.rateCtx
		n.mu.Unlock()
		if limiter.Limit() != rate.Inf {
			wait, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(generation, cancel)
			err := limiter.WaitN(wait, size)
			stop()
			cancel()
			if generation.Err() != nil && n.ctx.Err() == nil {
				continue
			}
			if err != nil {
				return err
			}
		}
		n.bytesScheduled.Add(uint64(size))
		return nil
	}
}
