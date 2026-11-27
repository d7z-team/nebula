package nebula

import (
	"container/heap"
	"container/list"
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

const (
	relayBlockSize  = 16 << 10
	relayQuantum    = 4 << 10
	peerWriteBlocks = 2
)

type byteRequest struct {
	turn chan struct{}
	size int
}

type byteQueue struct {
	peer      PeerID
	pending   list.List // *byteRequest, borrowed until the caller returns
	served    uint64
	remainder uint64
	order     uint64
	writing   int
	windows   int // open relay directions for this ingress
	active    bool
	index     int
}

// Only neighbors with queued, writable work participate in selection.
type readyQueues []*byteQueue

func (q readyQueues) Len() int { return len(q) }
func (q readyQueues) Less(i, j int) bool {
	if q[i].served == q[j].served {
		return q[i].order < q[j].order
	}
	return q[i].served < q[j].served
}

func (q readyQueues) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}

func (q *readyQueues) Push(v any) {
	b := v.(*byteQueue)
	b.index = len(*q)
	*q = append(*q, b)
}

func (q *readyQueues) Pop() any {
	i := len(*q) - 1
	b := (*q)[i]
	(*q)[i] = nil
	*q = (*q)[:i]
	b.index = -1
	return b
}

// A direction shares write credit across all circuits between two adjacent
// identities. An unresponsive exit cannot occupy another exit's credit.
type (
	relayDirection struct{ from, to PeerID }
	writeWindow    struct {
		slots chan struct{}
		users int
	}
)

type fairShaper struct {
	mu             sync.Mutex
	limiter        *rate.Limiter
	rateCtx        context.Context
	cancelRate     context.CancelFunc
	weights        map[PeerID]uint16
	bytesScheduled atomic.Uint64
	windows        map[relayDirection]*writeWindow
	peers          map[PeerID]*byteQueue
	ready          readyQueues
	floor, order   uint64
	active         int
	current        *byteQueue // one reservation at the shared token bucket
}

func (f *fairShaper) openWindow(d relayDirection) *writeWindow {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.windows[d]
	if w == nil {
		if f.windows == nil {
			f.windows = make(map[relayDirection]*writeWindow)
		}
		w = &writeWindow{slots: make(chan struct{}, peerWriteBlocks)}
		f.windows[d] = w
		f.queueLocked(d.from).windows++
	}
	w.users++
	return w
}

func (f *fairShaper) closeWindow(d relayDirection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.windows[d]
	w.users--
	if w.users == 0 {
		delete(f.windows, d)
		q := f.peers[d.from]
		q.windows--
		f.updateLocked(q)
	}
}

func (f *fairShaper) queueLocked(peer PeerID) *byteQueue {
	q := f.peers[peer]
	if q == nil {
		if f.peers == nil {
			f.peers = make(map[PeerID]*byteQueue)
		}
		q = &byteQueue{peer: peer, served: f.floor, index: -1}
		f.peers[peer] = q
	}
	return q
}

// updateLocked follows every change to the pending queue or write credit.
func (f *fairShaper) updateLocked(q *byteQueue) {
	eligible := q.pending.Len() > 0 && q != f.current
	switch {
	case eligible && q.index < 0:
		q.served = max(q.served, f.floor)
		f.order++
		q.order = f.order
		heap.Push(&f.ready, q)
	case !eligible && q.index >= 0:
		heap.Remove(&f.ready, q.index)
	}
	active := eligible || q.writing > 0 || f.current == q
	if active != q.active {
		if active {
			f.active++
		} else {
			f.active--
		}
		q.active = active
	}
	if !active && q.windows == 0 {
		delete(f.peers, q.peer)
	}
}

func (f *fairShaper) grantLocked(q *byteQueue, size int) int {
	f.current = q
	q.served = max(q.served, f.floor)
	f.floor = q.served
	f.updateLocked(q)
	if q.peer != (PeerID{}) && f.active > 1 {
		return min(size, relayQuantum)
	}
	return size
}

func (f *fairShaper) finishWrite(peer PeerID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := f.peers[peer]
	q.writing--
	f.updateLocked(q)
}

// schedule arbitrates byte service before taking tokens. The zero peer accounts
// for indivisible local packets and publications. Relay callers return write
// credit after the actual transport write, independently of the token wait.
func (f *fairShaper) schedule(ctx context.Context, peer PeerID, size int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	if peer == (PeerID{}) && f.limiter.Limit() == rate.Inf {
		f.mu.Unlock()
		f.bytesScheduled.Add(uint64(size))
		return size, nil
	}
	q := f.queueLocked(peer)
	if f.current == nil {
		// The ready heap is empty whenever there is no current reservation.
		size = f.grantLocked(q, size)
		f.mu.Unlock()
	} else {
		req := byteRequest{turn: make(chan struct{}), size: size}
		entry := q.pending.PushBack(&req)
		f.updateLocked(q)
		f.mu.Unlock()
		select {
		case <-req.turn:
		case <-ctx.Done():
			f.mu.Lock()
			select {
			case <-req.turn:
				// A concurrent grant must pass the reservation on below.
			default:
				q.pending.Remove(entry)
				f.updateLocked(q)
				f.mu.Unlock()
				return 0, ctx.Err()
			}
			f.mu.Unlock()
		}
		size = req.size
	}
	err := f.waitForTokens(ctx, size)
	f.mu.Lock()
	if err == nil {
		f.bytesScheduled.Add(uint64(size))
		weight := uint64(max(1, f.weights[peer]))
		units := q.remainder + uint64(size)
		q.served += units / weight
		q.remainder = units % weight
		if peer != (PeerID{}) {
			q.writing++
		}
	}
	f.current = nil
	f.updateLocked(q)
	if len(f.ready) > 0 {
		next := f.ready[0]
		req := next.pending.Remove(next.pending.Front()).(*byteRequest)
		req.size = f.grantLocked(next, req.size)
		close(req.turn)
	}
	f.mu.Unlock()
	return size, err
}

func (f *fairShaper) setRate(parent context.Context, bytesPerSecond int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	limit := rate.Inf
	if bytesPerSecond > 0 {
		limit = rate.Limit(bytesPerSecond)
	}
	if f.limiter == nil || limit != f.limiter.Limit() {
		if f.cancelRate != nil {
			f.cancelRate()
		}
		f.rateCtx, f.cancelRate = context.WithCancel(parent)
		f.limiter = rate.NewLimiter(limit, MaxIPPacketSize+1)
	}
}

func (f *fairShaper) waitForTokens(ctx context.Context, size int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		f.mu.Lock()
		limiter, generation := f.limiter, f.rateCtx
		f.mu.Unlock()
		if limiter.Limit() == rate.Inf {
			return nil
		}
		wait, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(generation, cancel)
		err := limiter.WaitN(wait, size)
		stop()
		cancel()
		if generation.Err() != nil {
			f.mu.Lock()
			replaced := limiter != f.limiter
			f.mu.Unlock()
			if replaced {
				continue
			}
		}
		return err
	}
}
