package nebula

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// EgressStats measures shaped outer UDP payloads, including any configured prefix.
// SentBytes includes ControlBytes. QueuedBytes includes a data packet waiting for tokens.
type EgressStats struct {
	QueuedBytes                           int
	SentBytes, ControlBytes, DroppedBytes uint64
	LastQueueDelay                        time.Duration
}

type egressItem struct {
	host, ingress *hostInfo
	path          tunnelRoute
	wire          []byte
	size          int
	finish        uint64
	queued        time.Time
	done          chan error
}

type egressShaper struct {
	mu            sync.Mutex
	wake          chan struct{}
	rateChanged   chan struct{}
	queues        map[netip.Addr][]egressItem
	virtual       uint64
	speed         int
	data, control *rate.Limiter
	counters      EgressStats
}

func (s *egressShaper) stats() EgressStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters
}

func (s *egressShaper) setRate(speed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.speed == speed {
		return
	}
	close(s.rateChanged)
	s.rateChanged = make(chan struct{})
	s.speed = speed
	// Independent buckets reserve a bounded share for prompt control submission.
	s.data = rate.NewLimiter(rate.Limit(float64(speed)*0.9), mtu+1024)
	s.control = rate.NewLimiter(rate.Limit(float64(speed)*0.1), mtu+1024)
}

func (s *egressShaper) submit(c *controlPlane, h *hostInfo, r tunnelRoute, b []byte, in *hostInfo) error {
	s.mu.Lock()
	if c.n.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrNodeClosed
	}
	if s.speed == 0 {
		s.mu.Unlock()
		return c.n.engine.submitPath(h, r, b, false, in)
	}
	size := len(b) + len(c.n.engine.datagramMagic)
	if size > mtu+1024 || s.counters.QueuedBytes+size > 256*1024 {
		s.counters.DroppedBytes += uint64(size)
		s.mu.Unlock()
		return ErrQueueFull
	}
	owner := h.vpnAddrs[0]
	if in != nil {
		owner = in.vpnAddrs[0]
	}
	if r.owner.IsValid() {
		owner = r.owner
	}
	q := s.queues[owner]
	if len(q) > 0 && q[len(q)-1].finish-q[0].finish+uint64(q[0].size+size) > 64*1024 {
		s.counters.DroppedBytes += uint64(size)
		s.mu.Unlock()
		return ErrQueueFull
	}
	start := s.virtual
	if len(q) > 0 {
		start = max(start, q[len(q)-1].finish)
	}
	item := egressItem{host: h, ingress: in, path: r, wire: slices.Clone(b), size: size, finish: start + uint64(size), queued: time.Now()}
	if in == nil {
		item.done = make(chan error, 1)
	}
	s.queues[owner] = append(q, item)
	s.counters.QueuedBytes += size
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	if item.done == nil {
		return nil
	}
	select {
	case <-c.n.ctx.Done():
		return ErrNodeClosed
	case err := <-item.done:
		return err
	}
}

// The caller holds a submission permit, so the configured rate is stable.
func (s *egressShaper) writeControl(c *controlPlane, packet []byte, to netip.AddrPort) error {
	size := len(packet) + len(c.n.engine.datagramMagic)
	now := time.Now()
	s.mu.Lock()
	// Control can borrow unused data tokens after consuming its reserved share.
	if !s.control.AllowN(now, size) && !s.data.AllowN(now, size) {
		s.counters.DroppedBytes += uint64(size)
		s.mu.Unlock()
		return errPathBudget
	}
	s.mu.Unlock()
	err := c.n.engine.writeDatagram(packet, to)
	s.mu.Lock()
	if err == nil {
		s.counters.ControlBytes += uint64(size)
		s.counters.SentBytes += uint64(size)
	} else {
		s.counters.DroppedBytes += uint64(size)
	}
	s.mu.Unlock()
	return err
}

func (s *egressShaper) run(c *controlPlane) {
	ctx := c.n.ctx
	defer func() {
		s.mu.Lock()
		s.counters.DroppedBytes += uint64(s.counters.QueuedBytes)
		s.counters.QueuedBytes = 0
		clear(s.queues)
		s.mu.Unlock()
	}()
	for ctx.Err() == nil {
		s.mu.Lock()
		var owner netip.Addr
		for a, q := range s.queues {
			if !owner.IsValid() || q[0].finish < s.queues[owner][0].finish {
				owner = a
			}
		}
		if !owner.IsValid() {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
			}
			continue
		}
		q := s.queues[owner]
		item := q[0]
		q[0] = egressItem{}
		if len(q) == 1 {
			delete(s.queues, owner)
		} else {
			s.queues[owner] = q[1:]
		}
		s.virtual = item.finish
		s.mu.Unlock()
		var err error
		for {
			s.mu.Lock()
			if s.speed == 0 {
				s.mu.Unlock()
				break
			}
			res := s.data.ReserveN(time.Now(), item.size)
			changed := s.rateChanged
			s.mu.Unlock()
			delay := res.Delay()
			if delay <= 0 {
				break
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				res.Cancel()
				err = ErrNodeClosed
			case <-changed:
				timer.Stop()
				res.Cancel()
				continue
			}
			break
		}
		if err == nil {
			err = c.n.engine.submitPath(item.host, item.path, item.wire, false, item.ingress)
		}
		s.mu.Lock()
		s.counters.QueuedBytes -= item.size
		s.counters.LastQueueDelay = time.Since(item.queued)
		if err == nil {
			s.counters.SentBytes += uint64(item.size)
		} else {
			s.counters.DroppedBytes += uint64(item.size)
		}
		s.mu.Unlock()
		if item.done != nil {
			item.done <- err
		}
	}
}
