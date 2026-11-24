package portshare

import (
	"net"
	"os"
	"sync"
	"time"
)

type datagram struct {
	data []byte
	from net.Addr
}

type packetConn struct {
	parent      *UDP
	in          chan datagram
	done        chan struct{}
	once        sync.Once
	read, write deadline
}

type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *deadline) set(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.at.Equal(at) {
		return
	}
	d.at = at
	close(d.changed)
	d.changed = make(chan struct{})
}

// A deadline change also wakes operations queued behind the other branch's writer.
func waitFor[T any](ready <-chan T, closed <-chan struct{}, d *deadline) (T, error) {
	var zero T
	for {
		select {
		case <-closed:
			return zero, net.ErrClosed
		default:
		}
		d.mu.Lock()
		at, changed := d.at, d.changed
		d.mu.Unlock()
		var timer *time.Timer
		var alarm <-chan time.Time
		if !at.IsZero() {
			left := time.Until(at)
			if left <= 0 {
				return zero, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(left)
			alarm = timer.C
		}
		var value T
		var err error
		retry := false
		select {
		case <-closed:
			err = net.ErrClosed
		case <-alarm:
			// The deadline may have been extended while the timer was ready.
			retry = true
		case <-changed:
			retry = true
		case value = <-ready:
		}
		if timer != nil {
			timer.Stop()
		}
		if !retry {
			return value, err
		}
	}
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pkt, err := waitFor(c.in, c.done, &c.read)
	if err != nil {
		return 0, nil, err
	}
	return copy(b, pkt.data), pkt.from, nil
}
func (c *packetConn) LocalAddr() net.Addr { return c.parent.raw.LocalAddr() }
func (c *packetConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		p := c.parent
		p.writeMu.Lock()
		defer p.writeMu.Unlock()
		if p.writer == c {
			p.raw.SetWriteDeadline(time.Now())
		}
	})
	return nil
}

func (c *packetConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.read.set(t)
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	p := c.parent
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.write.set(t)
	if p.writer == c {
		return p.raw.SetWriteDeadline(t)
	}
	return nil
}

func (c *packetConn) WriteTo(b []byte, to net.Addr) (int, error) {
	p := c.parent
	if _, err := waitFor(p.writeSlot, c.done, &c.write); err != nil {
		return 0, err
	}
	defer func() { p.writeSlot <- struct{}{} }()
	p.writeMu.Lock()
	select {
	case <-c.done:
		p.writeMu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	// SetWriteDeadline also holds writeMu when it changes c.write.at.
	if err := p.raw.SetWriteDeadline(c.write.at); err != nil {
		p.writeMu.Unlock()
		return 0, err
	}
	p.writer = c
	p.writeMu.Unlock()
	n, err := p.raw.WriteTo(b, to)
	p.writeMu.Lock()
	p.writer = nil
	p.writeMu.Unlock()
	if err != nil {
		select {
		case <-c.done:
			return n, net.ErrClosed
		default:
		}
	}
	return n, err
}

func (c *packetConn) deliver(pkt datagram) {
	select {
	case <-c.done:
		return
	default:
	}
	// Queue pressure on one branch must not stall the physical reader.
	select {
	case c.in <- pkt:
	default:
	}
}
