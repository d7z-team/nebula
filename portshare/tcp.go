// Package portshare multiplexes a node and host applications on the same underlay socket.
package portshare

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"gopkg.d7z.net/nebula/meshwire"
)

// TCP owns a physical listener and delivers original, unhandshaken connections to two listeners.
type TCP struct {
	alpn        string
	done        chan struct{}
	raw         net.Listener
	mesh, other *listener
	workers     sync.WaitGroup
	once        sync.Once
	err         error
}
type listener struct {
	err  error
	addr net.Addr
	in   chan net.Conn
	done chan struct{}
	once sync.Once
}

// NewTCP takes ownership of l and classifies incoming connections using meshwire.ALPN.
func NewTCP(l net.Listener) *TCP {
	return newTCP(l, meshwire.ALPN)
}

// NewTCPWithALPN takes ownership of l on success. Clients offering only alpn
// go to Mesh. An empty alpn selects meshwire.ALPN.
func NewTCPWithALPN(l net.Listener, alpn string) (*TCP, error) {
	alpn, err := meshwire.ResolveALPN(alpn)
	if err != nil {
		return nil, err
	}
	return newTCP(l, alpn), nil
}

func newTCP(l net.Listener, alpn string) *TCP {
	branch := func() *listener { return &listener{addr: l.Addr(), in: make(chan net.Conn), done: make(chan struct{})} }
	t := &TCP{alpn: alpn, done: make(chan struct{}), raw: l, mesh: branch(), other: branch()}
	t.workers.Go(func() {
		slots := make(chan struct{}, maxPending)
		for {
			c, err := meshwire.AcceptTCP(l, t.done)
			if err != nil {
				t.mesh.shutdown(err)
				t.other.shutdown(err)
				return
			}
			select {
			case slots <- struct{}{}:
				t.workers.Go(func() {
					defer func() { <-slots }()
					t.dispatch(c)
				})
			default:
				c.Close()
			}
		}
	})
	return t
}

// Mesh returns the listener for clients offering only the mesh ALPN.
func (t *TCP) Mesh() net.Listener { return t.mesh }

// Other returns the listener for the host's TLS and plaintext services.
func (t *TCP) Other() net.Listener { return t.other }

// Close closes the physical listener and both branches. Accepted connections belong to their recipient.
func (t *TCP) Close() error {
	t.once.Do(func() {
		close(t.done)
		t.err = t.raw.Close()
		t.mesh.Close()
		t.other.Close()
		t.workers.Wait()
	})
	return t.err
}
func (l *listener) Addr() net.Addr     { return l.addr }
func (l *listener) shutdown(err error) { l.once.Do(func() { l.err = err; close(l.done) }) }
func (l *listener) Close() error       { l.shutdown(net.ErrClosed); return nil }
func (l *listener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, l.err
	default:
	}
	select {
	case <-l.done:
		return nil, l.err
	case c := <-l.in:
		return c, nil
	}
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (t *TCP) dispatch(c net.Conn) {
	timer := time.NewTimer(classifyTimeout)
	defer timer.Stop()
	if err := c.SetReadDeadline(time.Now().Add(classifyTimeout)); err != nil {
		c.Close()
		return
	}
	r := bufio.NewReader(c)
	var original bytes.Buffer
	records := io.TeeReader(r, &original)
	var hello []byte
	branch := t.other
	for {
		first, err := r.Peek(1)
		if err != nil {
			if err == io.EOF {
				break
			}
			c.Close()
			return
		}
		if first[0] != 22 {
			break
		}
		var header [5]byte
		_, err = io.ReadFull(records, header[:])
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				break
			}
			c.Close()
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[1] != 3 || header[2] > 3 || length > 16384 {
			break
		}
		if original.Len()+length > helloLimit+4096 {
			c.Close()
			return
		}
		start := len(hello)
		hello = append(hello, make([]byte, length)...)
		_, err = io.ReadFull(records, hello[start:])
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			c.Close()
			return
		}
		if len(hello) == 0 {
			continue
		}
		if hello[0] != 1 {
			break
		}
		if len(hello) < 4 {
			continue
		}
		size := helloSize(hello)
		if size > helloLimit {
			c.Close()
			return
		}
		if len(hello) >= size {
			if offersOnlyALPN(hello[4:size], t.alpn) {
				branch = t.mesh
			}
			break
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return
	}
	select {
	case branch.in <- &replayConn{c, io.MultiReader(&original, r)}:
	case <-branch.done:
		c.Close()
	case <-timer.C:
		c.Close()
	}
}
