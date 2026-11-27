package portshare

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"sync"
	"time"

	"code.d7z.net/d7z-team/nebula/meshwire"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	meshCIDLen           = 20
	nonceLen             = 12
	branchQueueSize      = 256 // Datagrams per logical socket.
	maxPendingDatagrams  = 48
	maxPendingBytes      = 96 << 10
	maxInitialRoutes     = 4096
	initialRouteLifetime = 5 * time.Second
)

// UDP owns a physical packet socket. Its two branches share the local address
// and preserve each datagram's payload, boundary and source. A terminal read
// error on the physical socket is reported on both open branches.
type UDP struct {
	raw       net.PacketConn
	mesh      *meshSocket
	other     *packetConn
	secret    [32]byte
	readMAC   hash.Hash // used only by the reader
	digest    [sha256.Size]byte
	resets    resetRegistry
	writeSlot chan struct{}
	writeMu   sync.Mutex
	writer    *packetConn
	once      sync.Once
	err       error
	stopped   chan struct{}
	pending   map[initialFlow]*flight
	routes    map[initialFlow]initialRoute
}
type (
	meshSocket   struct{ *packetConn }
	initialFlow  struct{ address, cid string }
	initialRoute struct {
		branch *packetConn
		until  time.Time
	}
)

type flight struct {
	keys                    initialKeys
	data, seen              []byte
	contiguous, queuedBytes int
	queue                   []datagram
	until                   time.Time
}

// NewUDP takes ownership of socket and starts reading datagrams.
func NewUDP(socket net.PacketConn) *UDP {
	p := &UDP{
		raw: socket, writeSlot: make(chan struct{}, 1), stopped: make(chan struct{}),
		pending: make(map[initialFlow]*flight), routes: make(map[initialFlow]initialRoute),
	}
	p.writeSlot <- struct{}{}
	rand.Read(p.secret[:])
	p.readMAC = hmac.New(sha256.New, p.secret[:])
	branch := func() *packetConn {
		return &packetConn{
			parent: p, in: make(chan datagram, branchQueueSize), done: make(chan struct{}),
			read: deadline{changed: make(chan struct{})}, write: deadline{changed: make(chan struct{})},
		}
	}
	p.mesh, p.other = &meshSocket{branch()}, branch()
	go func() {
		err := p.read()
		p.mesh.shutdown(err)
		p.other.shutdown(err)
		close(p.stopped)
	}()
	return p
}

// Mesh returns the shared socket for the node's UDP4 or UDP6 option.
// Applications constructing their own QUIC transport can call its ConfigureMeshQUIC method.
func (p *UDP) Mesh() meshwire.SharedSocket { return p.mesh }

// Other returns the host application's packet socket, suitable for http3.Server.Serve.
func (p *UDP) Other() net.PacketConn { return p.other }

// Close closes the physical socket and releases both branches.
func (p *UDP) Close() error {
	p.once.Do(func() {
		p.mesh.Close()
		p.other.Close()
		p.err = p.raw.Close()
		<-p.stopped
	})
	return p.err
}

func (c *meshSocket) ConfigureMeshQUIC(t *quic.Transport, conf *quic.Config) {
	t.ConnectionIDGenerator = c
	conf.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return &c.parent.resets }
}
func (c *meshSocket) ConnectionIDLen() int { return meshCIDLen }
func (c *meshSocket) GenerateConnectionID() (quic.ConnectionID, error) {
	var id [meshCIDLen]byte
	rand.Read(id[:nonceLen])
	mac := hmac.New(sha256.New, c.parent.secret[:])
	mac.Write(id[:nonceLen])
	copy(id[nonceLen:], mac.Sum(nil))
	return quic.ConnectionIDFromBytes(id[:]), nil
}

func (p *UDP) ownsCID(cid []byte) bool {
	if len(cid) != meshCIDLen {
		return false
	}
	p.readMAC.Reset()
	p.readMAC.Write(cid[:nonceLen])
	return hmac.Equal(cid[nonceLen:], p.readMAC.Sum(p.digest[:0])[:meshCIDLen-nonceLen])
}

func (p *UDP) read() error {
	defer clear(p.pending)
	defer clear(p.routes)
	buf := make([]byte, 65535)
	var sweep time.Time
	if err := p.raw.SetReadDeadline(sweep); err != nil {
		return err
	}
	for {
		if sweep.IsZero() && (len(p.pending) != 0 || len(p.routes) != 0) {
			sweep = time.Now().Add(time.Second)
			if err := p.raw.SetReadDeadline(sweep); err != nil {
				return err
			}
		}
		n, from, err := p.raw.ReadFrom(buf)
		if err != nil {
			if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
				return err
			}
		}
		now := time.Now()
		if !sweep.IsZero() && !now.Before(sweep) {
			for k, f := range p.pending {
				if !now.Before(f.until) {
					delete(p.pending, k)
				}
			}
			for k, r := range p.routes {
				if !now.Before(r.until) {
					delete(p.routes, k)
				}
			}
			sweep = time.Time{}
			if e := p.raw.SetReadDeadline(sweep); e != nil {
				return e
			}
		}
		if err != nil {
			continue
		}
		p.route(datagram{bytes.Clone(buf[:n]), from}, now)
	}
}

func (p *UDP) route(pkt datagram, now time.Time) {
	b := pkt.data
	// The mesh NAT punch has no reply.
	if len(b) == 1 && b[0] == 0 {
		return
	}
	switch {
	case len(b) >= 1+meshCIDLen && b[0]&0xc0 == 0x40:
		if p.ownsCID(b[1:1+meshCIDLen]) || p.resets.owns([16]byte(b[len(b)-16:])) {
			p.mesh.deliver(pkt)
			return
		}
	case len(b) >= 7 && b[0]&0x80 != 0 && int(b[5])+7 <= len(b):
		cid := b[6 : 6+int(b[5])]
		if p.ownsCID(cid) {
			p.mesh.deliver(pkt)
			return
		}
		if len(b) >= 1200 && len(cid) >= 8 && len(cid) <= 20 && b[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(b[1:5]) == 1 {
			p.routeInitial(pkt, cid, now)
			return
		}
	}
	p.other.deliver(pkt)
}

func (p *UDP) routeInitial(pkt datagram, cid []byte, now time.Time) {
	b := pkt.data
	key := initialFlow{pkt.from.String(), string(cid)}
	if r, ok := p.routes[key]; ok && now.Before(r.until) {
		r.branch.deliver(pkt)
		return
	}
	f := p.pending[key]
	if f != nil && !now.Before(f.until) {
		delete(p.pending, key)
		f = nil
	}
	if f == nil {
		if len(p.pending) >= maxPending {
			return
		}
		keys, err := clientInitialKeys(cid)
		if err != nil {
			return
		}
		f = &flight{keys: keys, until: now.Add(classifyTimeout)}
	}
	if len(f.queue) >= maxPendingDatagrams || f.queuedBytes+len(b) > maxPendingBytes {
		return
	}
	if err := f.keys.readInitial(b, cid, f.addCrypto); err != nil {
		if errors.Is(err, errAssembly) {
			delete(p.pending, key)
		} else if len(f.queue) == 0 {
			p.other.deliver(pkt)
		}
		return
	}
	f.queue = append(f.queue, pkt)
	f.queuedBytes += len(b)
	if f.contiguous < 4 {
		p.pending[key] = f
		return
	}
	size := helloSize(f.data)
	if size > helloLimit {
		delete(p.pending, key)
		return
	}
	if f.data[0] == 1 && f.contiguous < size {
		p.pending[key] = f
		return
	}
	branch := p.other
	if f.data[0] == 1 && meshHello(f.data[:size]) {
		branch = p.mesh.packetConn
	}
	if len(p.routes) < maxInitialRoutes {
		p.routes[key] = initialRoute{branch, now.Add(initialRouteLifetime)}
	}
	delete(p.pending, key)
	for _, packet := range f.queue {
		branch.deliver(packet)
	}
}

func (f *flight) addCrypto(offset uint64, data []byte) error {
	if offset > helloLimit || len(data) > helloLimit-int(offset) {
		return errAssembly
	}
	end := int(offset) + len(data)
	if end > len(f.data) {
		f.data = append(f.data, make([]byte, end-len(f.data))...)
		f.seen = append(f.seen, make([]byte, end-len(f.seen))...)
	}
	for i, value := range data {
		j := int(offset) + i
		if f.seen[j] != 0 && f.data[j] != value {
			return errAssembly
		}
		f.seen[j] = 1
		f.data[j] = value
	}
	for f.contiguous < len(f.seen) && f.seen[f.contiguous] != 0 {
		f.contiguous++
	}
	return nil
}
