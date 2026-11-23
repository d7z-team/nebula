package nebula

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/control"
)

const (
	maxEvents         = 512
	inventoryPageSize = 8
	eventLifetime     = 5 * time.Minute
	maxEventPayload   = 384
)

// ControlEvent is signed by a network-authorized topic publisher. Expires is Unix time.
type ControlEvent struct {
	Origin    netip.Addr `json:"origin"`
	Topic     string     `json:"topic"`
	Nonce     string     `json:"nonce"`
	Expires   int64      `json:"expires"`
	Payload   []byte     `json:"payload"`
	Signature []byte     `json:"signature,omitempty"`
}

// DeliveredEvent includes the deduplication digest of the signed event body.
type DeliveredEvent struct {
	ID string
	ControlEvent
}

// Subscription delivers a single exact topic until Close or node shutdown.
type Subscription struct {
	c      *controlPlane
	topic  string
	events chan DeliveredEvent
	missed atomic.Uint64
}

func (s *Subscription) Events() <-chan DeliveredEvent { return s.events }

func (s *Subscription) Missed() uint64 { return s.missed.Load() }

func (s *Subscription) Close() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if _, ok := s.c.subs[s]; ok {
		delete(s.c.subs, s)
		close(s.events)
	}
}

// Subscribe registers a bounded local subscriber, including before Start.
func (n *Node) Subscribe(topic string) (*Subscription, error) {
	c := n.engine.control
	if c == nil || !control.ValidTopic(topic) {
		return nil, errors.New("invalid subscription")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n.ctx.Err() != nil {
		return nil, ErrNodeClosed
	}
	s := &Subscription{topic: topic, c: c, events: make(chan DeliveredEvent, 32)}
	c.subs[s] = struct{}{}
	return s, nil
}

func randomID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

func signedBytes(domain, kind string, value any) []byte {
	b, err := json.Marshal([]any{"nebula-control-v1", domain, kind, value})
	if err != nil {
		panic(err)
	}
	return b
}

func eventAuthorized(p *networkPolicy, e ControlEvent) bool {
	m := p.config.Members[e.Origin]
	if m.Certificate != "" && p.revoked[m.Certificate] {
		return false
	}
	for _, prefix := range m.Topics {
		if e.Topic == prefix || strings.HasPrefix(e.Topic, prefix+"/") {
			return true
		}
	}
	return false
}

// Publish signs and announces a short-lived application event for peer synchronization.
func (n *Node) Publish(ctx context.Context, topic string, payload []byte) (string, error) {
	if err := n.requireStarted(); err != nil {
		return "", err
	}
	if ctx != nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	c := n.engine.control
	if c == nil || len(c.opts.Publisher) != ed25519.PrivateKeySize || !control.ValidTopic(topic) || len(payload) > maxEventPayload {
		return "", errors.New("invalid publisher, topic or payload")
	}
	e := ControlEvent{Origin: n.engine.myVpnAddrs[0], Topic: topic, Nonce: randomID(), Expires: time.Now().Add(eventLifetime).Unix(), Payload: slices.Clone(payload)}
	e.Signature = ed25519.Sign(c.opts.Publisher, signedBytes(c.opts.Network, "event", e))
	return c.acceptEvent(e, netip.Addr{})
}

func (c *controlPlane) acceptEvent(e ControlEvent, from netip.Addr) (string, error) {
	now := time.Now()
	if !control.ValidTopic(e.Topic) || len(e.Payload) > maxEventPayload || len(e.Nonce) != 32 || e.Expires <= now.Unix() || e.Expires > now.Add(eventLifetime+time.Second).Unix() {
		return "", errors.New("invalid event")
	}
	sig := e.Signature
	e.Signature = nil
	body := signedBytes(c.opts.Network, "event", e)
	sum := sha256.Sum256(body)
	id := hex.EncodeToString(sum[:])
	p := c.policy()
	pk := p.config.Members[e.Origin].Publisher
	if len(pk) != ed25519.PublicKeySize || !eventAuthorized(p, e) || !ed25519.Verify(pk, body, sig) {
		return "", errors.New("unauthorized event")
	}
	e.Signature = sig
	c.mu.Lock()
	if c.policy() != p {
		c.mu.Unlock()
		return "", ErrPathChanged
	}
	if _, ok := c.events[id]; ok {
		c.mu.Unlock()
		return id, nil
	}
	if len(c.events) >= maxEvents {
		c.mu.Unlock()
		return "", ErrQueueFull
	}
	c.events[id] = e
	delete(c.fetches, id)
	for sub := range c.subs {
		if sub.topic == e.Topic {
			v := e
			v.Payload = slices.Clone(e.Payload)
			v.Signature = slices.Clone(sig)
			select {
			case sub.events <- DeliveredEvent{id, v}:
			default:
				sub.missed.Add(1)
				c.missed++
			}
		}
	}
	c.mu.Unlock()
	for _, a := range c.neighbors(from) {
		c.send(a, controlFrame{Kind: "inventory", Inventory: []string{id}})
	}
	return id, nil
}

type receivedFrame struct {
	from    netip.Addr
	message controlFrame
}

func (c *controlPlane) runEvents() {
	for {
		select {
		case <-c.n.ctx.Done():
			return
		case f := <-c.eventQueue:
			c.handleEventFrame(f.from, f.message)
		}
	}
}

func applicationKind(kind string) bool {
	return kind == "event" || kind == "inventory" || kind == "get-event"
}

// Event verification and inventory replies run independently of the control socket reader.
func (c *controlPlane) handleEventFrame(from netip.Addr, m controlFrame) {
	c.mu.Lock()
	_, known := c.peers[from]
	c.mu.Unlock()
	if !known || c.policy().bootstrapOnly {
		return
	}
	switch m.Kind {
	case "inventory":
		if len(m.Inventory) > inventoryPageSize {
			return
		}
		for _, id := range m.Inventory {
			if len(id) != 64 {
				continue
			}
			c.mu.Lock()
			_, exists := c.events[id]
			until := c.fetches[id]
			now := time.Now()
			request := !exists && !now.Before(until) && len(c.fetches) < maxEvents
			if request {
				c.fetches[id] = now.Add(c.opts.SyncInterval)
			}
			c.mu.Unlock()
			if request {
				c.send(from, controlFrame{Kind: "get-event", ID: id})
			}
		}
	case "get-event":
		c.mu.Lock()
		e, ok := c.events[m.ID]
		c.mu.Unlock()
		if ok && e.Expires > time.Now().Unix() {
			c.send(from, controlFrame{Kind: "event", Event: &e})
		}
	case "event":
		if m.Event != nil {
			_, _ = c.acceptEvent(*m.Event, from)
		}
	}
}

// advertiseEvents rotates through the retained IDs so reconnecting neighbors can catch up.
func (c *controlPlane) advertiseEvents(now time.Time, page, cursor int) int {
	c.mu.Lock()
	for k, t := range c.fetches {
		if !now.Before(t) {
			delete(c.fetches, k)
		}
	}
	var ids []string
	for id, e := range c.events {
		if e.Expires <= now.Unix() {
			delete(c.events, id)
		} else {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	if len(ids) == 0 {
		return 0
	}
	slices.Sort(ids)
	if page >= len(ids) {
		page = 0
	}
	end := min(page+inventoryPageSize, len(ids))
	neighbors := c.neighbors(netip.Addr{})
	for i := range neighbors {
		c.send(neighbors[(cursor+i)%len(neighbors)], controlFrame{Kind: "inventory", Inventory: ids[page:end]})
	}
	return end
}
