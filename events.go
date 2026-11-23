package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxEvents       = 512
	maxEventPayload = 4096
	eventLifetime   = 5 * time.Minute
)

// Event is a signed application publication. Origin identifies its publisher.
type Event struct {
	Origin       PeerID
	Topic, Nonce string
	Payload      []byte
	Expires      time.Time
}

// DeliveredEvent pairs an accepted event with its content ID.
type DeliveredEvent struct {
	ID string
	Event
}

type cachedEvent struct {
	record  statement
	expires time.Time
}

// Subscription receives new events on one exact topic.
type Subscription struct {
	n      *Node
	topic  string
	events chan DeliveredEvent
	missed atomic.Uint64
}

// Events returns a channel closed by Subscription.Close or Node.Close.
func (s *Subscription) Events() <-chan DeliveredEvent { return s.events }

// Missed counts deliveries dropped because this subscription was full.
func (s *Subscription) Missed() uint64 { return s.missed.Load() }

// Close releases the subscription. It is safe to call repeatedly.
func (s *Subscription) Close() {
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.subscriptions[s]; ok {
		delete(n.subscriptions, s)
		close(s.events)
	}
}

// Subscribe registers for future admissions to an exact topic, including before Start.
// Each subscription buffers 32 events. Earlier local admissions are not replayed.
func (n *Node) Subscribe(topic string) (*Subscription, error) {
	if !ValidTopic(topic) {
		return nil, errors.New("invalid topic")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == closed {
		return nil, ErrNodeClosed
	}
	s := &Subscription{n: n, topic: topic, events: make(chan DeliveredEvent, 32)}
	n.subscriptions[s] = struct{}{}
	return s, nil
}

// Publish signs and admits an event of up to 4096 bytes on an authorized topic.
// The returned ID confirms local admission. Neighbors receive it asynchronously.
func (n *Node) Publish(ctx context.Context, topic string, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !ValidTopic(topic) || len(payload) > maxEventPayload {
		return "", errors.New("invalid topic or event size")
	}
	n.mu.Lock()
	err := n.state.runningError()
	n.mu.Unlock()
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	e := Event{n.id, topic, hex.EncodeToString(nonce[:]), payload, time.Now().Add(eventLifetime)}
	record, err := n.signStatement("event", e, n.cred.Load().Object)
	if err != nil {
		return "", err
	}
	return n.acceptEvent(ctx, nil, record)
}

// verifyEvent applies the same publisher, topic and expiry rules on receipt
// and when the host revalidates cached events for forwarding.
func (n *Node) verifyEvent(ctx context.Context, p *topologyView, record statement) (DeliveredEvent, time.Time, error) {
	origin, body, until, err := n.verifyStatement(ctx, "event", record, p)
	if err != nil {
		return DeliveredEvent{}, time.Time{}, err
	}
	var e Event
	now := time.Now()
	if json.Unmarshal(body, &e) != nil || e.Origin != origin || len(e.Payload) > maxEventPayload ||
		!ValidTopic(e.Topic) || len(e.Nonce) != 32 || !now.Before(e.Expires) || e.Expires.After(now.Add(eventLifetime+time.Second)) {
		return DeliveredEvent{}, time.Time{}, errors.New("invalid event")
	}
	if !slices.ContainsFunc(p.members[origin].Topics, func(prefix string) bool {
		return e.Topic == prefix || strings.HasPrefix(e.Topic, prefix+"/")
	}) {
		return DeliveredEvent{}, time.Time{}, ErrPathPolicy
	}
	if e.Expires.Before(until) {
		until = e.Expires
	}
	sum := sha256.Sum256(body)
	return DeliveredEvent{hex.EncodeToString(sum[:]), e}, until, nil
}

func (n *Node) acceptEvent(ctx context.Context, from *session, record statement) (string, error) {
	p := n.policy.Load()
	event, until, err := n.verifyEvent(ctx, p, record)
	if err != nil {
		return "", err
	}
	id := event.ID
	n.mu.Lock()
	now := time.Now()
	if err := n.state.runningError(); err != nil {
		n.mu.Unlock()
		return "", err
	}
	if !n.memberOf(p) || !now.Before(until) || from != nil && !n.usableLocked(from) {
		n.mu.Unlock()
		return "", ErrPathPolicy
	}
	if _, ok := n.events[id]; ok {
		n.mu.Unlock()
		return id, nil
	}
	for k, v := range n.events {
		if !v.expires.After(now) {
			delete(n.events, k)
		}
	}
	if len(n.events) >= maxEvents {
		n.mu.Unlock()
		return "", ErrQueueFull
	}
	n.admissions++
	n.events[id] = cachedEvent{record: record, expires: until}
	for sub := range n.subscriptions {
		if sub.topic == event.Topic {
			delivery := event
			delivery.Payload = slices.Clone(event.Payload)
			select {
			case sub.events <- delivery:
			default:
				sub.missed.Add(1)
			}
		}
	}
	peers := n.sessionListLocked()
	n.mu.Unlock()
	for _, s := range peers {
		if s != from && len(s.path) == 0 {
			n.tryTask(n.backgroundSlots, func() {
				if n.allowEventSend(s, id, record) {
					s.request(n.ctx, opEvent, record, 0)
				}
			})
		}
	}
	return id, nil
}

// Publication and inventory repair must both recheck authorization after pacing.
func (n *Node) allowEventSend(s *session, id string, record statement) bool {
	if n.shape(n.ctx, len(record)) != nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ev, ok := n.events[id]
	return ok && bytes.Equal(ev.record, record) && time.Now().Before(ev.expires) && n.usableLocked(s)
}
