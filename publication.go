package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.d7z.net/nebula/pki"
)

const (
	publicationPurpose    = "publication"
	maxPublications       = 512
	maxPublicationPayload = 4096
	publicationLifetime   = 5 * time.Minute
)

// Publication carries the content of a signed message on an application topic.
// Origin identifies the member that signed it, including on relayed delivery.
type Publication struct {
	Origin  PeerID    `json:"origin"`
	Topic   string    `json:"topic"`
	Nonce   string    `json:"nonce"`
	Payload []byte    `json:"payload"`
	Expires time.Time `json:"expires"`
}

// DeliveredPublication pairs the signed message with its ID, the lowercase
// hex SHA-256 of the raw JSON bytes of the signed envelope's "value" field.
type DeliveredPublication struct {
	ID string `json:"id"`
	Publication
}

type cachedPublication struct {
	record  statement
	expires time.Time
}

func (n *Node) expirePublicationsLocked(now time.Time) {
	maps.DeleteFunc(n.publications, func(_ string, p cachedPublication) bool { return !now.Before(p.expires) })
}

// Subscription receives new publications on one exact topic.
type Subscription struct {
	n            *Node
	topic        string
	publications chan DeliveredPublication
	missed       atomic.Uint64
}

// Publications returns a channel closed by Subscription.Close or Node.Close.
func (s *Subscription) Publications() <-chan DeliveredPublication { return s.publications }

// Missed counts deliveries dropped because this subscription was full.
func (s *Subscription) Missed() uint64 { return s.missed.Load() }

// Close releases the subscription. It is safe to call repeatedly.
func (s *Subscription) Close() {
	n := s.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.subscriptions[s]; ok {
		delete(n.subscriptions, s)
		close(s.publications)
	}
}

// ValidTopic reports whether s is a valid application publication topic.
func ValidTopic(s string) bool {
	if len(s) > 128 || !strings.HasPrefix(s, "app/") {
		return false
	}
	for p := range strings.SplitSeq(s, "/") {
		if !pki.ValidName(p) {
			return false
		}
	}
	return true
}

// Subscribe registers for future admissions to an exact topic, including before Start.
// Each subscription buffers 32 publications. Earlier local admissions are not replayed.
func (n *Node) Subscribe(topic string) (*Subscription, error) {
	if !ValidTopic(topic) {
		return nil, errors.New("invalid topic")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.state == closed {
		return nil, ErrNodeClosed
	}
	s := &Subscription{n: n, topic: topic, publications: make(chan DeliveredPublication, 32)}
	n.subscriptions[s] = struct{}{}
	return s, nil
}

// Publish signs and admits a publication of up to 4096 bytes on an authorized topic.
// The returned ID confirms local admission. Neighbors receive it asynchronously.
func (n *Node) Publish(ctx context.Context, topic string, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !ValidTopic(topic) || len(payload) > maxPublicationPayload {
		return "", errors.New("invalid topic or publication size")
	}
	n.mu.Lock()
	err := n.state.runningError()
	n.mu.Unlock()
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	e := Publication{n.id, topic, hex.EncodeToString(nonce[:]), payload, time.Now().Add(publicationLifetime)}
	record, err := n.signStatement(publicationPurpose, e, n.cred.Load().cmsSigner)
	if err != nil {
		return "", err
	}
	return n.acceptPublication(ctx, nil, record, "")
}

// verifyPublication applies the same publisher, topic and expiry rules on receipt
// and when the host revalidates cached publications for forwarding.
func (n *Node) verifyPublication(ctx context.Context, p *topologyView, record statement) (DeliveredPublication, time.Time, error) {
	identity, body, until, err := n.verifyStatement(ctx, publicationPurpose, record, p)
	if err != nil {
		return DeliveredPublication{}, time.Time{}, err
	}
	origin := identity.ID
	var e Publication
	now := time.Now()
	if json.Unmarshal(body, &e) != nil || e.Origin != origin || len(e.Payload) > maxPublicationPayload ||
		!ValidTopic(e.Topic) || len(e.Nonce) != 32 || !now.Before(e.Expires) || e.Expires.After(now.Add(publicationLifetime+time.Second)) {
		return DeliveredPublication{}, time.Time{}, errors.New("invalid publication")
	}
	if !slices.ContainsFunc(p.members[origin].PublishTopics, func(prefix string) bool {
		return e.Topic == prefix || strings.HasPrefix(e.Topic, prefix+"/")
	}) {
		return DeliveredPublication{}, time.Time{}, ErrPathPolicy
	}
	sum := sha256.Sum256(body)
	return DeliveredPublication{hex.EncodeToString(sum[:]), e}, earlierDeadline(e.Expires, until), nil
}

func (n *Node) acceptPublication(ctx context.Context, from *session, record statement, requestedID string) (string, error) {
	p := n.policy.Load()
	publication, until, err := n.verifyPublication(ctx, p, record)
	if err != nil {
		return "", err
	}
	id := publication.ID
	if requestedID != "" && id != requestedID {
		return "", errors.New("publication ID differs from requested ID")
	}
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
	if existing, ok := n.publications[id]; ok && now.Before(existing.expires) {
		n.mu.Unlock()
		return id, nil
	}
	if len(n.publications) >= maxPublications {
		n.expirePublicationsLocked(now)
		if len(n.publications) >= maxPublications {
			n.mu.Unlock()
			return "", ErrQueueFull
		}
	}
	n.admissions++
	n.publications[id] = cachedPublication{record: record, expires: until}
	for sub := range n.subscriptions {
		if sub.topic == publication.Topic {
			delivery := publication
			delivery.Payload = slices.Clone(publication.Payload)
			select {
			case sub.publications <- delivery:
			default:
				sub.missed.Add(1)
			}
		}
	}
	var neighbors []*session
	for peer, paths := range n.peers {
		if from != nil && peer == from.peer {
			continue
		}
		if s := n.preferredSessionLocked(paths, true, nil); s != nil {
			neighbors = append(neighbors, s)
		}
	}
	n.mu.Unlock()
	for _, s := range neighbors {
		n.tryTask(n.backgroundSlots, func() {
			ctx, cancel := context.WithDeadline(s.ctx, until)
			defer cancel()
			if n.pacePublication(ctx, s, id, record) {
				s.request(ctx, opPushPublication, record, 0)
			}
		})
	}
	return id, nil
}

// Push and fetch both recheck the cached signature and path after waiting for bandwidth.
func (n *Node) pacePublication(ctx context.Context, s *session, id string, record statement) bool {
	if _, err := n.shaper.schedule(ctx, PeerID{}, len(record)); err != nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.publications[id]
	return ok && bytes.Equal(p.record, record) && time.Now().Before(p.expires) && n.usableLocked(s)
}

func (n *Node) addPublicationInventory(s *session, a *advert) {
	now := time.Now()
	n.mu.Lock()
	for id, e := range n.publications {
		if now.Before(e.expires) {
			a.Inventory = append(a.Inventory, id)
		}
	}
	n.mu.Unlock()
	// All maxPublications IDs fit in one frame without an introduction.
	if len(a.Record) == 0 || len(a.Inventory) == 0 {
		return
	}
	ids := a.Inventory
	a.Inventory = nil
	base, _ := json.Marshal(a)
	// Each lowercase SHA-256 ID costs two quotes and one comma.
	count := max(0, (maxControlFrame-len(base)-2)/67)
	if count >= len(ids) {
		a.Inventory = ids
		return
	}
	slices.Sort(ids)
	start := int((s.inventoryOffset.Add(uint64(count)) - uint64(count)) % uint64(len(ids)))
	for i := range count {
		a.Inventory = append(a.Inventory, ids[(start+i)%len(ids)])
	}
}

func (n *Node) fetchMissingPublications(s *session, ids []string) {
	if len(ids) > maxPublications {
		return
	}
	for _, id := range ids {
		if len(id) != 64 {
			continue
		}
		n.mu.Lock()
		_, known := n.publications[id]
		n.mu.Unlock()
		if !known {
			n.tryTask(n.backgroundSlots, func() {
				record, err := s.request(s.ctx, opGetPublication, []byte(id), pki.MaxDocument)
				if err == nil {
					n.acceptPublication(s.ctx, s, record, id)
				}
			})
		}
	}
}
