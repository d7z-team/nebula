package portshare

import (
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// A reset carries the peer's token instead of a locally issued destination CID.
// Observe quic-go's typed events in memory. quic-go itself verifies the reset
// after normal mesh admission; the index only selects the receiving socket.
type resetRegistry struct {
	mu     sync.RWMutex
	active map[[16]byte]int
}

func (r *resetRegistry) owns(token [16]byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active[token] != 0
}

func (r *resetRegistry) AddProducer() qlogwriter.Recorder {
	return &resetRecorder{registry: r, ids: make(map[uint64]*peerCID)}
}

type peerCID struct {
	cid    quic.ConnectionID
	token  [16]byte
	active bool
}
type resetRecorder struct {
	mu           sync.Mutex
	registry     *resetRegistry
	ids          map[uint64]*peerCID
	retireBefore uint64
	highestUsed  uint64
}

func (r *resetRecorder) activate(id *peerCID) {
	if id.active {
		return
	}
	id.active = true
	index := r.registry
	index.mu.Lock()
	defer index.mu.Unlock()
	if index.active == nil {
		index.active = make(map[[16]byte]int)
	}
	index.active[id.token]++
}

func (r *resetRecorder) retire(seq uint64) {
	id := r.ids[seq]
	if id == nil {
		return
	}
	delete(r.ids, seq)
	if id.active {
		index := r.registry
		index.mu.Lock()
		defer index.mu.Unlock()
		if index.active[id.token] <= 1 {
			delete(index.active, id.token)
		} else {
			index.active[id.token]--
		}
	}
}

func (r *resetRecorder) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case qlog.ParametersSet:
		if e.Initiator != qlog.InitiatorRemote {
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if e.StatelessResetToken != nil && r.ids[0] == nil && r.retireBefore == 0 {
			id := &peerCID{cid: e.InitialSourceConnectionID, token: *e.StatelessResetToken}
			r.ids[0] = id
			r.activate(id)
		}
		if e.PreferredAddress != nil && r.ids[1] == nil && r.retireBefore <= 1 {
			r.ids[1] = &peerCID{cid: e.PreferredAddress.ConnectionID, token: e.PreferredAddress.StatelessResetToken}
		}
	case qlog.PacketReceived:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		for _, f := range e.Frames {
			newID, ok := f.Frame.(*qlog.NewConnectionIDFrame)
			if !ok {
				continue
			}
			r.mu.Lock()
			if newID.RetirePriorTo > r.retireBefore {
				r.retireBefore = newID.RetirePriorTo
				for seq, id := range r.ids {
					// An active CID may still be in use until its replacement is sent.
					if seq < r.retireBefore && !id.active {
						delete(r.ids, seq)
					}
				}
			}
			// The node advertises quic-go's four active CID slots. Leave room
			// for the initial CID and a path being retired.
			if seq := newID.SequenceNumber; seq >= r.retireBefore && seq > r.highestUsed && r.ids[seq] == nil && len(r.ids) < 8 {
				r.ids[seq] = &peerCID{cid: newID.ConnectionID, token: newID.StatelessResetToken}
			}
			r.mu.Unlock()
		}
	case qlog.PacketSent:
		if e.Header.PacketType != qlog.PacketType1RTT {
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		for seq, id := range r.ids {
			if !id.active && id.cid == e.Header.DestConnectionID {
				r.activate(id)
				r.highestUsed = max(r.highestUsed, seq)
				break
			}
		}
		for _, f := range e.Frames {
			if retired, ok := f.Frame.(*qlog.RetireConnectionIDFrame); ok {
				r.retire(retired.SequenceNumber)
			}
		}
	}
}

func (r *resetRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for seq := range r.ids {
		r.retire(seq)
	}
	return nil
}
