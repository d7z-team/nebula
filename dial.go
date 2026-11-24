package nebula

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// A peer dial wakes waiters on registration and on completion. Node.mu guards both fields.
type peerAttempt struct {
	changed chan struct{}
	err     error
}

type endpointAttempt struct {
	done    chan struct{}
	err     error
	session *session
}

type directDial struct {
	peer     PeerID
	endpoint Endpoint
}

// ConnectPeer waits for an authenticated path in either direction to the member
// owning either overlay address, subject to the current path policy.
// A canceled context cannot start a new dial. Once started, a dial belongs
// to the node. Canceling ctx ends only this caller's wait.
func (n *Node) ConnectPeer(ctx context.Context, address netip.Addr) error {
	peer, _ := n.LookupPeer(address)
	return n.connectPeer(ctx, peer, nil)
}

// ConnectPeerID waits for a path authenticated as the exact certified address
// pair. Use it with IPMatch.Peer to keep the selected identity across topology
// updates. It shares in-flight attempts with ConnectPeer.
func (n *Node) ConnectPeerID(ctx context.Context, peer PeerID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := n.Cluster().ValidateMember(peer); err != nil {
		return errors.Join(ErrPeerUnavailable, err)
	}
	return n.connectPeer(ctx, peer, nil)
}

// ConnectEndpoint connects to a physical TCP or UDP endpoint and returns the
// authenticated member on the registered direct path. Concurrent calls to the
// same endpoint share a dial. Canceling ctx ends this caller's wait. The node
// owns the bounded dial and the resulting session. The caller chooses when to retry.
func (n *Node) ConnectEndpoint(ctx context.Context, ep Endpoint) (PeerID, error) {
	s, err := n.dialEndpoint(ctx, PeerID{}, ep)
	if err != nil {
		return PeerID{}, fmt.Errorf("connect %s %s: %w", ep.Network, ep.Address, err)
	}
	return s.peer, nil
}

func (n *Node) connectPeer(ctx context.Context, peer PeerID, slots chan struct{}) error {
	var a *peerAttempt
	var reserved chan struct{}
	for {
		var acquire chan struct{}
		var changed <-chan struct{}
		var err error
		n.mu.Lock()
		switch {
		case ctx.Err() != nil:
			err = ctx.Err()
		case peer == (PeerID{}) || peer == n.id:
			err = ErrPeerUnavailable
		case n.state != running:
			err = n.state.runningError()
		case n.modeLocked(peer) == Blocked:
			err = ErrPathPolicy
		case n.preferredSessionLocked(n.peers[peer], false, nil) != nil:
			// A registered path in either direction satisfies the caller.
		case a != nil && a.changed == nil:
			err = a.err
			if err == nil {
				err = ErrPeerUnavailable
			}
		case a == nil && slots != nil && reserved == nil && n.attempts[peer] == nil:
			acquire = slots
		default:
			if a == nil {
				a = n.startDialLocked(peer, reserved)
				reserved = nil
			}
			changed = a.changed
		}
		n.mu.Unlock()
		if changed == nil && acquire == nil {
			if reserved != nil {
				<-reserved
			}
			return err
		}
		select {
		case acquire <- struct{}{}:
			reserved = acquire
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-n.ctx.Done():
			return ErrNodeClosed
		}
	}
}

// startDialLocked owns the reserved slot, if any, until the shared dial ends.
func (n *Node) startDialLocked(peer PeerID, reserved chan struct{}) *peerAttempt {
	if a := n.attempts[peer]; a != nil {
		if reserved != nil {
			<-reserved
		}
		return a
	}
	a := &peerAttempt{changed: make(chan struct{})}
	n.attempts[peer] = a
	n.wg.Go(func() {
		err := n.establishPath(peer)
		n.mu.Lock()
		defer n.mu.Unlock()
		a.err = err
		if err != nil && n.preferredSessionLocked(n.peers[peer], false, nil) == nil {
			n.lastConnectError = err.Error()
		}
		delete(n.attempts, peer)
		close(a.changed)
		a.changed = nil
		if reserved != nil {
			<-reserved
		}
	})
	return a
}

func (n *Node) establishPath(peer PeerID) error {
	n.mu.Lock()
	mode := n.modeLocked(peer)
	n.mu.Unlock()
	if mode == Blocked {
		return ErrPathPolicy
	}
	var directErr, relayErr error
	if mode.allowsDirect() {
		_, directErr = n.dialDirect(n.ctx, peer)
		if directErr == nil || n.preferredSession(peer, false) != nil {
			return nil
		}
	}
	if mode.allowsRelay() {
		relayErr = n.dialRelay(n.ctx, peer, maxCircuitAttempts)
		if relayErr == nil || n.preferredSession(peer, false) != nil {
			return nil
		}
	}
	return errors.Join(ErrPeerUnavailable, directErr, relayErr)
}

func (n *Node) dialDirect(ctx context.Context, peer PeerID) (*session, error) {
	n.mu.Lock()
	eps := n.endpointsLocked(peer)
	mode := n.modeLocked(peer)
	n.mu.Unlock()
	if !mode.allowsDirect() {
		return nil, ErrPathPolicy
	}
	var last error
	tried := make(map[Endpoint]bool)
	for pass := 0; pass < 2; pass++ {
		var udp, tcp []Endpoint
		for _, e := range eps {
			if tried[e] {
				continue
			}
			tried[e] = true
			if e.Network == "udp" {
				udp = append(udp, e)
			} else {
				tcp = append(tcp, e)
			}
		}
		if len(udp)+len(tcp) > 0 {
			var s *session
			s, last = n.dialCandidates(ctx, peer, udp, tcp)
			if s != nil {
				return s, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s := n.preferredSession(peer, true); s != nil {
			return s, nil
		}
		if pass == 0 {
			if n.rendezvous(ctx, peer) {
				// Both peers have had a chance to open their UDP filters.
				maps.DeleteFunc(tried, func(e Endpoint, _ bool) bool { return e.Network == "udp" })
			}
			n.mu.Lock()
			eps = n.endpointsLocked(peer)
			n.mu.Unlock()
		}
	}
	return nil, errors.Join(ErrPeerUnavailable, last)
}

// Each transport tries its endpoints in order. Start TCP when UDP exhausts its
// list or when the first UDP handshake is still pending after a short delay.
func (n *Node) dialCandidates(ctx context.Context, peer PeerID, udp, tcp []Endpoint) (*session, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dial := func(endpoints []Endpoint) (*session, error) {
		var last error
		for _, ep := range endpoints {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			s, err := n.dialEndpoint(ctx, peer, ep)
			if err != nil {
				s = n.preferredSession(peer, true)
			}
			if s != nil {
				cancel()
				return s, nil
			}
			last = err
		}
		return nil, last
	}
	if len(udp) == 0 {
		return dial(tcp)
	}
	if len(tcp) == 0 {
		return dial(udp)
	}

	udpDone := make(chan struct{})
	var backup *session
	var backupErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		timer := time.NewTimer(min(250*time.Millisecond, n.o.DialTimeout/2))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-udpDone:
		case <-timer.C:
		}
		backup, backupErr = dial(tcp)
	})
	s, err := dial(udp)
	close(udpDone)
	wg.Wait()
	if s != nil {
		return s, nil
	}
	if backup != nil {
		return backup, nil
	}
	return nil, errors.Join(err, backupErr)
}

func (n *Node) dialEndpoint(ctx context.Context, peer PeerID, e Endpoint) (*session, error) {
	key := directDial{peer, e}
	for {
		n.mu.Lock()
		if err := ctx.Err(); err != nil {
			n.mu.Unlock()
			return nil, err
		}
		if err := n.state.runningError(); err != nil {
			n.mu.Unlock()
			return nil, err
		}
		byEndpoint := peer == (PeerID{})
		if byEndpoint && (!e.Valid() || n.policy.Load().isOverlayAddress(e.Address.Addr())) {
			n.mu.Unlock()
			return nil, errors.New("invalid physical endpoint")
		}
		if (!byEndpoint && !n.modeLocked(peer).allowsDirect()) || !n.endpointAllowedLocked(e.Network, e.Address, false) {
			n.mu.Unlock()
			return nil, ErrPathPolicy
		}
		if s, _ := n.directEndpointLocked(peer, e); s != nil {
			n.mu.Unlock()
			return s, nil
		}
		a := n.directDials[key]
		if a == nil {
			a = &endpointAttempt{done: make(chan struct{})}
			n.directDials[key] = a
			if !byEndpoint {
				// A peer dial races transports and cancels the losing candidate.
				n.mu.Unlock()
				n.finishEndpointDial(ctx, key, a)
				return a.session, a.err
			}
			n.wg.Go(func() { n.finishEndpointDial(n.ctx, key, a) })
		}
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.ctx.Done():
			return nil, ErrNodeClosed
		case <-a.done:
			if n.ctx.Err() != nil {
				return nil, ErrNodeClosed
			}
			if byEndpoint || !errors.Is(a.err, context.Canceled) || ctx.Err() != nil {
				return a.session, a.err
			}
			// The originating peer dial won on its other transport. Try again.
		}
	}
}

func (n *Node) finishEndpointDial(ctx context.Context, key directDial, a *endpointAttempt) {
	e, peer := key.endpoint, key.peer
	dctx, cancel := context.WithTimeout(ctx, n.o.DialTimeout)
	defer cancel()
	if e.Network == "udp" {
		if transport := n.transports[e.Address.Addr().Is6()]; transport == nil {
			a.err = fmt.Errorf("%w: no UDP socket for address family of %s", ErrPeerUnavailable, e.Address.Addr())
		} else {
			var q *quic.Conn
			q, a.err = transport.Dial(dctx, net.UDPAddrFromAddrPort(e.Address), n.tlsConfig(peer, false), transport.config)
			if a.err == nil {
				a.session, a.err = n.attachQUIC(dctx, q, peer, true)
			}
		}
	} else {
		var c net.Conn
		network := "tcp4"
		if e.Address.Addr().Is6() {
			network = "tcp6"
		}
		c, a.err = n.o.DialTCP(dctx, network, e.Address.String())
		if a.err == nil {
			a.session, a.err = n.attachTLS(dctx, c, peer, nil, true, nil)
		}
	}
	if a.err != nil {
		if ctx.Err() != nil {
			a.err = ctx.Err()
		} else {
			n.dialFailures.Add(1)
		}
	}
	n.mu.Lock()
	if peer == (PeerID{}) && a.err != nil && n.ctx.Err() == nil {
		n.lastConnectError = fmt.Sprintf("connect %s %s: %v", e.Network, e.Address, a.err)
	}
	delete(n.directDials, key)
	close(a.done)
	n.mu.Unlock()
}
