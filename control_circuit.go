package nebula

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/slackhq/nebula/control"
)

const maxCircuitNodes = 16

// Each active circuit has its own receive index on each adjacent session.
type circuitMessage struct {
	ID      string       `json:"id"`
	Route   []netip.Addr `json:"route"`
	Digest  string       `json:"config"`
	Session uint32       `json:"session"`
	Index   uint32       `json:"index"`
}

type circuitLeg struct {
	h     *hostInfo
	index uint32
}

type managedCircuit struct {
	id                                    string
	route                                 []netip.Addr
	pos                                   int
	left, right                           circuitLeg
	created, confirmed, requested, demand time.Time
}

// CircuitStatus identifies one generation of a signed-topology route using local relay mappings.
type CircuitStatus struct {
	ID    string
	Route []netip.Addr
	Ready bool
}

type circuitTable struct {
	mu      sync.Mutex
	entries map[string]*managedCircuit
}

func (t *circuitTable) status() []CircuitStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	var v []CircuitStatus
	for _, x := range t.entries {
		v = append(v, CircuitStatus{x.id, slices.Clone(x.route), !x.confirmed.IsZero()})
	}
	slices.SortFunc(v, func(a, b CircuitStatus) int { return strings.Compare(a.ID, b.ID) })
	return v
}

// shortestCircuit finds an authorized loop-free path with the specified first
// hop. Removing one edge of the primary path finds alternatives behind that hop.
func shortestCircuit(nodes map[netip.Addr]control.Member, start, first, end, skipA, skipB netip.Addr) []netip.Addr {
	if !slices.Contains(nodes[start].Links, first) || start == end || first == end {
		return nil
	}
	parents := map[netip.Addr]netip.Addr{start: {}, first: start}
	queue := []netip.Addr{first}
	for len(queue) > 0 {
		a := queue[0]
		queue = queue[1:]
		if !nodes[a].Transit {
			continue
		}
		for _, b := range nodes[a].Links {
			if a == skipA && b == skipB || a == skipB && b == skipA {
				continue
			}
			if _, ok := parents[b]; ok {
				continue
			}
			parents[b] = a
			if b == end {
				var path []netip.Addr
				for hop := end; hop.IsValid(); hop = parents[hop] {
					path = append(path, hop)
				}
				if len(path) > maxCircuitNodes {
					return nil
				}
				slices.Reverse(path)
				return path
			}
			queue = append(queue, b)
		}
	}
	return nil
}

func (c *controlPlane) circuitPaths(target, first netip.Addr) [][]netip.Addr {
	p := c.policy()
	nodes := p.config.Members
	self := c.n.engine.myVpnAddrs[0]
	primary := shortestCircuit(nodes, self, first, target, netip.Addr{}, netip.Addr{})
	if len(primary) < 3 {
		return nil
	}
	paths := [][]netip.Addr{primary}
	for i := 1; i+1 < len(primary); i++ {
		alt := shortestCircuit(nodes, self, first, target, primary[i], primary[i+1])
		if len(alt) >= 4 {
			paths = append(paths, alt)
			break
		}
	}
	return paths
}

func (c *controlPlane) newCircuitLocked(path []netip.Addr, pos int, id string, from *hostInfo, remote uint32) *managedCircuit {
	t := &c.circuits
	if t.entries == nil {
		t.entries = make(map[string]*managedCircuit)
	}
	hm := c.n.engine.hostMap
	if len(t.entries) >= hm.maxRelayMappings {
		return nil
	}
	x := &managedCircuit{id: id, route: slices.Clone(path), pos: pos, left: circuitLeg{h: from}, created: time.Now()}
	if pos+1 < len(path) {
		next := path[pos+1]
		c.mu.Lock()
		neighbor, known := c.peers[next]
		c.mu.Unlock()
		h := hm.QueryVpnAddr(next)
		if !known || (pos+2 < len(path) && !neighbor.transit) || h == nil || !h.GetRemote().IsValid() || !c.n.engine.allowed(h, tunnelRoute{}) {
			return nil
		}
		x.right.h = h
	}

	hm.Lock()
	defer hm.Unlock()
	size, role := 1, relayTypeTerminal
	if x.left.h != nil && x.right.h != nil {
		size, role = 2, relayTypeCircuit
	}
	if len(hm.Relays)+size > hm.maxRelayMappings {
		return nil
	}
	legs := [2]*circuitLeg{&x.left, &x.right}
	for _, leg := range legs {
		if leg.h == nil {
			continue
		}
		if hm.Indexes[leg.h.localIndexId] != leg.h {
			return nil
		}
		idx, err := hm.unusedRelayIndex(x.left.index)
		if err != nil {
			return nil
		}
		leg.index = idx
	}
	// Both indices are reserved. A failed reservation publishes neither leg.
	for _, leg := range legs {
		if leg.h == nil {
			continue
		}
		origin, peer := path[0], path[len(path)-1]
		var remoteIndex uint32
		if leg == &x.left {
			origin, peer = peer, origin
			remoteIndex = remote
		}
		hm.storeRelay(leg.h, &relay{
			Origin: origin, PeerAddr: peer, Circuit: id, LocalIndex: leg.index, RemoteIndex: remoteIndex,
			Type: role, State: relayRequested, created: x.created,
		})
	}
	t.entries[id] = x
	return x
}

func (c *controlPlane) sendCircuit(x *managedCircuit, kind string, l circuitLeg) {
	if l.h == nil {
		return
	}
	m := circuitMessage{ID: x.id, Digest: c.policy().digest, Route: x.route, Session: l.h.remoteIndexId, Index: l.index}
	c.send(l.h.vpnAddrs[0], controlFrame{Kind: kind, Circuit: &m})
}

func (c *controlPlane) initiateCircuit(path []netip.Addr) (tunnelRoute, bool) {
	t := &c.circuits
	t.mu.Lock()
	var x *managedCircuit
	for _, v := range t.entries {
		if v.pos == 0 && slices.Equal(v.route, path) {
			if !v.confirmed.IsZero() {
				x = v
				break
			}
			if x == nil {
				x = v
			}
			continue
		}
		if v.pos == len(path)-1 && len(v.route) == len(path) && !v.confirmed.IsZero() {
			same := true
			for i, a := range path {
				if a != v.route[len(path)-1-i] {
					same = false
					break
				}
			}
			if same && (x == nil || x.confirmed.IsZero() || v.id < x.id) {
				x = v
			}
		}
	}
	if x == nil {
		x = c.newCircuitLocked(path, 0, randomID(), nil, 0)
	}
	if x == nil {
		t.mu.Unlock()
		return tunnelRoute{}, false
	}
	x.demand = time.Now()
	leg := x.right
	if x.pos != 0 {
		leg = x.left
	}
	ready := !x.confirmed.IsZero()
	due := !ready && x.pos == 0 && time.Since(x.requested) >= c.n.engine.hostMap.relayRequestInterval
	if due {
		x.requested = time.Now()
	}
	t.mu.Unlock()
	if due {
		c.sendCircuit(x, "build", leg)
	}
	if !ready {
		return tunnelRoute{}, false
	}
	return leg.route()
}

func (leg circuitLeg) route() (tunnelRoute, bool) {
	r, ok := leg.h.relayState.mappingByIndex(leg.index)
	if !ok || r.State != relayEstablished {
		return tunnelRoute{}, false
	}
	return receivedRoute(packetSender{UdpAddr: leg.h.GetRemote(), relayHI: leg.h, relay: r, IsRelayed: true}), true
}

// terminalRoute resolves a specific circuit generation for an endpoint probe.
func (t *circuitTable) terminalRoute(want TunnelPath) (tunnelRoute, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	x := t.entries[want.Circuit]
	if x == nil || x.confirmed.IsZero() {
		return tunnelRoute{}, false
	}
	var leg circuitLeg
	switch x.pos {
	case 0:
		leg = x.right
	case len(x.route) - 1:
		leg = x.left
	default:
		return tunnelRoute{}, false
	}
	if !slices.Contains(leg.h.vpnAddrs, want.Relay) {
		return tunnelRoute{}, false
	}
	return leg.route()
}

func (c *controlPlane) handleCircuit(h *hostInfo, kind string, m circuitMessage) {
	p := c.policy()
	path := m.Route
	// A pair may retain two valid direct sessions after simultaneous dials.
	// The control socket can use either; bind the data mapping to the named
	// session only after verifying that it belongs to the same certified peer.
	leg := c.n.engine.hostMap.QueryIndex(m.Session)
	if leg == nil || !slices.Equal(leg.vpnAddrs, h.vpnAddrs) || !leg.GetRemote().IsValid() || !c.n.engine.allowed(leg, tunnelRoute{}) {
		return
	}
	h = leg
	if m.Digest != p.digest || len(m.ID) != 32 || m.Index == 0 || len(path) < 4 || len(path) > maxCircuitNodes {
		return
	}
	self := c.n.engine.myVpnAddrs[0]
	pos := slices.Index(path, self)
	if pos < 0 || (pos > 0 && pos < len(path)-1 && !c.n.engine.servesRelays) {
		return
	}
	if !p.permitsCircuit(path) {
		return
	}
	if kind == "build" && (pos == 0 || !slices.Contains(h.vpnAddrs, path[pos-1])) || kind == "ready" && (pos == len(path)-1 || !slices.Contains(h.vpnAddrs, path[pos+1])) {
		return
	}
	if pos == len(path)-1 && !c.n.engine.paths.config.Load().allows([]netip.Addr{path[0]}, path[pos-1], nil, h.vpnAddrs...) {
		return
	}
	t := &c.circuits
	t.mu.Lock()
	if c.policy() != p {
		t.mu.Unlock()
		return
	}
	x := t.entries[m.ID]
	if x == nil && kind == "build" {
		x = c.newCircuitLocked(path, pos, m.ID, h, m.Index)
	}
	if x == nil || !slices.Equal(x.route, path) {
		t.mu.Unlock()
		return
	}
	var send circuitLeg
	if kind == "build" {
		r, ok := h.relayState.mappingByIndex(x.left.index)
		if x.left.h != h || !ok || r.RemoteIndex != m.Index {
			t.mu.Unlock()
			return
		}
		if pos == len(path)-1 {
			x.confirmed = time.Now()
			h.relayState.establishRelay(x.left.index, m.Index)
			send = x.left
			kind = "ready"
		} else {
			send = x.right
		}
	} else {
		if x.right.h != h {
			t.mu.Unlock()
			return
		}
		r, ok := h.relayState.mappingByIndex(x.right.index)
		if !ok || (r.RemoteIndex != 0 && r.RemoteIndex != m.Index) {
			t.mu.Unlock()
			return
		}
		h.relayState.establishRelay(x.right.index, m.Index)
		x.confirmed = time.Now()
		if x.left.h != nil {
			r, ok = x.left.h.relayState.mappingByIndex(x.left.index)
			if !ok {
				t.mu.Unlock()
				return
			}
			x.left.h.relayState.establishRelay(x.left.index, r.RemoteIndex)
			send = x.left
		}
	}
	t.mu.Unlock()
	c.sendCircuit(x, kind, send)
	if pos == 0 && kind == "ready" {
		select {
		case c.n.handshake.trigger <- path[len(path)-1]:
		default:
		}
	}
}

func (t *circuitTable) forward(id string, h *hostInfo, idx uint32) (*hostInfo, *relay) {
	t.mu.Lock()
	defer t.mu.Unlock()
	x := t.entries[id]
	if x == nil || x.confirmed.IsZero() {
		return nil, nil
	}
	dest := x.right
	if x.right.h == h && x.right.index == idx {
		dest = x.left
	} else if x.left.h != h || x.left.index != idx {
		return nil, nil
	}
	if dest.h == nil {
		return nil, nil
	}
	r, ok := dest.h.relayState.mappingByIndex(dest.index)
	if !ok {
		return nil, nil
	}
	return dest.h, r
}

func (t *circuitTable) removeLocked(c *controlPlane, x *managedCircuit) {
	hm := c.n.engine.hostMap
	hm.Lock()
	defer hm.Unlock()
	for _, l := range []circuitLeg{x.left, x.right} {
		if l.h != nil && hm.Relays[l.index] == l.h {
			delete(hm.Relays, l.index)
			rs := &l.h.relayState
			rs.Lock()
			delete(rs.relayForByIdx, l.index)
			rs.Unlock()
		}
	}
	delete(t.entries, x.id)
}

func (p *networkPolicy) permitsCircuit(path []netip.Addr) bool {
	for i, a := range path {
		if slices.Contains(path[:i], a) || (i > 0 && !slices.Contains(p.config.Members[path[i-1]].Links, a)) || (i > 0 && i < len(path)-1 && !p.config.Members[a].Transit) {
			return false
		}
	}
	return true
}

func (t *circuitTable) prunePolicy(c *controlPlane, p *networkPolicy) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, x := range t.entries {
		if !p.permitsCircuit(x.route) || (x.left.h != nil && p.denies(x.left.h.GetCert())) || (x.right.h != nil && p.denies(x.right.h.GetCert())) {
			t.removeLocked(c, x)
		}
	}
}

func (t *circuitTable) sweep(c *controlPlane, now time.Time) {
	t.mu.Lock()
	refreshEvery := max(3*c.opts.SyncInterval, 2*time.Second)
	var refresh []*managedCircuit
	for _, x := range t.entries {
		live := true
		for _, l := range []circuitLeg{x.left, x.right} {
			if l.h != nil && c.n.engine.hostMap.QueryRelayIndex(l.index) != l.h {
				live = false
			}
		}
		last := x.created
		if !x.confirmed.IsZero() {
			last = x.confirmed
		}
		if x.pos == 0 && now.Sub(x.demand) > c.n.engine.paths.probes.IdleTimeout {
			peer := x.route[len(x.route)-1]
			h := c.n.engine.hostMap.QueryVpnAddr(peer)
			live = live && h != nil
			if live {
				monitored := c.n.engine.paths.config.Load().effectivePolicy(h.vpnAddrs, c.n.engine.hostMap).MonitorInterval > 0
				h.paths.mu.Lock()
				selected := h.paths.active.Circuit == x.id || h.paths.standby.Circuit == x.id
				live = selected && (monitored || now.Sub(h.paths.demand) <= c.n.engine.paths.probes.IdleTimeout)
				h.paths.mu.Unlock()
			}
		}
		if !live || now.Sub(last) > 3*refreshEvery {
			t.removeLocked(c, x)
			continue
		}
		interval := refreshEvery
		if x.confirmed.IsZero() {
			interval = c.opts.SyncInterval
		}
		if x.pos == 0 && now.Sub(x.requested) >= interval {
			x.requested = now
			refresh = append(refresh, x)
		}
	}
	t.mu.Unlock()
	for _, x := range refresh {
		c.sendCircuit(x, "build", x.right)
	}
}
