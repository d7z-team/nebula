package nebula

import (
	"net"
	"net/netip"
	"slices"
	"time"
)

// PathMode limits which paths the local node may use for a peer. Auto permits
// direct and relayed paths within the current topology.
type PathMode uint8

const (
	Auto PathMode = iota
	DirectOnly
	RelayOnly
	Blocked
)

func (m PathMode) allowsDirect() bool { return m == Auto || m == DirectOnly }
func (m PathMode) allowsRelay() bool  { return m == Auto || m == RelayOnly }

func (n *Node) usable(s *session) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.usableLocked(s)
}

func (n *Node) usableLocked(s *session) bool {
	paths := n.peers[s.peer]
	return paths != nil && slices.Contains(paths.sessions, s) && !s.closed.Load() && n.sessionAllowedLocked(s)
}

func (n *Node) sessionAllowedLocked(s *session) bool {
	p := n.policy.Load()
	if !time.Now().Before(s.until) || !n.memberOf(p) {
		return false
	}
	if len(s.path) > 0 {
		return s.lease.allowedLocked()
	}
	return n.modeLocked(s.peer).allowsDirect()
}

func (n *Node) modeLocked(a PeerID) PathMode {
	mode := n.modes[a]
	if mode == Blocked {
		return Blocked
	}
	p := n.policy.Load()
	if !n.memberOf(p) {
		return Blocked
	}
	m := p.members[n.id]
	if _, ok := p.members[a]; !ok {
		return Blocked
	}
	if (m.Restricted || p.members[a].Restricted) && !slices.Contains(m.Links, a) {
		if mode == DirectOnly {
			return Blocked
		}
		return RelayOnly
	}
	return mode
}

// SetPeerPathPolicy applies a local policy to either overlay address and prunes
// disallowed paths. It may be called before Start.
func (n *Node) SetPeerPathPolicy(address netip.Addr, mode PathMode) error {
	n.mu.Lock()
	a := n.policy.Load().owners[address]
	if a == (PeerID{}) || a == n.id || mode > Blocked {
		n.mu.Unlock()
		return ErrPathPolicy
	}
	if n.state == closed {
		n.mu.Unlock()
		return ErrNodeClosed
	}
	n.modes[a] = mode
	n.mu.Unlock()
	n.enforcePathPolicy()
	return nil
}

func (n *Node) enforcePathPolicy() {
	n.prunePaths()
	// Wait for physical writes admitted under the previous policy.
	n.udpWrites.Lock()
	n.udpWrites.Unlock()
}

type deniedEndpoint struct {
	peer    PeerID
	expires time.Time
}

func (n *Node) prunePaths() {
	n.mu.Lock()
	now := time.Now()
	for peer, intro := range n.discovered {
		if !now.Before(intro.authorizedUntil) {
			n.forgetIntroductionLocked(peer, intro)
		}
	}
	for ep, entry := range n.deniedUDP {
		mode := n.modeLocked(entry.peer)
		if !now.Before(entry.expires) || mode.allowsDirect() {
			delete(n.deniedUDP, ep)
		}
	}
	var dead []*session
	disconnected := make(map[PeerID]bool)
	for peer, paths := range n.peers {
		for i := len(paths.sessions) - 1; i >= 0; i-- {
			s := paths.sessions[i]
			if n.sessionAllowedLocked(s) {
				continue
			}
			if s.q != nil && !n.modeLocked(s.peer).allowsDirect() {
				n.deniedUDP[addrPort(s.q.RemoteAddr())] = deniedEndpoint{s.peer, now.Add(time.Minute)}
			}
			n.removeSessionLocked(s)
			dead = append(dead, s)
		}
		if len(paths.sessions) == 0 {
			disconnected[peer] = true
		}
	}
	port := n.port
	var leases []*circuitLease
	for l := range n.circuits {
		if !l.allowedLocked() {
			leases = append(leases, l)
		}
	}
	n.mu.Unlock()
	if port != nil {
		port.revalidateQueues(disconnected)
	}
	for _, s := range dead {
		s.close()
	}
	for _, l := range leases {
		l.close()
	}
}

type policySocket struct {
	net.PacketConn
	n *Node
}

func (p *policySocket) WriteTo(b []byte, a net.Addr) (int, error) {
	p.n.udpWrites.RLock()
	defer p.n.udpWrites.RUnlock()
	if !p.n.endpointAllowed("udp", addrPort(a), false) {
		return 0, ErrPathPolicy
	}
	return p.PacketConn.WriteTo(b, a)
}

func (p *policySocket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := p.PacketConn.ReadFrom(b)
		if e != nil {
			return n, a, e
		}
		if p.n.endpointAllowed("udp", addrPort(a), true) {
			return n, a, nil
		}
	}
}

func (n *Node) endpointAllowed(network string, ep netip.AddrPort, in bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.endpointAllowedLocked(network, ep, in)
}

func (n *Node) endpointAllowedLocked(network string, ep netip.AddrPort, in bool) bool {
	if !ep.IsValid() {
		return false
	}
	if network == "udp" {
		if entry, ok := n.deniedUDP[ep]; ok && time.Now().Before(entry.expires) {
			mode := n.modeLocked(entry.peer)
			if !mode.allowsDirect() {
				return false
			}
		}
	}
	p := n.policy.Load()
	restricted := !n.memberOf(p) || p.members[n.id].Restricted
	tcpAccept := in && network == "tcp"
	if tcpAccept {
		ep = netip.AddrPortFrom(ep.Addr(), 0)
	}
	key := Endpoint{Network: network, Address: ep}
	allowed, denied := false, false
	for _, a := range p.endpointOwners[key] {
		if a == n.id {
			continue
		}
		mode := n.modeLocked(a)
		if !mode.allowsDirect() {
			denied = true
		} else {
			allowed = true
		}
	}
	if allowed || denied {
		return allowed && (tcpAccept || !denied)
	}
	if restricted {
		return false
	}
	for a, until := range n.introduced[key] {
		mode := n.modeLocked(a)
		if time.Now().Before(until) && !mode.allowsDirect() {
			return false
		}
	}
	return true
}
