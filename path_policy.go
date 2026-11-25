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
	if !p.acceptsIdentity(a) {
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

// SetPeerPathPolicy applies a local policy to an exact address pair and prunes
// disallowed paths. A valid remote identity may be configured before discovery
// or Start. Auto clears its override.
func (n *Node) SetPeerPathPolicy(peer PeerID, mode PathMode) error {
	if peer == n.id || mode > Blocked || n.Cluster().ValidateMember(peer) != nil {
		return ErrPathPolicy
	}
	n.mu.Lock()
	if n.state == closed {
		n.mu.Unlock()
		return ErrNodeClosed
	}
	if mode == Auto {
		delete(n.modes, peer)
	} else {
		n.modes[peer] = mode
	}
	n.mu.Unlock()
	n.enforcePathPolicy()
	return nil
}

// PeerPathPolicy returns the local override (Auto by default) and the mode
// allowed by the current topology. It does not check connectivity or credentials.
// The effective mode is Blocked for an invalid or local identity or a closed node.
func (n *Node) PeerPathPolicy(peer PeerID) (configured, effective PathMode) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if peer == n.id || n.state == closed || n.Cluster().ValidateMember(peer) != nil {
		return n.modes[peer], Blocked
	}
	return n.modes[peer], n.modeLocked(peer)
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
	expiredPeers := make(map[PeerID]bool)
	for peer, paths := range n.peers {
		var authorized bool
		for i := len(paths.sessions) - 1; i >= 0; i-- {
			s := paths.sessions[i]
			authorized = authorized || now.Before(s.until)
			if n.sessionAllowedLocked(s) {
				continue
			}
			if s.q != nil && !n.modeLocked(s.peer).allowsDirect() {
				n.deniedUDP[addrPort(s.q.RemoteAddr())] = deniedEndpoint{s.peer, now.Add(time.Minute)}
			}
			n.removeSessionLocked(s)
			dead = append(dead, s)
		}
		// Losing every credential withdraws the backlog. Losing an allowed
		// transport leaves queued packets free to dial the same identity.
		if !authorized && len(paths.sessions) == 0 {
			expiredPeers[peer] = true
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
		port.revalidateQueues(expiredPeers)
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
