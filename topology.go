package nebula

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"gopkg.d7z.net/nebula/pki"
)

// Endpoint identifies a UDP or TCP address on the physical network.
type Endpoint struct {
	Network string         `json:"network"`
	Address netip.AddrPort `json:"address"`
}

// Valid reports whether e identifies a physical TCP or UDP peer at a nonzero port.
func (e Endpoint) Valid() bool {
	ip := e.Address.Addr()
	return (e.Network == "udp" || e.Network == "tcp") && e.Address.Port() != 0 &&
		ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Is4In6() && ip != limitedBroadcast
}

// PeerID identifies a member by the SHA-256 digest of its node public key.
type PeerID = pki.PeerID

// Member contains the local routing and forwarding policy for one peer.
type Member struct {
	ID   PeerID     `json:"id"`
	IPv4 netip.Addr `json:"ipv4"`
	IPv6 netip.Addr `json:"ipv6"`
	// Links declares reciprocal neighbors to maintain and use as circuit hops.
	Links []PeerID `json:"links,omitempty"`
	// Endpoints lists physical addresses outside the member subnets and anycast
	// pools. A member that dials its neighbors can serve as a hop with an empty list.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// Restricted limits direct connections to the neighbors in Links.
	Restricted bool `json:"restricted,omitempty"`
	// Transit authorizes this member to relay mesh circuits.
	Transit bool `json:"transit,omitempty"`

	// RoutedPrefixes permits this gateway to send and receive downstream traffic
	// within its certificate grants. The host selects the next hop, including for default routes.
	RoutedPrefixes []netip.Prefix `json:"routedPrefixes,omitempty"`
	// AnycastIPs permits this member to carry the listed service addresses.
	AnycastIPs []netip.Addr `json:"anycastIPs,omitempty"`
	// MulticastGroups subscribes this member to exact multicast destinations.
	MulticastGroups []netip.Addr `json:"multicastGroups,omitempty"`
	// BytesPerSecond limits the combined rate of locally sent IP packets and
	// relayed data on this node. Zero is unlimited.
	BytesPerSecond int `json:"bytesPerSecond,omitempty"`
}

func (m Member) addresses() pki.Addresses {
	return pki.Addresses{IPv4: m.IPv4, IPv6: m.IPv6}
}

// Clone returns an independent copy of the member's policy.
func (m Member) Clone() Member {
	m.Links = slices.Clone(m.Links)
	m.Endpoints = slices.Clone(m.Endpoints)
	m.RoutedPrefixes = slices.Clone(m.RoutedPrefixes)
	m.AnycastIPs = slices.Clone(m.AnycastIPs)
	m.MulticastGroups = slices.Clone(m.MulticastGroups)
	return m
}

// Topology is the host-approved local view.
type Topology struct {
	Network         string   `json:"network"`
	EnableBroadcast bool     `json:"enableBroadcast,omitempty"`
	EnableMulticast bool     `json:"enableMulticast,omitempty"`
	Members         []Member `json:"members"`
}

type topologyView struct {
	cluster              pki.Cluster
	broadcast, multicast bool
	allMembers           []PeerID
	directedBroadcast    netip.Addr
	instances            map[netip.Addr][]PeerID
	groups               map[netip.Addr][]PeerID
	members              map[PeerID]Member
	owners               map[netip.Addr]PeerID
	endpointOwners       map[Endpoint][]PeerID
}

func (c *topologyView) physicalEndpoint(ep Endpoint) bool {
	ip := ep.Address.Addr().WithZone("")
	return ep.Valid() && !c.cluster.Subnet(ip).IsValid() && !c.cluster.InAnycastPool(ip)
}

var (
	limitedBroadcast = netip.MustParseAddr("255.255.255.255")
	allHosts         = netip.MustParseAddr("224.0.0.1")
	allNodes         = netip.MustParseAddr("ff02::1")
)

func validGroup(a netip.Addr) bool {
	if !a.IsMulticast() || a.Zone() != "" {
		return false
	}
	if a.Is6() {
		scope := a.As16()[1] & 15
		return scope != 0 && scope != 15
	}
	return true
}

// groupRecipients classifies group addresses even when distribution is disabled.
func (s *topologyView) groupRecipients(dst netip.Addr) ([]PeerID, bool, error) {
	switch {
	case dst == limitedBroadcast || dst == s.directedBroadcast && dst.IsValid():
		if !s.broadcast {
			return nil, true, ErrPathPolicy
		}
		return s.allMembers, true, nil
	case dst.IsMulticast():
		if !s.multicast || !validGroup(dst) {
			return nil, true, ErrPathPolicy
		}
		if dst.Is6() && dst.As16()[1]&15 == 1 {
			return nil, true, nil
		}
		if dst == allHosts || dst == allNodes {
			return s.allMembers, true, nil
		}
		return s.groups[dst], true, nil
	default:
		return nil, false, nil
	}
}

func comparePeer(a, b PeerID) int { return bytes.Compare(a[:], b[:]) }

// Validate checks the topology against the certified address plan. New and
// ApplyTopology also check the local introduction against its signing credential.
func (c Topology) Validate(cluster pki.Cluster) error {
	_, err := c.compile(cluster)
	return err
}

func (c Topology) compile(cluster pki.Cluster) (*topologyView, error) {
	if !pki.ValidName(c.Network) || c.Network != cluster.Network() || len(c.Members) == 0 {
		return nil, errors.New("cluster network and members required")
	}
	v4, _ := cluster.MemberPrefixes()
	s := &topologyView{
		cluster: cluster, broadcast: c.EnableBroadcast, multicast: c.EnableMulticast,
		directedBroadcast: pki.Broadcast(v4), allMembers: make([]PeerID, 0, len(c.Members)),
		instances: make(map[netip.Addr][]PeerID), groups: make(map[netip.Addr][]PeerID), members: make(map[PeerID]Member, len(c.Members)),
		owners: make(map[netip.Addr]PeerID), endpointOwners: make(map[Endpoint][]PeerID),
	}
	for _, m := range c.Members {
		if err := s.indexMember(m); err != nil {
			return nil, err
		}
	}
	for a, m := range s.members {
		for i, b := range m.Links {
			if a == b || slices.Contains(m.Links[:i], b) || !slices.Contains(s.members[b].Links, a) {
				return nil, fmt.Errorf("invalid adjacency %s to %s", a, b)
			}
		}
	}
	for _, peers := range s.groups {
		slices.SortFunc(peers, comparePeer)
	}
	slices.SortFunc(s.allMembers, comparePeer)
	return s, nil
}

func (s *topologyView) indexMember(m Member) error {
	id := m.ID
	if _, dup := s.members[id]; id == (PeerID{}) || dup {
		return fmt.Errorf("missing or duplicate member ID %s", id)
	}
	if err := s.cluster.ValidateMember(m.addresses()); err != nil {
		return err
	}
	if m.BytesPerSecond < 0 {
		return fmt.Errorf("negative shaping rate for %s", id)
	}
	for _, p := range m.RoutedPrefixes {
		if !s.cluster.AllowsRoute(p) {
			return fmt.Errorf("invalid routed prefix %s", p)
		}
	}
	for _, ip := range []netip.Addr{m.IPv4, m.IPv6} {
		if owner, exists := s.owners[ip]; exists {
			return fmt.Errorf("duplicate primary address %s: %s and %s", ip, owner, id)
		}
		s.owners[ip] = id
	}
	for _, ep := range m.Endpoints {
		if !s.physicalEndpoint(ep) {
			return fmt.Errorf("invalid physical endpoint %v for member %s", ep, id)
		}
		s.endpointOwners[ep] = append(s.endpointOwners[ep], id)
		if ep.Network == "tcp" {
			// Incoming TCP connections use ephemeral source ports.
			ep.Address = netip.AddrPortFrom(ep.Address.Addr(), 0)
			s.endpointOwners[ep] = append(s.endpointOwners[ep], id)
		}
	}
	m = m.Clone()
	slices.SortFunc(m.AnycastIPs, netip.Addr.Compare)
	m.AnycastIPs = slices.Compact(m.AnycastIPs)
	for _, vip := range m.AnycastIPs {
		if !s.cluster.ValidAnycast(vip) {
			return fmt.Errorf("invalid service address %s", vip)
		}
		s.instances[vip] = append(s.instances[vip], id)
	}
	slices.SortFunc(m.MulticastGroups, netip.Addr.Compare)
	m.MulticastGroups = slices.Compact(m.MulticastGroups)
	for _, group := range m.MulticastGroups {
		if !validGroup(group) {
			return fmt.Errorf("invalid multicast group %s", group)
		}
		s.groups[group] = append(s.groups[group], id)
	}
	s.allMembers = append(s.allMembers, id)
	s.members[id] = m
	return nil
}

// acceptsIdentity prevents dynamic discovery from overriding a configured primary address.
func (s *topologyView) acceptsIdentity(identity pki.Identity) bool {
	if m, ok := s.members[identity.ID]; ok {
		return m.addresses() == identity.Addresses
	}
	_, v4Taken := s.owners[identity.IPv4]
	_, v6Taken := s.owners[identity.IPv6]
	return !v4Taken && !v6Taken
}

// LookupPeer returns the local binding for a primary address. A confirmed instance
// conflict retains this binding even after the last usable path closes.
func (n *Node) LookupPeer(primary netip.Addr) (PeerID, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := n.ownerLocked(primary)
	return id, id != (PeerID{})
}

func (n *Node) addressConflictLocked(identity pki.Identity) bool {
	if !n.policy.Load().acceptsIdentity(identity) {
		return true
	}
	id := identity.ID
	if intro := n.discovered[id]; time.Now().Before(intro.authorizedUntil) && intro.Addresses != identity.Addresses {
		return true
	}
	if active := n.preferredSessionLocked(n.peers[id], false, nil); active != nil && active.remoteIdentity.Addresses != identity.Addresses {
		return true
	}
	for _, addr := range []netip.Addr{identity.IPv4, identity.IPv6} {
		if owner := n.ownerLocked(addr); owner != (PeerID{}) && owner != id {
			return true
		}
	}
	return false
}

func (n *Node) ownerLocked(addr netip.Addr) PeerID {
	p := n.policy.Load()
	if id, ok := p.owners[addr]; ok {
		return id
	}
	if !p.cluster.Subnet(addr).IsValid() {
		return PeerID{}
	}
	// A confirmed dispute keeps both primaries bound even after cache expiry
	// and loss of the incumbent's last path.
	for peer, conflict := range n.conflicts {
		if !conflict.confirmedAt.IsZero() {
			for _, w := range conflict.claims {
				if w.addresses.IPv4 == addr || w.addresses.IPv6 == addr {
					return peer
				}
			}
		}
	}
	if id, ok := n.discoveredOwners[addr]; ok && time.Now().Before(n.discovered[id].authorizedUntil) {
		return id
	}
	for id, paths := range n.peers {
		if s := n.preferredSessionLocked(paths, false, nil); s != nil && (addr == s.remoteIdentity.IPv4 || addr == s.remoteIdentity.IPv6) {
			return id
		}
	}
	return PeerID{}
}

// AnycastMembers returns a copy of the members permitted to carry vip in the
// local topology. Readiness and admission of new flows are host decisions.
func (n *Node) AnycastMembers(vip netip.Addr) []PeerID {
	return slices.Clone(n.policy.Load().instances[vip])
}
