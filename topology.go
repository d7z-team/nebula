package nebula

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

// Endpoint identifies a UDP or TCP address on the physical network.
type Endpoint struct {
	Network string         `json:"network"`
	Address netip.AddrPort `json:"address"`
}

func (e Endpoint) Valid() bool {
	return (e.Network == "udp" || e.Network == "tcp") && e.Address.IsValid() && e.Address.Port() != 0 && !e.Address.Addr().IsUnspecified() && !e.Address.Addr().IsMulticast() && !e.Address.Addr().Is4In6()
}

// PeerID identifies a member by its two certified overlay addresses.
type PeerID = pki.PeerID

// Member contains the local routing and application permissions for one peer.
type Member struct {
	IPv4 netip.Addr `json:"ipv4"`
	IPv6 netip.Addr `json:"ipv6"`
	// Links declares reciprocal neighbors to maintain and use as circuit hops.
	Links []PeerID `json:"links,omitempty"`
	// Endpoints lists host-configured physical addresses. A member that dials
	// its neighbors can serve as a circuit hop with an empty list.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// RoutedPrefixes enables downstream prefixes within the session certificate's authority.
	RoutedPrefixes []netip.Prefix `json:"routedPrefixes,omitempty"`
	// AnycastIPs permits this member to carry the listed service addresses.
	AnycastIPs []netip.Addr `json:"anycastIPs,omitempty"`
	// MulticastGroups subscribes this member to exact multicast destinations.
	MulticastGroups []netip.Addr `json:"multicastGroups,omitempty"`
	// Transit authorizes this member to relay mesh circuits.
	Transit bool `json:"transit,omitempty"`
	// Restricted limits direct connections to the neighbors in Links.
	Restricted bool `json:"restricted,omitempty"`
	// BytesPerSecond shapes this member's total outbound application bytes. Zero is unlimited.
	BytesPerSecond int `json:"bytesPerSecond,omitempty"`
	// Topics grants publication on each topic and its descendants.
	Topics []string `json:"topics,omitempty"`
}

// Clone returns an independent copy of the member's routing and application grants.
func (m Member) Clone() Member {
	m.Links = slices.Clone(m.Links)
	m.Endpoints = slices.Clone(m.Endpoints)
	m.RoutedPrefixes = slices.Clone(m.RoutedPrefixes)
	m.AnycastIPs = slices.Clone(m.AnycastIPs)
	m.MulticastGroups = slices.Clone(m.MulticastGroups)
	m.Topics = slices.Clone(m.Topics)
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
	subnets              map[netip.Prefix][]PeerID
	directed             map[netip.Addr]netip.Prefix
	instances            map[netip.Addr][]PeerID
	groups               map[multicastGroup][]PeerID
	members              map[PeerID]Member
	owners               map[netip.Addr]PeerID
	endpointOwners       map[Endpoint][]PeerID
}

func (c *topologyView) isOverlayAddress(ip netip.Addr) bool {
	return c.cluster.Subnet(ip).IsValid() || c.cluster.InAnycastPool(ip)
}

type multicastGroup struct {
	addr netip.Addr
	link netip.Prefix
}

var (
	limitedBroadcast = netip.MustParseAddr("255.255.255.255")
	allHosts         = netip.MustParseAddr("224.0.0.1")
	allNodes         = netip.MustParseAddr("ff02::1")
	localGroups      = netip.MustParsePrefix("224.0.0.0/24")
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

func (s *topologyView) memberSubnet(peer PeerID, a netip.Addr) netip.Prefix {
	if a.Is4() {
		return s.cluster.Subnet(peer.IPv4())
	}
	return s.cluster.Subnet(peer.IPv6())
}

func (s *topologyView) groupKey(peer PeerID, a netip.Addr) multicastGroup {
	k := multicastGroup{addr: a}
	if localGroups.Contains(a) || a.Is6() && a.As16()[1]&15 == 2 {
		k.link = s.memberSubnet(peer, a)
	}
	return k
}

// groupRecipients classifies group addresses even when distribution is disabled.
func (s *topologyView) groupRecipients(from PeerID, dst netip.Addr) ([]PeerID, bool, error) {
	subnet, directed := s.directed[dst]
	switch {
	case dst == limitedBroadcast || directed:
		link := s.memberSubnet(from, dst)
		if !s.broadcast || directed && subnet != link {
			return nil, true, ErrPathPolicy
		}
		return s.subnets[link], true, nil
	case dst.IsMulticast():
		if !s.multicast || !validGroup(dst) {
			return nil, true, ErrPathPolicy
		}
		if dst.Is6() && dst.As16()[1]&15 == 1 {
			return nil, true, nil
		}
		if dst == allHosts || dst == allNodes {
			return s.subnets[s.memberSubnet(from, dst)], true, nil
		}
		return s.groups[s.groupKey(from, dst)], true, nil
	default:
		return nil, false, nil
	}
}

func comparePeer(a, b PeerID) int { return bytes.Compare(a[:], b[:]) }

// Validate checks the topology using the same rules as New and ApplyTopology.
func (c Topology) Validate(cluster pki.Cluster) error {
	_, err := c.compile(cluster)
	return err
}

func (c Topology) compile(cluster pki.Cluster) (*topologyView, error) {
	if !pki.ValidName(c.Network) || c.Network != cluster.Network() || len(c.Members) == 0 {
		return nil, errors.New("cluster network and members required")
	}
	s := &topologyView{
		cluster: cluster, broadcast: c.EnableBroadcast, multicast: c.EnableMulticast,
		subnets: make(map[netip.Prefix][]PeerID), directed: make(map[netip.Addr]netip.Prefix),
		instances: make(map[netip.Addr][]PeerID), groups: make(map[multicastGroup][]PeerID), members: make(map[PeerID]Member, len(c.Members)),
		owners: make(map[netip.Addr]PeerID), endpointOwners: make(map[Endpoint][]PeerID),
	}
	for _, subnet := range cluster.Subnets() {
		if a := pki.Broadcast(subnet); a.IsValid() {
			s.directed[a] = subnet
		}
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
	for _, peers := range s.subnets {
		slices.SortFunc(peers, comparePeer)
	}
	return s, nil
}

func (s *topologyView) indexMember(m Member) error {
	id, err := pki.NewPeerID(m.IPv4, m.IPv6)
	if err != nil {
		return err
	}
	if err := s.cluster.ValidateMember(id); err != nil {
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
	for _, topic := range m.Topics {
		if !ValidTopic(topic) {
			return fmt.Errorf("invalid topic %q", topic)
		}
	}
	for _, ip := range []netip.Addr{m.IPv4, m.IPv6} {
		if _, exists := s.owners[ip]; exists {
			return fmt.Errorf("duplicate address %s", ip)
		}
		s.owners[ip] = id
		subnet := s.cluster.Subnet(ip)
		s.subnets[subnet] = append(s.subnets[subnet], id)
	}
	for _, ep := range m.Endpoints {
		if !ep.Valid() {
			return fmt.Errorf("invalid endpoint %v", ep)
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
		key := s.groupKey(id, group)
		s.groups[key] = append(s.groups[key], id)
	}
	s.members[id] = m
	return nil
}

// acceptsIdentity prevents dynamic discovery from overriding a configured primary address.
func (s *topologyView) acceptsIdentity(id PeerID) bool {
	for _, addr := range []netip.Addr{id.IPv4(), id.IPv6()} {
		if owner, ok := s.owners[addr]; ok && owner != id {
			return false
		}
	}
	return true
}

// LookupPeer returns the configured or authenticated owner of a primary address from local state.
func (n *Node) LookupPeer(primary netip.Addr) (PeerID, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := n.ownerLocked(primary)
	return id, id != (PeerID{})
}

func (n *Node) conflictingOwnerLocked(id PeerID) bool {
	for _, addr := range []netip.Addr{id.IPv4(), id.IPv6()} {
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
	if id, ok := n.discoveredOwners[addr]; ok && time.Now().Before(n.discovered[id].authorizedUntil) {
		return id
	}
	for id, paths := range n.peers {
		if (addr == id.IPv4() || addr == id.IPv6()) && n.preferredSessionLocked(paths, false, nil) != nil {
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
