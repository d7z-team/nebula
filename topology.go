package nebula

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

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
	// Endpoints lists reachable physical addresses of this member.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// RoutedPrefixes enables downstream prefixes within the session certificate's authority.
	RoutedPrefixes []netip.Prefix `json:"routedPrefixes,omitempty"`
	// Transit authorizes this member to relay mesh circuits.
	Transit bool `json:"transit,omitempty"`
	// Restricted limits direct connections to the neighbors in Links.
	Restricted bool `json:"restricted,omitempty"`
	// BytesPerSecond shapes this member's total outbound application bytes. Zero is unlimited.
	BytesPerSecond int `json:"bytesPerSecond,omitempty"`
	// Topics grants publication on each topic and its descendants.
	Topics []string `json:"topics,omitempty"`
}

// Topology is the host-approved local view.
type Topology struct {
	Network  string         `json:"network"`
	Networks []netip.Prefix `json:"networks"`
	Members  []Member       `json:"members"`
}

type topologyView struct {
	Network        string
	Networks       []netip.Prefix
	members        map[PeerID]Member
	owners         map[netip.Addr]PeerID
	endpointOwners map[Endpoint][]PeerID
}

func (c *topologyView) containsIP(ip netip.Addr) bool {
	for _, p := range c.Networks {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *topologyView) authorizes(peer PeerID, addr netip.Addr) bool {
	if s.containsIP(addr) {
		owner, assigned := s.owners[addr]
		return assigned && owner == peer
	}
	for _, p := range s.members[peer].RoutedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidTopic reports whether s is a valid application event topic.
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

// Validate checks the topology using the same rules as New and ApplyTopology.
func (c Topology) Validate() error {
	_, err := c.compile()
	return err
}

func (c Topology) compile() (*topologyView, error) {
	if !pki.ValidName(c.Network) || len(c.Networks) == 0 || len(c.Members) == 0 {
		return nil, errors.New("missing network, prefixes or members")
	}
	for _, p := range c.Networks {
		if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
			return nil, errors.New("invalid overlay prefix")
		}
	}
	s := &topologyView{
		Network: c.Network, Networks: slices.Clone(c.Networks), members: make(map[PeerID]Member, len(c.Members)),
		owners: make(map[netip.Addr]PeerID), endpointOwners: make(map[Endpoint][]PeerID),
	}
	for _, m := range c.Members {
		a, err := pki.NewPeerID(m.IPv4, m.IPv6)
		if err != nil {
			return nil, err
		}
		if m.BytesPerSecond < 0 {
			return nil, fmt.Errorf("negative shaping rate for %s", a)
		}
		m.Links = slices.Clone(m.Links)
		m.Endpoints = slices.Clone(m.Endpoints)
		m.RoutedPrefixes = slices.Clone(m.RoutedPrefixes)
		m.Topics = slices.Clone(m.Topics)
		s.members[a] = m
		for _, ip := range []netip.Addr{m.IPv4, m.IPv6} {
			if !s.containsIP(ip) || s.owners[ip] != (PeerID{}) {
				return nil, fmt.Errorf("invalid or duplicate address %s", ip)
			}
			s.owners[ip] = a
		}
		for _, e := range m.Endpoints {
			if !e.Valid() {
				return nil, errors.New("invalid endpoint")
			}
			s.endpointOwners[e] = append(s.endpointOwners[e], a)
			if e.Network == "tcp" {
				// Incoming TCP connections use ephemeral source ports.
				e.Address = netip.AddrPortFrom(e.Address.Addr(), 0)
				s.endpointOwners[e] = append(s.endpointOwners[e], a)
			}
		}
		for _, p := range m.RoutedPrefixes {
			if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
				return nil, errors.New("invalid routed prefix")
			}
		}
		for _, t := range m.Topics {
			if !ValidTopic(t) {
				return nil, errors.New("invalid topic")
			}
		}
	}
	for a, m := range s.members {
		for i, b := range m.Links {
			if a == b || slices.Contains(m.Links[:i], b) || !slices.Contains(s.members[b].Links, a) {
				return nil, fmt.Errorf("invalid adjacency %s to %s", a, b)
			}
		}
	}
	return s, nil
}
