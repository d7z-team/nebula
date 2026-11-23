package nebula

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/gaissmai/bart"
)

// A discovery record keeps the wire address family and the identity that
// supplied each endpoint, so a lighthouse can answer on behalf of that peer.
type discoveryRecord struct {
	v4     endpointSet[V4AddrPort]
	v6     endpointSet[V6AddrPort]
	relays []netip.Addr
}

type endpointSet[T any] struct {
	learned  *T
	reported []*T
}

func (s *endpointSet[T]) replaceReported(reported []*T, limit int, overlay *bart.Lite, addrPort func(*T) netip.AddrPort) {
	clear(s.reported)
	s.reported = s.reported[:0]
	for _, v := range reported {
		if v == nil || overlay.Contains(addrPort(v).Addr()) {
			continue
		}
		s.reported = append(s.reported, v)
		if len(s.reported) == limit {
			break
		}
	}
}

func (s *endpointSet[T]) appendWire(dst []*T) []*T {
	if s.learned != nil {
		dst = append(dst, s.learned)
	}
	return append(dst, s.reported...)
}

func (s *endpointSet[T]) appendEndpoints(dst []netip.AddrPort, addrPort func(*T) netip.AddrPort) []netip.AddrPort {
	if s.learned != nil {
		dst = append(dst, addrPort(s.learned))
	}
	for _, v := range s.reported {
		dst = append(dst, addrPort(v))
	}
	return dst
}

// All slices in a candidate snapshot are immutable after publication. Handshake,
// relay and punch workers can use them without holding the discovery lock over I/O.
type remoteCandidates struct {
	addresses []netip.Addr
	endpoints []netip.AddrPort
	relays    []netip.Addr
}

type remoteList struct {
	sync.RWMutex
	vpnAddrs        []netip.Addr
	preferredRanges []netip.Prefix
	records         map[netip.Addr]*discoveryRecord
	staticEndpoints map[netip.Addr][]netip.AddrPort
	introduced      []netip.AddrPort
	introRelays     []netip.Addr
	introExpiry     time.Time
	introCert       string
	badRemotes      []netip.AddrPort
	cached          *remoteCandidates
}

// recordForUpdate requires the write lock.
func (r *remoteList) recordForUpdate(owner netip.Addr) *discoveryRecord {
	r.cached = nil
	record := r.records[owner]
	if record == nil {
		record = &discoveryRecord{}
		r.records[owner] = record
	}
	return record
}

func (r *remoteList) LearnRemote(owner netip.Addr, remote netip.AddrPort) {
	r.Lock()
	defer r.Unlock()
	record := r.recordForUpdate(owner)
	if remote.Addr().Is4() {
		record.v4.learned = netAddrToProtoV4AddrPort(remote.Addr(), remote.Port())
	} else {
		record.v6.learned = netAddrToProtoV6AddrPort(remote.Addr(), remote.Port())
	}
}

// BlockRemote excludes a direct endpoint that answered with the wrong identity.
func (r *remoteList) BlockRemote(bad packetSender) {
	if bad.IsRelayed {
		return
	}
	r.Lock()
	defer r.Unlock()
	if !slices.Contains(r.badRemotes, bad.UdpAddr) {
		r.badRemotes = append(r.badRemotes, bad.UdpAddr)
		r.cached = nil
	}
}

func (r *remoteList) RefreshFromHandshake(vpnAddrs []netip.Addr) {
	r.Lock()
	defer r.Unlock()
	r.badRemotes = nil
	r.vpnAddrs = slices.Clone(vpnAddrs)
	r.cached = nil
}

func (r *remoteList) candidates() *remoteCandidates {
	if r == nil {
		return nil
	}
	r.Lock()
	defer r.Unlock()
	if !r.introExpiry.IsZero() && !time.Now().Before(r.introExpiry) {
		r.introCert = ""
		r.introduced = nil
		r.introRelays = nil
		r.introExpiry = time.Time{}
		r.cached = nil
	}
	if r.cached != nil {
		return r.cached
	}

	c := &remoteCandidates{addresses: r.vpnAddrs, endpoints: slices.Clone(r.introduced), relays: slices.Clone(r.introRelays)}
	for _, endpoints := range r.staticEndpoints {
		c.endpoints = append(c.endpoints, endpoints...)
	}
	for _, record := range r.records {
		c.endpoints = record.v4.appendEndpoints(c.endpoints, protoV4AddrPortToNetAddrPort)
		c.endpoints = record.v6.appendEndpoints(c.endpoints, protoV6AddrPortToNetAddrPort)
		c.relays = append(c.relays, record.relays...)
	}
	c.endpoints = slices.DeleteFunc(c.endpoints, func(addr netip.AddrPort) bool {
		return slices.Contains(r.badRemotes, addr)
	})
	// Within each preference group, try IPv6, then public IPv4, then private IPv4.
	priority := func(addr netip.Addr) int {
		rank := 0
		if !isPreferred(addr, r.preferredRanges) {
			rank = 3
		}
		if addr.Is4() {
			rank++
			if addr.IsPrivate() {
				rank++
			}
		}
		return rank
	}
	slices.SortFunc(c.endpoints, func(a, b netip.AddrPort) int {
		if order := cmp.Compare(priority(a.Addr()), priority(b.Addr())); order != 0 {
			return order
		}
		return a.Compare(b)
	})
	c.endpoints = slices.Compact(c.endpoints)
	slices.SortFunc(c.relays, netip.Addr.Compare)
	c.relays = slices.Compact(c.relays)
	r.cached = c
	return c
}

func isPreferred(ip netip.Addr, preferredRanges []netip.Prefix) bool {
	for _, p := range preferredRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
