package nebula

import (
	"net/netip"
	"slices"
	"sort"
	"sync"
)

// forEachFunc is used to benefit folks that want to do work inside the lock
type forEachFunc func(addr netip.AddrPort, preferred bool)

// The checkFuncs here are to simplify bulk importing LH query response logic into a single function (reset slice and iterate)
type checkFuncV4 func(vpnIp netip.Addr, to *V4AddrPort) bool
type checkFuncV6 func(vpnIp netip.Addr, to *V6AddrPort) bool

// cache is an internal struct that splits v4 and v6 addresses inside the cache map
type cache struct {
	v4    *cacheV4
	v6    *cacheV6
	relay *cacheRelay
}

type cacheRelay struct {
	relay []netip.Addr
}

// cacheV4 stores learned and reported ipv4 records under cache
type cacheV4 struct {
	learned  *V4AddrPort
	reported []*V4AddrPort
}

// cacheV4 stores learned and reported ipv6 records under cache
type cacheV6 struct {
	learned  *V6AddrPort
	reported []*V6AddrPort
}

// remoteList is a unifying concept for lighthouse servers and clients as well as hostinfos.
// It serves as a local cache of query replies, host update notifications, and locally learned addresses
type remoteList struct {
	// Every interaction with internals requires a lock!
	sync.RWMutex

	// The full list of vpn addresses assigned to this host
	vpnAddrs []netip.Addr

	// A deduplicated set of underlay addresses. Any accessor should lock beforehand.
	addrs []netip.AddrPort

	// A set of relay addresses. VpnIp addresses that the remote identified as relays.
	relays []netip.Addr

	// These are maps to store v4 and v6 addresses per lighthouse
	// Map key is the vpnIp of the person that told us about this the cached entries underneath.
	// For learned addresses, this is the vpnIp that sent the packet
	cache map[netip.Addr]*cache

	// This is a list of remotes that we have tried to handshake with and have returned from the wrong vpn ip.
	// They should not be tried again during a handshake
	badRemotes []netip.AddrPort

	// A flag that the cache may have changed and addrs needs to be rebuilt
	shouldRebuild bool
}

func newRemoteList(vpnAddrs []netip.Addr) *remoteList {
	r := &remoteList{
		vpnAddrs: make([]netip.Addr, len(vpnAddrs)),
		addrs:    make([]netip.AddrPort, 0),
		relays:   make([]netip.Addr, 0),
		cache:    make(map[netip.Addr]*cache),
	}
	copy(r.vpnAddrs, vpnAddrs)
	return r
}

// ForEach locks and will call the forEachFunc for every deduplicated address in the list
// The deduplication work may need to occur here, so you must pass preferredRanges
func (r *remoteList) ForEach(preferredRanges []netip.Prefix, forEach forEachFunc) {
	r.Rebuild(preferredRanges)
	r.RLock()
	for _, v := range r.addrs {
		forEach(v, isPreferred(v.Addr(), preferredRanges))
	}
	r.RUnlock()
}

// CopyAddrs locks and makes a deep copy of the deduplicated address list
// The deduplication work may need to occur here, so you must pass preferredRanges
func (r *remoteList) CopyAddrs(preferredRanges []netip.Prefix) []netip.AddrPort {
	if r == nil {
		return nil
	}

	r.Rebuild(preferredRanges)

	r.RLock()
	defer r.RUnlock()
	c := make([]netip.AddrPort, len(r.addrs))
	for i, v := range r.addrs {
		c[i] = v
	}
	return c
}

// LearnRemote locks and sets the learned slot for the owner vpn ip to the provided addr
// Currently this is only needed when hostInfo.SetRemote is called as that should cover both handshaking and roaming.
// It will mark the deduplicated address list as dirty, so do not call it unless new information is available
func (r *remoteList) LearnRemote(ownerVpnIp netip.Addr, remote netip.AddrPort) {
	r.Lock()
	defer r.Unlock()
	if remote.Addr().Is4() {
		r.unlockedSetLearnedV4(ownerVpnIp, netAddrToProtoV4AddrPort(remote.Addr(), remote.Port()))
	} else {
		r.unlockedSetLearnedV6(ownerVpnIp, netAddrToProtoV6AddrPort(remote.Addr(), remote.Port()))
	}
}

// BlockRemote locks and records the address as bad, it will be excluded from the deduplicated address list
func (r *remoteList) BlockRemote(bad packetSender) {
	if bad.IsRelayed {
		return
	}

	r.Lock()
	defer r.Unlock()

	// Check if we already blocked this addr
	if r.unlockedIsBad(bad.UdpAddr) {
		return
	}

	// We copy here because we are taking something else's memory and we can't trust everything
	r.badRemotes = append(r.badRemotes, bad.UdpAddr)

	// Mark the next interaction must recollect/dedupe
	r.shouldRebuild = true
}

// RefreshFromHandshake locks and updates the remoteList to account for data learned upon a completed handshake
func (r *remoteList) RefreshFromHandshake(vpnAddrs []netip.Addr) {
	r.Lock()
	r.badRemotes = nil
	r.vpnAddrs = make([]netip.Addr, len(vpnAddrs))
	copy(r.vpnAddrs, vpnAddrs)
	r.Unlock()
}

// Rebuild locks and generates the deduplicated address list only if there is work to be done
// There is generally no reason to call this directly but it is safe to do so
func (r *remoteList) Rebuild(preferredRanges []netip.Prefix) {
	r.Lock()
	defer r.Unlock()

	// Only rebuild if the cache changed
	if r.shouldRebuild {
		r.unlockedCollect()
		r.shouldRebuild = false
	}

	// Always re-sort because callers may supply different preferences.
	r.unlockedSort(preferredRanges)
}

// unlockedIsBad assumes you have the write lock and checks if the remote matches any entry in the blocked address list
func (r *remoteList) unlockedIsBad(remote netip.AddrPort) bool {
	return slices.Contains(r.badRemotes, remote)
}

// unlockedSetLearnedV4 assumes you have the write lock and sets the current learned address for this owner and marks the
// deduplicated address list as dirty
func (r *remoteList) unlockedSetLearnedV4(ownerVpnIp netip.Addr, to *V4AddrPort) {
	r.shouldRebuild = true
	r.unlockedGetOrMakeV4(ownerVpnIp).learned = to
}

// unlockedSetV4 assumes you have the write lock and resets the reported list of ips for this owner to the list provided
// and marks the deduplicated address list as dirty
func (r *remoteList) unlockedSetV4(ownerVpnIp, vpnIp netip.Addr, to []*V4AddrPort, check checkFuncV4) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV4(ownerVpnIp)

	// Reset the slice
	c.reported = c.reported[:0]

	// We can't take their array but we can take their pointers.
	// Filter before capping so denied addrs do not crowd out allowed ones reported later in the list.
	for _, v := range to {
		if check(vpnIp, v) {
			c.reported = append(c.reported, v)
			if len(c.reported) == maxRemotes {
				break
			}
		}
	}
}

func (r *remoteList) unlockedSetRelay(ownerVpnIp netip.Addr, to []netip.Addr) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeRelay(ownerVpnIp)

	// Reset the slice
	c.relay = c.relay[:0]

	// We can't take their array but we can take their pointers
	c.relay = append(c.relay, to[:minInt(len(to), maxRemotes)]...)
}

// unlockedPrependV4 assumes you have the write lock and prepends the address in the reported list for this owner
// This is only useful for establishing static hosts
func (r *remoteList) unlockedPrependV4(ownerVpnIp netip.Addr, to *V4AddrPort) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV4(ownerVpnIp)

	// We are doing the easy append because this is rarely called
	c.reported = append([]*V4AddrPort{to}, c.reported...)
	if len(c.reported) > maxRemotes {
		c.reported = c.reported[:maxRemotes]
	}
}

// unlockedSetLearnedV6 assumes you have the write lock and sets the current learned address for this owner and marks the
// deduplicated address list as dirty
func (r *remoteList) unlockedSetLearnedV6(ownerVpnIp netip.Addr, to *V6AddrPort) {
	r.shouldRebuild = true
	r.unlockedGetOrMakeV6(ownerVpnIp).learned = to
}

// unlockedSetV6 assumes you have the write lock and resets the reported list of ips for this owner to the list provided
// and marks the deduplicated address list as dirty
func (r *remoteList) unlockedSetV6(ownerVpnIp, vpnIp netip.Addr, to []*V6AddrPort, check checkFuncV6) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV6(ownerVpnIp)

	// Reset the slice
	c.reported = c.reported[:0]

	// We can't take their array but we can take their pointers.
	// Filter before capping so denied addrs do not crowd out allowed ones reported later in the list.
	for _, v := range to {
		if check(vpnIp, v) {
			c.reported = append(c.reported, v)
			if len(c.reported) == maxRemotes {
				break
			}
		}
	}
}

// unlockedPrependV6 assumes you have the write lock and prepends the address in the reported list for this owner
// This is only useful for establishing static hosts
func (r *remoteList) unlockedPrependV6(ownerVpnIp netip.Addr, to *V6AddrPort) {
	r.shouldRebuild = true
	c := r.unlockedGetOrMakeV6(ownerVpnIp)

	// We are doing the easy append because this is rarely called
	c.reported = append([]*V6AddrPort{to}, c.reported...)
	if len(c.reported) > maxRemotes {
		c.reported = c.reported[:maxRemotes]
	}
}

func (r *remoteList) unlockedGetOrMakeRelay(ownerVpnIp netip.Addr) *cacheRelay {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for relay if we never have any
	if am.relay == nil {
		am.relay = &cacheRelay{}
	}
	return am.relay
}

// unlockedGetOrMakeV4 assumes you have the write lock and builds the cache and owner entry. Only the v4 pointer is established.
// The caller must dirty the learned address cache if required
func (r *remoteList) unlockedGetOrMakeV4(ownerVpnIp netip.Addr) *cacheV4 {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for v6 addresses if we never have any
	if am.v4 == nil {
		am.v4 = &cacheV4{}
	}
	return am.v4
}

// unlockedGetOrMakeV6 assumes you have the write lock and builds the cache and owner entry. Only the v6 pointer is established.
// The caller must dirty the learned address cache if required
func (r *remoteList) unlockedGetOrMakeV6(ownerVpnIp netip.Addr) *cacheV6 {
	am := r.cache[ownerVpnIp]
	if am == nil {
		am = &cache{}
		r.cache[ownerVpnIp] = am
	}
	// Avoid occupying memory for v4 addresses if we never have any
	if am.v6 == nil {
		am.v6 = &cacheV6{}
	}
	return am.v6
}

// unlockedCollect assumes you have the write lock and collects/transforms the cache into the deduped address list.
// The result of this function can contain duplicates. unlockedSort handles cleaning it.
func (r *remoteList) unlockedCollect() {
	addrs := r.addrs[:0]
	relays := r.relays[:0]

	for _, c := range r.cache {
		if c.v4 != nil {
			if c.v4.learned != nil {
				u := protoV4AddrPortToNetAddrPort(c.v4.learned)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}

			for _, v := range c.v4.reported {
				if v == nil {
					continue
				}
				u := protoV4AddrPortToNetAddrPort(v)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}
		}

		if c.v6 != nil {
			if c.v6.learned != nil {
				u := protoV6AddrPortToNetAddrPort(c.v6.learned)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}

			for _, v := range c.v6.reported {
				if v == nil {
					continue
				}
				u := protoV6AddrPortToNetAddrPort(v)
				if !r.unlockedIsBad(u) {
					addrs = append(addrs, u)
				}
			}
		}

		if c.relay != nil {
			for _, v := range c.relay.relay {
				relays = append(relays, v)
			}
		}
	}

	r.addrs = addrs
	r.relays = relays

}

// unlockedSort assumes you have the write lock and performs the deduping and sorting of the address list
func (r *remoteList) unlockedSort(preferredRanges []netip.Prefix) {
	// Use a map to deduplicate any relay addresses
	dedupedRelays := map[netip.Addr]struct{}{}
	for _, relay := range r.relays {
		dedupedRelays[relay] = struct{}{}
	}
	r.relays = r.relays[:0]
	for relay := range dedupedRelays {
		r.relays = append(r.relays, relay)
	}
	// Put them in a somewhat consistent order after de-duplication
	slices.SortFunc(r.relays, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	// Now the addrs
	n := len(r.addrs)
	if n < 2 {
		return
	}

	lessFunc := func(i, j int) bool {
		a := r.addrs[i]
		b := r.addrs[j]
		// Preferred addresses first

		aPref := isPreferred(a.Addr(), preferredRanges)
		bPref := isPreferred(b.Addr(), preferredRanges)
		switch {
		case aPref && !bPref:
			// If i is preferred and j is not, i is less than j
			return true

		case !aPref && bPref:
			// If j is preferred then i is not due to the else, i is not less than j
			return false

		default:
			// Both i an j are either preferred or not, sort within that
		}

		// ipv6 addresses 2nd
		a4 := a.Addr().Is4()
		b4 := b.Addr().Is4()
		switch {
		case a4 == false && b4 == true:
			// If i is v6 and j is v4, i is less than j
			return true

		case a4 == true && b4 == false:
			// If j is v6 and i is v4, i is not less than j
			return false

		case a4 == true && b4 == true:
			// i and j are both ipv4
			aPrivate := a.Addr().IsPrivate()
			bPrivate := b.Addr().IsPrivate()
			switch {
			case !aPrivate && bPrivate:
				// If i is a public ip (not private) and j is a private ip, i is less then j
				return true

			case aPrivate && !bPrivate:
				// If j is public (not private) then i is private due to the else, i is not less than j
				return false

			default:
				// Both i an j are either public or private, sort within that
			}

		default:
			// Both i an j are either ipv4 or ipv6, sort within that
		}

		// lexical order of ips 3rd
		c := a.Addr().Compare(b.Addr())
		if c == 0 {
			// Ips are the same, Lexical order of ports 4th
			return a.Port() < b.Port()
		}

		// Ip wasn't the same
		return c < 0
	}

	// Sort it
	sort.Slice(r.addrs, lessFunc)

	// Deduplicate
	a, b := 0, 1
	for b < n {
		if r.addrs[a] != r.addrs[b] {
			a++
			if a != b {
				r.addrs[a], r.addrs[b] = r.addrs[b], r.addrs[a]
			}
		}
		b++
	}

	r.addrs = r.addrs[:a+1]
	return
}

// minInt returns the minimum integer of a or b
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isPreferred returns true of the ip is contained in the preferredRanges list
func isPreferred(ip netip.Addr, preferredRanges []netip.Prefix) bool {
	for _, p := range preferredRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
