package nebula

import (
	"cmp"
	"crypto/tls"
	"maps"
	"net/netip"
	"slices"
	"time"
)

// PathStatus describes one established path to Peer. Active marks the preferred
// general-purpose path. QUIC counters are populated for UDP paths.
type PathStatus struct {
	AuthorizedUntil time.Time
	Peer            PeerID
	// Transport is "udp" (QUIC), "tcp" (TLS), or "relay" (an end-to-end circuit).
	Transport, ALPN     string
	TLSGroup            tls.CurveID
	TLSVersion          uint16
	Serial, LocalSerial string
	Expires             time.Time
	// Endpoint is the physical peer address for a direct path. It is zero for a relay.
	Endpoint netip.AddrPort
	// Circuit lists the local endpoint, intermediate relays and peer on a relayed path.
	Circuit     []PeerID
	RTT, Jitter time.Duration
	Failures    int
	// RemoteIPLimit is the peer's authenticated receive ceiling for complete IP packets.
	RemoteIPLimit int
	// DatagramSize is the current directional QUIC payload budget in bytes.
	DatagramSize                     int64
	QUICBytesSent, QUICBytesReceived uint64
	QUICPacketsLost, QUICPacketsSent uint64
	CongestionWindow                 uint64
	StreamFallbacks                  uint64
	Active                           bool
}

// Paths returns a snapshot ordered by peer, preferred path first, then transport.
func (n *Node) Paths() []PathStatus {
	n.mu.Lock()
	out := make([]PathStatus, 0, len(n.peers))
	for _, paths := range n.peers {
		active := n.preferredSessionLocked(paths, false, nil)
		for _, s := range paths.sessions {
			out = append(out, s.pathStatusLocked(active == s))
		}
	}
	n.mu.Unlock()
	slices.SortFunc(out, func(a, b PathStatus) int {
		if c := comparePeer(a.Peer, b.Peer); c != 0 {
			return c
		}
		if a.Active != b.Active {
			if a.Active {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Transport, b.Transport)
	})
	return out
}

// PreferredPath returns the currently preferred established path for general traffic
// to peer. It performs no I/O and returns false if no authorized session is usable.
// On a direct path Peer is the next hop. On a relay path Circuit[1] is the next hop.
func (n *Node) PreferredPath(peer PeerID) (PathStatus, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.preferredSessionLocked(n.peers[peer], false, nil)
	if s == nil {
		return PathStatus{}, false
	}
	return s.pathStatusLocked(true), true
}

// The caller holds Node.mu while reading the session's authorization and path.
func (s *session) pathStatusLocked(active bool) PathStatus {
	leaf := s.state.PeerCertificates[0]
	st := PathStatus{
		Peer: s.peer, Transport: s.kind, Endpoint: s.remoteEndpoint(), RemoteIPLimit: s.remoteIPLimit, Circuit: slices.Clone(s.path),
		AuthorizedUntil: s.until, ALPN: s.state.NegotiatedProtocol, TLSGroup: s.state.CurveID, TLSVersion: s.state.Version,
		LocalSerial: s.localChain[0].SerialNumber.String(), Serial: leaf.SerialNumber.String(), Expires: leaf.NotAfter, Active: active,
		DatagramSize: s.budget.Load(), StreamFallbacks: s.overflow.Load(),
	}
	s.healthMu.Lock()
	st.RTT, st.Jitter, st.Failures = s.rtt, s.jitter, s.failures
	s.healthMu.Unlock()
	if s.q != nil {
		q := s.q.ConnectionStats()
		st.RTT = q.SmoothedRTT
		st.Jitter = q.MeanDeviation
		st.QUICBytesSent, st.QUICBytesReceived = q.BytesSent, q.BytesReceived
		st.QUICPacketsLost, st.QUICPacketsSent, st.CongestionWindow = q.PacketsLost, q.PacketsSent, q.CongestionWindow
	}
	return st
}

// ControlStatus describes local node readiness and cumulative transport activity.
type ControlStatus struct {
	Peer               PeerID
	Serial             string
	CertificateExpires time.Time
	Started, Closed    bool
	// LastError records the most recent failed peer connection attempt.
	LastError string
	// ListenerErrors records terminal listener errors keyed by udp4, udp6, tcp4 or tcp6.
	ListenerErrors map[string]string
	// Ready means local membership and credentials are valid, including before Start.
	Ready    bool
	Circuits int
	// BytesScheduled counts shaped application bytes. DialFailures counts failed endpoint dials.
	BytesScheduled, DialFailures uint64
}

// ControlStatus returns a snapshot of this node. Started indicates that I/O has started.
func (n *Node) ControlStatus() ControlStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := ControlStatus{Circuits: len(n.circuits), BytesScheduled: n.bytesScheduled.Load(), DialFailures: n.dialFailures.Load(), LastError: n.lastConnectError, ListenerErrors: maps.Clone(n.listenerErrors)}
	credentials := n.cred.Load()
	leaf := credentials.Client.Leaf
	v.Peer, v.Serial, v.CertificateExpires = n.id, leaf.SerialNumber.String(), leaf.NotAfter
	v.Started, v.Closed = n.state == running, n.state == closed
	if p := n.policy.Load(); p != nil {
		v.Ready = !v.Closed && n.ready(p)
	}
	return v
}
