package nebula

import (
	"bytes"
	"cmp"
	"net/netip"
	"slices"
	"time"
)

type PeerStatus struct {
	AuthorizedUntil                  time.Time
	Peer                             PeerID
	Transport, ALPN, Group           string
	TLSVersion                       uint16
	Serial, LocalSerial              string
	Expires                          time.Time
	Endpoint                         netip.AddrPort
	Circuit                          []PeerID
	RTT, Jitter                      time.Duration
	Failures                         int
	DatagramSize                     int64
	QUICBytesSent, QUICBytesReceived uint64
	QUICPacketsLost, QUICPacketsSent uint64
	CongestionWindow                 uint64
	StreamFallbacks                  uint64
	Active                           bool
}

func (n *Node) Peers() []PeerStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]PeerStatus, 0, len(n.peers))
	for _, paths := range n.peers {
		active := n.preferredSessionLocked(paths, false, nil)
		for _, s := range paths.sessions {
			leaf := s.state.PeerCertificates[0]
			s.healthMu.Lock()
			st := PeerStatus{
				Peer: s.peer, Transport: s.kind, Endpoint: s.endpoint, Circuit: slices.Clone(s.path),
				AuthorizedUntil: s.until, ALPN: s.state.NegotiatedProtocol, Group: s.state.CurveID.String(), TLSVersion: s.state.Version,
				LocalSerial: s.localChain[0].SerialNumber.String(), Serial: leaf.SerialNumber.String(), Expires: leaf.NotAfter, Active: active == s,
				RTT: s.rtt, Jitter: s.jitter, Failures: s.failures,
				DatagramSize: s.budget.Load(), StreamFallbacks: s.overflow.Load(),
			}
			s.healthMu.Unlock()
			if s.q != nil {
				st.Endpoint = addrPort(s.q.RemoteAddr())
				q := s.q.ConnectionStats()
				st.RTT = q.SmoothedRTT
				st.Jitter = q.MeanDeviation
				st.QUICBytesSent, st.QUICBytesReceived = q.BytesSent, q.BytesReceived
				st.QUICPacketsLost, st.QUICPacketsSent, st.CongestionWindow = q.PacketsLost, q.PacketsSent, q.CongestionWindow
			}
			out = append(out, st)
		}
	}
	slices.SortFunc(out, func(a, b PeerStatus) int {
		if c := bytes.Compare(a.Peer[:], b.Peer[:]); c != 0 {
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

type ControlStatus struct {
	Peer                         PeerID
	Serial                       string
	CertificateExpires           time.Time
	Started, Closed              bool
	LastError                    string
	Ready                        bool
	Circuits                     int
	BytesScheduled, DialFailures uint64
}

func (n *Node) ControlStatus() ControlStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := ControlStatus{Circuits: len(n.circuits), BytesScheduled: n.shaped.Load(), DialFailures: n.retries.Load(), LastError: n.lastError}
	credentials := n.cred.Load()
	leaf := credentials.Client.Leaf
	v.Peer, v.Serial, v.CertificateExpires = n.id, leaf.SerialNumber.String(), leaf.NotAfter
	v.Started, v.Closed = n.state == running, n.state == closed
	if p := n.policy.Load(); p != nil {
		v.Ready = !v.Closed && n.ready(p)
	}
	return v
}
