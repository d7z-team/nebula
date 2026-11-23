package nebula

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/control"
	"golang.org/x/time/rate"
)

const (
	controlMTU = 1180
	chunkSize  = 640
)

type controlFrame struct {
	Version   int             `json:"v"`
	Network   string          `json:"network"`
	Kind      string          `json:"kind"`
	Observed  netip.AddrPort  `json:"observed,omitzero"`
	Transit   bool            `json:"transit,omitempty"`
	Revision  uint64          `json:"rev,omitempty"`
	ID        string          `json:"id,omitempty"`
	Offset    int             `json:"off,omitempty"`
	Size      int             `json:"size,omitempty"`
	Data      []byte          `json:"data,omitempty"`
	Inventory []string        `json:"ids,omitempty"`
	Event     *ControlEvent   `json:"event,omitempty"`
	Intro     *introduction   `json:"intro,omitempty"`
	Circuit   *circuitMessage `json:"circuit,omitempty"`
}

type controlNeighbor struct {
	seen                 time.Time
	transit              bool
	remote, observedSelf netip.AddrPort
}

type configPull struct {
	progress time.Time
	id       string
	rev      uint64
	size     int
	data     []byte
}
type receiptKey struct {
	peer netip.Addr
	hash [32]byte
}
type receipt struct {
	h      *hostInfo
	direct netip.AddrPort
	at     time.Time
}
type peerBudget struct {
	rate *rate.Limiter
	last time.Time
}

// Only unfragmented UDP between dedicated control ports is eligible for bootstrap.
func controlPayload(packet []byte, port uint16) []byte {
	if len(packet) < 28 {
		return nil
	}
	var off int
	switch packet[0] >> 4 {
	case 4:
		if packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return nil
		}
		off = int(packet[0]&15) * 4
		if off < 20 {
			return nil
		}
	case 6:
		if len(packet) < 48 || packet[6] != 17 {
			return nil
		}
		off = 40
	default:
		return nil
	}
	if off+8 >= len(packet) {
		return nil
	}
	u := packet[off:]
	if binary.BigEndian.Uint16(u) != port || binary.BigEndian.Uint16(u[2:]) != port || int(binary.BigEndian.Uint16(u[4:])) != len(u) || len(u) > controlMTU+8 {
		return nil
	}
	return u[8:]
}

// The dedicated service header classifies locally generated UDP for bootstrap
// admission and shaping. Peer authentication still occurs at socket delivery.
func controlKind(packet []byte, port uint16) string {
	payload := controlPayload(packet, port)
	if payload == nil {
		return ""
	}
	var h struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(payload, &h) != nil {
		return ""
	}
	return h.Kind
}

func bootstrapKind(kind string) bool {
	return kind == "hello" || kind == "get-config" || kind == "config"
}

func priorityControl(packet []byte, port uint16) bool {
	kind := controlKind(packet, port)
	return kind != "" && !applicationKind(kind)
}

// Associate the userspace socket delivery with the actual authenticated tunnel.
// Packets injected through a host LAN or loopback have no corresponding receipt.
func (c *controlPlane) recordIngress(h *hostInfo, ip innerPacket, packet []byte, via packetSender) {
	body := controlPayload(packet, c.opts.Port)
	if body == nil {
		return
	}
	if !slices.Contains(h.vpnAddrs, ip.source) || ip.destination != c.n.engine.myVpnAddrs[0] {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.receipts) < 2048 {
		r := receipt{h: h, at: time.Now()}
		if !via.IsRelayed {
			r.direct = unmapAddrPort(via.UdpAddr)
		}
		c.receipts[receiptKey{ip.source, sha256.Sum256(body)}] = r
	}
}

func (c *controlPlane) send(to netip.Addr, m controlFrame) {
	if c.n.ctx.Err() != nil || c.n.engine.hostMap.QueryVpnAddr(to) == nil {
		return
	}
	m.Version = 1
	m.Network = c.opts.Network
	b, err := json.Marshal(m)
	budget := c.tx
	if applicationKind(m.Kind) {
		budget = c.eventTX
	}
	if err != nil || len(b) > controlMTU || !budget.Allow() {
		return
	}
	_, _ = c.socket.WriteTo(b, net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, c.opts.Port)))
}

func (c *controlPlane) neighbors(except netip.Addr) []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	var peers []netip.Addr
	for a := range c.peers {
		if a != except {
			peers = append(peers, a)
		}
	}
	slices.SortFunc(peers, netip.Addr.Compare)
	return peers
}

func (c *controlPlane) read() {
	buf := make([]byte, controlMTU+1)
	for {
		size, src, err := c.socket.ReadFrom(buf)
		if err != nil {
			if c.n.ctx.Err() == nil {
				_ = c.n.shutdown(err)
			}
			return
		}
		a, err := addrPort(src)
		if err != nil || a.Port() != c.opts.Port || size > controlMTU || size <= 0 {
			continue
		}
		from := a.Addr().Unmap()
		key := receiptKey{from, sha256.Sum256(buf[:size])}
		c.mu.Lock()
		r, ok := c.receipts[key]
		delete(c.receipts, key)
		if ok && (c.rx[from] != nil || len(c.rx) < 4096) {
			budget := c.rx[from]
			if budget == nil {
				budget = &peerBudget{rate: rate.NewLimiter(200, 256)}
				c.rx[from] = budget
			}
			budget.last = time.Now()
			ok = budget.rate.Allow()
		} else {
			ok = false
		}
		c.mu.Unlock()
		if !ok || time.Since(r.at) > 10*time.Second || c.n.engine.hostMap.QueryIndex(r.h.localIndexId) != r.h || c.policy().denies(r.h.GetCert()) {
			continue
		}
		var m controlFrame
		if json.Unmarshal(buf[:size], &m) != nil || m.Version != 1 || m.Network != c.opts.Network {
			continue
		}
		if applicationKind(m.Kind) {
			select {
			case c.eventQueue <- receivedFrame{from, m}:
			default:
			}
			continue
		}
		c.handleControlFrame(from, r, m)
	}
}

func (c *controlPlane) handleControlFrame(from netip.Addr, r receipt, m controlFrame) {
	p := c.policy()
	if p.bootstrapOnly && !bootstrapKind(m.Kind) {
		return
	}
	c.mu.Lock()
	_, known := c.peers[from]
	if m.Kind == "hello" {
		neighbor := controlNeighbor{seen: time.Now(), transit: m.Transit, remote: r.direct}
		if r.direct.IsValid() {
			neighbor.observedSelf = m.Observed
		}
		c.peers[from] = neighbor
		c.lastSync = neighbor.seen
	}
	c.mu.Unlock()
	if m.Kind != "hello" && !known {
		return
	}
	switch m.Kind {
	case "hello":
		if !known || (m.Revision < p.config.Revision && !slices.Contains(p.direct, from)) {
			c.hello(from)
		}
		if m.Revision == 0 || m.Revision < p.config.Revision || m.Revision < c.opts.MinimumRevision || len(m.ID) != 64 || m.Size <= 0 || m.Size > control.MaxDocument {
			return
		}
		if m.Revision == p.config.Revision && m.ID == p.digest {
			return
		}
		c.mu.Lock()
		pull := c.pulls[from]
		if pull == nil || pull.id != m.ID || pull.rev != m.Revision || pull.size != m.Size {
			if pull == nil && len(c.pulls) >= 4 {
				c.mu.Unlock()
				return
			}
			pull = &configPull{id: m.ID, rev: m.Revision, size: m.Size, progress: time.Now()}
			c.pulls[from] = pull
		}
		offset := len(pull.data)
		c.mu.Unlock()
		c.send(from, controlFrame{Kind: "get-config", ID: m.ID, Offset: offset})
	case "get-config":
		if p.digest != m.ID || m.Offset < 0 || m.Offset >= len(p.document) {
			return
		}
		c.send(from, controlFrame{Kind: "config", ID: p.digest, Offset: m.Offset, Data: p.document[m.Offset:min(m.Offset+chunkSize, len(p.document))]})
	case "config":
		c.mu.Lock()
		pull := c.pulls[from]
		if pull == nil || m.ID != pull.id || m.Offset != len(pull.data) || len(m.Data) != min(chunkSize, pull.size-m.Offset) {
			c.mu.Unlock()
			return
		}
		pull.data = append(pull.data, m.Data...)
		pull.progress = time.Now()
		offset := len(pull.data)
		if offset == pull.size {
			delete(c.pulls, from)
		}
		c.mu.Unlock()
		if offset < pull.size {
			c.send(from, controlFrame{Kind: "get-config", ID: m.ID, Offset: offset})
			return
		}
		_ = c.installConfig(c.n.ctx, pull.data, true, pull)
	case "lookup", "answer":
		if m.Intro != nil {
			c.handleIntro(from, m.Kind, *m.Intro, m.Offset)
		}
	case "build", "ready":
		if r.direct.IsValid() && m.Circuit != nil {
			c.handleCircuit(r.h, m.Kind, *m.Circuit)
		}
	}
}

func (c *controlPlane) hello(to netip.Addr) {
	p := c.policy()
	c.mu.Lock()
	observed := c.peers[to].remote
	c.mu.Unlock()
	c.send(to, controlFrame{Kind: "hello", Observed: observed, Transit: p.local.Transit && c.n.engine.servesRelays, ID: p.digest, Revision: p.config.Revision, Size: len(p.document)})
}

func (c *controlPlane) run() {
	tick := time.NewTicker(c.opts.SyncInterval)
	defer tick.Stop()
	page, cursor := 0, 0
maintenance:
	for {
		cursor = c.syncNeighbors(cursor)
		now := time.Now()
		c.mu.Lock()
		for a, pull := range c.pulls {
			if now.Sub(pull.progress) > max(3*c.opts.SyncInterval, 5*time.Second) {
				delete(c.pulls, a)
			}
		}
		for k, r := range c.receipts {
			if now.Sub(r.at) > 10*time.Second {
				delete(c.receipts, k)
			}
		}
		for a, v := range c.rx {
			if now.Sub(v.last) > time.Minute {
				delete(c.rx, a)
			}
		}
		for a, t := range c.peers {
			if now.Sub(t.seen) > max(3*c.opts.SyncInterval, 3*time.Second) {
				delete(c.peers, a)
				delete(c.pulls, a)
			}
		}
		for k, q := range c.queries {
			if now.After(q.expires) {
				delete(c.queries, k)
			}
		}
		c.mu.Unlock()
		page = c.advertiseEvents(now, page, cursor)
		c.circuits.sweep(c, now)
		for {
			select {
			case <-c.n.ctx.Done():
				return
			case a := <-c.lookups:
				c.lookup(a)
			case <-tick.C:
				continue maintenance
			}
		}
	}
}

// syncNeighbors starts missing adjacencies and advertises the current signed revision.
func (c *controlPlane) syncNeighbors(cursor int) int {
	p := c.policy()
	targets := p.direct
	if !p.bootstrapOnly && !p.local.Restricted {
		targets = slices.Clone(targets)
		for _, seed := range c.opts.Bootstrap {
			if !slices.Contains(targets, seed) {
				targets = append(targets, seed)
			}
		}
		if len(p.direct) == 0 {
			for _, peer := range c.n.Peers() {
				if peer.State == PeerStateEstablished && !slices.Contains(targets, peer.Addresses[0]) {
					targets = append(targets, peer.Addresses[0])
				}
			}
		}
	}
	for i := range targets {
		a := targets[(cursor+i)%len(targets)]
		if c.n.engine.hostMap.QueryVpnAddr(a) == nil {
			c.n.handshake.startHandshake(a, nil, slices.Contains(p.direct, a))
		} else {
			c.hello(a)
		}
	}
	if len(targets) > 0 {
		cursor = (cursor + 1) % len(targets)
	}
	return cursor
}
