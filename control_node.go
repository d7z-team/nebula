package nebula

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/control"
	"golang.org/x/time/rate"
)

// DefaultControlPort is the UDP port on the authenticated overlay.
const DefaultControlPort = 42842

// ControlOptions enables the managed control plane. Bind its overlay socket with
// AttachControl before Start. StateFile is dedicated to this Node.
type ControlOptions struct {
	Network         string
	Authority       cert.Certificate
	StateFile       string
	MinimumRevision uint64
	Bootstrap       []netip.Addr
	Publisher       ed25519.PrivateKey
	Port            uint16
	SyncInterval    time.Duration
}

type controlPlane struct {
	n             *Node
	opts          ControlOptions
	socket        net.PacketConn
	applyMu       sync.Mutex
	durabilityErr error // protected by applyMu
	mu            sync.Mutex
	receipts      map[receiptKey]receipt
	rx            map[netip.Addr]*peerBudget
	tx            *rate.Limiter
	eventTX       *rate.Limiter
	eventQueue    chan receivedFrame
	fetches       map[string]time.Time
	peers         map[netip.Addr]controlNeighbor
	lastSync      time.Time
	lastError     error
	events        map[string]ControlEvent
	subs          map[*Subscription]struct{}
	pulls         map[netip.Addr]*configPull
	queries       map[string]lookupRequest
	lookups       chan netip.Addr
	missed        uint64 // protected by mu
	circuits      circuitTable
	shaper        egressShaper
}

// ControlStatus describes the installed snapshot, recent control neighbors and local forwarding.
type ControlStatus struct {
	Revision     uint64
	Digest       string
	Neighbors    []netip.Addr
	LastSync     time.Time
	LastError    string
	MissedEvents uint64
	Circuits     []CircuitStatus
	Egress       EgressStats
}

func (n *Node) ControlStatus() ControlStatus {
	c := n.engine.control
	if c == nil {
		return ControlStatus{}
	}
	p := c.policy()
	c.mu.Lock()
	status := ControlStatus{Revision: p.config.Revision, Digest: p.digest, LastSync: c.lastSync, MissedEvents: c.missed}
	if c.lastError != nil {
		status.LastError = c.lastError.Error()
	}
	for a := range c.peers {
		status.Neighbors = append(status.Neighbors, a)
	}
	c.mu.Unlock()
	slices.SortFunc(status.Neighbors, netip.Addr.Compare)
	status.Circuits = c.circuits.status()
	status.Egress = c.shaper.stats()
	return status
}

func (n *Node) initControl(o ControlOptions) error {
	if !control.ValidNetwork(o.Network) || o.Authority == nil || !o.Authority.IsCA() || o.StateFile == "" || (len(o.Publisher) != 0 && len(o.Publisher) != ed25519.PrivateKeySize) {
		return errors.New("invalid control configuration")
	}
	if o.Port == 0 {
		o.Port = DefaultControlPort
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = 2 * time.Second
	}
	o.Bootstrap = slices.Clone(o.Bootstrap)
	o.Publisher = slices.Clone(o.Publisher)
	for _, a := range o.Bootstrap {
		if err := n.validatePeerAddress(a); err != nil {
			return err
		}
	}
	c := &controlPlane{
		n: n, opts: o,
		tx: rate.NewLimiter(800, 256), eventTX: rate.NewLimiter(200, 64),
		rx: make(map[netip.Addr]*peerBudget), receipts: make(map[receiptKey]receipt),
		peers: make(map[netip.Addr]controlNeighbor), pulls: make(map[netip.Addr]*configPull),
		queries: make(map[string]lookupRequest), lookups: make(chan netip.Addr, 64),
		fetches: make(map[string]time.Time), events: make(map[string]ControlEvent),
		subs: make(map[*Subscription]struct{}), eventQueue: make(chan receivedFrame, 128),
	}
	c.shaper.queues = make(map[netip.Addr][]egressItem)
	c.shaper.wake = make(chan struct{}, 1)
	c.shaper.rateChanged = make(chan struct{})
	n.engine.control = c
	n.lighthouse.control = c
	p := *n.engine.paths.config.Load()
	p.network = c.compileNetworkPolicy(control.Config{}, "", nil)
	n.engine.paths.config.Store(&p)
	f, err := os.Open(o.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, control.MaxDocument+1))
	if err != nil {
		return err
	}
	return c.installConfig(n.ctx, b, false, nil)
}

// AttachControl transfers ownership of an overlay UDP socket on success.
func (n *Node) AttachControl(conn net.PacketConn) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.engine.control
	if n.state != NodeStateReady || c == nil || conn == nil || c.socket != nil {
		return errors.New("control socket must be attached once before Start")
	}
	a, err := addrPort(conn.LocalAddr())
	if err != nil || a.Addr().Unmap() != n.engine.myVpnAddrs[0] || a.Port() != c.opts.Port {
		return errors.New("control socket must bind the node overlay identity and control port")
	}
	c.socket = conn
	return nil
}

// SignedNetworkConfig returns a detached copy of the current signed document.
// It returns nil until installation. Applications can read their settings with control.Verify.
func (n *Node) SignedNetworkConfig() []byte {
	if c := n.engine.control; c != nil {
		return slices.Clone(c.policy().document)
	}
	return nil
}

// ApplyNetworkConfig verifies, persists and installs a complete signed document.
func (n *Node) ApplyNetworkConfig(ctx context.Context, b []byte) error {
	c := n.engine.control
	if c == nil {
		return errors.New("control service disabled")
	}
	return c.installConfig(ctx, b, true, nil)
}

func (c *controlPlane) installConfig(ctx context.Context, b []byte, persist bool, expected *configPull) (err error) {
	if persist {
		defer func() {
			c.mu.Lock()
			c.lastError = err
			c.mu.Unlock()
		}()
	}
	cfg, digest, err := control.Verify(b, c.opts.Network, c.opts.Authority)
	if err != nil {
		return err
	}
	if expected != nil && (cfg.Revision != expected.rev || digest != expected.id) {
		return errors.New("document does not match advertisement")
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	n := c.n
	if n.ctx.Err() != nil {
		return ErrNodeClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pm := &n.engine.paths
	old := pm.config.Load().network
	if cfg.Revision < c.opts.MinimumRevision || cfg.Revision < old.config.Revision {
		return errors.New("stale configuration")
	}
	if cfg.Revision == old.config.Revision {
		if digest != old.digest {
			return errors.New("conflicting signed revision")
		}
		if persist && c.durabilityErr != nil {
			_, c.durabilityErr = saveDocument(c.opts.StateFile, b)
		}
		return c.durabilityErr
	}
	if err := pm.submit.Acquire(ctx, math.MaxInt64); err != nil {
		return err
	}
	defer pm.submit.Release(math.MaxInt64)
	if n.ctx.Err() != nil {
		return ErrNodeClosed
	}
	var durabilityErr error
	if persist {
		var committed bool
		committed, durabilityErr = saveDocument(c.opts.StateFile, b)
		if !committed {
			return durabilityErr
		}
	}
	p := c.compileNetworkPolicy(cfg, digest, b)
	c.shaper.setRate(p.local.BytesPerSecond)
	hm := n.engine.hostMap
	hm.Lock()
	next := *pm.config.Load()
	next.network = p
	pm.config.Store(&next)
	for _, h := range hm.Indexes {
		if p.denies(h.GetCert()) {
			hm.unlockedDeleteHostInfo(h)
			continue
		}
		h.paths.mu.Lock()
		h.paths.policyVersion++
		h.paths.samples = nil
		h.paths.standby = tunnelRoute{}
		h.paths.nextActive = time.Time{}
		h.paths.nextBackup = time.Time{}
		h.paths.mu.Unlock()
	}
	hm.Unlock()
	lh := n.lighthouse
	lh.RLock()
	for addr, remotes := range lh.addrMap {
		remotes.Lock()
		newMember := p.config.Members[addr]
		if remotes.introCert != "" && (p.revoked[remotes.introCert] || (newMember.Certificate != "" && newMember.Certificate != remotes.introCert) || !slices.Equal(old.config.Members[addr].Publisher, newMember.Publisher)) {
			remotes.introExpiry = time.Now()
		}
		remotes.Unlock()
	}
	lh.RUnlock()
	c.circuits.prunePolicy(c, p)
	c.mu.Lock()
	for id, rec := range c.events {
		if !eventAuthorized(p, rec) || !slices.Equal(old.config.Members[rec.Origin].Publisher, p.config.Members[rec.Origin].Publisher) {
			delete(c.events, id)
		}
	}
	c.mu.Unlock()
	c.durabilityErr = durabilityErr
	return durabilityErr
}

func saveDocument(path string, b []byte) (committed bool, err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".nebula-config-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		return true, nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return true, err
	}
	defer d.Close()
	return true, d.Sync()
}

func (c *controlPlane) policy() *networkPolicy { return c.n.engine.paths.config.Load().network }
