package overlay

import (
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"gvisor.dev/gvisor/pkg/buffer"
)

func NewUserDeviceFromConfig(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		r.RestartRequiredIfChanged("tun.disabled")
	})

	d, err := NewUserDevice(vpnNetworks)
	if err != nil {
		return nil, err
	}

	_, routes, err := getAllRoutesFromConfig(l, c, vpnNetworks, true)
	if err != nil {
		return nil, err
	}

	routeTree, err := makeRouteTree(l, routes, true)
	if err != nil {
		return nil, err
	}

	// this is needed to enable the "unsafe_routes" feature in combination with port forwarding.
	d.routeTree.Store(routeTree)

	return d, nil
}

func NewUserDevice(vpnNetworks []netip.Prefix) (*UserDevice, error) {
	// Packet views preserve packet boundaries across the user device.
	return &UserDevice{
		vpnNetworks:     vpnNetworks,
		outboundChannel: make(chan *buffer.View, 16),
		inboundChannel:  make(chan *buffer.View, 16),
	}, nil
}

type UserDevice struct {
	vpnNetworks []netip.Prefix

	// using channel of *buffer.View significantly improves performance
	outboundChannel chan *buffer.View
	inboundChannel  chan *buffer.View

	routeTree atomic.Pointer[bart.Table[routing.Gateways]]
}

func (d *UserDevice) Activate() error {
	return nil
}

func (d *UserDevice) Networks() []netip.Prefix { return d.vpnNetworks }
func (d *UserDevice) Name() string             { return "faketun0" }
func (d *UserDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	ptr := d.routeTree.Load()
	if ptr != nil {
		r, _ := ptr.Lookup(ip)
		return r
	} else {
		return routing.Gateways{routing.NewGateway(ip, 1)}
	}
}

func (d *UserDevice) Queues(n int) ([]tio.Queue, error) {
	out := make([]tio.Queue, n)
	for i := range out {
		// All queues share the underlying pipes (the io.Pipe serializes
		// concurrent callers) but each owns a private scratch buffer so
		// concurrent Reads across queues never alias. NoClose: the pipes are
		// owned by the UserDevice and torn down once by UserDevice.Close.
		out[i] = tio.NewSingleQueueNoClose(d, defaultBatchBufSize)
	}
	return out, nil
}

func (d *UserDevice) Pipe() (<-chan *buffer.View, chan<- *buffer.View) {
	return d.inboundChannel, d.outboundChannel
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	defer view.Release()
	return view.Read(p)
}

func (d *UserDevice) WriteTo(w io.Writer) (n int64, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	defer view.Release()
	return view.WriteTo(w)
}

func (d *UserDevice) Write(p []byte) (n int, err error) {
	view := buffer.NewViewWithData(p)
	d.inboundChannel <- view
	// Ownership of view transfers to the channel receiver at the send above.
	return len(p), nil
}

func (d *UserDevice) ReadFrom(r io.Reader) (n int64, err error) {
	view := buffer.NewView(2048)
	n, err = view.ReadFrom(r)
	if n > 0 {
		d.inboundChannel <- view
	} else {
		view.Release()
	}
	return
}

func (d *UserDevice) Close() error {
	// There is nothing to be done for the UserDevice.
	// It doesn't start any goroutines on its own.
	// It doesn't manage any resources that needs closing.
	return nil
}
