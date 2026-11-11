package port_forwarder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
)

type ForwardConfigOutgoingTcp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.tcp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingTcp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.tcp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

type PortForwardingCommonTcp struct {
	ctx                   context.Context
	wg                    *sync.WaitGroup
	l                     *slog.Logger
	tunService            *service.Service
	localListenConnection net.Listener
}

func (fwd PortForwardingCommonTcp) Close() error {
	fwd.localListenConnection.Close()
	fwd.wg.Wait()
	return nil
}

type PortForwardingOutgoingTcp struct {
	PortForwardingCommonTcp
	cfg ForwardConfigOutgoingTcp
}

func (cf ForwardConfigOutgoingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *slog.Logger,
) (io.Closer, error) {
	localTcpListenAddr, err := net.ResolveTCPAddr("tcp", cf.localListen)
	if err != nil {
		return nil, err
	}
	localListenPort, err := net.ListenTCP("tcp", localTcpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Info("TCP port forwarding is listening", "dialAddress", cf.remoteConnect, "listenAddress", localTcpListenAddr)

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingOutgoingTcp{
		PortForwardingCommonTcp: PortForwardingCommonTcp{
			ctx:                   ctx,
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenPort,
		},
		cfg: cf,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		portForwarding.acceptOnLocalListenPort_generic(portForwarding.handleClientConnectionWithErrorReturn)
	}()

	return portForwarding, nil
}

func (pt *PortForwardingCommonTcp) acceptOnLocalListenPort_generic(
	handleClientConnectionWithErrorReturn func(localConnection net.Conn) error,
) error {
	for {
		pt.l.Debug("listening on local TCP port ...")
		connection, err := pt.localListenConnection.Accept()
		if err != nil {
			return err
		}

		connCtx, cancel := context.WithCancel(pt.ctx)

		pt.l.Debug("Accepted TCP connection", "remoteAddress", connection.RemoteAddr())

		pt.wg.Add(1)
		go func() {
			defer pt.wg.Done()
			defer connection.Close()
			<-connCtx.Done()
		}()

		pt.wg.Add(1)
		go func() {
			defer pt.wg.Done()
			defer cancel()
			err := handleClientConnectionWithErrorReturn(connection)
			if err != nil {
				pt.l.Debug("Closed TCP client connection", "localAddress", connection.LocalAddr(), "error", err)
			}
		}()
	}
}

func (pt *PortForwardingOutgoingTcp) handleClientConnectionWithErrorReturn(localConnection net.Conn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.cfg.remoteConnect)
	if err != nil {
		return err
	}
	return handleTcpClientConnectionPair_generic(pt.l, localConnection, remoteConnection)
}

func handleTcpClientConnectionPair_generic(l *slog.Logger, connA, connB net.Conn) error {

	dataTransferHandler := func(from, to net.Conn) error {

		name := fmt.Sprintf("%s -> %s", from.LocalAddr().String(), to.LocalAddr().String())

		defer from.Close()
		defer to.Close()

		// no write/read timeout
		to.SetDeadline(time.Time{})
		from.SetDeadline(time.Time{})
		megabyte := (1 << 20)
		buf := make([]byte, 1*megabyte)
		if false {
			// this variant seems to be slightly slower on the local speed-test. 1.60GiB/s vs. 1.70GiB/s
			n, err := io.CopyBuffer(to, from, buf)
			l.Debug("Stopped forwarding TCP data",
				"error", err,
				"payloadSize", n,
				"from", from.RemoteAddr(),
				"to", to.RemoteAddr(),
				"localFrom", from.LocalAddr(),
				"localTo", to.LocalAddr(),
			)
			return err
		} else {
			for {
				rn, r_err := from.Read(buf)
				l.Debug("Read forwarded TCP data", "connection", name, "bytes", rn, "error", r_err)
				for i := 0; i < rn; {
					wn, w_err := to.Write(buf[i:rn])
					if w_err != nil {
						l.Debug("Writing forwarded TCP data failed", "connection", name, "bytes", rn, "error", w_err)
						return w_err
					}
					i += wn
				}
				if r_err != nil {
					l.Debug("Reading forwarded TCP data stopped", "connection", name, "bytes", rn, "error", r_err)
					return r_err
				}
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(connA, connB) })
	errGroup.Go(func() error { return dataTransferHandler(connB, connA) })

	return errGroup.Wait()
}

type PortForwardingIncomingTcp struct {
	PortForwardingCommonTcp
	cfg ForwardConfigIncomingTcp
}

func (cf ForwardConfigIncomingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *slog.Logger,
) (io.Closer, error) {

	localListenPort, err := tunService.Listen("tcp", fmt.Sprintf(":%d", cf.port))
	if err != nil {
		return nil, err
	}

	l.Info("Inbound TCP port forwarding is listening", "dialAddress", cf.forwardLocalAddress, "listenPort", cf.port)

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingIncomingTcp{
		PortForwardingCommonTcp: PortForwardingCommonTcp{
			ctx:                   ctx,
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenPort,
		},
		cfg: cf,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		portForwarding.acceptOnLocalListenPort_generic(portForwarding.handleClientConnectionWithErrorReturn)
	}()

	return portForwarding, nil
}

func (pt *PortForwardingIncomingTcp) handleClientConnectionWithErrorReturn(outsideConnection net.Conn) error {

	fwdAddr, err := net.ResolveTCPAddr("tcp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	localConnection, err := net.DialTCP("tcp", nil, fwdAddr)
	if err != nil {
		return err
	}

	return handleTcpClientConnectionPair_generic(pt.l, outsideConnection, localConnection)
}
