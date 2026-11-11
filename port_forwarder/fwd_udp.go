package port_forwarder

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/slackhq/nebula/service"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type ForwardConfigOutgoingUdp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.udp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingUdp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.udp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

// use UDP timeout of 300 seconds according to
// https://support.goto.com/connect/help/what-are-the-recommended-nat-keep-alive-settings
var UDP_CONNECTION_TIMEOUT_SECONDS uint32 = 300

type udpConnInterface interface {
	io.Closer
	WriteTo(b []byte, addr net.Addr) (int, error)
	Write(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	LocalAddr() net.Addr
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func handleUdpDestinationPortResponseReading[destConn udpConnInterface, srcConn udpConnInterface](
	l *slog.Logger,
	closedConnections *chan string,
	sourceAddr net.Addr,
	destConnection destConn,
	localListenConnection srcConn,
) error {
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for remoteConnection to protect by mutex

	defer func() { (*closedConnections) <- sourceAddr.String() }()

	l.Debug("Begin reading UDP responses")
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	timeout := time.Second * time.Duration(UDP_CONNECTION_TIMEOUT_SECONDS)
	timer := time.NewTimer(timeout)

	rr := newUdpPortReader(wg, l, destConnection)
	defer close(rr.receivedDataDone)
	for {
		select {
		case <-timer.C:
			destConnection.Close()
			l.Debug("UDP response reader closed due to timeout")
			return nil
		case data, ok := <-rr.receivedData:
			if !ok {
				return nil
			}
			resetTimer(timer, timeout)

			l.Debug("Forwarding UDP response", "payloadSize", data.n)
			n, err := localListenConnection.WriteTo(rr.buf[:data.n], sourceAddr)
			rr.receivedDataDone <- 1
			if (n == 0) && (err != nil) {
				l.Debug("Forwarding UDP response failed", "error", err)
				return err
			}
		}
	}
}

type PortForwardingCommonUdp struct {
	wg         *sync.WaitGroup
	l          *slog.Logger
	tunService *service.Service
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection io.Closer
}

func (fwd PortForwardingCommonUdp) Close() error {
	fwd.localListenConnection.Close()
	fwd.wg.Wait()
	return nil
}

type PortForwardingOutgoingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigOutgoingUdp
}

func (cfg ForwardConfigOutgoingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *slog.Logger,
) (io.Closer, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", cfg.localListen)
	if err != nil {
		return nil, err
	}

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Info("UDP port forwarding is listening", "dialAddress", cfg.remoteConnect, "listenAddress", localUdpListenAddr)

	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingOutgoingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenConnection,
		},
		cfg: cfg,
	}

	forwardLogger := l.With(
		"forwardingDirection", "outbound",
		"listenAddress", localListenConnection.LocalAddr(),
		"dialAddress", cfg.remoteConnect,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := listenLocalPort_generic(
			wg,
			forwardLogger,
			localListenConnection,
			func(address string) (*gonet.UDPConn, error) {
				return tunService.DialUDP(address)
			},
			cfg.remoteConnect,
		)
		if err != nil {
			forwardLogger.Error("UDP forwarding listener stopped", "error", err)
		}
	}()

	return portForwarding, nil
}

type readData struct {
	n    int
	addr net.Addr
}

type readerRoutine struct {
	buf              []byte
	receivedData     chan readData
	receivedDataDone chan int
}

func newUdpPortReader(
	wg *sync.WaitGroup,
	l *slog.Logger,
	conn udpConnInterface,
) *readerRoutine {
	r := &readerRoutine{
		buf:              make([]byte, 512*1024),
		receivedData:     make(chan readData),
		receivedDataDone: make(chan int, 1),
	}
	r.receivedDataDone <- 1

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(r.receivedData)
		l.Debug("Started UDP listener", "address", conn.LocalAddr())
		for {
			_, ok := <-r.receivedDataDone
			if !ok {
				return
			}
			l.Debug("Reading UDP data", "address", conn.LocalAddr())
			n, addr, err := conn.ReadFrom(r.buf[0:])
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				l.Error("Reading UDP data failed", "address", conn.LocalAddr(), "error", err)
				return
			}
			r.receivedData <- readData{
				n:    n,
				addr: addr,
			}
		}
	}()

	return r
}

func listenLocalPort_generic[destConn udpConnInterface](
	wg *sync.WaitGroup,
	l *slog.Logger,
	localListenConnection udpConnInterface,
	dial func(address string) (destConn, error),
	remoteConnect string,
) error {
	dialConnResponseReaders := make(map[string]bool)
	dialConnections := make(map[string]destConn)
	closedConnections := make(chan string, 5)
	mr := newUdpPortReader(wg, l, localListenConnection)
	defer close(mr.receivedDataDone)

	defer func() {
		// close and wait for remaining connections
		for _, connection := range dialConnections {
			connection.Close()
		}
		for range dialConnResponseReaders {
			<-closedConnections
		}
	}()

	for {
		select {
		case closedOne := <-closedConnections:
			l.Debug("Closing UDP forwarding connection", "source", closedOne)
			delete(dialConnections, closedOne)
			delete(dialConnResponseReaders, closedOne)
		case data, ok := <-mr.receivedData:
			if !ok {
				return nil
			}
			l.Debug("Read UDP data", "source", data.addr, "payloadSize", data.n)
			dialConnection, ok := dialConnections[data.addr.String()]
			if !ok {
				newConnection, err := dial(remoteConnect)
				if err != nil {
					l.Error("Dialing UDP forwarding address failed", "error", err)
					continue
				}
				dialConnections[data.addr.String()] = newConnection
				dialConnection = newConnection
			}

			l.Debug("Forwarding UDP data",
				"source", data.addr,
				"dialSource", dialConnection.LocalAddr(),
				"payloadSize", data.n,
			)

			dialConnection.Write(mr.buf[:data.n])
			mr.receivedDataDone <- 1

			_, ok = dialConnResponseReaders[data.addr.String()]
			if !ok {
				responseLogger := l.With("source", data.addr, "dialSource", dialConnection.LocalAddr())
				dialConnResponseReaders[data.addr.String()] = true
				go func() error {
					return handleUdpDestinationPortResponseReading(
						responseLogger, &closedConnections, data.addr,
						dialConnection, localListenConnection)
				}()
			}
		}
	}
}

type PortForwardingIncomingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigIncomingUdp
}

func (cfg ForwardConfigIncomingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *slog.Logger,
) (io.Closer, error) {

	conn, err := tunService.ListenUDP(fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, err
	}

	l.Info("Inbound UDP port forwarding is listening", "dialAddress", cfg.forwardLocalAddress, "listenPort", cfg.port)

	forwardLogger := l.With(
		"forwardingDirection", "inbound",
		"listenPort", cfg.port,
		"dialAddress", cfg.forwardLocalAddress,
	)

	wg := &sync.WaitGroup{}

	forwarding := &PortForwardingIncomingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: conn,
		},
		cfg: cfg,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := listenLocalPort_generic(
			wg,
			forwardLogger,
			conn,
			func(address string) (*net.UDPConn, error) {
				fwdAddr, err := net.ResolveUDPAddr("udp", cfg.forwardLocalAddress)
				if err != nil {
					forwardLogger.Error("Resolving UDP forwarding address failed", "error", err)
					return nil, err
				}
				return net.DialUDP("udp", nil, fwdAddr)
			},
			cfg.forwardLocalAddress,
		)
		if err != nil {
			forwardLogger.Error("UDP forwarding listener stopped", "error", err)
		}
	}()

	return forwarding, nil
}
