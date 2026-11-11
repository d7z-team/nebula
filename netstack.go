package nebula

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	netstackNIC           = 1
	netstackListenBacklog = 4096
)

type userNetstack struct {
	stack    *stack.Stack
	link     *channel.Endpoint
	routes   *packetRouteTable
	lifetime context.Context
	cancel   context.CancelFunc
	close    sync.Once
	mu       sync.RWMutex
	closed   bool
}

func newUserNetstack(routes *packetRouteTable, overlayNetworks []netip.Prefix, virtual []netip.Addr, mtu uint32) (*userNetstack, error) {
	if mtu < 1280 {
		return nil, fmt.Errorf("MTU must be at least 1280, got %d", mtu)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	s := &userNetstack{routes: routes, lifetime: lifetime, cancel: cancel}
	s.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	sack := tcpip.TCPSACKEnabled(true)
	if err := s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		s.stack.Destroy()
		return nil, fmt.Errorf("enable TCP SACK: %v", err)
	}
	s.link = channel.New(512, mtu, "")
	if err := s.stack.CreateNIC(netstackNIC, s.link); err != nil {
		s.stack.Destroy()
		return nil, fmt.Errorf("create userspace NIC: %v", err)
	}

	v4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFrom(strings.Repeat("\x00", 4)))
	v6Subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFrom(strings.Repeat("\x00", 16)))
	s.stack.SetRouteTable([]tcpip.Route{
		{Destination: v4Subnet, NIC: netstackNIC},
		{Destination: v6Subnet, NIC: netstackNIC},
	})

	seen := make(map[netip.Addr]struct{}, len(overlayNetworks)+len(virtual))
	for _, network := range overlayNetworks {
		addr := network.Addr().Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		if err := s.addAddress(addr); err != nil {
			s.destroy()
			return nil, err
		}
	}
	for _, addr := range virtual {
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		if err := s.addAddress(addr); err != nil {
			s.destroy()
			return nil, err
		}
	}

	return s, nil
}

func (s *userNetstack) addAddress(addr netip.Addr) error {
	protocol := ipv4.ProtocolNumber
	if addr.Is6() {
		protocol = ipv6.ProtocolNumber
	}
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		Protocol:          protocol,
	}
	if err := s.stack.AddProtocolAddress(netstackNIC, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint,
		ConfigType: stack.AddressConfigStatic,
	}); err != nil {
		return fmt.Errorf("add userspace address %s: %v", addr, err)
	}
	return nil
}

func (s *userNetstack) readPacket(ctx context.Context) (*buffer.View, error) {
	packet := s.link.ReadContext(ctx)
	if packet == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	view := packet.ToView()
	packet.DecRef()
	return view, nil
}

func (s *userNetstack) inject(packet []byte) error {
	if len(packet) == 0 {
		return ErrInvalidPacketAddress
	}
	var protocol tcpip.NetworkProtocolNumber
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		protocol = ipv4.ProtocolNumber
	case header.IPv6Version:
		protocol = ipv6.ProtocolNumber
	default:
		return ErrInvalidPacketAddress
	}
	view := buffer.NewViewWithData(packet)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(view)})
	s.link.InjectInbound(protocol, pb)
	pb.DecRef()
	return nil
}

func (s *userNetstack) destroy() {
	s.close.Do(func() {
		// Cancel blocking dials before waiting for their read lock. Once the
		// write lock is held no endpoint can be created concurrently with the
		// stack's endpoint snapshot in Destroy.
		s.cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		s.stack.Destroy()
	})
}

func (s *userNetstack) dialContext(ctx context.Context, network, address string, local netip.Addr) (net.Conn, error) {
	if !isTCPNetwork(network) && !isUDPNetwork(network) {
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	remote, protocol, err := parseEndpoint(network, address, false)
	if err != nil {
		return nil, err
	}
	if local.IsValid() && !s.routes.isLocal(local) {
		return nil, fmt.Errorf("%w: %s", ErrAddressNotLocal, local)
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer func() {
		stop()
		cancel()
	}()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.lifetime.Err() != nil {
		return nil, net.ErrClosed
	}
	fullRemote := tcpip.FullAddress{NIC: netstackNIC, Addr: tcpip.AddrFromSlice(remote.Addr().AsSlice()), Port: remote.Port()}
	switch {
	case isTCPNetwork(network):
		var conn *gonet.TCPConn
		if !local.IsValid() {
			conn, err = gonet.DialContextTCP(dialCtx, s.stack, fullRemote, protocol)
		} else {
			fullLocal := tcpip.FullAddress{NIC: netstackNIC, Addr: tcpip.AddrFromSlice(local.AsSlice())}
			conn, err = gonet.DialTCPWithBind(dialCtx, s.stack, fullLocal, fullRemote, protocol)
		}
		if err != nil {
			return nil, err
		}
		return conn, nil
	case isUDPNetwork(network):
		var fullLocal *tcpip.FullAddress
		if local.IsValid() {
			fullLocal = &tcpip.FullAddress{NIC: netstackNIC, Addr: tcpip.AddrFromSlice(local.AsSlice())}
		}
		conn, err := gonet.DialUDP(s.stack, fullLocal, &fullRemote, protocol)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

func (s *userNetstack) listen(network, address string) (net.Listener, error) {
	if !isTCPNetwork(network) {
		return nil, fmt.Errorf("unsupported stream network %q", network)
	}
	local, protocol, err := parseListenEndpoint(network, address)
	if err != nil {
		return nil, err
	}
	if local.Addr().IsValid() && !s.routes.isLocal(local.Addr()) {
		return nil, fmt.Errorf("%w: %s", ErrAddressNotLocal, local.Addr())
	}
	fullLocal := tcpip.FullAddress{NIC: netstackNIC, Port: local.Port()}
	if local.Addr().IsValid() {
		fullLocal.Addr = tcpip.AddrFromSlice(local.Addr().AsSlice())
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.lifetime.Err() != nil {
		return nil, net.ErrClosed
	}
	if network != "tcp6" || local.Addr().IsValid() {
		listener, err := gonet.ListenTCP(s.stack, fullLocal, protocol)
		if err != nil {
			return nil, err
		}
		return listener, nil
	}

	// gonet.ListenTCP leaves IPV6_V6ONLY disabled. Construct the wildcard
	// tcp6 endpoint directly so tcp6 never consumes or accepts IPv4 traffic.
	var queue waiter.Queue
	endpoint, tcpErr := s.stack.NewEndpoint(tcp.ProtocolNumber, protocol, &queue)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	endpoint.SocketOptions().SetV6Only(true)
	if tcpErr := endpoint.Bind(fullLocal); tcpErr != nil {
		endpoint.Close()
		return nil, fmt.Errorf("bind TCP port %d: %s", fullLocal.Port, tcpErr.String())
	}
	if tcpErr := endpoint.Listen(netstackListenBacklog); tcpErr != nil {
		endpoint.Close()
		return nil, fmt.Errorf("listen on TCP port %d: %s", fullLocal.Port, tcpErr.String())
	}
	return gonet.NewTCPListener(s.stack, &queue, endpoint), nil
}

func (s *userNetstack) listenPacket(network, address string) (net.PacketConn, error) {
	if !isUDPNetwork(network) {
		return nil, fmt.Errorf("unsupported packet network %q", network)
	}
	local, protocol, err := parseListenEndpoint(network, address)
	if err != nil {
		return nil, err
	}
	if local.Addr().IsValid() && !s.routes.isLocal(local.Addr()) {
		return nil, fmt.Errorf("%w: %s", ErrAddressNotLocal, local.Addr())
	}
	fullLocal := tcpip.FullAddress{NIC: netstackNIC, Port: local.Port()}
	if local.Addr().IsValid() {
		fullLocal.Addr = tcpip.AddrFromSlice(local.Addr().AsSlice())
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.lifetime.Err() != nil {
		return nil, net.ErrClosed
	}
	if network != "udp6" || local.Addr().IsValid() {
		conn, err := gonet.DialUDP(s.stack, &fullLocal, nil, protocol)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	// As with TCP, use an explicitly v6-only endpoint for wildcard udp6.
	var queue waiter.Queue
	endpoint, tcpErr := s.stack.NewEndpoint(udp.ProtocolNumber, protocol, &queue)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}
	endpoint.SocketOptions().SetV6Only(true)
	if tcpErr := endpoint.Bind(fullLocal); tcpErr != nil {
		endpoint.Close()
		return nil, fmt.Errorf("bind UDP port %d: %s", fullLocal.Port, tcpErr.String())
	}
	return gonet.NewUDPConn(&queue, endpoint), nil
}

func isTCPNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}

func isUDPNetwork(network string) bool {
	return network == "udp" || network == "udp4" || network == "udp6"
}

func parseEndpoint(network, address string, forListen bool) (netip.AddrPort, tcpip.NetworkProtocolNumber, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 && !forListen {
		return netip.AddrPort{}, 0, fmt.Errorf("invalid port in %q", address)
	}
	host = strings.Trim(host, "[]")
	if host == "" && forListen {
		return netip.AddrPortFrom(netip.Addr{}, uint16(port)), 0, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, 0, fmt.Errorf("address must contain an IP literal: %w", err)
	}
	addr = addr.Unmap()
	if strings.HasSuffix(network, "4") && !addr.Is4() {
		return netip.AddrPort{}, 0, fmt.Errorf("%s requires an IPv4 address", network)
	}
	if strings.HasSuffix(network, "6") && !addr.Is6() {
		return netip.AddrPort{}, 0, fmt.Errorf("%s requires an IPv6 address", network)
	}
	protocol := ipv4.ProtocolNumber
	if addr.Is6() {
		protocol = ipv6.ProtocolNumber
	}
	return netip.AddrPortFrom(addr, uint16(port)), protocol, nil
}

func parseListenEndpoint(network, address string) (netip.AddrPort, tcpip.NetworkProtocolNumber, error) {
	addr, protocol, err := parseEndpoint(network, address, true)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	if addr.Addr().IsValid() {
		return addr, protocol, nil
	}
	if strings.HasSuffix(network, "4") {
		return addr, ipv4.ProtocolNumber, nil
	}
	// A wildcard tcp/udp listener is a dual-stack IPv6 endpoint. gVisor
	// atomically reserves the same port in both network protocol demuxers.
	return addr, ipv6.ProtocolNumber, nil
}
