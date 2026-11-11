package port_forwarder

import (
	"io"
	"log/slog"

	"github.com/slackhq/nebula/service"
)

type ForwardConfig interface {
	SetupPortForwarding(tunService *service.Service, l *slog.Logger) (io.Closer, error)
	ConfigDescriptor() string
}

type ConfigList interface {
	AddConfig(cfg ForwardConfig)
}

type ForwardConfigOutgoing struct {
	localListen   string
	remoteConnect string
}

type ForwardConfigIncoming struct {
	port                uint32
	forwardLocalAddress string
}
