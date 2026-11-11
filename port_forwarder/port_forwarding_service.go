package port_forwarder

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/slackhq/nebula/service"
)

type PortForwardingService struct {
	l          *slog.Logger
	tunService *service.Service

	configPortForwardings map[string]ForwardConfig
	portForwardings       map[string]io.Closer
}

func (t *PortForwardingService) AddConfig(cfg ForwardConfig) {
	t.configPortForwardings[cfg.ConfigDescriptor()] = cfg
}

func (t *PortForwardingService) Activate() error {
	return t.ActivateNew(t.configPortForwardings)
}

func (t *PortForwardingService) ActivateNew(newForwards map[string]ForwardConfig) error {
	var errs []error
	for descriptor, config := range newForwards {
		fwdInstance, err := config.SetupPortForwarding(t.tunService, t.l)
		if err == nil {
			t.configPortForwardings[config.ConfigDescriptor()] = config
			t.portForwardings[config.ConfigDescriptor()] = fwdInstance
		} else {
			t.l.Error("Failed to set up port forwarding", "descriptor", descriptor, "error", err)
			errs = append(errs, fmt.Errorf("set up port forwarding %s: %w", descriptor, err))
		}
	}

	return errors.Join(errs...)
}

func (t *PortForwardingService) CloseSelective(descriptors []string) error {
	var errs []error
	for _, descriptor := range descriptors {
		delete(t.configPortForwardings, descriptor)
		pf, ok := t.portForwardings[descriptor]
		if ok {
			t.l.Info("Closing port forwarding", "descriptor", descriptor)
			if err := pf.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close port forwarding %s: %w", descriptor, err))
			}
			delete(t.portForwardings, descriptor)
		}
	}

	return errors.Join(errs...)
}

func (t *PortForwardingService) CloseAll() error {
	var errs []error
	for descriptor, pf := range t.portForwardings {
		t.l.Info("Closing port forwarding", "descriptor", descriptor)
		if err := pf.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close port forwarding %s: %w", descriptor, err))
		}
		delete(t.portForwardings, descriptor)
	}

	return errors.Join(errs...)
}
