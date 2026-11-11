package port_forwarder

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"
)

type serviceTestConfig map[string]any

func newServiceForForwarding(caCrt cert.Certificate, caKey []byte, udpIP netip.Addr, overrides serviceTestConfig) (*service.Service, *slog.Logger) {
	_, _, privateKey, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, caCrt, caKey, "a", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.PrefixFrom(udpIP, 24)}, nil, nil)
	caPEM, err := caCrt.MarshalPEM()
	if err != nil {
		panic(err)
	}

	settings := serviceTestConfig{
		"pki": serviceTestConfig{
			"ca":   string(caPEM),
			"cert": string(certPEM),
			"key":  string(privateKey),
		},
		"firewall": serviceTestConfig{
			"outbound": []serviceTestConfig{{"proto": "any", "port": "any", "host": "any"}},
			"inbound":  []serviceTestConfig{{"proto": "any", "port": "any", "host": "any"}},
		},
		"timers": serviceTestConfig{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
		"handshakes": serviceTestConfig{"try_interval": "200ms"},
	}

	if overrides != nil {
		if err := mergo.Merge(&overrides, settings, mergo.WithAppendSlice); err != nil {
			panic(err)
		}
		settings = overrides
	}

	body, err := yaml.Marshal(settings)
	if err != nil {
		panic(err)
	}
	c := config.NewC(slog.New(slog.DiscardHandler))
	if err := c.LoadString(string(body)); err != nil {
		panic(err)
	}

	logger := slog.New(slog.DiscardHandler)
	control, err := nebula.Main(c, false, "test", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		panic(err)
	}
	srv, err := service.New(control)
	if err != nil {
		panic(err)
	}
	return srv, logger
}

func createTwoConnectedServices(t *testing.T, port int) (*service.Service, *slog.Logger, *service.Service, *slog.Logger) {
	t.Helper()
	port += 100 * (rand.Int() % 10)
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	server, serverLog := newServiceForForwarding(ca, caKey, netip.MustParseAddr("10.0.0.1"), serviceTestConfig{
		"static_host_map": serviceTestConfig{},
		"lighthouse":      serviceTestConfig{"am_lighthouse": true},
		"listen":          serviceTestConfig{"host": "0.0.0.0", "port": port},
	})
	t.Cleanup(func() { assert.NoError(t, server.CloseAndWait()) })

	client, clientLog := newServiceForForwarding(ca, caKey, netip.MustParseAddr("10.0.0.2"), serviceTestConfig{
		"static_host_map": serviceTestConfig{
			"10.0.0.1": []string{fmt.Sprintf("localhost:%d", port)},
		},
		"lighthouse": serviceTestConfig{"hosts": []string{"10.0.0.1"}, "interval": 1},
	})
	t.Cleanup(func() { assert.NoError(t, client.CloseAndWait()) })
	return server, serverLog, client, clientLog
}
