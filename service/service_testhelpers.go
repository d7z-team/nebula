package service

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
	"github.com/stretchr/testify/assert"
	"go.yaml.in/yaml/v3"
)

type forwardingTestConfig map[string]any

func newForwardingTestService(caCrt cert.Certificate, caKey []byte, name string, udpIp netip.Addr, overrides forwardingTestConfig) (*Service, *slog.Logger) {
	_, _, myPrivKey, myPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, caCrt, caKey, "a", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{netip.PrefixFrom(udpIp, 24)}, nil, []string{})
	caB, err := caCrt.MarshalPEM()
	if err != nil {
		panic(err)
	}

	mc := forwardingTestConfig{
		"pki": forwardingTestConfig{
			"ca":   string(caB),
			"cert": string(myPEM),
			"key":  string(myPrivKey),
		},
		//"tun": m{"disabled": true},
		"firewall": forwardingTestConfig{
			"outbound": []forwardingTestConfig{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
			"inbound": []forwardingTestConfig{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
		},
		"timers": forwardingTestConfig{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
		"handshakes": forwardingTestConfig{
			"try_interval": "200ms",
		},
	}

	if overrides != nil {
		err = mergo.Merge(&overrides, mc, mergo.WithAppendSlice)
		if err != nil {
			panic(err)
		}
		mc = overrides
	}

	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	var c config.C
	if err := c.LoadString(string(cb)); err != nil {
		panic(err)
	}

	logger := slog.New(slog.DiscardHandler)

	control, err := nebula.Main(&c, false, "custom-app", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		panic(err)
	}

	s, err := New(control)
	if err != nil {
		panic(err)
	}
	return s, logger
}

func CreateTwoConnectedServices(t *testing.T, port int) (*Service, *slog.Logger, *Service, *slog.Logger) {
	port += 100 * (rand.Int() % 10)
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	a, al := newForwardingTestService(ca, caKey, fmt.Sprintf("a_port_%d_test_name_%s", port, t.Name()), netip.MustParseAddr("10.0.0.1"), forwardingTestConfig{
		"static_host_map": forwardingTestConfig{},
		"lighthouse": forwardingTestConfig{
			"am_lighthouse": true,
		},
		"listen": forwardingTestConfig{
			"host": "0.0.0.0",
			"port": port,
		},
	})
	t.Cleanup(func() {
		assert.NoError(t, a.CloseAndWait())
	})
	b, bl := newForwardingTestService(ca, caKey, fmt.Sprintf("b_port_%d_test_name_%s", port, t.Name()), netip.MustParseAddr("10.0.0.2"), forwardingTestConfig{
		"static_host_map": forwardingTestConfig{
			"10.0.0.1": []string{fmt.Sprintf("localhost:%d", port)},
		},
		"lighthouse": forwardingTestConfig{
			"hosts":    []string{"10.0.0.1"},
			"interval": 1,
		},
	})
	t.Cleanup(func() {
		assert.NoError(t, b.CloseAndWait())
	})
	return a, al, b, bl
}
