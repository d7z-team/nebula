package control

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidateRevokedFingerprints(t *testing.T) {
	fp := strings.Repeat("0123456789abcdef", 4)
	cfg := Config{Format: 1, Network: "office", Revision: 1, Authority: fp, Revoked: []string{fp}}
	require.NoError(t, cfg.Validate())
	for _, invalid := range []string{fp[:63], fp + "0", strings.ToUpper(fp), fp[:63] + "g", fp[:63] + "/"} {
		cfg.Revoked[0] = invalid
		require.Error(t, cfg.Validate(), "revoked fingerprint %q", invalid)
	}
}

func TestSignedSnapshot(t *testing.T) {
	for _, curve := range []cert.Curve{cert.Curve_CURVE25519, cert.Curve_P256} {
		t.Run(curve.String(), func(t *testing.T) {
			ca, key, err := cert.CreateCA(cert.CAOptions{Name: "operator", Curve: curve})
			require.NoError(t, err)
			var signer crypto.Signer = ed25519.PrivateKey(key)
			if curve == cert.Curve_P256 {
				signer, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
				require.NoError(t, err)
			}
			cfg := Config{Format: 1, Network: "production", Revision: 3}
			wire, err := Sign(cfg, ca, signer)
			require.NoError(t, err)
			cfg, id, err := Verify(wire, cfg.Network, ca)
			require.NoError(t, err)
			require.Len(t, id, 64)
			again, err := Sign(cfg, ca, signer)
			require.NoError(t, err)
			_, otherID, err := Verify(again, cfg.Network, ca)
			require.NoError(t, err)
			require.Equal(t, id, otherID)
			_, _, err = Verify(wire, "development", ca)
			require.Error(t, err)
			other, _, err := cert.CreateCA(cert.CAOptions{Name: "other", Curve: curve})
			require.NoError(t, err)
			_, _, err = Verify(wire, cfg.Network, other)
			require.Error(t, err)
			var envelope document
			require.NoError(t, json.Unmarshal(wire, &envelope))
			cfg.Revision++
			envelope.Body, err = json.Marshal(cfg)
			require.NoError(t, err)
			tampered, err := json.Marshal(envelope)
			require.NoError(t, err)
			_, _, err = Verify(tampered, cfg.Network, ca)
			require.Error(t, err)
		})
	}
}
