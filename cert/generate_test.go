package cert

import (
	"crypto/fips140"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateAndIssueCertificate(t *testing.T) {
	for _, version := range []Version{Version1, Version2} {
		for _, curve := range []Curve{Curve_CURVE25519, Curve_P256} {
			t.Run(fmt.Sprintf("v%d-%s", version, curve), func(t *testing.T) {
				if fips140.Enforced() && curve == Curve_CURVE25519 {
					t.Skip("Curve25519 is intentionally unavailable in FIPS 140-only mode")
				}
				now := time.Now().Add(-time.Minute)
				ca, caKey, err := CreateCA(CAOptions{
					Version: version, Curve: curve, Name: "root",
					Networks:       []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
					UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")},
					Groups:         []string{"servers"}, NotBefore: now, NotAfter: now.Add(time.Hour),
				})
				require.NoError(t, err)
				require.True(t, ca.IsCA())
				require.NoError(t, ca.VerifyPrivateKey(curve, caKey))
				caKeyPEM := MarshalSigningPrivateKeyToPEM(curve, caKey)
				decodedCAKey, rest, decodedCurve, err := UnmarshalSigningPrivateKeyFromPEM(caKeyPEM)
				require.NoError(t, err)
				require.Empty(t, rest)
				require.Equal(t, curve, decodedCurve)
				require.Equal(t, caKey, decodedCAKey)

				host, hostKey, err := IssueCertificate(ca, caKey, CertificateOptions{
					Version: version, Name: "host", Networks: []netip.Prefix{netip.MustParsePrefix("10.20.0.1/16")},
					UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("172.20.1.0/24")},
					Groups:         []string{"servers"}, NotBefore: now, NotAfter: now.Add(30 * time.Minute),
				})
				require.NoError(t, err)
				require.False(t, host.IsCA())
				require.NoError(t, host.VerifyPrivateKey(curve, hostKey))
				hostKeyPEM := MarshalPrivateKeyToPEM(curve, hostKey)
				decodedHostKey, rest, decodedCurve, err := UnmarshalPrivateKeyFromPEM(hostKeyPEM)
				require.NoError(t, err)
				require.Empty(t, rest)
				require.Equal(t, curve, decodedCurve)
				require.Equal(t, hostKey, decodedHostKey)
				pool := NewCAPool()
				require.NoError(t, pool.AddCA(ca))
				_, err = pool.VerifyCertificate(time.Now(), host)
				require.NoError(t, err)

				publicKey, _, err := GenerateKeyAgreementKey(curve)
				require.NoError(t, err)
				provided, generatedKey, err := IssueCertificate(ca, caKey, CertificateOptions{
					Version: version, Name: "provided-key", PublicKey: publicKey,
					Networks:  []netip.Prefix{netip.MustParsePrefix("10.20.0.2/16")},
					NotBefore: now, NotAfter: now.Add(30 * time.Minute),
				})
				require.NoError(t, err)
				require.Nil(t, generatedKey)
				require.Equal(t, publicKey, provided.PublicKey())
			})
		}
	}
}

func TestCreateCADefaultCurve(t *testing.T) {
	ca, _, err := CreateCA(CAOptions{Name: "default-curve"})
	require.NoError(t, err)
	want := Curve_CURVE25519
	if fips140.Enforced() {
		want = Curve_P256
	}
	require.Equal(t, want, ca.Curve())
}
