package cert_test

import (
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// testCertNow is the reference "now" used to derive default before/after times
// in NewTestCaCert and NewTestCert. Holding it fixed for the lifetime of the
// test binary keeps CA and leaf defaults aligned at the same second, so a leaf
// signed with default times can never expire after its CA on a rounding race.
var testCertNow = time.Now().Round(time.Second)

// NewTestCaCert will create a new ca certificate
func NewTestCaCert(version cert.Version, curve cert.Curve, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
	pub, priv, err := cert.GenerateSigningKey(curve)
	if err != nil {
		panic(err)
	}

	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}
	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	t := &cert.TBSCertificate{
		Curve:          curve,
		Version:        version,
		Name:           "test ca",
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		IsCA:           true,
	}

	c, err := t.Sign(nil, curve, priv)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, priv, pem
}

// NewTestCert will generate a signed certificate with the provided details.
// Expiry times are defaulted if you do not pass them in
func NewTestCert(v cert.Version, curve cert.Curve, ca cert.Certificate, key []byte, name string, before, after time.Time, networks, unsafeNetworks []netip.Prefix, groups []string) (cert.Certificate, []byte, []byte, []byte) {
	if before.IsZero() {
		before = testCertNow.Add(time.Second * -60)
	}

	if after.IsZero() {
		after = testCertNow.Add(time.Second * 60)
	}

	pub, priv := mustAgreementKey(curve)

	nc := &cert.TBSCertificate{
		Version:        v,
		Curve:          curve,
		Name:           name,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		Groups:         groups,
		NotBefore:      time.Unix(before.Unix(), 0),
		NotAfter:       time.Unix(after.Unix(), 0),
		PublicKey:      pub,
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pub, cert.MarshalPrivateKeyToPEM(curve, priv), pem
}

func NewTestCertDifferentVersion(c cert.Certificate, v cert.Version, ca cert.Certificate, key []byte) (cert.Certificate, []byte) {
	nc := &cert.TBSCertificate{
		Version:        v,
		Curve:          c.Curve(),
		Name:           c.Name(),
		Networks:       c.Networks(),
		UnsafeNetworks: c.UnsafeNetworks(),
		Groups:         c.Groups(),
		NotBefore:      time.Unix(c.NotBefore().Unix(), 0),
		NotAfter:       time.Unix(c.NotAfter().Unix(), 0),
		PublicKey:      c.PublicKey(),
		IsCA:           false,
	}

	c, err := nc.Sign(ca, ca.Curve(), key)
	if err != nil {
		panic(err)
	}

	pem, err := c.MarshalPEM()
	if err != nil {
		panic(err)
	}

	return c, pem
}

func X25519Keypair() ([]byte, []byte) {
	return mustAgreementKey(cert.Curve_CURVE25519)
}

func P256Keypair() ([]byte, []byte) {
	return mustAgreementKey(cert.Curve_P256)
}

func mustAgreementKey(curve cert.Curve) ([]byte, []byte) {
	pub, priv, err := cert.GenerateKeyAgreementKey(curve)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// NewTestCAPool creates a CAPool from the given CA certificates, panicking on error.
func NewTestCAPool(cas ...cert.Certificate) *cert.CAPool {
	pool := cert.NewCAPool()
	for _, ca := range cas {
		if err := pool.AddCA(ca); err != nil {
			panic(err)
		}
	}
	return pool
}
