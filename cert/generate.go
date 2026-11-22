package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// GenerateSigningKey creates a CA signing key pair. Curve25519 selects
// Ed25519 here; P256 selects ECDSA. Returned keys use Nebula's raw key format.
func GenerateSigningKey(curve Curve) (publicKey, privateKey []byte, err error) {
	switch curve {
	case Curve_CURVE25519:
		if fips140.Enforced() {
			return nil, nil, errors.New("Ed25519 is not allowed in FIPS 140-only mode")
		}
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		return publicKey, privateKey, err
	case Curve_P256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, nil, err
		}
		return ecdhKey.PublicKey().Bytes(), ecdhKey.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("unsupported curve %v", curve)
	}
}

// GenerateKeyAgreementKey creates a host key-agreement pair. Curve25519
// selects X25519 here; P256 selects ECDH. Returned keys use Nebula's raw key
// format and can be passed directly to IssueCertificate and nebula.Identity.
func GenerateKeyAgreementKey(curve Curve) (publicKey, privateKey []byte, err error) {
	if curve == Curve_CURVE25519 && fips140.Enforced() {
		return nil, nil, errors.New("X25519 is not allowed in FIPS 140-only mode")
	}
	var c ecdh.Curve
	switch curve {
	case Curve_CURVE25519:
		c = ecdh.X25519()
	case Curve_P256:
		c = ecdh.P256()
	default:
		return nil, nil, fmt.Errorf("unsupported curve %v", curve)
	}
	key, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key.PublicKey().Bytes(), key.Bytes(), nil
}

type CAOptions struct {
	Version        Version
	Curve          Curve
	Name           string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	Groups         []string
	NotBefore      time.Time
	NotAfter       time.Time
}

// CreateCA creates a self-signed CA and returns its raw signing private key.
func CreateCA(options CAOptions) (Certificate, []byte, error) {
	if options.Version == 0 {
		options.Version = Version2
	}
	if options.Curve == 0 {
		if fips140.Enforced() {
			options.Curve = Curve_P256
		} else {
			options.Curve = Curve_CURVE25519
		}
	}
	if options.Name == "" {
		return nil, nil, errors.New("CA name is required")
	}
	if options.NotBefore.IsZero() {
		options.NotBefore = time.Now()
	}
	if options.NotAfter.IsZero() {
		options.NotAfter = options.NotBefore.Add(365 * 24 * time.Hour)
	}
	options.NotBefore = time.Unix(options.NotBefore.Unix(), 0)
	options.NotAfter = time.Unix(options.NotAfter.Unix(), 0)
	if !options.NotAfter.After(options.NotBefore) {
		return nil, nil, errors.New("CA expiration must be after its start time")
	}
	publicKey, privateKey, err := GenerateSigningKey(options.Curve)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := (&TBSCertificate{
		Version:        options.Version,
		Name:           options.Name,
		Networks:       options.Networks,
		UnsafeNetworks: options.UnsafeNetworks,
		Groups:         options.Groups,
		IsCA:           true,
		NotBefore:      options.NotBefore,
		NotAfter:       options.NotAfter,
		PublicKey:      publicKey,
		Curve:          options.Curve,
	}).Sign(nil, options.Curve, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return certificate, privateKey, nil
}

type CertificateOptions struct {
	Version        Version
	Name           string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	Groups         []string
	NotBefore      time.Time
	NotAfter       time.Time
	PublicKey      []byte
}

// IssueCertificate signs a host certificate. When PublicKey is empty a new
// key-agreement pair is generated and its private key is returned. When a
// public key is supplied, the returned private key is nil.
func IssueCertificate(ca Certificate, caPrivateKey []byte, options CertificateOptions) (Certificate, []byte, error) {
	if ca == nil || !ca.IsCA() {
		return nil, nil, errors.New("signer must be a CA certificate")
	}
	if len(caPrivateKey) == 0 {
		return nil, nil, errors.New("CA private key is required")
	}
	if err := ca.VerifyPrivateKey(ca.Curve(), caPrivateKey); err != nil {
		return nil, nil, fmt.Errorf("CA private key does not match certificate: %w", err)
	}
	if options.Version == 0 {
		options.Version = ca.Version()
	}
	if options.Name == "" {
		return nil, nil, errors.New("certificate name is required")
	}
	if len(options.Networks) == 0 {
		return nil, nil, errors.New("at least one overlay network is required")
	}
	if options.NotBefore.IsZero() {
		options.NotBefore = time.Now()
	}
	if options.NotAfter.IsZero() {
		options.NotAfter = ca.NotAfter().Add(-time.Second)
	}
	options.NotBefore = time.Unix(options.NotBefore.Unix(), 0)
	options.NotAfter = time.Unix(options.NotAfter.Unix(), 0)
	if !options.NotAfter.After(options.NotBefore) {
		return nil, nil, errors.New("certificate expiration must be after its start time")
	}

	publicKey := options.PublicKey
	var privateKey []byte
	var err error
	if len(publicKey) == 0 {
		publicKey, privateKey, err = GenerateKeyAgreementKey(ca.Curve())
		if err != nil {
			return nil, nil, err
		}
	}
	certificate, err := (&TBSCertificate{
		Version:        options.Version,
		Name:           options.Name,
		Networks:       options.Networks,
		UnsafeNetworks: options.UnsafeNetworks,
		Groups:         options.Groups,
		NotBefore:      options.NotBefore,
		NotAfter:       options.NotAfter,
		PublicKey:      publicKey,
		Curve:          ca.Curve(),
	}).Sign(ca, ca.Curve(), caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return certificate, privateKey, nil
}
