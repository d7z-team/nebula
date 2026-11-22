package nebula

import (
	"crypto/fips140"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/noiseutil"
)

// Identity pairs a parsed Nebula host certificate with its raw key-agreement
// private key. A Node may carry one v1 and one v2 identity backed by the same
// key so it can negotiate either wire certificate version.
type Identity struct {
	Certificate cert.Certificate
	PrivateKey  []byte
}

type pkiState struct {
	cs     *certificateState
	caPool *cert.CAPool
}

type certificateState struct {
	v1Cert       cert.Certificate
	v1Credential *handshake.Credential

	v2Cert       cert.Certificate
	v2Credential *handshake.Credential

	initiatingVersion cert.Version
	privateKey        []byte
	cipher            string

	myVpnNetworks      []netip.Prefix
	myVpnNetworksTable *bart.Lite
	myVpnAddrs         []netip.Addr
	myVpnAddrsTable    *bart.Lite
}

func newPKI(identities []Identity, caPool *cert.CAPool, cipher string, initiatingVersion cert.Version) (*pkiState, error) {
	if len(identities) == 0 {
		return nil, errors.New("at least one identity is required")
	}
	if caPool == nil || len(caPool.CAs) == 0 {
		return nil, errors.New("at least one trusted CA is required")
	}
	if cipher == "" {
		cipher = "aes"
	}
	if !validCipher(cipher) {
		return nil, fmt.Errorf("unknown cipher %q", cipher)
	}
	if initiatingVersion != 0 && initiatingVersion != cert.Version1 && initiatingVersion != cert.Version2 {
		return nil, fmt.Errorf("unsupported initiating certificate version %v", initiatingVersion)
	}

	var v1, v2 cert.Certificate
	var privateKey []byte
	var curve cert.Curve
	now := time.Now()
	for _, identity := range identities {
		crt := identity.Certificate
		if crt == nil {
			return nil, errors.New("identity certificate is nil")
		}
		if crt.IsCA() {
			return nil, errors.New("identity certificate must not be a CA")
		}
		if crt.Expired(now) {
			return nil, fmt.Errorf("identity certificate %q is expired", crt.Name())
		}
		if _, err := caPool.VerifyCertificate(now, crt); err != nil {
			return nil, fmt.Errorf("verify identity certificate %q: %w", crt.Name(), err)
		}
		if len(crt.Networks()) == 0 {
			return nil, fmt.Errorf("identity certificate %q has no overlay networks", crt.Name())
		}
		if err := cert.CheckKnownCurve(crt); err != nil {
			return nil, err
		}
		if len(identity.PrivateKey) == 0 {
			return nil, fmt.Errorf("identity certificate %q has no private key", crt.Name())
		}
		if privateKey == nil {
			privateKey = slices.Clone(identity.PrivateKey)
			curve = crt.Curve()
		} else if !slices.Equal(privateKey, identity.PrivateKey) || curve != crt.Curve() {
			return nil, errors.New("v1 and v2 identities must use the same private key and curve")
		}
		switch crt.Version() {
		case cert.Version1:
			if v1 != nil {
				return nil, errors.New("multiple v1 identities")
			}
			v1 = crt
		case cert.Version2:
			if v2 != nil {
				return nil, errors.New("multiple v2 identities")
			}
			v2 = crt
		default:
			return nil, fmt.Errorf("unsupported certificate version %v", crt.Version())
		}
	}
	if initiatingVersion == 0 {
		if v1 != nil {
			initiatingVersion = cert.Version1
		} else {
			initiatingVersion = cert.Version2
		}
	}
	if initiatingVersion == cert.Version1 && v1 == nil || initiatingVersion == cert.Version2 && v2 == nil {
		return nil, fmt.Errorf("initiating certificate version %v is not configured", initiatingVersion)
	}
	cs, err := newCertState(initiatingVersion, v1, v2, curve, privateKey, cipher)
	if err != nil {
		return nil, err
	}
	return &pkiState{cs: cs, caPool: caPool}, nil
}

func (p *pkiState) GetCAPool() *cert.CAPool { return p.caPool }

func (p *pkiState) getCertState() *certificateState { return p.cs }

func validCipher(cipher string) bool {
	return cipher == "aes" || cipher == "chachapoly"
}

func (cs *certificateState) GetDefaultCertificate() cert.Certificate {
	c := cs.getCertificate(cs.initiatingVersion)
	if c == nil {
		panic("No default certificate found")
	}
	return c
}

// DefaultVersion returns the preferred cert version for initiating handshakes.
func (cs *certificateState) DefaultVersion() cert.Version { return cs.initiatingVersion }

// GetCredential returns the pre-computed handshake credential for the given version, or nil.
func (cs *certificateState) GetCredential(v cert.Version) *handshake.Credential {
	switch v {
	case cert.Version1:
		return cs.v1Credential
	case cert.Version2:
		return cs.v2Credential
	}
	return nil
}

func (cs *certificateState) getCertificate(v cert.Version) cert.Certificate {
	switch v {
	case cert.Version1:
		return cs.v1Cert
	case cert.Version2:
		return cs.v2Cert
	}

	return nil
}

// newCipherSuite builds the noise.CipherSuite for the given curve and cipher.
// When fips140Enforced is true (FIPS 140-only mode), non-approved algorithms
// (Curve25519 and ChaChaPoly) are rejected with an error. Callers pass
// fips140.Enforced() for fips140Enforced.
func newCipherSuite(curve cert.Curve, cipher string, fips140Enforced bool) (noise.CipherSuite, error) {
	var dhFunc noise.DHFunc
	switch curve {
	case cert.Curve_CURVE25519:
		if fips140Enforced {
			return nil, errors.New("pki: use of Curve25519 is not allowed in FIPS 140-only mode")
		}
		dhFunc = noise.DH25519
	case cert.Curve_P256:
		dhFunc = noiseutil.DHP256
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	if cipher == "chachapoly" {
		if fips140Enforced {
			return nil, errors.New("pki: use of ChaChaPoly is not allowed in FIPS 140-only mode")
		}
		return noise.NewCipherSuite(dhFunc, noise.CipherChaChaPoly, noise.HashSHA256), nil
	}
	return noise.NewCipherSuite(dhFunc, noiseutil.CipherAESGCM, noise.HashSHA256), nil
}

func newCertState(dv cert.Version, v1, v2 cert.Certificate, privateKeyCurve cert.Curve, privateKey []byte, cipher string) (*certificateState, error) {
	cs := certificateState{
		privateKey:         privateKey,
		cipher:             cipher,
		myVpnNetworksTable: new(bart.Lite),
		myVpnAddrsTable:    new(bart.Lite),
	}

	if v1 != nil && v2 != nil {
		if !slices.Equal(v1.PublicKey(), v2.PublicKey()) {
			return nil, errors.New("v1 and v2 public keys are not the same")
		}

		if v1.Curve() != v2.Curve() {
			return nil, errors.New("v1 and v2 curves are not the same")
		}

		if !slices.Equal(v1.Networks(), v2.Networks()) {
			return nil, errors.New("v1 and v2 networks are not the same")
		}
		if !slices.Equal(v1.UnsafeNetworks(), v2.UnsafeNetworks()) {
			return nil, errors.New("v1 and v2 unsafe networks are not the same")
		}

		cs.initiatingVersion = dv
	}

	if v1 != nil {
		if err := v1.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
			return nil, fmt.Errorf("private key is not a pair with public key in nebula cert: %w", err)
		}

		v1hs, err := v1.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v1 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v1.Curve(), cipher, fips140.Enforced())
		if err != nil {
			return nil, err
		}
		cs.v1Cert = v1
		cs.v1Credential = handshake.NewCredential(v1, v1hs, privateKey, ncs)

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version1
		}
	}

	if v2 != nil {
		if err := v2.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
			return nil, fmt.Errorf("private key is not a pair with public key in nebula cert: %w", err)
		}

		v2hs, err := v2.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling v2 certificate for handshake: %w", err)
		}
		ncs, err := newCipherSuite(v2.Curve(), cipher, fips140.Enforced())
		if err != nil {
			return nil, err
		}
		cs.v2Cert = v2
		cs.v2Credential = handshake.NewCredential(v2, v2hs, privateKey, ncs)

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version2
		}
	}

	var crt cert.Certificate
	crt = cs.getCertificate(cert.Version2)
	if crt == nil {
		// v2 certificates are a superset, only look at v1 if its all we have
		crt = cs.getCertificate(cert.Version1)
	}

	for _, network := range crt.Networks() {
		cs.myVpnNetworks = append(cs.myVpnNetworks, network)
		cs.myVpnNetworksTable.Insert(network)

		cs.myVpnAddrs = append(cs.myVpnAddrs, network.Addr())
		cs.myVpnAddrsTable.Insert(netip.PrefixFrom(network.Addr(), network.Addr().BitLen()))

	}

	return &cs, nil
}
