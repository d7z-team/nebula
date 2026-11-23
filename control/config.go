// Package control defines the offline-signed network configuration consumed by
// managed Nebula nodes. A document is a complete replacement for its predecessor.
package control

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
)

// MaxDocument is the maximum size in bytes of an encoded signed document.
const MaxDocument = 1 << 20

// Member describes a node in the signed topology. Links authorize bidirectional
// overlay adjacencies. Transit permits forwarding and Restricted pins UDP exits.
type Member struct {
	Links          []netip.Addr      `json:"links,omitempty"`
	Endpoints      []netip.AddrPort  `json:"endpoints,omitempty"`
	Transit        bool              `json:"transit,omitempty"`
	Restricted     bool              `json:"restricted,omitempty"`
	BytesPerSecond int               `json:"bytesPerSecond,omitempty"`
	Certificate    string            `json:"certificate,omitempty"`
	Publisher      ed25519.PublicKey `json:"publisher,omitempty"`
	Topics         []string          `json:"topics,omitempty"`
}

// Config is a complete revision of the network topology and administrator settings.
type Config struct {
	Format    int                   `json:"format"`
	Network   string                `json:"network"`
	Revision  uint64                `json:"revision"`
	Authority string                `json:"authority"`
	Revoked   []string              `json:"revoked,omitempty"`
	Members   map[netip.Addr]Member `json:"members,omitempty"`
	// Settings carries application-defined administrator configuration in the same signed revision.
	Settings map[string]json.RawMessage `json:"settings,omitempty"`
}

type document struct {
	Body      []byte `json:"body"`
	Signature []byte `json:"signature"`
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

// Validate checks the configuration fields and the reciprocity of topology links.
func (c Config) Validate() error {
	if c.Format != 1 || !ValidNetwork(c.Network) || c.Revision == 0 {
		return errors.New("invalid configuration format, domain or revision")
	}
	if !validFingerprint(c.Authority) {
		return fmt.Errorf("invalid configuration authority fingerprint %q", c.Authority)
	}
	for _, fp := range c.Revoked {
		if !validFingerprint(fp) {
			return fmt.Errorf("invalid certificate fingerprint %q", fp)
		}
	}
	for a, m := range c.Members {
		if !a.IsGlobalUnicast() || a.Is4In6() || a.Zone() != "" || m.BytesPerSecond < 0 || (len(m.Publisher) != 0 && len(m.Publisher) != ed25519.PublicKeySize) {
			return fmt.Errorf("invalid member %v", a)
		}
		if m.Certificate != "" && !validFingerprint(m.Certificate) {
			return fmt.Errorf("invalid certificate fingerprint for %s", a)
		}
		if len(m.Topics) > 0 && len(m.Publisher) == 0 {
			return fmt.Errorf("missing publisher key for %s", a)
		}
		for _, topic := range m.Topics {
			if !ValidTopic(topic) {
				return fmt.Errorf("invalid application topic %q", topic)
			}
		}
		for i, b := range m.Links {
			if a == b || slices.Contains(m.Links[:i], b) || !slices.Contains(c.Members[b].Links, a) {
				return fmt.Errorf("invalid reciprocal link %v to %v", a, b)
			}
		}
		for _, ep := range m.Endpoints {
			if !ep.IsValid() || ep.Port() == 0 || ep.Addr().IsUnspecified() || ep.Addr().IsMulticast() || ep.Addr().Is4In6() {
				return fmt.Errorf("invalid endpoint %v", ep)
			}
		}
	}
	return nil
}

func validFingerprint(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

const nameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

// ValidNetwork reports whether s can identify a signed configuration domain.
func ValidNetwork(s string) bool {
	return s != "" && len(s) <= 128 && strings.Trim(s, nameChars) == ""
}

// ValidTopic reports whether s is an application topic under app/.
func ValidTopic(s string) bool {
	if len(s) > 128 || !strings.HasPrefix(s, "app/") {
		return false
	}
	for p := range strings.SplitSeq(s, "/") {
		if p == "" || strings.Trim(p, nameChars) != "" {
			return false
		}
	}
	return true
}

func signatureInput(b []byte) []byte {
	return append([]byte("nebula/network-configuration/v1\x00"), b...)
}

// Sign accepts an offline Nebula CA signing key, including a hardware-backed signer.
func Sign(c Config, ca cert.Certificate, signer crypto.Signer) ([]byte, error) {
	if ca == nil || !ca.IsCA() || signer == nil {
		return nil, errors.New("configuration CA and signer required")
	}
	fp, err := ca.Fingerprint()
	if err != nil {
		return nil, err
	}
	c.Authority = fp
	if err = c.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	input := signatureInput(body)
	var hash crypto.Hash
	if ca.Curve() == cert.Curve_P256 {
		sum := sha256.Sum256(input)
		input = sum[:]
		hash = crypto.SHA256
	}
	sig, err := signer.Sign(rand.Reader, input, hash)
	if err != nil {
		return nil, err
	}
	wire, err := json.Marshal(document{Body: body, Signature: sig})
	if err != nil {
		return nil, err
	}
	_, _, err = Verify(wire, c.Network, ca)
	if err != nil {
		return nil, err
	}
	return wire, nil
}

// Verify checks the pinned configuration authority, domain and exact signed bytes.
// Digest identifies the body independently of randomized ECDSA signatures.
func Verify(wire []byte, network string, ca cert.Certificate) (Config, string, error) {
	var c Config
	if ca == nil || !ca.IsCA() || ca.Expired(time.Now()) || len(wire) > MaxDocument {
		return c, "", errors.New("invalid authority or oversized document")
	}
	var d document
	if err := decode(wire, &d); err != nil {
		return c, "", err
	}
	input := signatureInput(d.Body)
	valid := false
	switch ca.Curve() {
	case cert.Curve_CURVE25519:
		pk := ca.PublicKey()
		valid = len(pk) == ed25519.PublicKeySize && ed25519.Verify(pk, input, d.Signature)
	case cert.Curve_P256:
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ca.PublicKey())
		if err == nil {
			sum := sha256.Sum256(input)
			valid = ecdsa.VerifyASN1(pk, sum[:], d.Signature)
		}
	}
	if !valid {
		return c, "", errors.New("invalid configuration signature")
	}
	if err := decode(d.Body, &c); err != nil {
		return c, "", err
	}
	fp, err := ca.Fingerprint()
	if err != nil || fp != c.Authority || c.Network != network {
		return c, "", errors.New("unexpected configuration authority or network")
	}
	if err := c.Validate(); err != nil {
		return c, "", err
	}
	sum := sha256.Sum256(d.Body)
	return c, hex.EncodeToString(sum[:]), nil
}
