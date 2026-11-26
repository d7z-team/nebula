package pki

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// PeerID identifies a node public key by its canonical SPKI SHA-256 digest.
type PeerID [sha256.Size]byte

// NewPeerID hashes the DER SubjectPublicKeyInfo of key.
func NewPeerID(key crypto.PublicKey) (PeerID, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return PeerID{}, err
	}
	return sha256.Sum256(der), nil
}
func (id PeerID) String() string               { return hex.EncodeToString(id[:]) }
func (id PeerID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *PeerID) UnmarshalText(b []byte) error {
	if len(b) != hex.EncodedLen(len(id)) {
		return errors.New("invalid peer ID length")
	}
	var next PeerID
	if _, err := hex.Decode(next[:], b); err != nil {
		return err
	}
	*id = next
	return nil
}

// Addresses holds the two exclusive primary addresses in a cluster grant.
type Addresses struct {
	IPv4 netip.Addr `json:"ipv4"`
	IPv6 netip.Addr `json:"ipv6"`
}

// OID generated from GUID 6823cd53-e1ed-409b-96d5-90ce56aa0c3b using Microsoft's GUID OID arc.
var meshOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554, 0x6823, 0xcd53, 0xe1ed, 0x409b, 0x96d5, 0x90ce56, 0xaa0c3b}

// Scope is a leaf's routed authority or a CA's delegation ceiling.
// A CA without the extension inherits its ancestors' restrictions.
type Scope struct {
	Network        string
	RoutedPrefixes []netip.Prefix
	// Cluster marks the CA whose IP name constraints define the two member prefixes.
	Cluster bool
	// AnycastPools delegates ranges to issuers; AnycastIPs grants exact addresses to leaves.
	AnycastPools []netip.Prefix
	AnycastIPs   []netip.Addr
}

// AllowsRoute reports whether the scope delegates all of p.
func (s Scope) AllowsRoute(p netip.Prefix) bool { return covers(s.RoutedPrefixes, p) }

type scopeDER struct {
	Network  string `asn1:"utf8"`
	Prefixes []prefixDER
	Cluster  bool
	Pools    []prefixDER
	VIPs     [][]byte
}

type prefixDER struct {
	Address []byte
	Bits    int
}

func (s Scope) extension() (pkix.Extension, error) {
	d := scopeDER{Network: s.Network}
	if !ValidName(s.Network) {
		return pkix.Extension{}, errors.New("invalid mesh network")
	}
	for _, p := range s.RoutedPrefixes {
		if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() {
			return pkix.Extension{}, fmt.Errorf("invalid routed prefix %s", p)
		}
		d.Prefixes = append(d.Prefixes, prefixDER{p.Addr().AsSlice(), p.Bits()})
	}
	d.Cluster = s.Cluster
	for i, p := range s.AnycastPools {
		if !validUnicastPrefix(p) || slices.ContainsFunc(s.AnycastPools[:i], p.Overlaps) {
			return pkix.Extension{}, fmt.Errorf("invalid anycast pool %s", p)
		}
		d.Pools = append(d.Pools, prefixDER{p.Addr().AsSlice(), p.Bits()})
	}
	for i, a := range s.AnycastIPs {
		if !a.IsGlobalUnicast() || a.Zone() != "" || a.Is4In6() || slices.Contains(s.AnycastIPs[:i], a) {
			return pkix.Extension{}, fmt.Errorf("invalid anycast address %s", a)
		}
		d.VIPs = append(d.VIPs, a.AsSlice())
	}
	value, err := asn1.Marshal(d)
	return pkix.Extension{Id: meshOID, Value: value}, err
}

// CertificateScope reads the signed mesh extension. An unconstrained CA may omit it.
func CertificateScope(c *x509.Certificate) (Scope, bool, error) {
	if c == nil {
		return Scope{}, false, errors.New("missing certificate")
	}
	for _, e := range c.Extensions {
		if !e.Id.Equal(meshOID) {
			continue
		}
		var d scopeDER
		rest, err := asn1.Unmarshal(e.Value, &d)
		if err != nil || len(rest) != 0 || !ValidName(d.Network) {
			return Scope{}, true, errors.New("invalid mesh extension")
		}
		s := Scope{Network: d.Network, Cluster: d.Cluster}
		if c.IsCA && len(d.VIPs) > 0 || !c.IsCA && (d.Cluster || len(d.Pools) > 0) {
			return Scope{}, true, errors.New("mesh extension has invalid certificate role")
		}
		s.RoutedPrefixes = decodePrefixes(d.Prefixes)
		s.AnycastPools = decodePrefixes(d.Pools)
		for _, v := range d.VIPs {
			a, _ := netip.AddrFromSlice(v)
			s.AnycastIPs = append(s.AnycastIPs, a)
		}
		canonical, err := s.extension()
		if err != nil || !bytes.Equal(e.Value, canonical.Value) {
			return Scope{}, true, errors.New("invalid mesh extension encoding")
		}
		return s, true, nil
	}
	return Scope{}, false, nil
}

func decodePrefixes(encoded []prefixDER) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, p := range encoded {
		addr, _ := netip.AddrFromSlice(p.Address)
		prefixes = append(prefixes, netip.PrefixFrom(addr, p.Bits))
	}
	return prefixes
}

type Identity struct {
	ID PeerID
	Addresses
	Scope
}

// ReadIdentity extracts the address pair and mesh scope; VerifyGrant establishes trust.
func ReadIdentity(c *x509.Certificate) (Identity, error) {
	if c == nil || c.IsCA || c.Version != 3 || len(c.IPAddresses) != 2 || c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Identity{}, errors.New("invalid mesh signing leaf")
	}
	a, _ := netip.AddrFromSlice(c.IPAddresses[0])
	b, _ := netip.AddrFromSlice(c.IPAddresses[1])
	if b.Is4() {
		a, b = b, a
	}
	id, err := NewPeerID(c.PublicKey)
	if err != nil {
		return Identity{}, err
	}
	s, ok, err := CertificateScope(c)
	if err != nil {
		return Identity{}, err
	}
	if !ok {
		return Identity{}, errors.New("missing mesh extension")
	}
	if !a.Is4() || !b.Is6() || b.Is4In6() {
		return Identity{}, errors.New("dual-stack grant required")
	}
	return Identity{id, Addresses{a, b}, s}, nil
}

// checkDelegation checks every mesh issuer on the path and returns its cluster CA, if present.
func checkDelegation(child *Scope, ancestors []*x509.Certificate) (*x509.Certificate, error) {
	var clusterCA *x509.Certificate
	issuingCluster := child != nil && child.Cluster
	for i, c := range ancestors {
		s, ok, err := CertificateScope(c)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if s.Cluster {
			if issuingCluster || clusterCA != nil {
				return nil, errors.New("nested cluster CA")
			}
			clusterCA = c
			for j, issuer := range ancestors[:i+1] {
				if err := checkDelegatedRanges(issuer, ancestors[j+1:], j < i); err != nil {
					return nil, err
				}
			}
		}
		if child == nil {
			child = &s
			continue
		}
		if s.Network != child.Network {
			return nil, errors.New("issuer network mismatch")
		}
		for _, p := range child.RoutedPrefixes {
			if !s.AllowsRoute(p) {
				return nil, fmt.Errorf("issuer does not delegate route %s", p)
			}
		}
		for _, a := range child.AnycastIPs {
			if !contains(s.AnycastPools, a) {
				return nil, fmt.Errorf("issuer does not delegate anycast address %s", a)
			}
		}
		for _, p := range child.AnycastPools {
			if !covers(s.AnycastPools, p) {
				return nil, fmt.Errorf("issuer does not delegate anycast pool %s", p)
			}
		}
		child = &s
	}
	return clusterCA, nil
}
