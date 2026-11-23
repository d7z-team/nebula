package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// PeerID is the network-order IPv4 address followed by the IPv6 address.
type PeerID [20]byte

// NewPeerID binds one unicast IPv4 address and one native unicast IPv6 address.
func NewPeerID(v4, v6 netip.Addr) (PeerID, error) {
	var id PeerID
	if !v4.Is4() || !v6.Is6() || v6.Is4In6() || v6.Zone() != "" || !v4.IsGlobalUnicast() || !v6.IsGlobalUnicast() {
		return id, errors.New("one unicast IPv4 and one native IPv6 address required")
	}
	copy(id[:4], v4.AsSlice())
	copy(id[4:], v6.AsSlice())
	return id, nil
}
func (id PeerID) IPv4() netip.Addr             { return netip.AddrFrom4([4]byte(id[:4])) }
func (id PeerID) IPv6() netip.Addr             { return netip.AddrFrom16([16]byte(id[4:])) }
func (id PeerID) String() string               { return id.IPv4().String() + "@" + id.IPv6().String() }
func (id PeerID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *PeerID) UnmarshalText(b []byte) error {
	a, c, _ := strings.Cut(string(b), "@")
	v4, err := netip.ParseAddr(a)
	if err != nil {
		return err
	}
	v6, err := netip.ParseAddr(c)
	if err != nil {
		return err
	}
	v, err := NewPeerID(v4, v6)
	if err == nil {
		*id = v
	}
	return err
}

// OID generated from GUID 6823cd53-e1ed-409b-96d5-90ce56aa0c3b using Microsoft's GUID OID arc.
var meshOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554, 0x6823, 0xcd53, 0xe1ed, 0x409b, 0x96d5, 0x90ce56, 0xaa0c3b}

// Scope is a leaf's routed authority or a CA's delegation ceiling.
// A CA without the extension inherits its ancestors' restrictions.
type Scope struct {
	Network        string
	RoutedPrefixes []netip.Prefix
}
type scopeDER struct {
	Network  string `asn1:"utf8"`
	Prefixes []prefixDER
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
		s := Scope{Network: d.Network}
		for _, v := range d.Prefixes {
			addr, ok := netip.AddrFromSlice(v.Address)
			p := netip.PrefixFrom(addr, v.Bits)
			if !ok || !p.IsValid() || p != p.Masked() || addr.Is4In6() {
				return Scope{}, true, errors.New("invalid mesh routed prefix")
			}
			s.RoutedPrefixes = append(s.RoutedPrefixes, p)
		}
		return s, true, nil
	}
	return Scope{}, false, nil
}

type Identity struct {
	ID PeerID
	Scope
}

// ReadIdentity extracts the address pair and mesh scope; VerifyChain establishes trust.
func ReadIdentity(c *x509.Certificate) (Identity, error) {
	if c == nil || c.IsCA || c.Version != 3 || len(c.IPAddresses) != 2 || c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Identity{}, errors.New("invalid mesh signing leaf")
	}
	a, _ := netip.AddrFromSlice(c.IPAddresses[0])
	b, _ := netip.AddrFromSlice(c.IPAddresses[1])
	if b.Is4() {
		a, b = b, a
	}
	id, err := NewPeerID(a, b)
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
	return Identity{id, s}, nil
}

// AllowsIP reports whether this certificate covers an inner address.
func (i Identity) AllowsIP(addr netip.Addr) bool {
	if addr == i.ID.IPv4() || addr == i.ID.IPv6() {
		return true
	}
	for _, p := range i.RoutedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// checkDelegation checks the mesh restrictions on one complete PKIX path.
func checkDelegation(leaf Scope, ancestors []*x509.Certificate) error {
	for _, c := range ancestors {
		s, ok, err := CertificateScope(c)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if s.Network != leaf.Network {
			return errors.New("issuer network mismatch")
		}
		for _, p := range leaf.RoutedPrefixes {
			if !slices.ContainsFunc(s.RoutedPrefixes, func(within netip.Prefix) bool { return within.Bits() <= p.Bits() && within.Contains(p.Addr()) }) {
				return fmt.Errorf("issuer does not delegate %s", p)
			}
		}
		leaf = s
	}
	return nil
}
