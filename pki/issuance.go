package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Issuer owns the signing key of the first CA in Chain. Ancestors follow in issuing order.
type Issuer struct {
	Chain  []*x509.Certificate
	Signer crypto.Signer
}
type CAProfile struct {
	Subject             pkix.Name
	NotBefore, NotAfter time.Time
	MaxPathLen          int
	Scope               *Scope
	PermittedIPs        []netip.Prefix
}

// Enrollment describes the identity and SPKI SHA-256 digest approved by the registration authority.
type Enrollment struct {
	Name       string
	IPv4, IPv6 netip.Addr
	Scope
	Usages              []x509.ExtKeyUsage
	PublicKeyHash       [32]byte
	NotBefore, NotAfter time.Time
}

func (ca Issuer) authority(at time.Time) (*x509.Certificate, error) {
	if len(ca.Chain) == 0 || ca.Chain[0] == nil || !MatchesKey(ca.Signer, ca.Chain[0]) {
		return nil, errors.New("issuer key mismatch")
	}
	for i, c := range ca.Chain {
		if c == nil || !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || at.Before(c.NotBefore) || !at.Before(c.NotAfter) || ((c.MaxPathLenZero || c.MaxPathLen > 0) && i > c.MaxPathLen) {
			return nil, errors.New("invalid issuer path or validity")
		}
		if i > 0 {
			if err := ca.Chain[i-1].CheckSignatureFrom(c); err != nil {
				return nil, err
			}
		}
	}
	return ca.Chain[0], nil
}
func issue(template, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) (*x509.Certificate, error) {
	// DER encodes certificate validity to whole seconds. Validate the interval
	// that relying parties will actually see.
	template.NotBefore = template.NotBefore.Truncate(time.Second)
	template.NotAfter = template.NotAfter.Truncate(time.Second)
	if !template.NotAfter.After(template.NotBefore) || template.NotBefore.Before(parent.NotBefore) || template.NotAfter.After(parent.NotAfter) {
		return nil, errors.New("invalid certificate interval")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
func caTemplate(p CAProfile) (*x509.Certificate, error) {
	c := &x509.Certificate{Subject: p.Subject, NotBefore: p.NotBefore, NotAfter: p.NotAfter, IsCA: true, BasicConstraintsValid: true, MaxPathLen: p.MaxPathLen, MaxPathLenZero: p.MaxPathLen == 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if p.Scope != nil {
		e, err := p.Scope.extension()
		if err != nil {
			return nil, err
		}
		c.ExtraExtensions = []pkix.Extension{e}
	}
	for _, prefix := range p.PermittedIPs {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid CA IP constraint")
		}
		c.PermittedIPRanges = append(c.PermittedIPRanges, &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())})
		c.PermittedDNSDomainsCritical = true
	}
	return c, nil
}
func CreateRoot(key crypto.Signer, p CAProfile) (*x509.Certificate, error) {
	if key == nil || p.Subject.String() == "" || p.MaxPathLen < -1 {
		return nil, errors.New("invalid CA profile or key")
	}
	c, err := caTemplate(p)
	if err != nil {
		return nil, err
	}
	return issue(c, c, key.Public(), key)
}
func CreateCSR(key crypto.Signer, subject pkix.Name) (*x509.CertificateRequest, error) {
	if key == nil {
		return nil, errors.New("invalid request key")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// checkIPRanges applies every issuer's standard SAN name constraints to the requested ranges.
func (ca Issuer) checkIPRanges(prefixes []netip.Prefix) error {
	for _, c := range ca.Chain {
		for _, p := range prefixes {
			for _, r := range c.ExcludedIPRanges {
				a, _ := netip.AddrFromSlice(r.IP)
				if r.Contains(p.Addr().AsSlice()) || p.Contains(a.Unmap()) {
					return fmt.Errorf("issuer excludes addresses in %s", p)
				}
			}
			if len(c.PermittedIPRanges) > 0 && !slices.ContainsFunc(c.PermittedIPRanges, func(r *net.IPNet) bool {
				bits, _ := r.Mask.Size()
				return bits <= p.Bits() && r.Contains(p.Addr().AsSlice())
			}) {
				return fmt.Errorf("IP range %s exceeds issuer permission", p)
			}
		}
	}
	return nil
}
func (ca Issuer) IssueCA(csr *x509.CertificateRequest, p CAProfile) (*x509.Certificate, error) {
	parent, err := ca.authority(time.Now())
	if err != nil {
		return nil, err
	}
	if csr == nil || csr.CheckSignature() != nil || p.Subject.String() == "" || p.MaxPathLen < -1 {
		return nil, errors.New("invalid CA request")
	}
	for i, c := range ca.Chain {
		if (c.MaxPathLenZero || c.MaxPathLen > 0) && (p.MaxPathLen < 0 || p.MaxPathLen > c.MaxPathLen-i-1) {
			return nil, errors.New("issuer path length exceeded")
		}
	}
	if p.Scope != nil {
		if err := checkDelegation(*p.Scope, ca.Chain); err != nil {
			return nil, err
		}
	}
	c, err := caTemplate(p)
	if err != nil {
		return nil, err
	}
	if err := ca.checkIPRanges(p.PermittedIPs); err != nil {
		return nil, err
	}
	return issue(c, parent, csr.PublicKey, ca.Signer)
}

func (ca Issuer) IssueLeaf(csr *x509.CertificateRequest, e Enrollment) (*x509.Certificate, error) {
	parent, err := ca.authority(time.Now())
	if err != nil {
		return nil, err
	}
	if csr == nil || csr.CheckSignature() != nil || sha256.Sum256(csr.RawSubjectPublicKeyInfo) != e.PublicKeyHash || len(e.Usages) == 0 {
		return nil, errors.New("incomplete or mismatched enrollment")
	}
	t := &x509.Certificate{Subject: pkix.Name{CommonName: e.Name}, NotBefore: e.NotBefore, NotAfter: e.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: e.Usages}
	if _, err := NewPeerID(e.IPv4, e.IPv6); err != nil {
		return nil, err
	}
	if err := checkDelegation(e.Scope, ca.Chain); err != nil {
		return nil, err
	}
	ext, err := e.Scope.extension()
	if err != nil {
		return nil, err
	}
	t.ExtraExtensions = []pkix.Extension{ext}
	t.IPAddresses = []net.IP{e.IPv4.AsSlice(), e.IPv6.AsSlice()}
	if err := ca.checkIPRanges([]netip.Prefix{netip.PrefixFrom(e.IPv4, 32), netip.PrefixFrom(e.IPv6, 128)}); err != nil {
		return nil, err
	}
	return issue(t, parent, csr.PublicKey, ca.Signer)
}
