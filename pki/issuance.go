package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Issuer owns the signing key of the first CA in Chain. Ancestors follow in issuing order.
type Issuer struct {
	Chain  []*x509.Certificate
	Signer crypto.Signer
}

// CAProfile specifies an issuing authority's validity, name and delegation limits.
// MaxPathLen of zero permits leaf issuance only. Use -1 for an unconstrained depth.
type CAProfile struct {
	Subject             pkix.Name
	NotBefore, NotAfter time.Time
	MaxPathLen          int
	Scope               *Scope
	// SignatureAlgorithm selects how the issuer signs this CA certificate.
	// Zero lets crypto/x509 choose the signature algorithm for that key.
	// An explicit signature must pass x509.Certificate.CheckSignatureFrom.
	SignatureAlgorithm x509.SignatureAlgorithm
	// PermittedIPs defines one prefix per family on a cluster CA. Issuers
	// below it must explicitly delegate member addresses in both families.
	PermittedIPs []netip.Prefix
}

// Enrollment describes the identity and SPKI SHA-256 digest approved by the registration authority.
type Enrollment struct {
	Name       string
	IPv4, IPv6 netip.Addr
	Scope
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

func signCertificate(template, issuer *x509.Certificate, subjectKey crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	// DER encodes certificate validity to whole seconds. Validate the interval
	// that relying parties will actually see.
	template.NotBefore = template.NotBefore.Truncate(time.Second)
	template.NotAfter = template.NotAfter.Truncate(time.Second)
	if !template.NotAfter.After(template.NotBefore) || template.NotBefore.Before(issuer.NotBefore) || template.NotAfter.After(issuer.NotAfter) {
		return nil, errors.New("invalid certificate interval")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectKey, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || template.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return cert, err
	}
	// crypto/x509 can sign with legacy algorithms it rejects for certification.
	if issuer == template {
		issuer = cert
	}
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		return nil, err
	}
	return cert, nil
}

func caTemplate(p CAProfile) (*x509.Certificate, error) {
	if p.Subject.String() == "" || p.MaxPathLen < -1 {
		return nil, errors.New("invalid CA profile")
	}
	c := &x509.Certificate{
		Subject: p.Subject, NotBefore: p.NotBefore, NotAfter: p.NotAfter,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: p.MaxPathLen, MaxPathLenZero: p.MaxPathLen == 0,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SignatureAlgorithm: p.SignatureAlgorithm,
	}
	if p.Scope != nil {
		if len(p.Scope.AnycastIPs) > 0 {
			return nil, errors.New("CA cannot hold service addresses")
		}
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
	if p.Scope != nil && p.Scope.Cluster {
		if _, err := clusterAddressPlan(c, *p.Scope); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// CreateRoot creates a self-signed X.509 trust anchor using key.
func CreateRoot(key crypto.Signer, p CAProfile) (*x509.Certificate, error) {
	if key == nil {
		return nil, errors.New("CA signing key required")
	}
	if p.Scope != nil || len(p.PermittedIPs) != 0 {
		return nil, errors.New("ordinary root cannot carry network constraints")
	}
	c, err := caTemplate(p)
	if err != nil {
		return nil, err
	}
	return signCertificate(c, c, key.Public(), key)
}

// CreateCSR signs a PKCS#10 request with the applicant's key.
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

func verifyRequest(csr *x509.CertificateRequest, approvedKeyHash [sha256.Size]byte) error {
	if csr == nil {
		return errors.New("certificate request required")
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR signature: %w", err)
	}
	if sha256.Sum256(csr.RawSubjectPublicKeyInfo) != approvedKeyHash {
		return errors.New("CSR public key does not match approved SPKI fingerprint")
	}
	return nil
}

// IssueCA verifies the CSR signature and independently approved SHA-256 digest
// of its SubjectPublicKeyInfo, then signs a subordinate CA with the supplied profile.
func (ca Issuer) IssueCA(csr *x509.CertificateRequest, p CAProfile, approvedKeyHash [sha256.Size]byte) (*x509.Certificate, error) {
	parent, err := ca.authority(time.Now())
	if err != nil {
		return nil, err
	}
	if err := verifyRequest(csr, approvedKeyHash); err != nil {
		return nil, err
	}
	if p.Scope != nil && p.Scope.Cluster {
		if err := ValidateRoot(parent); err != nil {
			return nil, err
		}
	}
	for i, c := range ca.Chain {
		if (c.MaxPathLenZero || c.MaxPathLen > 0) && (p.MaxPathLen < 0 || p.MaxPathLen > c.MaxPathLen-i-1) {
			return nil, errors.New("issuer path length exceeded")
		}
	}
	cluster, err := checkDelegation(p.Scope, ca.Chain)
	if err != nil {
		return nil, err
	}
	if cluster == nil && (p.Scope == nil || !p.Scope.Cluster) {
		return nil, errors.New("site CA requires a cluster issuer")
	}
	if cluster != nil {
		if _, err := ReadClusterCA(cluster); err != nil {
			return nil, err
		}
	}
	c, err := caTemplate(p)
	if err != nil {
		return nil, err
	}
	if err := checkDelegatedRanges(c, ca.Chain, cluster != nil); err != nil {
		return nil, err
	}
	return signCertificate(c, parent, csr.PublicKey, ca.Signer)
}

// IssueGrant checks the CSR signature and approved public key hash, then issues
// a code-signing grant for the approved addresses and network permissions.
func (ca Issuer) IssueGrant(csr *x509.CertificateRequest, e Enrollment) (*x509.Certificate, error) {
	parent, err := ca.authority(time.Now())
	if err != nil {
		return nil, err
	}
	if err := verifyRequest(csr, e.PublicKeyHash); err != nil {
		return nil, err
	}
	t := &x509.Certificate{Subject: pkix.Name{CommonName: e.Name}, NotBefore: e.NotBefore, NotAfter: e.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	clusterCA, err := checkDelegation(&e.Scope, ca.Chain)
	if err != nil {
		return nil, err
	}
	cluster, err := ReadClusterCA(clusterCA)
	if err != nil {
		return nil, err
	}
	if err := cluster.validateIdentity(Identity{Addresses: Addresses{e.IPv4, e.IPv6}, Scope: e.Scope}); err != nil {
		return nil, err
	}
	ext, err := e.extension()
	if err != nil {
		return nil, err
	}
	t.ExtraExtensions = []pkix.Extension{ext}
	t.IPAddresses = []net.IP{e.IPv4.AsSlice(), e.IPv6.AsSlice()}
	for _, a := range []netip.Addr{e.IPv4, e.IPv6} {
		if err := checkPermittedRange(netip.PrefixFrom(a, a.BitLen()), ca.Chain); err != nil {
			return nil, err
		}
	}
	leaf, err := signCertificate(t, parent, csr.PublicKey, ca.Signer)
	if err != nil {
		return nil, err
	}
	// Check the issued grant against the supplied delegation path.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Chain[len(ca.Chain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range ca.Chain[:len(ca.Chain)-1] {
		intermediates.AddCert(cert)
	}
	at := leaf.NotBefore
	for _, issuer := range ca.Chain {
		if issuer.NotBefore.After(at) {
			at = issuer.NotBefore
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return nil, err
	}
	return leaf, nil
}

// IssueNode issues an address-free node identity directly from an ordinary root.
func (ca Issuer) IssueNode(csr *x509.CertificateRequest, approved [32]byte, start, end time.Time) (*x509.Certificate, error) {
	root, err := ca.authority(time.Now())
	if err != nil {
		return nil, err
	}
	if err := ValidateRoot(root); err != nil {
		return nil, err
	}
	if err := verifyRequest(csr, approved); err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: nodeCommonName}, NotBefore: start, NotAfter: end,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{nodeUsage},
	}
	node, err := signCertificate(template, root, csr.PublicKey, ca.Signer)
	if err != nil {
		return nil, err
	}
	for _, usage := range template.ExtKeyUsage {
		if _, err := VerifyNode(node, root, usage, node.NotBefore); err != nil {
			return nil, err
		}
	}
	return node, nil
}
