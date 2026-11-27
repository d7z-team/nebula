package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	_ "crypto/sha512"
)

// MaxDocument is the largest DER object accepted by the mesh CMS profile.
const MaxDocument = 44 << 10

// ErrDocumentTooLarge means the content or its CMS envelope exceeds MaxDocument.
var ErrDocumentTooLarge = errors.New("oversized CMS document")

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSigned        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidEd            = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
)

type (
	algorithm   = pkix.AlgorithmIdentifier
	contentInfo struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
)

type issuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type signerInfo struct {
	Version   int
	SID       issuerSerial
	Digest    algorithm
	Attrs     asn1.RawValue
	Algorithm algorithm
	Signature []byte
}
type signedData struct {
	Version      int
	Digests      []algorithm `asn1:"set"`
	Content      contentInfo
	Certificates []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs         []asn1.RawValue `asn1:"optional,set,tag:1"`
	Signers      []signerInfo    `asn1:"set"`
}

func raw(b []byte) asn1.RawValue { return asn1.RawValue{FullBytes: b} }
func explicit(b []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b}
}

func readDER(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing DER data")
	}
	return nil
}

func validAlg(a algorithm, oid asn1.ObjectIdentifier) bool {
	return a.Algorithm.Equal(oid) && len(a.Parameters.FullBytes) == 0
}

func wrapCMS(s signedData) ([]byte, error) {
	b, err := asn1.Marshal(s)
	if err != nil {
		return nil, err
	}
	wire, err := asn1.Marshal(contentInfo{oidSigned, explicit(b)})
	if len(wire) > MaxDocument {
		return nil, ErrDocumentTooLarge
	}
	return wire, err
}

func parseCMS(b []byte) (signedData, error) {
	var c contentInfo
	var s signedData
	if len(b) > MaxDocument || readDER(b, &c) != nil || !c.Type.Equal(oidSigned) || c.Value.Class != 2 || c.Value.Tag != 0 || !c.Value.IsCompound || readDER(c.Value.Bytes, &s) != nil || s.Version != 1 || !s.Content.Type.Equal(oidData) {
		return s, errors.New("invalid CMS SignedData")
	}
	canonical, err := wrapCMS(s)
	if err != nil || !bytes.Equal(canonical, b) {
		return s, errors.New("noncanonical SignedData")
	}
	return s, nil
}

type cmsAlgorithm struct {
	oid       asn1.ObjectIdentifier
	signature x509.SignatureAlgorithm
	digest    crypto.Hash
	prehash   crypto.Hash
}

func objectAlgorithm(pub crypto.PublicKey) (cmsAlgorithm, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return cmsAlgorithm{oidEd, x509.PureEd25519, crypto.SHA512, 0}, nil
	case *ecdsa.PublicKey:
		return cmsAlgorithm{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, x509.ECDSAWithSHA256, crypto.SHA256, crypto.SHA256}, nil
	case *rsa.PublicKey:
		return cmsAlgorithm{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, x509.SHA256WithRSA, crypto.SHA256, crypto.SHA256}, nil
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return cmsAlgorithm{oidMLDSA44, x509.MLDSA44, crypto.SHA512, 0}, nil
		case mldsa.MLDSA65():
			return cmsAlgorithm{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, x509.MLDSA65, crypto.SHA512, 0}, nil
		case mldsa.MLDSA87():
			return cmsAlgorithm{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, x509.MLDSA87, crypto.SHA512, 0}, nil
		}
	}
	return cmsAlgorithm{}, errors.New("unsupported CMS key")
}

func (a cmsAlgorithm) digestID() algorithm {
	if a.digest == crypto.SHA512 {
		return algorithm{Algorithm: oidSHA512}
	}
	return algorithm{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
}

func (a cmsAlgorithm) attributes(payload []byte) ([]byte, asn1.RawValue) {
	h := a.digest.New()
	h.Write(payload)
	d, _ := asn1.Marshal(h.Sum(nil))
	ct, _ := asn1.Marshal(oidData)
	set, _ := asn1.MarshalWithParams([]attribute{{oidContentType, []asn1.RawValue{raw(ct)}}, {oidMessageDigest, []asn1.RawValue{raw(d)}}}, "set")
	var v asn1.RawValue
	asn1.Unmarshal(set, &v)
	return set, explicit(v.Bytes)
}

type signedContent struct {
	Network, Kind                       string `asn1:"utf8"`
	Fingerprint, CertificatesHash, Body []byte
}

// The DER SET OF encoding puts the certificate bag in canonical order.
func certificateSetHash(certs []asn1.RawValue) ([sha256.Size]byte, error) {
	set, err := asn1.MarshalWithParams(certs, "set")
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(set), nil
}

// SignObject creates an encapsulated CMS signature bound to its publisher, network and purpose.
func SignObject(network, kind string, body []byte, cert tls.Certificate) ([]byte, error) {
	return encodeObject(network, kind, body, cert, true)
}

// CheckObjectSize checks that the complete CMS envelope fits MaxDocument, even
// with the largest signature for the key. It does not invoke the private signer.
func CheckObjectSize(network, kind string, body []byte, cert tls.Certificate) error {
	_, err := encodeObject(network, kind, body, cert, false)
	return err
}

func encodeObject(network, kind string, body []byte, cert tls.Certificate, sign bool) ([]byte, error) {
	if len(body) > MaxDocument {
		return nil, ErrDocumentTooLarge
	}
	if !ValidName(network) || !ValidName(kind) || len(cert.Certificate) == 0 {
		return nil, errors.New("invalid object or signing credential")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if sign && !MatchesKey(cert.PrivateKey, leaf) {
		return nil, errors.New("signing key mismatch")
	}
	a, err := objectAlgorithm(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(leaf.Raw)
	var certs []asn1.RawValue
	for _, der := range cert.Certificate {
		certs = append(certs, raw(der))
	}
	evidence, err := certificateSetHash(certs)
	if err != nil {
		return nil, err
	}
	payload, err := asn1.Marshal(signedContent{network, kind, hash[:], evidence[:], body})
	if err != nil {
		return nil, err
	}
	attrs, tag := a.attributes(payload)
	var sig []byte
	if sign {
		sig, err = crypto.SignMessage(cert.PrivateKey.(crypto.Signer), rand.Reader, attrs, a.prehash)
	} else {
		switch key := leaf.PublicKey.(type) {
		case ed25519.PublicKey:
			sig = make([]byte, ed25519.SignatureSize)
		case *ecdsa.PublicKey:
			// Both signature integers are positive and smaller than the curve order.
			order := key.Params().N
			sig, err = asn1.Marshal(struct{ R, S *big.Int }{order, order})
		case *rsa.PublicKey:
			sig = make([]byte, key.Size())
		case *mldsa.PublicKey:
			sig = make([]byte, key.Parameters().SignatureSize())
		}
	}
	if err != nil {
		return nil, err
	}
	octets, _ := asn1.Marshal(payload)
	sigAlg := algorithm{Algorithm: a.oid}
	if a.signature == x509.SHA256WithRSA {
		sigAlg.Parameters = asn1.NullRawValue
	}
	si := signerInfo{1, issuerSerial{raw(leaf.RawIssuer), leaf.SerialNumber}, a.digestID(), tag, sigAlg, sig}
	sd := signedData{Version: 1, Digests: []algorithm{a.digestID()}, Content: contentInfo{oidData, explicit(octets)}, Certificates: certs, Signers: []signerInfo{si}}
	return wrapCMS(sd)
}

// VerifyObjectSignature checks the CMS signature, domain and certificate set.
// Pass the returned certificates to [VerifyObjectSigner] to verify cluster membership.
func VerifyObjectSignature(der []byte, network, kind string) ([]byte, []*x509.Certificate, error) {
	s, err := parseCMS(der)
	if err != nil {
		return nil, nil, err
	}
	var payload []byte
	var v signedContent
	if len(s.Signers) != 1 || len(s.Digests) != 1 || len(s.CRLs) != 0 {
		return nil, nil, errors.New("expected single-signer CMS")
	}
	if s.Content.Value.Class != 2 || s.Content.Value.Tag != 0 || !s.Content.Value.IsCompound || readDER(s.Content.Value.Bytes, &payload) != nil || readDER(payload, &v) != nil || v.Network != network || v.Kind != kind {
		return nil, nil, errors.New("invalid CMS content or domain")
	}
	evidence, err := certificateSetHash(s.Certificates)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(evidence[:], v.CertificatesHash) {
		return nil, nil, errors.New("CMS certificate evidence mismatch")
	}
	si := s.Signers[0]
	var leaf *x509.Certificate
	var extra []*x509.Certificate
	for _, rv := range s.Certificates {
		c, err := x509.ParseCertificate(rv.FullBytes)
		if err != nil {
			return nil, nil, err
		}
		hash := sha256.Sum256(c.Raw)
		if bytes.Equal(hash[:], v.Fingerprint) {
			if leaf != nil {
				return nil, nil, errors.New("duplicate signer")
			}
			leaf = c
		} else {
			extra = append(extra, c)
		}
	}
	if leaf == nil || si.Version != 1 || si.SID.Serial == nil || si.SID.Serial.Cmp(leaf.SerialNumber) != 0 || !bytes.Equal(si.SID.Issuer.FullBytes, leaf.RawIssuer) {
		return nil, nil, errors.New("unknown CMS signer")
	}
	a, err := objectAlgorithm(leaf.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	attrs, tag := a.attributes(payload)
	expected, _ := asn1.Marshal(tag)
	digest := a.digestID().Algorithm
	if !validAlg(si.Digest, digest) || !validAlg(s.Digests[0], digest) {
		return nil, nil, errors.New("invalid CMS digest")
	}
	params := si.Algorithm.Parameters.FullBytes
	nullRSA := a.signature == x509.SHA256WithRSA && bytes.Equal(params, asn1.NullBytes)
	if !si.Algorithm.Algorithm.Equal(a.oid) || len(params) != 0 && !nullRSA {
		return nil, nil, errors.New("invalid CMS signature algorithm")
	}
	if !bytes.Equal(si.Attrs.FullBytes, expected) {
		return nil, nil, errors.New("invalid signed attributes")
	}
	if err := leaf.CheckSignature(a.signature, attrs, si.Signature); err != nil {
		return nil, nil, err
	}
	return v.Body, append([]*x509.Certificate{leaf}, extra...), nil
}

// VerifyObjectSigner verifies the node identity and grant attached to a signed mesh object.
// Pass certificates returned by VerifyObjectSignature. Apply host policy to both paths
// and check the returned identity against the publisher authorized for the operation.
func VerifyObjectSigner(certs []*x509.Certificate, root *x509.Certificate, cluster Cluster, now time.Time) (Identity, []*x509.Certificate, [][]*x509.Certificate, error) {
	if len(certs) < 2 {
		return Identity{}, nil, nil, errors.New("missing signed membership evidence")
	}
	var node *x509.Certificate
	grant := []*x509.Certificate{certs[0]}
	for _, c := range certs[1:] {
		switch {
		case c == nil:
			return Identity{}, nil, nil, errors.New("nil signer evidence")
		case c.IsCA:
			grant = append(grant, c)
		case node == nil:
			node = c
		default:
			return Identity{}, nil, nil, errors.New("ambiguous node identity")
		}
	}
	peer, err := VerifyNode(node, root, x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		return Identity{}, nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	id, paths, err := verifyGrantIdentity(grant, roots, cluster, peer, now)
	if err != nil {
		return Identity{}, nil, nil, err
	}
	return id, []*x509.Certificate{node, root}, paths, nil
}
