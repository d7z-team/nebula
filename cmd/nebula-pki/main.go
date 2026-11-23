// Command nebula-pki manages keys, certificate requests and X.509 certificates offline.
package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"code.d7z.net/d7z-team/nebula/pki"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func input(path string, in io.Reader) ([]byte, error) {
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		in = f
	}
	b, err := io.ReadAll(io.LimitReader(in, (4<<20)+1))
	if len(b) > (4 << 20) {
		return nil, errors.New("oversized input")
	}
	return b, err
}
func save(path string, b []byte, out io.Writer) error {
	if path == "-" {
		_, err := out.Write(b)
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	err = errors.Join(err, f.Close())
	if err != nil {
		os.Remove(path)
	}
	return err
}
func readKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pki.ParseKeyPEM(b)
}
func readChain(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pki.ParseCertificates(b)
}

func run(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: nebula-pki {keygen|root|request|issue|inspect|verify} [flags]")
	}
	op := args[0]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	var key, caFile, caKey, src, dst, alg, name, network, ipv4, ipv6, routed, permitted, role, approved, roots string
	var days, pathLen int
	var fingerprint bool
	fs.StringVar(&src, "in", "-", "input path or stdin")
	fs.StringVar(&dst, "out", "-", "new output file or stdout")
	switch op {
	case "keygen":
		fs.StringVar(&alg, "algorithm", "ed25519", "ed25519, p256, rsa or ml-dsa-44")
	case "root", "request":
		fs.StringVar(&key, "key", "", "local PKCS#8 private key")
		fs.StringVar(&name, "name", "", "subject common name")
	case "issue":
		fs.StringVar(&caFile, "ca", "", "issuing CA PEM chain")
		fs.StringVar(&caKey, "ca-key", "", "issuing CA key")
		fs.StringVar(&name, "name", "", "approved subject common name")
		fs.StringVar(&approved, "approved-key", "", "approved SHA-256 SPKI in hex")
	case "inspect":
		fs.BoolVar(&fingerprint, "fingerprint", false, "print the SPKI SHA-256 digest")
	case "verify":
		fs.StringVar(&roots, "roots", "", "trusted root PEM bundle")
	default:
		return fmt.Errorf("unknown command %q", op)
	}
	if op == "root" || op == "issue" {
		fs.IntVar(&days, "days", 30, "validity in days")
		fs.IntVar(&pathLen, "path-len", 0, "allowed intermediate CA depth")
		fs.StringVar(&routed, "routes", "", "approved routed prefixes, comma separated")
		fs.StringVar(&permitted, "permit-ips", "", "permitted IP SAN ranges for a CA")
	}
	if op == "issue" || op == "verify" || op == "root" {
		fs.StringVar(&network, "network", "", "mesh network")
	}
	if op == "issue" || op == "verify" {
		fs.StringVar(&ipv4, "ipv4", "", "overlay IPv4 address")
		fs.StringVar(&ipv6, "ipv6", "", "overlay IPv6 address")
		fs.StringVar(&role, "role", "node", "node, server, client, object or ca (issue only)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	now := time.Now().UTC().Truncate(time.Second)
	var data []byte
	var label string
	profile := pki.CAProfile{Subject: pkix.Name{CommonName: name}, NotBefore: now, NotAfter: now.AddDate(0, 0, days), MaxPathLen: pathLen}
	if network != "" || routed != "" {
		routes, err := parsePrefixes(routed)
		if err != nil {
			return err
		}
		profile.Scope = &pki.Scope{Network: network, RoutedPrefixes: routes}
	}
	var err error
	if profile.PermittedIPs, err = parsePrefixes(permitted); err != nil {
		return err
	}
	var peer pki.PeerID
	if op == "verify" || op == "issue" && role != "ca" {
		if permitted != "" {
			return errors.New("-permit-ips requires a CA")
		}
		v4, err := netip.ParseAddr(ipv4)
		if err != nil {
			return err
		}
		v6, err := netip.ParseAddr(ipv6)
		if err != nil {
			return err
		}
		peer, err = pki.NewPeerID(v4, v6)
		if err != nil {
			return err
		}
	}
	switch op {
	case "keygen":
		if dst == "-" {
			return errors.New("specify -out for private key")
		}
		k, e := pki.GenerateKey(alg)
		if e != nil {
			return e
		}
		data, err = x509.MarshalPKCS8PrivateKey(k)
		label = "PRIVATE KEY"
	case "root":
		k, e := readKey(key)
		if e != nil {
			return e
		}
		c, e := pki.CreateRoot(k, profile)
		if e != nil {
			return e
		}
		data, label = c.Raw, "CERTIFICATE"
	case "request":
		k, e := readKey(key)
		if e != nil {
			return e
		}
		csr, err := pki.CreateCSR(k, pkix.Name{CommonName: name})
		if err != nil {
			return err
		}
		data, label = csr.Raw, "CERTIFICATE REQUEST"
	case "issue":
		chain, e := readChain(caFile)
		if e != nil {
			return e
		}
		k, e := readKey(caKey)
		if e != nil {
			return e
		}
		ca := pki.Issuer{Chain: chain, Signer: k}
		if profile.NotAfter.After(chain[0].NotAfter) {
			profile.NotAfter = chain[0].NotAfter
		}
		b, e := input(src, in)
		if e != nil {
			return e
		}
		c, err := issueCertificate(ca, b, profile, peer, approved, role)
		if err != nil {
			return err
		}
		data, label = c.Raw, "CERTIFICATE"
	case "verify":
		cs, e := readChain(roots)
		if e != nil {
			return e
		}
		pool := x509.NewCertPool()
		for _, c := range cs {
			pool.AddCert(c)
		}
		b, e := input(src, in)
		if e != nil {
			return e
		}
		chain, e := pki.ParseCertificates(b)
		if e != nil {
			return e
		}
		purposes, e := usages(role)
		if e != nil {
			return e
		}
		for _, u := range purposes {
			if _, e = pki.VerifyChain(chain, pool, network, peer, u, now); e != nil {
				return e
			}
		}
		data = fmt.Appendf(nil, "%s network=%s peer=%s\n", chain[0].Subject, network, peer)
	case "inspect":
		b, e := input(src, in)
		if e != nil {
			return e
		}
		var result bytes.Buffer
		if err := inspect(b, fingerprint, &result); err != nil {
			return err
		}
		data = result.Bytes()
	}
	if err != nil {
		return err
	}
	if label != "" {
		data = pem.EncodeToMemory(&pem.Block{Type: label, Bytes: data})
	}
	return save(dst, data, out)
}

func parsePrefixes(list string) ([]netip.Prefix, error) {
	if list == "" {
		return nil, nil
	}
	var prefixes []netip.Prefix
	for value := range strings.SplitSeq(list, ",") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func usages(role string) ([]x509.ExtKeyUsage, error) {
	switch role {
	case "node":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}, nil
	case "server":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil
	case "client":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	case "object":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, nil
	}
	return nil, errors.New("unknown certificate purpose")
}

func issueCertificate(ca pki.Issuer, request []byte, profile pki.CAProfile, peer pki.PeerID, approved, role string) (*x509.Certificate, error) {
	if bytes.HasPrefix(bytes.TrimSpace(request), []byte("-----BEGIN ")) {
		block, rest := pem.Decode(request)
		if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("expected one CERTIFICATE REQUEST")
		}
		request = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(request)
	if err != nil {
		return nil, err
	}
	hash, err := hex.DecodeString(approved)
	sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if err != nil || !bytes.Equal(hash, sum[:]) {
		return nil, errors.New("CSR does not match -approved-key")
	}
	if role == "ca" {
		return ca.IssueCA(csr, profile)
	}
	purposes, err := usages(role)
	if err != nil {
		return nil, err
	}
	if profile.Scope == nil {
		return nil, errors.New("-network is required for a leaf certificate")
	}
	return ca.IssueLeaf(csr, pki.Enrollment{
		Name: profile.Subject.CommonName, IPv4: peer.IPv4(), IPv6: peer.IPv6(), Scope: *profile.Scope,
		NotBefore: profile.NotBefore, NotAfter: profile.NotAfter, PublicKeyHash: sum, Usages: purposes,
	})
}

func inspect(b []byte, fingerprint bool, out io.Writer) error {
	block, _ := pem.Decode(b)
	if block != nil {
		b = block.Bytes
	}
	var pub crypto.PublicKey
	var detail string
	if c, e := x509.ParseCertificate(b); e == nil {
		pub = c.PublicKey
		detail = fmt.Sprintf("certificate subject=%s issuer=%s serial=%s expires=%s", c.Subject, c.Issuer, c.SerialNumber, c.NotAfter)
		if c.IsCA {
			scope, present, err := pki.CertificateScope(c)
			if err != nil {
				return err
			}
			if present {
				detail += fmt.Sprintf(" network=%s routes=%v", scope.Network, scope.RoutedPrefixes)
			}
			detail += fmt.Sprintf(" permittedIPs=%v", c.PermittedIPRanges)
		} else {
			identity, err := pki.ReadIdentity(c)
			if err != nil {
				return err
			}
			detail += fmt.Sprintf(" network=%s peer=%s routes=%v", identity.Network, identity.ID, identity.RoutedPrefixes)
		}
	} else if r, e := x509.ParseCertificateRequest(b); e == nil {
		pub = r.PublicKey
		detail = "CSR " + r.Subject.String()
	} else if k, e := x509.ParsePKCS8PrivateKey(b); e == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return errors.New("unsupported key")
		}
		pub = signer.Public()
		detail = "private key"
	} else if k, e := x509.ParsePKIXPublicKey(b); e == nil {
		pub = k
		detail = "public key"
	} else {
		return errors.New("unrecognized certificate, CSR, or key")
	}
	spki, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return e
	}
	if fingerprint {
		_, e = fmt.Fprintf(out, "%x\n", sha256.Sum256(spki))
	} else {
		_, e = fmt.Fprintf(out, "%s SPKI-SHA256=%x\n", detail, sha256.Sum256(spki))
	}
	return e
}
