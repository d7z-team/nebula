// Command nebula-pki manages keys, certificate requests and X.509 certificates offline.
package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.d7z.net/nebula/pki"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
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
		defer f.Close() //nolint:errcheck // The input file is read-only.
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	err = errors.Join(err, f.Close())
	if err != nil {
		return errors.Join(err, os.Remove(path))
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
	return pki.ParseCertificatesPEM(b)
}

func run(args []string, in io.Reader, out, diagnostics io.Writer) error {
	const usage = "usage: nebula-pki {keygen|root|request|issue|inspect|verify} [flags]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, err := fmt.Fprintln(out, usage)
		return err
	}
	op := args[0]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	var key, caFile, caKey, src, dst, alg, name, role, approved, rootFile, pin string
	var peer pki.PeerID
	var v4, v6 netip.Addr
	var scope pki.Scope
	var profile pki.CAProfile
	var days int
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
		fs.Func("anycast-ips", "exact service addresses for a leaf", listFlag(&scope.AnycastIPs, netip.ParseAddr))
		fs.StringVar(&scope.Network, "network", "", "mesh network")
		fs.BoolVar(&scope.Cluster, "cluster", false, "define the cluster address plan on this CA")
		fs.Func("routes", "routed traffic a leaf may carry or a CA may delegate (including /0)", listFlag(&scope.RoutedPrefixes, netip.ParsePrefix))
		fs.Func("anycast-pools", "delegated service prefixes for a CA", listFlag(&scope.AnycastPools, netip.ParsePrefix))
		fs.Func("permit-ips", "cluster: one IPv4 and one IPv6 member prefix; subordinate issuer: delegated ranges for both families", listFlag(&profile.PermittedIPs, netip.ParsePrefix))
		fs.TextVar(&v4, "ipv4", netip.Addr{}, "overlay IPv4 address")
		fs.TextVar(&v6, "ipv6", netip.Addr{}, "overlay IPv6 address")
	case "inspect":
		fs.BoolVar(&fingerprint, "fingerprint", false, "print the SPKI SHA-256 digest")
	case "verify":
		fs.TextVar(&peer, "peer", pki.PeerID{}, "expected SPKI fingerprint")
		fs.StringVar(&pin, "cluster-ca", "", "pinned cluster CA PEM certificate")
		fs.StringVar(&rootFile, "root", "", "ordinary root certificate")
	default:
		return fmt.Errorf("unknown command %q", op)
	}
	if op == "root" || op == "issue" {
		fs.IntVar(&days, "days", 30, "validity in days")
		fs.IntVar(&profile.MaxPathLen, "path-len", 0, "allowed intermediate CA depth")
		fs.Func("signature-algorithm", "CA certificate signature (e.g. SHA256-RSAPSS); default chosen by crypto/x509 for the issuer key", func(name string) error {
			for _, alg := range []x509.SignatureAlgorithm{
				x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
				x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
				x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
				x509.PureEd25519, x509.MLDSA44, x509.MLDSA65, x509.MLDSA87,
			} {
				if strings.EqualFold(name, alg.String()) {
					profile.SignatureAlgorithm = alg
					return nil
				}
			}
			return fmt.Errorf("unknown CA signature algorithm %q", name)
		})
	}
	if op == "issue" || op == "verify" {
		fs.StringVar(&role, "role", "node", "node, grant or ca (issue only)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if op == "issue" && role != "ca" && profile.SignatureAlgorithm != 0 {
		return errors.New("-signature-algorithm requires -role ca")
	}
	now := time.Now().UTC().Truncate(time.Second)
	var data []byte
	var label string
	profile.Subject = pkix.Name{CommonName: name}
	profile.NotBefore, profile.NotAfter = now, now.AddDate(0, 0, days)
	if scope.Network != "" || scope.Cluster || len(scope.RoutedPrefixes)+len(scope.AnycastPools)+len(scope.AnycastIPs) != 0 {
		profile.Scope = &scope
	}
	var err error
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
		c, err := issueCertificate(ca, b, profile, pki.Addresses{IPv4: v4, IPv6: v6}, approved, role)
		if err != nil {
			return err
		}
		data, label = c.Raw, "CERTIFICATE"
	case "verify":
		cs, e := readChain(rootFile)
		if e != nil {
			return e
		}
		if len(cs) != 1 || peer == (pki.PeerID{}) {
			return errors.New("one ordinary root and -peer required")
		}
		b, e := input(src, in)
		if e != nil {
			return e
		}
		chain, e := pki.ParseCertificatesPEM(b)
		if e != nil {
			return e
		}
		switch role {
		case "node":
			if len(chain) != 1 {
				return errors.New("one node leaf required")
			}
			for _, u := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
				id, err := pki.VerifyNode(chain[0], cs[0], u, now)
				if err != nil {
					return err
				}
				if id != peer {
					return errors.New("unexpected node key")
				}
			}
		case "grant":
			pins, err := readChain(pin)
			if err != nil {
				return err
			}
			if len(pins) != 1 || pins[0].CheckSignatureFrom(cs[0]) != nil {
				return errors.New("root-issued cluster CA required")
			}
			cluster, err := pki.ReadClusterCA(pins[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(cs[0])
			if _, err = pki.VerifyGrant(chain, pool, cluster, peer, now); err != nil {
				return err
			}
		default:
			return errors.New("unknown verification role")
		}
		data = fmt.Appendf(nil, "%s peer=%s role=%s\n", chain[0].Subject, peer, role)
	case "inspect":
		b, e := input(src, in)
		if e != nil {
			return e
		}
		data, err = inspect(b, fingerprint)
	}
	if err != nil {
		return err
	}
	if label != "" {
		data = pem.EncodeToMemory(&pem.Block{Type: label, Bytes: data})
	}
	return save(dst, data, out)
}

func listFlag[T any](dst *[]T, parse func(string) (T, error)) func(string) error {
	return func(list string) error {
		var values []T
		if list != "" {
			for value := range strings.SplitSeq(list, ",") {
				v, err := parse(value)
				if err != nil {
					return err
				}
				values = append(values, v)
			}
		}
		*dst = values
		return nil
	}
}

func issueCertificate(ca pki.Issuer, request []byte, profile pki.CAProfile, addr pki.Addresses, approved, role string) (*x509.Certificate, error) {
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
	var approvedKeyHash pki.PeerID
	if err := approvedKeyHash.UnmarshalText([]byte(approved)); err != nil {
		return nil, errors.New("-approved-key requires a hex-encoded SHA-256 SPKI fingerprint")
	}
	switch role {
	case "ca":
		return ca.IssueCA(csr, profile, approvedKeyHash)
	case "node":
		if profile.Scope != nil || len(profile.PermittedIPs) > 0 || addr.IPv4.IsValid() || addr.IPv6.IsValid() {
			return nil, errors.New("node certificate takes no network settings")
		}
		return ca.IssueNode(csr, approvedKeyHash, profile.NotBefore, profile.NotAfter)
	case "grant":
		if len(profile.PermittedIPs) > 0 {
			return nil, errors.New("-permit-ips requires a CA")
		}
		if profile.Scope == nil {
			return nil, errors.New("-network is required for a grant")
		}
		return ca.IssueGrant(csr, pki.Enrollment{
			Name: profile.Subject.CommonName, IPv4: addr.IPv4, IPv6: addr.IPv6, Scope: *profile.Scope,
			NotBefore: profile.NotBefore, NotAfter: profile.NotAfter, PublicKeyHash: approvedKeyHash,
		})
	default:
		return nil, errors.New("unknown certificate role")
	}
}

func inspect(b []byte, fingerprint bool) ([]byte, error) {
	block, _ := pem.Decode(b)
	if block != nil {
		b = block.Bytes
	}
	var spki []byte
	var detail string
	if c, e := x509.ParseCertificate(b); e == nil {
		spki = c.RawSubjectPublicKeyInfo
		detail = fmt.Sprintf("certificate subject=%s issuer=%s serial=%s expires=%s publicKey=%s signature=%s", c.Subject, c.Issuer, c.SerialNumber, c.NotAfter, c.PublicKeyAlgorithm, c.SignatureAlgorithm)
		if c.IsCA {
			scope, present, err := pki.CertificateScope(c)
			if err != nil {
				return nil, err
			}
			if present {
				detail += fmt.Sprintf(" network=%s cluster=%t routes=%v anycastPools=%v", scope.Network, scope.Cluster, scope.RoutedPrefixes, scope.AnycastPools)
			}
			if scope.Cluster {
				plan, err := pki.ReadClusterCA(c)
				if err != nil {
					return nil, err
				}
				v4, v6 := plan.MemberPrefixes()
				detail += fmt.Sprintf(" memberIPv4=%s memberIPv6=%s", v4, v6)
			} else {
				detail += fmt.Sprintf(" permittedIPs=%v", c.PermittedIPRanges)
			}
		} else if len(c.IPAddresses) > 0 {
			identity, err := pki.ReadIdentity(c)
			if err != nil {
				return nil, err
			}
			detail += fmt.Sprintf(" network=%s peer=%s ipv4=%s ipv6=%s routes=%v anycastIPs=%v", identity.Network, identity.ID, identity.IPv4, identity.IPv6, identity.RoutedPrefixes, identity.AnycastIPs)
		}
	} else if r, e := x509.ParseCertificateRequest(b); e == nil {
		spki = r.RawSubjectPublicKeyInfo
		detail = "CSR " + r.Subject.String()
	} else if k, e := x509.ParsePKCS8PrivateKey(b); e == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported key")
		}
		spki, e = x509.MarshalPKIXPublicKey(signer.Public())
		if e != nil {
			return nil, e
		}
		detail = "private key"
	} else if _, e := x509.ParsePKIXPublicKey(b); e == nil {
		spki = b
		detail = "public key"
	} else {
		return nil, errors.New("unrecognized certificate, CSR, or key")
	}
	if fingerprint {
		return fmt.Appendf(nil, "%x\n", sha256.Sum256(spki)), nil
	}
	return fmt.Appendf(nil, "%s SPKI-SHA256=%x\n", detail, sha256.Sum256(spki)), nil
}
