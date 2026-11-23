// Command nebula-config signs a complete JSON network configuration offline.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/control"
)

func main() {
	ca := flag.String("ca", "ca.crt", "configuration CA certificate")
	key := flag.String("key", "ca.key", "configuration CA signing key")
	flag.Parse()
	if err := run(*ca, *key); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(caFile, keyFile string) error {
	b, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	ca, _, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return err
	}
	b, err = os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	key, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(b)
	if err != nil {
		return err
	}
	var signer crypto.Signer
	switch curve {
	case cert.Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return errors.New("invalid Ed25519 key")
		}
		signer = ed25519.PrivateKey(key)
	case cert.Curve_P256:
		signer, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported signing key")
	}
	b, err = io.ReadAll(io.LimitReader(os.Stdin, control.MaxDocument+1))
	if err != nil {
		return err
	}
	if len(b) > control.MaxDocument {
		return errors.New("oversized configuration")
	}
	var cfg control.Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data")
	}
	wire, err := control.Sign(cfg, ca, signer)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(wire)
	return err
}
