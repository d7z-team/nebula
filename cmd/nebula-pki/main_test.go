package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOfflinePKI(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", "")
	command := func(args ...string) string {
		t.Helper()
		var b bytes.Buffer
		require.NoError(t, run(args, nil, &b, &b), "%v", args)
		return b.String()
	}
	command("keygen", "-algorithm", "rsa", "-out", "ca.key")
	command("root", "-name", "Test CA", "-key", "ca.key", "-path-len", "1", "-signature-algorithm", "SHA384-RSAPSS", "-out", "ca.pem")
	require.Contains(t, command("inspect", "-in", "ca.pem"), "signature=SHA384-RSAPSS")
	err := run([]string{"root", "-name", "Mismatched signer", "-key", "ca.key", "-signature-algorithm", "Ed25519"}, nil, io.Discard, io.Discard)
	require.Error(t, err)
	command("keygen", "-out", "issuer.key")
	command("request", "-key", "issuer.key", "-out", "issuer.csr")
	issuerHash := strings.TrimSpace(command("inspect", "-in", "issuer.csr", "-fingerprint"))
	issuer := command("issue", "-role", "ca", "-signature-algorithm", "SHA256-RSAPSS", "-name", "Lab CA", "-in", "issuer.csr", "-approved-key", issuerHash,
		"-ca", "ca.pem", "-ca-key", "ca.key", "-network", "lab", "-routes", "192.0.2.0/24", "-cluster", "-anycast-pools", "10.0.0.128/26", "-permit-ips", "10.0.0.0/24,fd42::/64")
	require.NoError(t, os.WriteFile("issuer.pem", []byte(issuer), 0o600))
	caDetails := command("inspect", "-in", "issuer.pem")
	require.Contains(t, caDetails, "publicKey=Ed25519 signature=SHA256-RSAPSS")
	require.Contains(t, caDetails, "memberIPv4=10.0.0.0/24 memberIPv6=fd42::/64")
	command("keygen", "-out", "node.key")
	command("request", "-key", "node.key", "-name", "client", "-out", "node.csr")
	hash := strings.TrimSpace(command("inspect", "-in", "node.csr", "-fingerprint"))
	for _, role := range []string{"grant", "ca"} {
		err := run([]string{
			"issue", "-role", role, "-in", "node.csr", "-approved-key", issuerHash,
			"-name", "node", "-ca", "ca.pem", "-ca-key", "ca.key", "-network", "lab",
			"-ipv4", "10.0.0.1", "-ipv6", "fd42::1",
		}, nil, io.Discard, io.Discard)
		require.ErrorContains(t, err, "fingerprint")
	}
	command("issue", "-role", "node", "-in", "node.csr", "-approved-key", hash, "-ca", "ca.pem", "-ca-key", "ca.key", "-out", "node.pem")
	command("verify", "-peer", hash, "-root", "ca.pem", "-in", "node.pem")
	leaf := command("issue", "-role", "grant", "-in", "node.csr", "-name", "node", "-approved-key", hash, "-ca", "issuer.pem", "-ca-key", "issuer.key",
		"-network", "lab", "-anycast-ips", "10.0.0.130,10.0.0.131", "-routes", "192.0.2.0/25", "-ipv4", "10.0.0.1", "-ipv6", "fd42::1")
	require.NoError(t, os.WriteFile("chain.pem", []byte(leaf+issuer), 0o600))
	details := command("inspect", "-in", "chain.pem")
	require.Contains(t, details, "routes=[192.0.2.0/25]")
	require.Contains(t, details, "anycastIPs=[10.0.0.130 10.0.0.131]")
	require.Contains(t, command("verify", "-role", "grant", "-peer", hash, "-root", "ca.pem", "-cluster-ca", "issuer.pem", "-in", "chain.pem"), "node")
}

func TestHelp(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-h"}, "keygen|root|request|issue|inspect|verify"},
		{[]string{"issue", "-h"}, "-approved-key"},
	} {
		var b bytes.Buffer
		require.NoError(t, run(tc.args, nil, &b, &b))
		require.Contains(t, b.String(), tc.want)
	}
	var b bytes.Buffer
	require.Error(t, run([]string{"issue", "-unknown"}, nil, &b, &b))
}
