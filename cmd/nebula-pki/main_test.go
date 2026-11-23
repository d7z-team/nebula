package main

import (
	"bytes"
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
	command("keygen", "-algorithm", "p256", "-out", "ca.key")
	command("root", "-name", "Test CA", "-key", "ca.key", "-path-len", "1", "-out", "ca.pem")
	command("keygen", "-out", "issuer.key")
	command("request", "-key", "issuer.key", "-out", "issuer.csr")
	issuerHash := strings.TrimSpace(command("inspect", "-in", "issuer.csr", "-fingerprint"))
	issuer := command("issue", "-role", "ca", "-name", "Lab CA", "-in", "issuer.csr", "-approved-key", issuerHash,
		"-ca", "ca.pem", "-ca-key", "ca.key", "-network", "lab", "-routes", "192.0.2.0/24", "-permit-ips", "10.0.0.0/24,fd42::/64")
	require.NoError(t, os.WriteFile("issuer.pem", []byte(issuer), 0o600))
	command("keygen", "-out", "node.key")
	command("request", "-key", "node.key", "-name", "client", "-out", "node.csr")
	hash := strings.TrimSpace(command("inspect", "-in", "node.csr", "-fingerprint"))
	leaf := command("issue", "-in", "node.csr", "-name", "node", "-approved-key", hash, "-ca", "issuer.pem", "-ca-key", "issuer.key",
		"-network", "lab", "-routes", "192.0.2.0/25", "-ipv4", "10.0.0.1", "-ipv6", "fd42::1")
	require.NoError(t, os.WriteFile("chain.pem", []byte(leaf+issuer), 0o600))
	require.Contains(t, command("inspect", "-in", "chain.pem"), "routes=[192.0.2.0/25]")
	require.Contains(t, command("verify", "-roots", "ca.pem", "-network", "lab", "-ipv4", "10.0.0.1", "-ipv6", "fd42::1", "-in", "chain.pem"), "node")
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
