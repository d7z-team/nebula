package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.d7z.net/nebula/examples/demo"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Run the actual command in a child process, including under -race.
	if len(os.Args) > 1 && os.Args[1] == "--" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		main()
		return
	}
	os.Exit(m.Run())
}

func TestPeerProcesses(t *testing.T) {
	alice, bob := demo.NewHost(1), demo.NewHost(2)
	opts, err := demo.NodeOptions(alice, bob)
	require.NoError(t, err)
	dir := t.TempDir()
	writePEM := func(file, kind string, der []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
	}
	writePEM("root.pem", "CERTIFICATE", opts[0].Auth.RootCA.Raw)
	writePEM("ca.pem", "CERTIFICATE", opts[0].Auth.ClusterCA.Raw)
	for i, name := range []string{"alice", "bob"} {
		var chain []byte
		for _, der := range opts[i].Auth.Certificates.Grant {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".grant"), chain, 0o600))
		pair := opts[i].Auth.Certificates.Node
		key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
		require.NoError(t, err)
		writePEM(name+".pem", "CERTIFICATE", pair.Certificate[0])
		writePEM(name+".key", "PRIVATE KEY", key)
	}
	data, err := json.Marshal(opts[0].Topology)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "topology.json"), data, 0o600))
	exe, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, config, want string
	}{
		{"unknown member field", strings.Replace(string(data), `"id"`, `"restrictd":true,"id"`, 1), `unknown field "restrictd"`},
		{"second value", string(data) + "\n{}", "unexpected data after topology"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "invalid.json"), []byte(tc.config), 0o600))
			cmd := exec.CommandContext(ctx, exe, "--", "-grant", "alice.grant", "-cert", "alice.pem", "-key", "alice.key", "-topology", "invalid.json")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(out), "invalid.json: ")
			require.Contains(t, string(out), tc.want)
		})
	}
	server := exec.CommandContext(ctx, exe, "--", "-grant", "alice.grant", "-cert", "alice.pem", "-key", "alice.key")
	server.Dir, server.Stderr = dir, os.Stderr
	stdout, err := server.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, server.Start())
	defer func() { cancel(); _ = server.Wait() }()
	lines := bufio.NewScanner(stdout)
	require.True(t, lines.Scan(), "server exited before announcing its UDP port")
	fields := strings.Fields(lines.Text())
	require.Len(t, fields, 5)
	address := fields[2]
	lookup := exec.CommandContext(ctx, exe, "--", "-grant", "bob.grant", "-cert", "bob.pem", "-key", "bob.key", "-connect", address, "-resolve", alice.IPv6.String())
	lookup.Dir = dir
	out, err := lookup.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.Contains(t, string(out), "fd13::1 via "+alice.ID.String()+" (fd13::1/128)")
	require.Contains(t, string(out), "connected to "+alice.ID.String()+" at "+address)
}
