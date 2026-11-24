package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.d7z.net/d7z-team/nebula"
	"code.d7z.net/d7z-team/nebula/examples/demo"

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
	alice.Topics, bob.Topics = []string{"app/peer/receipt"}, []string{"app/peer/request"}
	opts, err := demo.NodeOptions(alice, bob)
	require.NoError(t, err)
	dir := t.TempDir()
	writePEM := func(file, kind string, der []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
	}
	writePEM("ca.pem", "CERTIFICATE", opts[0].ClusterCA.Raw)
	for i, name := range []string{"alice", "bob"} {
		pair := opts[i].Certificates.Client
		key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
		require.NoError(t, err)
		writePEM(name+".pem", "CERTIFICATE", pair.Certificate[0])
		writePEM(name+".key", "PRIVATE KEY", key)
	}
	writeView := func(view nebula.Topology) {
		t.Helper()
		data, err := json.Marshal(view)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "topology.json"), data, 0o600))
	}
	writeView(opts[0].Topology)
	exe, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, exe, "--", "-cert", "alice.pem", "-key", "alice.key", "-peer", bob.IPv6.String())
	server.Dir, server.Stderr = dir, os.Stderr
	stdout, err := server.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, server.Start())
	defer func() { cancel(); _ = server.Wait() }()
	lines := bufio.NewScanner(stdout)
	require.True(t, lines.Scan(), "server exited before announcing its UDP port")
	fields := strings.Fields(lines.Text())
	require.Len(t, fields, 5)
	address, err := netip.ParseAddrPort(fields[2])
	require.NoError(t, err)
	view := opts[1].Topology
	view.Members[0].Endpoints = []nebula.Endpoint{{Network: "udp", Address: address}}
	writeView(view)
	client := exec.CommandContext(ctx, exe, "--", "-cert", "bob.pem", "-key", "bob.key", "-peer", alice.IPv4.String(), "-send", "hello")
	client.Dir = dir
	out, err := client.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.Regexp(t, `receipt from 10\.13\.0\.1@fd13::1 for [0-9a-f]{64}`, string(out))
	require.True(t, lines.Scan())
	require.Equal(t, `request from 10.13.0.2@fd13::2: "hello"`, lines.Text())
}
