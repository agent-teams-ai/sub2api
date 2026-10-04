//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/gatewaylauncher"
)

// The command adds a JSON boundary absent from launcher/bootstrap tests.
// A numeric token here silently rounds process birth/inode identities in Node.
// Observe the actual output bytes through a pipe, with values above 2^53.
func TestEmittedBindingPreservesKernelIdentity(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	binding := gatewaylauncher.Binding{
		OriginRef: "native-origin-1", BootID: "boot-identity", Incarnation: "incarnation-identity",
		PID: 123, BirthTicks: 9007199254740993, LockDevice: 18446744073709551615,
		LockInode: 9007199254740995,
	}
	if err = emit(w, "ready", binding, "", nil); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		State   string            `json:"state"`
		Binding map[string]string `json:"binding"`
		Receipt json.RawMessage   `json:"receipt"`
	}
	// Decoding directly to strings also rejects every JSON numeric token.
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"originRef": "native-origin-1", "bootId": "boot-identity", "incarnation": "incarnation-identity",
		"pid": "123", "birthTicks": "9007199254740993", "lockDevice": "18446744073709551615",
		"lockInode": "9007199254740995",
	}
	if got.State != "ready" || len(got.Receipt) != 0 || len(got.Binding) != len(want) {
		t.Fatalf("unexpected metadata shape: %s", data)
	}
	for key, value := range want {
		if got.Binding[key] != value {
			t.Fatalf("%s: got %q, want %q", key, got.Binding[key], value)
		}
	}
}

// FD 2 is special in Go: a broken diagnostic pipe can terminate the actual
// executable with SIGPIPE before its fixed bootstrap-failure exit is returned.
// Use the real command, with no inherited authority/config or fixture hooks.
func TestClosedDiagnosticPipeReturnsBootstrapFailure(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "account-gateway")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goBinary, "build", "-o", binary, ".")
	build.Env = []string{
		"GOTOOLCHAIN=local", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off",
		"GOFLAGS=-mod=readonly -buildvcs=false", "PATH=" + filepath.Dir(goBinary) + ":/usr/bin:/bin",
	}
	// Only existing compiler/cache paths; never copy ambient credential env.
	for _, name := range []string{"HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR"} {
		if value := os.Getenv(name); value != "" {
			build.Env = append(build.Env, name+"="+value)
		}
	}
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual command: %v\n%s", err, output)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "--engine")
	child.Env = []string{}
	child.Stderr = w // Actual child FD 2, with every read endpoint already closed.
	err = child.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("closed diagnostic pipe bypassed bootstrap failure exit: %v", err)
	}
}
