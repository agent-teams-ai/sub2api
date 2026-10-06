//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
	binary := buildGatewayCommand(t)
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

func buildGatewayCommand(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "account-gateway")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("NOT_RUN: existing qualified Go compiler unavailable")
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
	return binary
}

func retirementRequest(t *testing.T, current gatewaylauncher.Binding, selectors []gatewaylauncher.RetirementSelector) string {
	t.Helper()
	data, err := json.Marshal(retirementInput{outputBinding(current), selectors})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestStrictRetirementInput(t *testing.T) {
	b := gatewaylauncher.Binding{OriginRef: "disposable-origin", BootID: "12345678-1234-4234-8234-123456789abc",
		Incarnation: "23456789-1234-4234-8234-123456789abc", PID: 123,
		BirthTicks: 9007199254740993, LockDevice: 18446744073709551615, LockInode: 9007199254740995}
	selector := gatewaylauncher.RetirementSelector{OriginRef: b.OriginRef, EngineIncarnation: "34567890-1234-4234-8234-123456789abc"}
	request := retirementRequest(t, b, []gatewaylauncher.RetirementSelector{selector})
	for _, data := range []string{request, strings.Replace(request, `"current"`, `"\u0063urrent"`, 1), request + strings.Repeat(" ", retirementBytes-len(request))} {
		got, selectors, err := parseRetirement(strings.NewReader(data))
		if err != nil || got != b || len(selectors) != 1 || selectors[0] != selector {
			t.Fatal("canonical/escaped/bounded input lost full decimal identity", err)
		}
	}
	bad := map[string]string{
		"duplicate-decoded": strings.Replace(request, `"current":`, `"current":null,"\u0063urrent":`, 1),
		"case-alias": strings.Replace(request, `"current"`, `"Current"`, 1),
		"nested-duplicate": strings.Replace(request, `"pid":"123"`, `"pid":"123","\u0070id":"123"`, 1),
		"nested-case": strings.Replace(request, `"birthTicks"`, `"BirthTicks"`, 1),
		"selector-duplicate": strings.Replace(request, `"engineIncarnation":`, `"engineIncarnation":"unused","engineIncarnation":`, 1),
		"selector-case": strings.Replace(request, `"engineIncarnation"`, `"EngineIncarnation"`, 1),
		"unknown": strings.Replace(request, `"current":`, `"authorityDir":"unused","current":`, 1),
		"nested-unknown": strings.Replace(request, `"pid":"123"`, `"pid":"123","path":"unused"`, 1),
		"misplaced-known-field": strings.Replace(request, `"pid":"123"`, `"pid":"123","engineIncarnation":"unused"`, 1),
		"trailing": request + `{}`,
		"truncated": request[:len(request)-1],
		"oversize": request + strings.Repeat(" ", retirementBytes+1-len(request)),
		"null-current": `{"current":null,"selectors":[{"originRef":"disposable-origin","engineIncarnation":"34567890-1234-4234-8234-123456789abc"}]}`,
		"empty-selectors": retirementRequest(t, b, []gatewaylauncher.RetirementSelector{}),
		"three-selectors": retirementRequest(t, b, []gatewaylauncher.RetirementSelector{selector, selector, selector}),
		"invalid-utf8": strings.Replace(request, "disposable-origin", string([]byte{0xff}), 1),
	}
	for _, value := range []string{`"01"`, `"+1"`, `"-1"`, `"0"`, `"1.0"`, `"1e3"`, `"18446744073709551616"`, `1`, `null`} {
		bad["decimal-"+value] = strings.Replace(request, `"birthTicks":"9007199254740993"`, `"birthTicks":`+value, 1)
	}
	bad["pid-overflow"] = strings.Replace(request, `"pid":"123"`, `"pid":"9223372036854775808"`, 1)
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRetirement(strings.NewReader(data)); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
}

// A pipe with an open writer proves that complete EOF, not one decoded object,
// is required before any positive query may start.
func TestRetirementInputRequiresEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	done := make(chan error, 1)
	go func() { _, _, e := parseRetirement(r); done <- e }()
	if _, err = w.Write([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("input proceeded before EOF")
	case <-time.After(30 * time.Millisecond):
	}
	_ = w.Close()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("incomplete binding accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("input did not finish at EOF")
	}
}

func TestRetirementOutputBound(t *testing.T) {
	// JSON expansion must be measured AFTER serialization, before any write.
	// A fixed origin of 512 '<' bytes is legal and expands sixfold in JSON.
	b := gatewaylauncher.Binding{OriginRef: strings.Repeat("<", 512), BootID: "12345678-1234-4234-8234-123456789abc",
		Incarnation: "23456789-1234-4234-8234-123456789abc", PID: 123,
		BirthTicks: 9007199254740993, LockDevice: 18446744073709551615, LockInode: 9007199254740995}
	r := gatewaylauncher.Receipt{Binding: b, Scope: gatewaylauncher.LocalTeardownScope, Method: "observed-child-exit"}
	var out bytes.Buffer
	if err := emitRetirements(&out, []gatewaylauncher.Receipt{r}); err != nil || out.Len() > retirementBytes {
		t.Fatal("bounded single positive receipt denied", err)
	}
	out.Reset()
	second := r
	second.Binding.Incarnation = "34567890-1234-4234-8234-123456789abc"
	if err := emitRetirements(&out, []gatewaylauncher.Receipt{r, second}); err == nil || out.Len() != 0 {
		t.Fatal("oversize output was partially emitted or accepted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	defer func() { _ = reader.Close() }()
	if err = emitRetirements(writer, []gatewaylauncher.Receipt{r}); err == nil {
		t.Fatal("failed output pipe certified success")
	}
}

// Reexec only this test ELF as a disposable non-root engine with the actual
// inherited FD/gate/readiness contract. No provider/bootstrap is involved.
func TestRetirementSyntheticEngine(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "retirement-synthetic-engine" {
		return
	}
	if os.Geteuid() != 65534 {
		os.Exit(70)
	}
	var st syscall.Stat_t
	if syscall.Fstat(3, &st) != nil || syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		os.Exit(70)
	}
	gate := os.NewFile(5, "owned-gate")
	var data [1]byte
	if _, err := io.ReadFull(gate, data[:]); err != nil || data[0] != 'G' {
		os.Exit(70)
	}
	_ = gate.Close()
	ready := os.NewFile(4, "owned-ready")
	if _, err := ready.Write([]byte("R")); err != nil {
		os.Exit(70)
	}
	_ = ready.Close()
	for {
		time.Sleep(time.Second)
	}
}

func TestActualRetirementCLI(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT_RUN: disposable root Linux fixture required")
	}
	root, err := os.MkdirTemp("/run", "account-gateway-retirement-fixture-")
	if err != nil {
		t.Skip("NOT_RUN: owned /run fixture unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "protected")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	engine := filepath.Join(root, "owned-engine")
	if err = os.WriteFile(engine, image, 0755); err != nil {
		t.Fatal(err)
	}
	config := gatewaylauncher.Config{Authority: gatewaylauncher.AuthorityConfig{Directory: dir, OriginRef: "disposable-cli-origin"},
		EnginePath: engine, Args: []string{"-test.run=^TestRetirementSyntheticEngine$", "--", "retirement-synthetic-engine"}, EngineUID: 65534, EngineGID: 65534}
	start := func() *gatewaylauncher.Launcher {
		l, e := gatewaylauncher.Start(config)
		if l != nil {
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, e := l.Shutdown(ctx); e != nil {
					t.Error("owned engine disposal failed", e)
				}
			})
		}
		if e != nil || l == nil {
			t.Fatal("owned engine start failed", e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e = l.AwaitReady(ctx); e != nil {
			t.Fatal(e)
		}
		return l
	}
	a := start()
	stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	rA, err := a.Shutdown(stopCtx)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	old := []gatewaylauncher.Receipt{rA}
	current := start()
	built := buildGatewayCommand(t)
	binary := filepath.Join(root, "account-gateway")
	commandImage, err := os.ReadFile(built)
	if err != nil || os.WriteFile(binary, commandImage, 0755) != nil {
		t.Fatal("cannot copy readonly command to owned protected fixture")
	}
	args := []string{"--read-retirement", "--authority-dir", dir, "--origin-ref", config.Authority.OriginRef}
	selectors := []gatewaylauncher.RetirementSelector{{OriginRef: old[0].Binding.OriginRef, EngineIncarnation: old[0].Binding.Incarnation}}
	journal := filepath.Join(dir, "origin.json")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	query := func(argv []string, data string, want []gatewaylauncher.Receipt) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p := exec.CommandContext(ctx, binary, argv...)
		p.Env, p.Dir, p.Stdin = []string{}, "/", strings.NewReader(data)
		var stdout, stderr bytes.Buffer
		p.Stdout, p.Stderr = &stdout, &stderr
		e := p.Run()
		if ctx.Err() != nil {
			t.Fatal("readonly subprocess timed out")
		}
		if want == nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() <= 0 || stdout.Len() != 0 {
				t.Fatal("denial leaked positive output or failed to exit")
			}
			switch stderr.String() {
			case "account-gateway: invalid retirement configuration\n", "account-gateway: invalid retirement input\n", "account-gateway: retirement evidence denied\n":
			default:
				t.Fatal("unclassified retirement diagnostic")
			}
		} else {
			if e != nil || stderr.Len() != 0 || stdout.Len() > retirementBytes {
				t.Fatal("positive CLI failed bound/exit", e)
			}
			var response struct {
				Receipts []receiptOutput `json:"receipts"`
			}
			d := json.NewDecoder(&stdout)
			d.DisallowUnknownFields()
			if d.Decode(&response) != nil || len(response.Receipts) != len(want) {
				t.Fatal("positive response incomplete")
			}
			var extra any
			if d.Decode(&extra) != io.EOF {
				t.Fatal("positive response trailing bytes")
			}
			for i, r := range want {
				if response.Receipts[i] != (receiptOutput{outputBinding(r.Binding), r.Scope, r.Method}) {
					t.Fatal("positive CLI changed full receipt/order")
				}
			}
		}
		after, e := os.ReadFile(journal)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("CLI changed source journal")
		}
		stat, e := os.ReadFile("/proc/" + strconv.Itoa(current.Binding().PID) + "/stat")
		end := strings.LastIndexByte(string(stat), ')')
		if e != nil || end < 0 {
			t.Fatal("CLI affected current engine")
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 20 || fields[19] != strconv.FormatUint(current.Binding().BirthTicks, 10) || fields[0] == "Z" || fields[0] == "X" || fields[0] == "T" || fields[0] == "t" {
			t.Fatal("CLI affected current engine's exact live birth/state")
		}
		if _, e = os.Stat(filepath.Join(dir, "origin.next")); !os.IsNotExist(e) {
			t.Fatal("CLI attempted journal publication")
		}
	}
	request := retirementRequest(t, current.Binding(), selectors)
	// Real B inherits the live flock and can read A; after B's exact exit a
	// real C can still read A (and B), in caller selector order.
	query(args, request, old)
	query(args, request+strings.Repeat(" ", retirementBytes-len(request)), old)
	stopCtx, stop = context.WithTimeout(context.Background(), 5*time.Second)
	rB, err := current.Shutdown(stopCtx)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	old = append(old, rB)
	current = start()
	selectors = append(selectors, gatewaylauncher.RetirementSelector{OriginRef: rB.Binding.OriginRef, EngineIncarnation: rB.Binding.Incarnation})
	before, err = os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	request = retirementRequest(t, current.Binding(), selectors)
	query(args, request, old)
	query(args, retirementRequest(t, current.Binding(), selectors[:1]), old[:1])
	query(args, retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{selectors[1], selectors[0]}), []gatewaylauncher.Receipt{old[1], old[0]})
	for _, data := range []string{
		request + strings.Repeat(" ", retirementBytes+1-len(request)), request + `{}`,
		strings.Replace(request, `"current":`, `"Current":`, 1),
		strings.Replace(request, `"pid":`, `"pid":"0","pid":`, 1),
		retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{selectors[0], selectors[0]}),
		retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{{OriginRef: current.Binding().OriginRef, EngineIncarnation: current.Binding().Incarnation}}),
		retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{{OriginRef: "foreign-origin", EngineIncarnation: selectors[0].EngineIncarnation}}),
		retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{{OriginRef: current.Binding().OriginRef, EngineIncarnation: "00000000-0000-0000-0000-000000000000"}}),
		retirementRequest(t, current.Binding(), []gatewaylauncher.RetirementSelector{selectors[0], {OriginRef: current.Binding().OriginRef, EngineIncarnation: "00000000-0000-0000-0000-000000000000"}}),
		retirementRequest(t, old[0].Binding, selectors[:1]),
	} {
		query(args, data, nil)
	}
	wrong := current.Binding()
	wrong.BootID = "00000000-0000-0000-0000-000000000000"
	query(args, retirementRequest(t, wrong, selectors[:1]), nil)
	wrong = current.Binding()
	wrong.LockInode++
	query(args, retirementRequest(t, wrong, selectors[:1]), nil)
	wrong = current.Binding()
	wrong.BirthTicks++
	query(args, retirementRequest(t, wrong, selectors[:1]), nil)
	// A caller with the correct original binding still cannot read through a
	// replaced fixed lock inode. Replace only this fixture's pathname while C
	// retains the original inherited description, then restore its exact inode.
	lock := filepath.Join(dir, "origin.lock")
	retainedLock := filepath.Join(dir, "owned-original-lock")
	if err = os.Rename(lock, retainedLock); err != nil {
		t.Fatal(err)
	}
	lockReplaced := true
	t.Cleanup(func() {
		if lockReplaced {
			_ = os.Remove(lock)
			if e := os.Rename(retainedLock, lock); e != nil {
				t.Error("owned lock restore failed", e)
			}
		}
	})
	if err = os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	query(args, request, nil)
	if err = os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(retainedLock, lock); err != nil {
		t.Fatal(err)
	}
	lockReplaced = false
	query(args, request, old)
	query(append(append([]string{}, args...), "--bootstrap-file", "unused"), request, nil)
	// An unprivileged CLI must exit BEFORE reading even one byte. Keep the
	// stdin writer open and send nothing; a misplaced UID check would time out.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p := exec.CommandContext(ctx, binary, args...)
	p.Env, p.Dir, p.Stdin = []string{}, "/", r
	p.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	var stdout, stderr bytes.Buffer
	p.Stdout, p.Stderr = &stdout, &stderr
	err = p.Run()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 2 || stdout.Len() != 0 || stderr.String() != "account-gateway: invalid retirement configuration\n" {
		t.Fatal("unprivileged CLI did not deny before reading stdin", err)
	}
}
