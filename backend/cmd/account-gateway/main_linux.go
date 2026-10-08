//go:build linux

// account-gateway is the foreground Linux private native service.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/gatewaybootstrap"
	"github.com/Wei-Shaw/sub2api/internal/gatewaylauncher"
)

// Decimal strings preserve kernel identities across JavaScript/JSON consumers.
type bindingOutput struct {
	OriginRef   string `json:"originRef"`
	BootID      string `json:"bootId"`
	Incarnation string `json:"incarnation"`
	PID         string `json:"pid"`
	BirthTicks  string `json:"birthTicks"`
	LockDevice  string `json:"lockDevice"`
	LockInode   string `json:"lockInode"`
}

type receiptOutput struct {
	Binding bindingOutput `json:"binding"`
	Scope   string        `json:"scope"`
	Method  string        `json:"method"`
}

type serviceEvent struct {
	State        string         `json:"state"`
	Binding      bindingOutput  `json:"binding"`
	Receipt      *receiptOutput `json:"receipt,omitempty"`
	AuthorityDir string         `json:"authorityDir,omitempty"`
}

func outputBinding(b gatewaylauncher.Binding) bindingOutput {
	return bindingOutput{
		OriginRef: b.OriginRef, BootID: b.BootID, Incarnation: b.Incarnation,
		PID: strconv.Itoa(b.PID), BirthTicks: strconv.FormatUint(b.BirthTicks, 10),
		LockDevice: strconv.FormatUint(b.LockDevice, 10), LockInode: strconv.FormatUint(b.LockInode, 10),
	}
}

func emit(w io.Writer, state string, b gatewaylauncher.Binding, dir string, receipt *gatewaylauncher.Receipt) error {
	event := serviceEvent{State: state, Binding: outputBinding(b), AuthorityDir: dir}
	if receipt != nil {
		event.Receipt = &receiptOutput{Binding: outputBinding(receipt.Binding), Scope: receipt.Scope, Method: receipt.Method}
	}
	return json.NewEncoder(w).Encode(event)
}

func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

const retirementBytes = 4096

type retirementInput struct {
	Current   bindingOutput                        `json:"current"`
	Selectors []gatewaylauncher.RetirementSelector `json:"selectors"`
}

// Token validation precedes struct decoding: encoding/json alone accepts
// duplicate decoded names and case aliases. Exact escaped names remain valid.
func retirementJSON(d *json.Decoder, depth int) error {
	if depth > 3 {
		return gatewaylauncher.ErrBinding
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' && delim != '[' {
		return gatewaylauncher.ErrBinding
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return gatewaylauncher.ErrBinding
			}
			switch name {
			case "current", "selectors", "originRef", "bootId", "incarnation", "pid", "birthTicks", "lockDevice", "lockInode", "engineIncarnation":
			default:
				return gatewaylauncher.ErrBinding
			}
			seen[name] = true
		}
		if err = retirementJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token() // Decoder validates the matching closing delimiter.
	return err
}

func parseRetirement(r io.Reader) (gatewaylauncher.Binding, []gatewaylauncher.RetirementSelector, error) {
	data, err := io.ReadAll(io.LimitReader(r, retirementBytes+1))
	if err != nil || len(data) > retirementBytes || !utf8.Valid(data) {
		return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if retirementJSON(d, 0) != nil {
		return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
	}
	if _, err = d.Token(); err != io.EOF {
		return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
	}
	var input retirementInput
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || len(input.Selectors) < 1 || len(input.Selectors) > 2 {
		return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
	}
	b := input.Current
	pid, err := strconv.ParseInt(b.PID, 10, strconv.IntSize)
	if err != nil || pid <= 0 || strconv.FormatInt(pid, 10) != b.PID {
		return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
	}
	numbers := []string{b.BirthTicks, b.LockDevice, b.LockInode}
	var values [3]uint64
	for i, value := range numbers {
		values[i], err = strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(values[i], 10) != value || (i != 1 && values[i] == 0) {
			return gatewaylauncher.Binding{}, nil, gatewaylauncher.ErrBinding
		}
	}
	return gatewaylauncher.Binding{OriginRef: b.OriginRef, BootID: b.BootID, Incarnation: b.Incarnation,
		PID: int(pid), BirthTicks: values[0], LockDevice: values[1], LockInode: values[2]}, input.Selectors, nil
}

func readRetirement(args []string, in io.Reader, out, diagnostic io.Writer) int {
	// Root and the exact fixed-purpose argv are checked BEFORE any stdin read.
	if os.Geteuid() != 0 || len(args) != 5 || args[0] != "--read-retirement" || args[1] != "--authority-dir" ||
		!absolute(args[2]) || args[2] == "/" || args[3] != "--origin-ref" || args[4] == "" {
		fmt.Fprintln(diagnostic, "account-gateway: invalid retirement configuration")
		return 2
	}
	current, selectors, err := parseRetirement(in)
	if err != nil {
		fmt.Fprintln(diagnostic, "account-gateway: invalid retirement input")
		return 2
	}
	receipts, err := gatewaylauncher.ReadRetirements(gatewaylauncher.AuthorityConfig{Directory: args[2], OriginRef: args[4]}, current, selectors)
	if err != nil {
		fmt.Fprintln(diagnostic, "account-gateway: retirement evidence denied")
		return 1
	}
	if emitRetirements(out, receipts) != nil {
		fmt.Fprintln(diagnostic, "account-gateway: retirement output failed")
		return 1
	}
	return 0
}

func emitRetirements(out io.Writer, receipts []gatewaylauncher.Receipt) error {
	response := struct {
		Receipts []receiptOutput `json:"receipts"`
	}{Receipts: make([]receiptOutput, len(receipts))}
	for i, r := range receipts {
		response.Receipts[i] = receiptOutput{Binding: outputBinding(r.Binding), Scope: r.Scope, Method: r.Method}
	}
	data, err := json.Marshal(response)
	data = append(data, '\n')
	if err != nil || len(data) > retirementBytes {
		return gatewaylauncher.ErrBinding
	}
	n, err := out.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "--read-retirement" {
		return readRetirement(args, os.Stdin, os.Stdout, os.Stderr)
	}
	// A lost metadata/diagnostic reader must reach exact-handle shutdown.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if len(args) == 1 && args[0] == "--engine" {
		// Only the accepted inherited FD/bootstrap contract can authorize work.
		if gatewaybootstrap.Run(ctx, gatewaybootstrap.Options{}) != nil {
			fmt.Fprintln(os.Stderr, "account-gateway: private bootstrap denied")
			return 1
		}
		return 0
	}

	flags := flag.NewFlagSet("account-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Never echo malformed configuration arguments.
	bootstrap := flags.String("bootstrap-file", "", "fixed protected server bootstrap file")
	dir := flags.String("authority-dir", "", "fixed root-owned 0700 authority directory")
	origin := flags.String("origin-ref", "", "fixed opaque origin reference")
	uid := flags.Uint64("engine-uid", 0, "separate non-root engine UID")
	gid := flags.Uint64("engine-gid", 0, "separate non-root engine GID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 ||
		!absolute(*bootstrap) || !absolute(*dir) || *origin == "" ||
		*uid == 0 || *gid == 0 || *uid >= uint64(^uint32(0)) || *gid >= uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "account-gateway: invalid server configuration")
		return 2
	}

	engine, err := os.Executable()
	if err != nil || !absolute(engine) {
		fmt.Fprintln(os.Stderr, "account-gateway: executable identity denied")
		return 1
	}
	self, selfErr := os.Stat("/proc/self/exe")
	image, imageErr := os.Stat(engine)
	if selfErr != nil || imageErr != nil || !os.SameFile(self, image) {
		fmt.Fprintln(os.Stderr, "account-gateway: executable identity denied")
		return 1
	}
	// Snapshot/capture in Start validates the executable's protected ancestors
	// and this pinned file's owner, readonly access, 0600 mode, link count/size.
	// NONBLOCK also avoids hanging on a substituted FIFO before that validation.
	fd, err := syscall.Open(*bootstrap, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "account-gateway: bootstrap file denied")
		return 1
	}
	file := os.NewFile(uintptr(fd), "native-bootstrap")
	authority := gatewaylauncher.AuthorityConfig{Directory: *dir, OriginRef: *origin}
	l, startErr := gatewaylauncher.Start(gatewaylauncher.Config{
		Authority: authority, EnginePath: engine, Args: []string{"--engine"},
		Env: []string{"GIN_MODE=release"}, EngineUID: uint32(*uid), EngineGID: uint32(*gid),
		BootstrapFile: file, EngineStderr: os.Stderr,
	})
	_ = file.Close() // Start captured its own duplicate; no pathname reopen.
	if l == nil {
		fmt.Fprintln(os.Stderr, "account-gateway: startup denied")
		return 1
	}
	// A nonnil handle remains authoritative even after post-exec Start failure.
	// Retain its ORIGINAL complete identity for every receipt readback.
	binding := l.Binding()
	shutdown := func() int {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := l.Shutdown(stopCtx)
		if err == nil {
			var receipt gatewaylauncher.Receipt
			receipt, err = gatewaylauncher.ReadReceipt(authority, binding)
			if err == nil {
				if emit(os.Stdout, "retired", binding, "", &receipt) == nil {
					return 0
				}
				fmt.Fprintln(os.Stderr, "account-gateway: metadata output failed")
				return 1
			}
		}
		// No authority reset, foreign PID signal or fabricated closure on timeout.
		// The handle lives through this return; disk evidence/child FD remain.
		if emit(os.Stdout, "pending", binding, authority.Directory, nil) != nil {
			fmt.Fprintln(os.Stderr, "account-gateway: metadata output failed")
		}
		fmt.Fprintln(os.Stderr, "account-gateway: teardown pending; protected evidence retained")
		return 1
	}
	if startErr != nil {
		fmt.Fprintln(os.Stderr, "account-gateway: startup incomplete")
		shutdown()
		return 1
	}
	// Publish the actual captured binding before enrollment waits on authority.
	// This event does not certify readiness or grant dispatch.
	if emit(os.Stdout, "starting", binding, "", nil) != nil {
		fmt.Fprintln(os.Stderr, "account-gateway: metadata output failed")
		shutdown()
		return 1
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = l.AwaitReady(readyCtx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return shutdown()
		}
		fmt.Fprintln(os.Stderr, "account-gateway: readiness unproven")
		shutdown()
		return 1
	}
	if emit(os.Stdout, "ready", binding, "", nil) != nil {
		fmt.Fprintln(os.Stderr, "account-gateway: metadata output failed")
		shutdown()
		return 1
	}
	exited := make(chan struct{}, 1)
	go func() {
		_, _ = l.Wait(context.Background())
		exited <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		return shutdown()
	case <-exited:
		fmt.Fprintln(os.Stderr, "account-gateway: engine stopped")
		shutdown()
		return 1
	}
}

func main() { os.Exit(run(os.Args[1:])) }
