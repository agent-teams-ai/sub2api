//go:build linux

package gatewaylauncher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fixtureUID uint32 = 65534
const fixtureGID uint32 = 65534

type fixture struct {
	root   string
	config Config
}

// Qualification uses only a new /run fixture, a COPY of this test executable,
// and dedicated synthetic UID/GID. Production ownership checks are unchanged.
// No test mode, same-UID bypass or failure-injection field exists in production.
func newFixture(t *testing.T) fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("NOT_RUN: disposable root Linux qualification required")
	}
	root, err := os.MkdirTemp("/run", "gatewaylauncher-fixture-")
	if err != nil {
		t.Skip("NOT_RUN: cannot create isolated /run fixture")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(root, "protected")
	if err = os.Mkdir(meta, 0700); err != nil {
		t.Fatal(err)
	}
	exchange := filepath.Join(root, "exchange")
	if err = os.Mkdir(exchange, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(exchange, int(fixtureUID), int(fixtureGID)); err != nil {
		t.Skip("NOT_RUN: separate synthetic uid/gid unavailable")
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	image := filepath.Join(root, "synthetic-engine")
	w, err := os.OpenFile(image, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(w, r)
	ce := w.Close()
	if err != nil || ce != nil {
		t.Fatal("copy synthetic image failed")
	}
	// Confirm actual synthetic non-root exec before interpreting qualification.
	q := exec.Command(image, "-test.run=^TestSyntheticProcess$", "--", "qualification", root, "credentials")
	q.Env = []string{}
	q.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: fixtureUID, Gid: fixtureGID, Groups: []uint32{}}}
	if err = q.Start(); err != nil {
		t.Skip("NOT_RUN: isolated synthetic credential exec unavailable")
	}
	if err = q.Wait(); err != nil {
		t.Fatal("synthetic credential preflight failed")
	}
	c := fixtureConfig(root, "hold")
	return fixture{root, c}
}

func fixtureConfig(root, mode string) Config {
	return Config{
		Authority:  AuthorityConfig{Directory: filepath.Join(root, "protected"), OriginRef: "opaque-disposable-origin"},
		EnginePath: filepath.Join(root, "synthetic-engine"),
		Args:       []string{"-test.run=^TestSyntheticProcess$", "--", "engine", root, mode},
		EngineUID:  fixtureUID, EngineGID: fixtureGID,
	}
}

func deadline(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func trackLauncher(t *testing.T, l *Launcher) {
	t.Helper()
	if l == nil {
		return
	}
	t.Cleanup(func() {
		// Test cleanup only, after positive exact-child exit observation.
		select {
		case <-l.done:
		default:
			_ = l.cmd.Process.Kill()
		}
		ctx, cancel := deadline(t)
		defer cancel()
		select {
		case <-l.done:
		case <-ctx.Done():
			t.Error("synthetic child cleanup unobserved")
			return
		}
		_, _ = l.Wait(ctx)
		l.mu.Lock()
		l.a.close()
		l.mu.Unlock()
	})
}

func startFixture(t *testing.T, c Config) *Launcher {
	t.Helper()
	l, err := Start(c)
	trackLauncher(t, l)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := deadline(t)
	defer cancel()
	if err = l.AwaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return l
}

func stopEngine(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "exchange", "stop"), []byte("stop"), 0644); err != nil {
		t.Fatal(err)
	}
}

func waitFile(t *testing.T, path string) []byte {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		b, err := os.ReadFile(path)
		if err == nil && json.Valid(b) {
			return b
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("synthetic result not observed: %s", filepath.Base(path))
	return nil
}

func probeLock(t *testing.T, c Config, busy bool) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(c.Authority.Directory, lockName), os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if busy {
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			t.Fatalf("independent flock: want occupied, got %v", err)
		}
	} else if err != nil {
		t.Fatalf("independent flock: want reacquired, got %v", err)
	}
	// Closing this descriptor, never explicit LOCK_UN, releases our test probe.
}

type engineReport struct {
	Device          uint64  `json:"device"`
	Inode           uint64  `json:"inode"`
	FDFlags         uintptr `json:"fdFlags"`
	AccessMode      uintptr `json:"accessMode"`
	SharedFlock     bool    `json:"sharedFlock"`
	MetadataDenied  bool    `json:"metadataDenied"`
	UID             int     `json:"uid"`
	GID             int     `json:"gid"`
	Groups          []int   `json:"groups"`
	SyntheticMarker string  `json:"syntheticMarker"`
}

type supervisorReport struct {
	Status  string  `json:"status"`
	Binding Binding `json:"binding"`
}

func writeSynthetic(path string, value any) {
	b, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, b, 0600) != nil {
		os.Exit(70)
	}
}

// Regression: all subprocesses are explicit new synthetic fixture processes;
// this helper is compiled ONLY into the Go test executable, never production.
func TestSyntheticProcess(t *testing.T) {
	t.Log("Regression: synthetic helper cannot run without explicit disposable fixture arguments")
	marker := -1
	for i, s := range os.Args {
		if s == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) < 3 {
		os.Exit(70)
	}
	kind, root, mode := args[0], args[1], args[2]
	if filepath.Dir(root) != "/run" || !strings.HasPrefix(filepath.Base(root), "gatewaylauncher-fixture-") {
		os.Exit(70)
	}
	if kind == "qualification" {
		if os.Geteuid() != int(fixtureUID) || os.Getegid() != int(fixtureGID) {
			os.Exit(70)
		}
		os.Exit(0)
	}
	if kind == "supervisor" {
		if os.Geteuid() != 0 {
			os.Exit(70)
		}
		if mode == "race" {
			for {
				if _, err := os.Stat(filepath.Join(root, "barrier")); err == nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		if len(args) != 4 {
			os.Exit(70)
		}
		result := filepath.Join(root, args[3])
		l, err := Start(fixtureConfig(root, "hold"))
		if l == nil {
			status := "denied"
			if errors.Is(err, ErrBusy) {
				status = "busy"
			}
			writeSynthetic(result, supervisorReport{Status: status})
			os.Exit(0)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err != nil || l.AwaitReady(ctx) != nil {
			cancel()
			_ = l.cmd.Process.Kill()
			os.Exit(70)
		}
		cancel()
		writeSynthetic(result, supervisorReport{Status: "started", Binding: l.Binding()})
		if _, err = l.Wait(context.Background()); err != nil {
			os.Exit(70)
		}
		os.Exit(0)
	}
	if kind == "retainer" {
		if os.Geteuid() != int(fixtureUID) || os.Getegid() != int(fixtureGID) {
			os.Exit(70)
		}
		var st syscall.Stat_t
		if syscall.Fstat(3, &st) != nil {
			os.Exit(70)
		}
		writeSynthetic(filepath.Join(root, "exchange", "retainer.json"), map[string]bool{"alive": true})
		for {
			if _, err := os.Stat(filepath.Join(root, "exchange", "stop-retainer")); err == nil {
				os.Exit(0)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if kind != "engine" || os.Geteuid() != int(fixtureUID) || os.Getegid() != int(fixtureGID) {
		os.Exit(70)
	}
	if mode == "stubborn" {
		signal.Ignore(syscall.SIGTERM)
	}
	var st syscall.Stat_t
	if syscall.Fstat(3, &st) != nil {
		os.Exit(70)
	}
	fdFlags, _, e := syscall.Syscall(syscall.SYS_FCNTL, 3, syscall.F_GETFD, 0)
	if e != 0 {
		os.Exit(70)
	}
	accessMode, _, e := syscall.Syscall(syscall.SYS_FCNTL, 3, syscall.F_GETFL, 0)
	if e != 0 {
		os.Exit(70)
	}
	groups, err := os.Getgroups()
	if err != nil {
		os.Exit(70)
	}
	shared := syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB) == nil
	// Access is genuinely denied under separate credentials, not simulated.
	metadataErr := os.WriteFile(filepath.Join(root, "protected", journalName), []byte("forged"), 0600)
	gate := os.NewFile(5, "synthetic-gate")
	var g [1]byte
	n, err := gate.Read(g[:])
	_ = gate.Close()
	if err != nil || n != 1 || g[0] != 'G' {
		os.Exit(70)
	}
	writeSynthetic(filepath.Join(root, "exchange", "engine.json"), engineReport{
		uint64(st.Dev), st.Ino, fdFlags, accessMode & syscall.O_ACCMODE, shared,
		os.IsPermission(metadataErr), os.Geteuid(), os.Getegid(), groups, os.Getenv("SYNTHETIC_VALUE"),
	})
	ready := os.NewFile(4, "synthetic-ready")
	if _, err = ready.Write([]byte("R")); err != nil {
		os.Exit(70)
	}
	_ = ready.Close()
	for {
		if _, err = os.Stat(filepath.Join(root, "exchange", "stop")); err == nil {
			os.Exit(0)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Regression: exec must retain the SAME open lock description with CLOEXEC
// cleared, while separate engine credentials cannot modify protected metadata.
func TestInheritedDescriptionAndAuthority(t *testing.T) {
	t.Log("Regression: inherited FD survives exec, shares flock and cannot write supervisor metadata")
	f := newFixture(t)
	l := startFixture(t, f.config)
	var report engineReport
	if err := json.Unmarshal(waitFile(t, filepath.Join(f.root, "exchange", "engine.json")), &report); err != nil {
		t.Fatal(err)
	}
	b := l.Binding()
	if report.Device != b.LockDevice || report.Inode != b.LockInode || report.FDFlags&syscall.FD_CLOEXEC != 0 || report.AccessMode != syscall.O_RDONLY || !report.SharedFlock || !report.MetadataDenied || report.UID != int(fixtureUID) || report.GID != int(fixtureGID) {
		t.Fatalf("inherited descriptor/authority violation: %+v", report)
	}
	for _, g := range report.Groups {
		if g == 0 {
			t.Fatal("root supplementary group inherited")
		}
	}
	probeLock(t, f.config, true)
	stopEngine(t, f.root)
	ctx, cancel := deadline(t)
	defer cancel()
	r, err := l.Wait(ctx)
	if err != nil || r.Binding != b || r.Scope != LocalTeardownScope || r.Method != "observed-child-exit" {
		t.Fatalf("exact exit receipt failed: %v", err)
	}
	probeLock(t, f.config, false)
	read, err := ReadReceipt(f.config.Authority, b)
	if err != nil || read != r {
		t.Fatal("protected exact readback failed")
	}
}

func runSupervisor(t *testing.T, f fixture, mode, result string) *exec.Cmd {
	t.Helper()
	p := exec.Command(f.config.EnginePath, "-test.run=^TestSyntheticProcess$", "--", "supervisor", f.root, mode, result)
	p.Env = []string{}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if p.ProcessState == nil {
			_ = p.Process.Kill()
			_ = p.Wait()
		}
	})
	return p
}

func exactBinding(t *testing.T, path string) supervisorReport {
	t.Helper()
	var r supervisorReport
	if err := json.Unmarshal(waitFile(t, path), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Regression: killing a supervisor must not drop the inherited flock or allow
// rollover/old-child cancellation. Recovery must preserve exact old evidence.
func TestSupervisorLossAndExactRecovery(t *testing.T) {
	t.Log("Regression: surviving child denies rollover after supervisor death, then exact recovery retains the previous receipt")
	f := newFixture(t)
	p := runSupervisor(t, f, "hold", "supervisor.json")
	old := exactBinding(t, filepath.Join(f.root, "supervisor.json"))
	if old.Status != "started" {
		t.Fatal("synthetic supervisor failed")
	}
	// Cleanup targets this synthetic child only, using its observed birth.
	t.Cleanup(func() {
		n, state, err := birth(old.Binding.PID)
		if err == nil && n == old.Binding.BirthTicks && state != 'Z' {
			_ = syscall.Kill(old.Binding.PID, syscall.SIGKILL)
		}
	})
	if err := p.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err == nil {
		t.Fatal("supervisor was not killed")
	}
	probeLock(t, f.config, true)
	l, startErr := Start(f.config)
	trackLauncher(t, l)
	if l != nil || !errors.Is(startErr, ErrBusy) {
		t.Fatalf("surviving child rollover: %v", startErr)
	}
	n, state, err := birth(old.Binding.PID)
	if err != nil || n != old.Binding.BirthTicks || state == 'Z' {
		t.Fatal("second launcher affected the surviving old child")
	}
	if _, err = ReadReceipt(f.config.Authority, old.Binding); err == nil {
		t.Fatal("live child certified retired")
	}
	stopEngine(t, f.root)
	until := time.Now().Add(5 * time.Second)
	for {
		n, state, err = birth(old.Binding.PID)
		if os.IsNotExist(err) || (err == nil && n == old.Binding.BirthTicks && state == 'Z') {
			break
		}
		if time.Now().After(until) {
			t.Fatal("synthetic old child exit not observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	probeLock(t, f.config, false)
	if err = os.Remove(filepath.Join(f.root, "exchange", "stop")); err != nil {
		t.Fatal(err)
	}
	fresh := startFixture(t, f.config)
	if fresh.Binding().Incarnation == old.Binding.Incarnation {
		t.Fatal("incarnation reused")
	}
	r, err := ReadReceipt(f.config.Authority, old.Binding)
	if err != nil || r.Binding != old.Binding || r.Method != "reacquired-after-supervisor-loss" {
		t.Fatalf("old recovery evidence overwritten: %v", err)
	}
	wrong := old.Binding
	wrong.Incarnation = strings.Repeat("a", 64)
	if _, err = ReadReceipt(f.config.Authority, wrong); !errors.Is(err, ErrBinding) {
		t.Fatal("wrong incarnation accepted")
	}
}

// Regression: actual competing root supervisor processes must have one winner;
// the losing startup must not kill the winner or replace its lock inode.
func TestRacingSupervisors(t *testing.T) {
	t.Log("Regression: two racing supervisor processes have one winner and one fail-closed flock denial")
	f := newFixture(t)
	p := runSupervisor(t, f, "race", "race-a.json")
	q := runSupervisor(t, f, "race", "race-b.json")
	if err := os.WriteFile(filepath.Join(f.root, "barrier"), []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	a := exactBinding(t, filepath.Join(f.root, "race-a.json"))
	b := exactBinding(t, filepath.Join(f.root, "race-b.json"))
	if (a.Status != "started" || b.Status != "busy") && (b.Status != "started" || a.Status != "busy") {
		t.Fatalf("race outcomes: %s/%s", a.Status, b.Status)
	}
	winner := a
	if b.Status == "started" {
		winner = b
	}
	t.Cleanup(func() {
		n, state, err := birth(winner.Binding.PID)
		if err == nil && n == winner.Binding.BirthTicks && state != 'Z' {
			_ = syscall.Kill(winner.Binding.PID, syscall.SIGKILL)
		}
	})
	probeLock(t, f.config, true)
	stopEngine(t, f.root)
	if err := p.Wait(); err != nil {
		t.Fatal("race supervisor a failed")
	}
	if err := q.Wait(); err != nil {
		t.Fatal("race supervisor b failed")
	}
	if _, err := ReadReceipt(f.config.Authority, winner.Binding); err != nil {
		t.Fatal("race winner receipt missing")
	}
}

// Regression: unsafe paths, owners, permissions, symlinks and hardlinks cannot
// become supervisor authority or an alternate fixed lock inode.
func TestUnsafeAuthority(t *testing.T) {
	t.Log("Regression: unsafe protected filesystem authority is rejected before starting any child")
	cases := []string{"directory-mode", "directory-owner", "directory-symlink", "lock-symlink", "lock-mode", "lock-owner", "lock-hardlink", "metadata-symlink", "metadata-mode", "staging-symlink", "ancestor-mode", "engine-symlink", "engine-mode", "root-engine-uid", "sentinel-engine-uid", "sentinel-engine-gid"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Log("Regression: reject " + name)
			f := newFixture(t)
			lock := filepath.Join(f.config.Authority.Directory, lockName)
			metadata := filepath.Join(f.config.Authority.Directory, journalName)
			if err := os.WriteFile(lock, nil, 0600); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "directory-mode":
				if err := os.Chmod(f.config.Authority.Directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-owner":
				if err := os.Chown(f.config.Authority.Directory, int(fixtureUID), int(fixtureGID)); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				old := f.config.Authority.Directory + "-real"
				if err := os.Rename(f.config.Authority.Directory, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old, f.config.Authority.Directory); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/dev/null", lock); err != nil {
					t.Fatal(err)
				}
			case "lock-mode":
				if err := os.Chmod(lock, 0666); err != nil {
					t.Fatal(err)
				}
			case "lock-owner":
				if err := os.Chown(lock, int(fixtureUID), int(fixtureGID)); err != nil {
					t.Fatal(err)
				}
			case "lock-hardlink":
				if err := os.Link(lock, filepath.Join(f.config.Authority.Directory, "second-link")); err != nil {
					t.Fatal(err)
				}
			case "metadata-symlink":
				if err := os.Symlink("/dev/null", metadata); err != nil {
					t.Fatal(err)
				}
			case "metadata-mode":
				if err := os.WriteFile(metadata, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			case "staging-symlink":
				if err := os.Symlink("/dev/null", filepath.Join(f.config.Authority.Directory, stagingName)); err != nil {
					t.Fatal(err)
				}
			case "ancestor-mode":
				if err := os.Chmod(f.root, 0777); err != nil {
					t.Fatal(err)
				}
			case "engine-symlink":
				if err := os.Rename(f.config.EnginePath, f.config.EnginePath+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.config.EnginePath+"-real", f.config.EnginePath); err != nil {
					t.Fatal(err)
				}
			case "engine-mode":
				if err := os.Chmod(f.config.EnginePath, 0777); err != nil {
					t.Fatal(err)
				}
			case "root-engine-uid":
				f.config.EngineUID = 0
			case "sentinel-engine-uid":
				f.config.EngineUID = ^uint32(0)
			case "sentinel-engine-gid":
				f.config.EngineGID = ^uint32(0)
			}
			l, err := Start(f.config)
			trackLauncher(t, l)
			if l != nil {
				t.Fatal("unsafe authority started a child")
			}
			if err == nil {
				t.Fatal("unsafe authority accepted")
			}
		})
	}
}

// Regression: a replaced live lock path cannot certify retirement or create
// new authority while the original child still holds its inherited old inode.
func TestLockInodeReplacement(t *testing.T) {
	t.Log("Regression: replacing the lock pathname never rolls authority or certifies old retirement")
	f := newFixture(t)
	l := startFixture(t, f.config)
	lock := filepath.Join(f.config.Authority.Directory, lockName)
	if err := os.Rename(lock, lock+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	next, startErr := Start(f.config)
	trackLauncher(t, next)
	if next != nil || !errors.Is(startErr, ErrBinding) {
		t.Fatalf("replacement accepted: %v", startErr)
	}
	stopEngine(t, f.root)
	ctx, cancel := deadline(t)
	defer cancel()
	if _, err := l.Wait(ctx); !errors.Is(err, ErrBinding) {
		t.Fatalf("replaced inode certified: %v", err)
	}
	if _, err := ReadReceipt(f.config.Authority, l.Binding()); !errors.Is(err, ErrBinding) {
		t.Fatal("replaced inode read accepted")
	}
	// Restore the exact original inode under root fixture control, then clean.
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(lock+"-original", lock); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

// Regression: an actual exec failure cannot produce ready or retirement proof;
// its durable no-child start-failed fact permits a later configured startup.
func TestFailedExec(t *testing.T) {
	t.Log("Regression: failed exec records no child and never produces a retirement receipt")
	f := newFixture(t)
	bad := filepath.Join(f.root, "not-an-executable-image")
	if err := os.WriteFile(bad, []byte("\x7fELFsynthetic-invalid-image"), 0755); err != nil {
		t.Fatal(err)
	}
	c := f.config
	c.EnginePath = bad
	l, startErr := Start(c)
	trackLauncher(t, l)
	if l != nil || !errors.Is(startErr, ErrStart) {
		t.Fatalf("failed exec result: %v", startErr)
	}
	a, err := openAuthority(c.Authority.Directory)
	if err != nil {
		t.Fatal(err)
	}
	j, exists, err := a.read()
	a.close()
	if err != nil || !exists || j.Current.Phase != "start-failed" || j.Current.Binding.PID != 0 || len(j.Receipts) != 0 {
		t.Fatal("failed exec lied about lifecycle")
	}
	startFixture(t, f.config)
}

// Regression: actual Linux directory fsync failure cannot report ready or a
// durable receipt. O_PATH permits openat/Fstat but fsync returns EBADF: no mock.
func TestFailedDirectoryFsync(t *testing.T) {
	t.Log("Regression: an actual failed directory fsync denies readiness and durable retirement")
	f := newFixture(t)
	l, err := Start(f.config)
	if l == nil || err != nil {
		t.Fatalf("synthetic start: %v", err)
	}
	trackLauncher(t, l)
	j, exists, err := l.a.read()
	if err != nil || !exists {
		t.Fatal("starting journal unavailable")
	}
	original := l.a.dir
	fd, err := syscall.Open(f.config.Authority.Directory, 0x200000|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0) // Linux O_PATH
	if err != nil {
		t.Fatal(err)
	}
	opath := os.NewFile(uintptr(fd), "synthetic-opath-directory")
	defer func() {
		if l.a.dir == opath {
			l.a.dir = original
		}
		_ = opath.Close()
	}()
	if e := opath.Sync(); !errors.Is(e, syscall.EBADF) {
		_ = opath.Close()
		t.Fatalf("actual fsync failure not established: %v", e)
	}
	l.a.dir = opath
	ctx, cancel := deadline(t)
	defer cancel()
	select {
	case <-l.readyDone:
	case <-ctx.Done():
		t.Fatal("synthetic readiness signal missing")
	}
	if !l.readyObserved {
		t.Fatal("synthetic child did not actually signal readiness")
	}
	j.Current.Phase = "ready"
	if err = l.a.write(j); !errors.Is(err, ErrStorage) {
		t.Fatalf("actual publication fsync failure ignored: %v", err)
	}
	if err = l.AwaitReady(ctx); !errors.Is(err, ErrStorage) {
		t.Fatalf("failed fsync reported ready: %v", err)
	}
	l.a.dir = original
	if err = l.AwaitReady(ctx); err != nil {
		t.Fatal("durability restoration did not recover actual readiness")
	}
	l.a.dir = opath
	stopEngine(t, f.root)
	if _, err = l.Wait(ctx); !errors.Is(err, ErrStorage) {
		t.Fatalf("failed fsync certified retirement: %v", err)
	}
	l.a.dir = original
	_ = opath.Close()
	if _, err = l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

// Regression: exact receipt readback rejects each altered original binding,
// including a reused PID identity, host boot, incarnation and receipt scope.
func TestExactReceiptBindings(t *testing.T) {
	t.Log("Regression: original scope and every binding field are mandatory for retirement readback")
	f := newFixture(t)
	l := startFixture(t, f.config)
	stopEngine(t, f.root)
	ctx, cancel := deadline(t)
	defer cancel()
	if _, err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	original := l.Binding()
	for _, field := range []string{"origin", "boot", "pid", "birth", "incarnation", "device", "inode"} {
		t.Run(field, func(t *testing.T) {
			t.Log("Regression: reject altered original " + field)
			b := original
			switch field {
			case "origin":
				b.OriginRef = "another-origin"
			case "boot":
				b.BootID = "00000000-0000-0000-0000-000000000000"
			case "pid":
				b.PID++
			case "birth":
				b.BirthTicks++
			case "incarnation":
				b.Incarnation = strings.Repeat("b", 64)
			case "device":
				b.LockDevice++
			case "inode":
				b.LockInode++
			}
			if _, err := ReadReceipt(f.config.Authority, b); !errors.Is(err, ErrBinding) {
				t.Fatal("altered binding accepted")
			}
		})
	}
	a, err := openAuthority(f.config.Authority.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if err = a.acquire(false); err != nil {
		t.Fatal(err)
	}
	j, _, err := a.read()
	if err != nil {
		t.Fatal(err)
	}
	j.Receipts[0].Scope = "provider-no-effect"
	if err = a.write(j); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadReceipt(f.config.Authority, original); !errors.Is(err, ErrBinding) {
		t.Fatal("wrong receipt scope accepted")
	}
}

// Regression: a free lock plus wrong protected boot/process identity must not
// turn PID reuse, a fresh boot, or a live process into old retirement proof.
func TestRecoveryIdentityDenials(t *testing.T) {
	t.Log("Regression: a free lock cannot certify wrong boot or reused/live process identity")
	for _, mode := range []string{"boot", "pid-reuse", "live-exact", "reserved"} {
		t.Run(mode, func(t *testing.T) {
			t.Log("Regression: recovery rejects " + mode)
			f := newFixture(t)
			l := startFixture(t, f.config)
			stopEngine(t, f.root)
			ctx, cancel := deadline(t)
			defer cancel()
			if _, err := l.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			a, err := openAuthority(f.config.Authority.Directory)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.acquire(false); err != nil {
				a.close()
				t.Fatal(err)
			}
			j, _, err := a.read()
			if err != nil {
				a.close()
				t.Fatal(err)
			}
			j.Receipts = nil
			j.Current.Phase = "starting"
			switch mode {
			case "boot":
				j.Current.Binding.BootID = "00000000-0000-0000-0000-000000000000"
			case "pid-reuse":
				j.Current.Binding.PID = os.Getpid()
				n, _, e := birth(os.Getpid())
				if e != nil {
					t.Fatal(e)
				}
				j.Current.Binding.BirthTicks = n + 1
			case "live-exact":
				j.Current.Binding.PID = os.Getpid()
				n, _, e := birth(os.Getpid())
				if e != nil {
					t.Fatal(e)
				}
				j.Current.Binding.BirthTicks = n
			case "reserved":
				j.Current.Phase = "reserved"
				j.Current.Binding.PID = 0
				j.Current.Binding.BirthTicks = 0
			}
			if err = a.write(j); err != nil {
				a.close()
				t.Fatal(err)
			}
			a.close()
			probeLock(t, f.config, false)
			next, startErr := Start(f.config)
			trackLauncher(t, next)
			if next != nil || startErr == nil {
				t.Fatal("identity mismatch or unresolved reservation recovered")
			}
			if _, err := ReadReceipt(f.config.Authority, l.Binding()); err == nil {
				t.Fatal("denial manufactured receipt")
			}
		})
	}
}

// Regression: bounded cancellation of a stubborn child must return pending,
// retain real lock ownership, deny a second start, and avoid false retirement.
func TestBoundedStubbornShutdown(t *testing.T) {
	t.Log("Regression: shutdown timeout is pending, not child exit or retirement")
	f := newFixture(t)
	c := fixtureConfig(f.root, "stubborn")
	l := startFixture(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := l.Shutdown(ctx); !errors.Is(err, ErrPending) {
		t.Fatalf("stubborn shutdown: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("shutdown exceeded its bound")
	}
	n, state, err := birth(l.Binding().PID)
	if err != nil || n != l.Binding().BirthTicks || state == 'Z' {
		t.Fatal("timeout was not a live exact child")
	}
	probeLock(t, c, true)
	next, startErr := Start(c)
	trackLauncher(t, next)
	if next != nil || !errors.Is(startErr, ErrBusy) {
		t.Fatal("pending child lost lock authority")
	}
	if _, err := ReadReceipt(c.Authority, l.Binding()); err == nil {
		t.Fatal("timeout certified retirement")
	}
	stopEngine(t, f.root)
	finish, done := deadline(t)
	defer done()
	if _, err = l.Wait(finish); err != nil {
		t.Fatal(err)
	}
}

// Regression: observing child exit is insufficient while another real helper
// retains the inherited description. All holders must exit before a receipt.
func TestRetainedHolderAfterChildExit(t *testing.T) {
	t.Log("Regression: an inherited description retained beyond child exit prevents retirement and new startup")
	f := newFixture(t)
	l := startFixture(t, f.config)
	p := exec.Command(f.config.EnginePath, "-test.run=^TestSyntheticProcess$", "--", "retainer", f.root, "hold")
	p.Env = []string{}
	p.ExtraFiles = []*os.File{l.a.lock}
	p.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: fixtureUID, Gid: fixtureGID, Groups: []uint32{}}}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if p.ProcessState == nil {
			_ = p.Process.Kill()
			_ = p.Wait()
		}
	})
	waitFile(t, filepath.Join(f.root, "exchange", "retainer.json"))
	stopEngine(t, f.root)
	ctx, cancel := deadline(t)
	defer cancel()
	if _, err := l.Wait(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("retained description certified retirement: %v", err)
	}
	probeLock(t, f.config, true)
	next, startErr := Start(f.config)
	trackLauncher(t, next)
	if next != nil || !errors.Is(startErr, ErrBusy) {
		t.Fatal("retained holder allowed startup")
	}
	if _, err := ReadReceipt(f.config.Authority, l.Binding()); err == nil {
		t.Fatal("retained holder got a receipt")
	}
	if err := os.WriteFile(filepath.Join(f.root, "exchange", "stop-retainer"), []byte("stop"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err != nil {
		t.Fatal("synthetic retainer failed")
	}
	if _, err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

// Regression: retained receipts cannot be evicted when fixed storage capacity
// is exhausted. Every retained record below comes from an ACTUAL child exit.
func TestRetentionSaturation(t *testing.T) {
	t.Log("Regression: saturation denies new startup without evicting actual exact local evidence")
	f := newFixture(t)
	var first Binding
	for i := 0; i < retainedLimit; i++ {
		if i > 0 {
			if err := os.Remove(filepath.Join(f.root, "exchange", "stop")); err != nil {
				t.Fatal(err)
			}
		}
		l := startFixture(t, f.config)
		if i == 0 {
			first = l.Binding()
		}
		stopEngine(t, f.root)
		ctx, cancel := deadline(t)
		_, err := l.Wait(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(filepath.Join(f.config.Authority.Directory, journalName))
	if err != nil {
		t.Fatal(err)
	}
	next, startErr := Start(f.config)
	trackLauncher(t, next)
	if next != nil || !errors.Is(startErr, ErrSaturated) {
		t.Fatal("saturated journal started child")
	}
	after, err := os.ReadFile(filepath.Join(f.config.Authority.Directory, journalName))
	if err != nil || string(before) != string(after) {
		t.Fatal("saturation evicted evidence")
	}
	if _, err = ReadReceipt(f.config.Authority, first); err != nil {
		t.Fatal("original actual receipt lost at saturation")
	}
}

// Regression: mutating caller-owned slices after startup must not modify the
// child's frozen environment/arguments or generated process authority.
func TestConfigurationSnapshot(t *testing.T) {
	t.Log("Regression: configuration and generated identity remain immutable for the launch")
	f := newFixture(t)
	c := f.config
	c.Env = []string{"SYNTHETIC_VALUE=original"}
	l := startFixture(t, c)
	b := l.Binding()
	c.Args[0] = "changed"
	c.Env[0] = "SYNTHETIC_VALUE=changed"
	c.Authority.OriginRef = "changed"
	data, err := os.ReadFile("/proc/" + strconv.Itoa(b.PID) + "/cmdline")
	if err != nil || !strings.Contains(string(data), "-test.run=^TestSyntheticProcess$") || strings.Contains(string(data), "changed") {
		t.Fatal("argv snapshot mutated")
	}
	if l.Binding() != b || b.OriginRef != "opaque-disposable-origin" {
		t.Fatal("immutable launch authority mutated")
	}
	var report engineReport
	if err = json.Unmarshal(waitFile(t, filepath.Join(f.root, "exchange", "engine.json")), &report); err != nil || report.SyntheticMarker != "original" {
		t.Fatal("synthetic environment snapshot mutated")
	}
}

// Regression: a crash-abandoned staging slot must not be overwritten or
// discarded, and a fresh startup must preserve already durable old evidence.
func TestBoundedAbandonedStaging(t *testing.T) {
	t.Log("Regression: abandoned staging denies new publication without overwriting unresolved or previous evidence")
	f := newFixture(t)
	l := startFixture(t, f.config)
	stopEngine(t, f.root)
	ctx, cancel := deadline(t)
	defer cancel()
	if _, err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	slot := filepath.Join(f.config.Authority.Directory, stagingName)
	content := []byte("synthetic unresolved staging bytes")
	if err := os.WriteFile(slot, content, 0600); err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(filepath.Join(f.config.Authority.Directory, journalName))
	if err != nil {
		t.Fatal(err)
	}
	next, startErr := Start(f.config)
	trackLauncher(t, next)
	if next != nil || startErr == nil {
		t.Fatal("abandoned staging slot allowed publication")
	}
	after, err := os.ReadFile(slot)
	if err != nil || string(after) != string(content) {
		t.Fatal("unresolved staging bytes discarded")
	}
	journalAfter, err := os.ReadFile(filepath.Join(f.config.Authority.Directory, journalName))
	if err != nil || string(journalAfter) != string(prior) {
		t.Fatal("old journal overwritten on staging denial")
	}
	if _, err = ReadReceipt(f.config.Authority, l.Binding()); err != nil {
		t.Fatal("previous exact receipt lost")
	}
}
