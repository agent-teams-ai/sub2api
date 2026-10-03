//go:build linux

package gatewaylauncher

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var (
	ErrConfig   = errors.New("launcher: invalid fixed configuration")
	ErrStart    = errors.New("launcher: child start failed")
	ErrNotReady = errors.New("launcher: child readiness unproven")
	ErrPending  = errors.New("launcher: exact child teardown pending")
)

// AuthorityConfig belongs to the private trusted supervisor composition. It
// must never be constructed from public account or execution request fields.
type AuthorityConfig struct {
	Directory string
	OriginRef string
}

// Config is a server-owned snapshot for a single foreground private engine.
// There is no ambient environment inheritance, shell, restart or public API.
// Credentials are composed separately; this package loads no provider keys.
type Config struct {
	Authority  AuthorityConfig
	EnginePath string
	Args       []string
	Env        []string
	EngineUID  uint32
	EngineGID  uint32
}

// Launcher retains the parent lock reference until positively observed child
// exit. On supervisor death the same open description lives in engine FD 3.
type Launcher struct {
	mu            sync.Mutex
	a             *authority
	binding       Binding
	cmd           *exec.Cmd
	done          chan struct{}
	readyDone     chan struct{}
	readyRead     *os.File
	readyObserved bool
	readyDurable  bool
	receipt       *Receipt
	publications  chan publication
	retired       chan struct{}
}

type publication struct {
	ready  bool
	result chan publicationResult
}

type publicationResult struct {
	receipt Receipt
	err     error
}

func validAuthority(c AuthorityConfig) bool {
	return c.OriginRef != "" && len(c.OriginRef) <= 512 && !strings.ContainsRune(c.OriginRef, 0)
}

// Pin the configured executable through all protected ancestors. Root-only
// write authority prevents a less-privileged engine from swapping this path
// between validation and exec. An executable FD is not a second lock holder.
func checkEngine(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrConfig
	}
	parent := filepath.Dir(path)
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafe
	}
	d := os.NewFile(uintptr(fd), "engine-parent")
	s, err := statFD(d)
	if err != nil || s.Uid != 0 || s.Mode&syscall.S_IFMT != syscall.S_IFDIR || s.Mode&0022 != 0 {
		_ = d.Close()
		return ErrUnsafe
	}
	for _, part := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(int(d.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		_ = d.Close()
		if e != nil {
			return ErrUnsafe
		}
		d = os.NewFile(uintptr(next), "engine-parent")
		s, e := statFD(d)
		if e != nil || s.Uid != 0 || s.Mode&0022 != 0 {
			_ = d.Close()
			return ErrUnsafe
		}
	}
	defer func() { _ = d.Close() }()
	n, err := syscall.Openat(int(d.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrStart
	}
	f := os.NewFile(uintptr(n), "engine-image")
	defer func() { _ = f.Close() }()
	s, err = statFD(f)
	if err != nil || s.Uid != 0 || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&0022 != 0 || s.Mode&0111 == 0 || s.Mode&06000 != 0 || s.Nlink != 1 {
		return ErrUnsafe
	}
	// A file capability could let the separate engine UID bypass protected
	// filesystem authority. Root-owned ancestors make this pathname stable
	// against the engine while checking its privilege-bearing attribute.
	ncaps, e := syscall.Getxattr(path, "security.capability", nil)
	if ncaps > 0 || (e != nil && e != syscall.ENODATA && e != syscall.ENOTSUP) {
		return ErrUnsafe
	}
	var magic [4]byte
	if _, err = io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		return ErrUnsafe
	}
	return nil
}

func snapshot(c Config) (Config, error) {
	if !validAuthority(c.Authority) || c.EngineUID == 0 || c.EngineGID == 0 || c.EngineUID == ^uint32(0) || c.EngineGID == ^uint32(0) {
		return Config{}, ErrConfig
	}
	c.Args = append([]string(nil), c.Args...)
	c.Env = append([]string(nil), c.Env...)
	if len(c.Args) > 128 || len(c.Env) > 128 {
		return Config{}, ErrConfig
	}
	total := len(c.EnginePath)
	for _, s := range c.Args {
		if strings.ContainsRune(s, 0) {
			return Config{}, ErrConfig
		}
		total += len(s)
	}
	seen := map[string]bool{}
	for _, s := range c.Env {
		key, _, ok := strings.Cut(s, "=")
		if !ok || key == "" || strings.ContainsRune(s, 0) || strings.HasPrefix(key, "GATEWAY_LAUNCHER_") || seen[key] {
			return Config{}, ErrConfig
		}
		seen[key] = true
		total += len(s)
	}
	if total > 64*1024 {
		return Config{}, ErrConfig
	}
	if err := checkEngine(c.EnginePath); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Start returns a nonnil handle whenever exec succeeded, INCLUDING on a later
// metadata or bootstrap failure. The caller must retain and shut down that
// handle. A nil handle means this call never started an engine. Startup errors
// never cause an old process to be signalled or its lock to be released.
func Start(config Config) (*Launcher, error) {
	c, err := snapshot(config)
	if err != nil {
		return nil, err
	}
	a, err := openAuthority(c.Authority.Directory)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			a.close()
		}
	}()
	if err = a.acquire(true); err != nil {
		return nil, err
	}
	boot, err := bootID()
	if err != nil {
		return nil, err
	}
	j, exists, err := a.read()
	if err != nil {
		return nil, err
	}
	if exists {
		if err = a.validate(j, c.Authority.OriginRef, boot); err != nil {
			return nil, err
		}
		if err = a.recover(&j); err != nil {
			return nil, err
		}
	}
	if len(j.Receipts) >= retainedLimit {
		return nil, ErrSaturated
	}
	inc, err := randomID()
	if err != nil {
		return nil, err
	}
	b := Binding{OriginRef: c.Authority.OriginRef, BootID: boot, Incarnation: inc, LockDevice: a.device, LockInode: a.inode}
	j.Version = 1
	j.Current = record{b, "reserved"}
	// This durable reservation prevents a crash between exec and recording
	// process birth from erasing an unresolved incarnation. Such a crash fails
	// closed; timestamps and a later fresh boot cannot repair missing identity.
	if err = a.write(j); err != nil {
		return nil, err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		j.Current.Phase = "start-failed"
		if e := a.write(j); e != nil {
			return nil, e
		}
		return nil, ErrStart
	}
	gateR, gateW, err := os.Pipe()
	if err != nil {
		_ = readyR.Close()
		_ = readyW.Close()
		j.Current.Phase = "start-failed"
		if e := a.write(j); e != nil {
			return nil, e
		}
		return nil, ErrStart
	}
	cmd := exec.Command(c.EnginePath, c.Args...)
	cmd.Env = append(c.Env,
		"GATEWAY_LAUNCHER_LOCK_FD=3",
		"GATEWAY_LAUNCHER_READY_FD=4",
		"GATEWAY_LAUNCHER_GATE_FD=5",
		"GATEWAY_LAUNCHER_ORIGIN_REF="+c.Authority.OriginRef,
		"GATEWAY_LAUNCHER_ENGINE_INCARNATION="+b.Incarnation)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.EngineUID, Gid: c.EngineGID, Groups: []uint32{}}}
	// ExtraFiles duplicates the SAME open lock description and clears CLOEXEC
	// on child FD 3. No reopen and no independently acquired child lock.
	cmd.ExtraFiles = []*os.File{a.lock, readyW, gateR}
	err = cmd.Start()
	_ = readyW.Close()
	_ = gateR.Close()
	if err != nil {
		_ = readyR.Close()
		_ = gateW.Close()
		j.Current.Phase = "start-failed"
		if e := a.write(j); e != nil {
			return nil, e
		}
		return nil, ErrStart
	}
	keep = true
	l := &Launcher{a: a, binding: b, cmd: cmd, done: make(chan struct{}), readyDone: make(chan struct{}), readyRead: readyR, publications: make(chan publication), retired: make(chan struct{})}
	b.PID = cmd.Process.Pid
	b.BirthTicks, _, err = birth(b.PID)
	l.binding = b
	go func() {
		_ = cmd.Wait() // any exit status proves exact child exit; never a later PID
		close(l.done)
	}()
	go func() {
		// Exactly one readiness byte followed by EOF. The local pipe cannot be
		// forged by account callers; it is not a provider/paid readiness probe.
		p, e := io.ReadAll(io.LimitReader(readyR, 2))
		l.mu.Lock()
		l.readyObserved = e == nil && string(p) == "R"
		l.mu.Unlock()
		close(l.readyDone)
	}()
	// One lifetime worker owns all post-start durability. Callers can abandon
	// their wait, but never its authority handle or in-flight publication.
	go l.publish()
	defer func() { _ = gateW.Close() }()
	if err != nil || !fullBinding(b) {
		return l, ErrEvidence
	}
	j.Current = record{b, "starting"}
	if err = a.write(j); err != nil {
		return l, err
	}
	// No engine transport work is allowed before this durable starting fact.
	if _, err = gateW.Write([]byte("G")); err != nil {
		return l, ErrStart
	}
	return l, nil
}

// Binding returns a value copy, never writable launch configuration.
func (l *Launcher) Binding() Binding { return l.binding }

// AwaitReady observes the private bootstrap handshake, then durably publishes
// ready before returning. A timeout has no retirement or effect implication.
func (l *Launcher) AwaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ErrNotReady
	case <-l.done:
		return ErrNotReady
	case <-l.readyDone:
	}
	return l.publication(ctx, true).err
}

// Unbuffered admission leaves at most one publication outstanding. Retries
// wait on the same worker without spawning workers or queuing durable work.
func (l *Launcher) publication(ctx context.Context, ready bool) publicationResult {
	pending := ErrPending
	var exited <-chan struct{}
	if ready {
		pending = ErrNotReady
		exited = l.done
	}
	if ctx.Err() != nil {
		return publicationResult{err: pending}
	}
	p := publication{ready: ready, result: make(chan publicationResult, 1)}
	select {
	case <-ctx.Done():
		return publicationResult{err: pending}
	case <-exited:
		return publicationResult{err: pending}
	case <-l.retired:
		if ready {
			return publicationResult{err: ErrNotReady}
		}
		return publicationResult{receipt: *l.receipt}
	case l.publications <- p:
	}
	select {
	case <-ctx.Done():
		return publicationResult{err: pending}
	case <-exited:
		return publicationResult{err: pending}
	case result := <-p.result:
		if ctx.Err() != nil {
			return publicationResult{err: pending}
		}
		return result
	}
}

func (l *Launcher) publish() {
	for p := range l.publications {
		l.mu.Lock()
		var result publicationResult
		if p.ready {
			result.err = l.publishReady()
		} else {
			result.receipt, result.err = l.publishRetirement()
		}
		finished := l.receipt != nil
		l.mu.Unlock()
		// A detached caller cannot block this worker; durable state is retained
		// on the launcher and subsequent callers can read the exact same fact.
		p.result <- result
		if finished {
			close(l.retired)
			return
		}
	}
}

func (l *Launcher) publishReady() error {
	select {
	case <-l.done:
		return ErrNotReady
	default:
	}
	if !l.readyObserved {
		return ErrNotReady
	}
	if l.readyDurable {
		return nil
	}
	if err := l.a.checkLock(); err != nil {
		return err
	}
	n, state, err := birth(l.binding.PID)
	if err != nil || n != l.binding.BirthTicks || state == 'Z' || state == 'X' {
		return ErrNotReady
	}
	j, exists, err := l.a.read()
	if err != nil {
		return err
	}
	if !exists || j.Current.Binding != l.binding || (j.Current.Phase != "starting" && j.Current.Phase != "ready") {
		return ErrBinding
	}
	// A failed directory fsync can leave ready bytes visible. read has now
	// re-established durability, and this exact live child actually signalled R.
	if j.Current.Phase == "ready" {
		l.readyDurable = true
		return nil
	}
	j.Current.Phase = "ready"
	if err = l.a.write(j); err != nil {
		return err
	}
	l.readyDurable = true
	return nil
}

// Wait certifies observed exact child exit and absence of retained lock holders.
// It is retryable after pending holders or durability errors. No receipt is
// returned until the protected replacement AND directory fsync succeed.
func (l *Launcher) Wait(ctx context.Context) (Receipt, error) {
	select {
	case <-ctx.Done():
		return Receipt{}, ErrPending
	case <-l.done:
	}
	r := l.publication(ctx, false)
	return r.receipt, r.err
}

func (l *Launcher) publishRetirement() (Receipt, error) {
	if l.receipt != nil {
		return *l.receipt, nil
	}
	if !fullBinding(l.binding) {
		return Receipt{}, ErrEvidence
	}
	_ = l.readyRead.Close()
	if err := l.a.checkLock(); err != nil {
		return Receipt{}, err
	}
	if l.a.lock != nil {
		// Child exit is observed. Drop our reference and try a NEW description:
		// flock on the original description cannot detect retained duplicates.
		_ = l.a.lock.Close()
		l.a.lock = nil
	}
	if err := l.a.acquire(false); err != nil {
		return Receipt{}, err
	}
	if l.a.device != l.binding.LockDevice || l.a.inode != l.binding.LockInode {
		return Receipt{}, ErrBinding
	}
	j, exists, err := l.a.read()
	if err != nil {
		return Receipt{}, err
	}
	if !exists {
		return Receipt{}, ErrEvidence
	}
	if err = l.a.validate(j, l.binding.OriginRef, l.binding.BootID); err != nil {
		return Receipt{}, err
	}
	// Another trusted supervisor can win the reacquisition race, durably
	// recover this exact receipt and begin a fresh incarnation. Preserve it.
	for _, r := range j.Receipts {
		if r.Binding == l.binding {
			l.receipt = &r
			l.a.close()
			return r, nil
		}
	}
	if j.Current.Binding != l.binding {
		return Receipt{}, ErrBinding
	}
	if len(j.Receipts) >= retainedLimit {
		return Receipt{}, ErrSaturated
	}
	r := Receipt{l.binding, LocalTeardownScope, "observed-child-exit"}
	j.Receipts = append(j.Receipts, r)
	j.Current.Phase = "retired"
	if err = l.a.write(j); err != nil {
		return Receipt{}, err
	}
	l.receipt = &r
	l.a.close()
	return r, nil
}

// Shutdown signals only the exact child handle. It never escalates to killing
// an old incarnation or restarts a process. If the child ignores cancellation,
// caller deadline returns pending with the inherited lock and evidence intact.
func (l *Launcher) Shutdown(ctx context.Context) (Receipt, error) {
	select {
	case <-l.done:
	default:
		if err := l.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return Receipt{}, ErrPending
		}
	}
	return l.Wait(ctx)
}

// ReadReceipt is a root-only private composition API. The complete original
// binding is mandatory; there is no lookup by PID, latest boot or incarnation
// string alone, and it does not modify kernel or SQL state.
func ReadReceipt(c AuthorityConfig, expected Binding) (Receipt, error) {
	if !validAuthority(c) || !fullBinding(expected) || expected.OriginRef != c.OriginRef {
		return Receipt{}, ErrBinding
	}
	a, err := openAuthority(c.Directory)
	if err != nil {
		return Receipt{}, err
	}
	defer a.close()
	f, err := a.openFile(lockName, syscall.O_RDWR)
	if err != nil {
		return Receipt{}, err
	}
	s, err := statFD(f)
	_ = f.Close()
	if err != nil {
		return Receipt{}, ErrUnsafe
	}
	a.device, a.inode = uint64(s.Dev), s.Ino
	boot, err := bootID()
	if err != nil {
		return Receipt{}, err
	}
	if expected.BootID != boot || expected.LockDevice != a.device || expected.LockInode != a.inode {
		return Receipt{}, ErrBinding
	}
	j, exists, err := a.read()
	if err != nil {
		return Receipt{}, err
	}
	if !exists {
		return Receipt{}, ErrEvidence
	}
	if err = a.validate(j, c.OriginRef, boot); err != nil {
		return Receipt{}, err
	}
	if err = a.checkLock(); err != nil {
		return Receipt{}, err
	}
	for _, r := range j.Receipts {
		if r.Binding == expected {
			return r, nil
		}
	}
	return Receipt{}, ErrBinding
}
