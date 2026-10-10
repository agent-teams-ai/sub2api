package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// GatewayNativeLifetime observes one actual private ForwardGatewayRoute call.
// It has no SQL/effect authority. The owner supplies the request cancellation
// and an interrupt for the ORIGINAL net/http writer, before Gin wraps it.
type GatewayNativeLifetime struct {
	mu                                                        sync.Mutex
	writerMu                                                  sync.Mutex
	ctx                                                       context.Context
	cancel                                                    context.CancelFunc
	interrupt                                                 func()
	stop                                                      func() bool
	body                                                      *gatewayNativeOwnedBody
	outputBytes                                               int64
	lease                                                     time.Time
	admitted, sealed, entered, returned, bodyKnown, completed bool
	consumer, accountRef, generation                          string
}

type GatewayNativeLifetimeSnapshot struct {
	ContextDone        bool `json:"contextDone"`
	Sealed             bool `json:"sealed"`
	ForwardingReturned bool `json:"forwardingReturned"`
	Entered            bool `json:"entered"`
	BodyKnown          bool `json:"bodyKnown"`
	BodyClosed         bool `json:"bodyClosed"`
	CloseFailed        bool `json:"closeFailed"`
	Completed          bool `json:"completed"`
}

type gatewayNativeLifetimeKey struct{}

func NewGatewayNativeLifetime(ctx context.Context, cancel context.CancelFunc, interrupt func(), outputBytes int64) (*GatewayNativeLifetime, error) {
	if ctx == nil || cancel == nil || interrupt == nil || outputBytes < 1 || outputBytes > gatewayNativeResponseLimit {
		return nil, ErrGatewayNativeIdentity
	}
	l := &GatewayNativeLifetime{ctx: ctx, cancel: cancel, interrupt: interrupt, outputBytes: outputBytes}
	l.stop = context.AfterFunc(ctx, l.Cancel)
	return l, nil
}

func WithGatewayNativeLifetime(ctx context.Context, l *GatewayNativeLifetime) context.Context {
	return context.WithValue(ctx, gatewayNativeLifetimeKey{}, l)
}
func gatewayNativeLifetime(ctx context.Context) *GatewayNativeLifetime {
	l, _ := ctx.Value(gatewayNativeLifetimeKey{}).(*GatewayNativeLifetime)
	return l
}

// BindAccount snapshots the authenticated consumer and logical mapping before
// the callback. The actual encrypted row must match this scope at Forward.
func (l *GatewayNativeLifetime) BindAccount(consumer, accountRef, generation string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.admitted && !l.sealed && l.consumer == "" {
		l.consumer, l.accountRef, l.generation = consumer, accountRef, generation
	}
}
func (l *GatewayNativeLifetime) matchesScope(scope GatewayNativeCredentialScope) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.consumer == scope.Consumer && l.accountRef == scope.Account && l.generation == scope.Generation
}

func (l *GatewayNativeLifetime) Admit(lease time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	deadline, bounded := l.ctx.Deadline()
	if !bounded || !deadline.After(time.Now()) || l.sealed || l.admitted || l.ctx.Err() != nil || !lease.After(time.Now()) {
		return false
	}
	l.admitted, l.lease = true, lease
	return true
}

// Cancellation never waits for Forward or physical Close, and never holds an
// observer lock across either. A late body is immediately closed by attach.
func (l *GatewayNativeLifetime) Cancel() {
	l.mu.Lock()
	if l.sealed {
		l.mu.Unlock()
		return
	}
	l.sealed = true
	body := l.body
	l.mu.Unlock()
	l.cancel()
	// An in-flight forward needs its I/O interrupted. After Forward returns,
	// leave the HTTP writer deadline intact so net/http can finish its framing.
	// Order the decision AND action with finish, without holding the observer
	// mutex across the writer callback or waiting for Forward/physical Close.
	l.writerMu.Lock()
	l.mu.Lock()
	returned := l.returned
	l.mu.Unlock()
	if !returned {
		l.interrupt()
	}
	l.writerMu.Unlock()
	if body != nil {
		body.startClose()
	}
}

// NoForward records positive absence of a service/transport entry.
// It is valid only for a reservation that never invoked ForwardGatewayRoute.
func (l *GatewayNativeLifetime) NoForward() { l.finish() }

func (l *GatewayNativeLifetime) finish() {
	l.writerMu.Lock()
	l.mu.Lock()
	l.returned = true
	if !l.entered {
		l.bodyKnown = true
	}
	stop := l.stop
	l.mu.Unlock()
	l.writerMu.Unlock()
	if stop != nil {
		stop()
	}
	l.Cancel()
}
func (l *GatewayNativeLifetime) success() { l.mu.Lock(); l.completed = l.entered; l.mu.Unlock() }

// This is the existing sole native CAS, under the cancellation/lease latch.
// There is no additional permit ledger, account counter or account mutex.
func gatewayNativeEntered(ctx context.Context, entered *atomic.Bool) bool {
	l := gatewayNativeLifetime(ctx)
	if l != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		deadline, bounded := l.ctx.Deadline()
		if !bounded || !deadline.After(time.Now()) || !l.admitted || l.sealed || l.entered || l.ctx.Err() != nil || !l.lease.After(time.Now()) {
			return false
		}
	}
	if !entered.CompareAndSwap(false, true) {
		return false
	}
	if l != nil {
		l.entered = true
	}
	return true
}

func (l *GatewayNativeLifetime) Snapshot() GatewayNativeLifetimeSnapshot {
	l.mu.Lock()
	s := GatewayNativeLifetimeSnapshot{ContextDone: l.ctx.Err() != nil, Sealed: l.sealed, ForwardingReturned: l.returned, Entered: l.entered, BodyKnown: l.bodyKnown, Completed: l.completed}
	body := l.body
	l.mu.Unlock()
	if s.BodyKnown && body == nil {
		s.BodyClosed = true
	}
	if body != nil {
		select {
		case <-body.closed:
			s.BodyClosed = body.closeErr == nil
			s.CloseFailed = body.closeErr != nil
		default:
		}
	}
	return s
}

func (l *GatewayNativeLifetime) attach(resp *http.Response) {
	l.mu.Lock()
	l.bodyKnown = true
	if resp != nil && resp.Body != nil {
		l.body = &gatewayNativeOwnedBody{ReadCloser: resp.Body, remaining: l.outputBytes, closed: make(chan struct{})}
		resp.Body = l.body
	}
	body, sealed := l.body, l.sealed
	l.mu.Unlock()
	if sealed && body != nil {
		body.startClose()
	}
}

// Private cap identity survives the reader wrappers; public forwarding still
// returns ErrGatewayNativeEffectUnknown and exports only the fixed phase.
var errGatewayNativeOutputLimit = errors.New("gateway native output limit")

// Physical Close is performed exactly once. Both service defers and cancel
// observe the same cached result. At most one closer exists per bounded entry;
// blocked Close retains evidence and capacity instead of inventing closure.
type gatewayNativeOwnedBody struct {
	io.ReadCloser
	once      sync.Once
	closed    chan struct{}
	closeErr  error
	remaining int64 // the native forwarding reader is the sole reader
}

func (b *gatewayNativeOwnedBody) startClose() {
	b.once.Do(func() { go func() { b.closeErr = b.ReadCloser.Close(); close(b.closed) }() })
}
func (b *gatewayNativeOwnedBody) Close() error { b.startClose(); <-b.closed; return b.closeErr }
func (b *gatewayNativeOwnedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return 0, errGatewayNativeOutputLimit
	}
	return n, err
}

// Install this wrapper through the EXISTING service constructor at private
// composition time. No mutable per-call service replacement or stock wiring.
// Ordinary transport calls delegate unchanged, including TLS methods.
type gatewayNativeLifetimeUpstream struct{ HTTPUpstream }

func NewGatewayNativeLifetimeUpstream(upstream HTTPUpstream) (HTTPUpstream, error) {
	if upstream == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return &gatewayNativeLifetimeUpstream{HTTPUpstream: upstream}, nil
}
func (s *OpenAIGatewayService) GatewayNativeLifetimeReady() bool {
	if s == nil || s.accountRepo == nil {
		return false
	}
	_, ok := s.httpUpstream.(*gatewayNativeLifetimeUpstream)
	_, locked := s.accountRepo.(GatewayNativeAccountLocker)
	return ok && locked
}
func (u *gatewayNativeLifetimeUpstream) Do(r *http.Request, proxy string, id int64, concurrency int) (*http.Response, error) {
	l := gatewayNativeLifetime(r.Context())
	if l == nil {
		return u.HTTPUpstream.Do(r, proxy, id, concurrency)
	}
	// Ordinary account Concurrency/pool partitioning is inert on this private path.
	resp, err := u.HTTPUpstream.Do(r, proxy, id, 0)
	l.attach(resp)
	return resp, err
}
