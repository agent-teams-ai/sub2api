//go:build unit

package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
)

// No provider, credential files or provider keys. These are NEWTEST local HTTP
// body/lifetime observations, not a claimed SQL/native assembly qualification.
type NEWTESTLifetimeHTTP struct {
	client      *http.Client
	concurrency atomic.Int64
}

// Regression: cancellation pauses after sealing, Forward finishes, then the
// stale cancellation must not truncate net/http's final response framing.
func TestNEWTESTNativeLifetimeDelayedCancelPreservesCompletedHTTP(t *testing.T) {
	const terminal = "data: {\"type\":\"response.completed\"}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, terminal)
	}))
	defer upstream.Close()
	var interrupted atomic.Int32
	observed := make(chan GatewayNativeLifetimeSnapshot, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancelContext := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancelContext()
		started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		life, err := NewGatewayNativeLifetime(ctx, func() {
			cancelContext()
			close(started)
			<-release
		}, func() {
			interrupted.Add(1)
			if err := http.NewResponseController(w).SetWriteDeadline(time.Now()); err != nil {
				t.Error(err)
			}
		}, 4096)
		if err != nil || !life.Admit(time.Now().Add(time.Minute)) {
			t.Error("fixture admission failed")
			return
		}
		var entered atomic.Bool
		ctx = WithGatewayNativeLifetime(ctx, life)
		if !gatewayNativeEntered(ctx, &entered) {
			t.Error("fixture entry failed")
			return
		}
		wrapped, err := NewGatewayNativeLifetimeUpstream(&NEWTESTLifetimeHTTP{client: upstream.Client()})
		if err != nil {
			t.Error(err)
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := wrapped.Do(req, "", 1, 0)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, copyErr := io.Copy(w, resp.Body)
		closeErr := resp.Body.Close()
		if copyErr != nil || closeErr != nil {
			t.Error("fixture forwarding or physical Close failed", copyErr, closeErr)
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error("fixture HTTP flush failed", err)
			return
		}
		life.success()
		go func() { life.Cancel(); close(done) }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Error("fixture cancellation did not start")
			return
		}
		life.finish()
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture cancellation did not return")
			return
		}
		observed <- life.Snapshot()
	}))
	defer server.Close()
	client := *server.Client()
	client.Timeout = 10 * time.Second
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || string(data) != terminal {
		t.Fatalf("completed HTTP framing truncated: read=%v close=%v body=%q", readErr, closeErr, data)
	}
	if interrupted.Load() != 0 {
		t.Fatal("completed writer interrupted by delayed cancellation")
	}
	select {
	case s := <-observed:
		if !s.ContextDone || !s.Sealed || !s.Entered || !s.ForwardingReturned || !s.BodyKnown || !s.BodyClosed || s.CloseFailed || !s.Completed {
			t.Fatalf("wrong completed closure facts: %+v", s)
		}
	case <-time.After(time.Second):
		t.Fatal("completed closure facts not observed")
	}
}

func (u *NEWTESTLifetimeHTTP) Do(r *http.Request, _ string, _ int64, concurrency int) (*http.Response, error) {
	u.concurrency.Store(int64(concurrency))
	return u.client.Do(r)
}
func (u *NEWTESTLifetimeHTTP) DoWithTLS(r *http.Request, proxy string, id int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(r, proxy, id, concurrency)
}

func TestNEWTESTNativeLifetimeHeldBodyCancel(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamDone)
	}))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	var interrupted atomic.Int32
	life, err := NewGatewayNativeLifetime(ctx, cancel, func() { interrupted.Add(1) }, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("admission rejected")
	}
	var cas atomic.Bool
	if !gatewayNativeEntered(WithGatewayNativeLifetime(ctx, life), &cas) {
		t.Fatal("entry rejected")
	}
	raw := &NEWTESTLifetimeHTTP{client: upstream.Client()}
	wrapped, err := NewGatewayNativeLifetimeUpstream(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequestWithContext(WithGatewayNativeLifetime(ctx, life), http.MethodPost, upstream.URL, strings.NewReader(`{"input":"NEWTEST"}`))
	resp, err := wrapped.Do(r, "", 1, 91)
	if err != nil {
		t.Fatal(err)
	}
	if raw.concurrency.Load() != 0 {
		t.Fatal("private ordinary concurrency was forwarded")
	}
	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, resp.Body); readDone <- err }()
	life.Cancel()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("blocked HTTP body read survived cancellation")
	}
	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Fatal("upstream request lifetime survived cancellation")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	life.finish()
	s := life.Snapshot()
	if !s.ContextDone || !s.ForwardingReturned || !s.BodyKnown || !s.BodyClosed || s.Completed {
		t.Fatalf("wrong closure evidence: %+v", s)
	}
	if interrupted.Load() == 0 {
		t.Fatal("writer was not interrupted")
	}
}

type NEWTESTCloseFailure struct {
	io.ReadCloser
	closes atomic.Int32
}

func (b *NEWTESTCloseFailure) Close() error {
	b.closes.Add(1)
	_ = b.ReadCloser.Close()
	return errors.New("NEWTEST physical close failure")
}

func TestNEWTESTNativeLifetimeRealBodyCloseErrorIsRetained(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "NEWTEST") }))
	defer upstream.Close()
	resp, err := upstream.Client().Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	actual := &NEWTESTCloseFailure{ReadCloser: resp.Body}
	resp.Body = actual
	ctx, cancel := context.WithCancel(context.Background())
	life, _ := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
	life.attach(resp)
	life.Cancel()
	firstCloseErr := resp.Body.Close()
	secondCloseErr := resp.Body.Close()
	if firstCloseErr == nil || secondCloseErr == nil {
		t.Fatal("cached physical close failure lost")
	}
	life.finish()
	s := life.Snapshot()
	if !s.CloseFailed || s.BodyClosed || actual.closes.Load() != 1 {
		t.Fatalf("close was inferred or repeated: %+v / %d", s, actual.closes.Load())
	}
}

func TestNEWTESTNativeLifetimeBlockedCloseDoesNotBlockCancel(t *testing.T) {
	gate := make(chan struct{})
	body := &NEWTESTBlockedClose{ReadCloser: io.NopCloser(strings.NewReader("NEWTEST")), gate: gate}
	ctx, cancel := context.WithCancel(context.Background())
	life, _ := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
	life.attach(&http.Response{Body: body})
	done := make(chan struct{})
	go func() { life.Cancel(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel waited on physical Close")
	}
	s := life.Snapshot()
	if s.BodyClosed {
		t.Fatal("blocked close certified closure")
	}
	close(gate)
	if err := life.body.Close(); err != nil {
		t.Fatal(err)
	}
	life.finish()
}

type NEWTESTBlockedClose struct {
	io.ReadCloser
	gate chan struct{}
}

func (b *NEWTESTBlockedClose) Close() error { <-b.gate; return b.ReadCloser.Close() }

func TestNEWTESTNativeLifetimeOvercapAndSealedEntry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "NEWTEST too large") }))
	defer upstream.Close()
	ctx, cancel := context.WithCancel(context.Background())
	life, _ := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4)
	wrapped, _ := NewGatewayNativeLifetimeUpstream(&NEWTESTLifetimeHTTP{client: upstream.Client()})
	req, _ := http.NewRequestWithContext(WithGatewayNativeLifetime(ctx, life), http.MethodGet, upstream.URL, nil)
	resp, err := wrapped.Do(req, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err != ErrGatewayNativeEffectUnknown {
		t.Fatal("output cap was not enforced", err)
	}
	_ = resp.Body.Close()
	life.finish()
	if life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("sealed lifetime rearmed")
	}
	var cas atomic.Bool
	if gatewayNativeEntered(WithGatewayNativeLifetime(ctx, life), &cas) {
		t.Fatal("sealed lifetime entered")
	}
}

func TestNEWTESTNativeLifetimeOriginalWriterBlockedWrite(t *testing.T) {
	started := make(chan struct{})
	returned := make(chan struct{})
	downstream := httptest.NewServer(http.HandlerFunc(func(raw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		ctrl := http.NewResponseController(raw)
		life, _ := NewGatewayNativeLifetime(ctx, cancel, func() { _ = ctrl.SetWriteDeadline(time.Now()) }, 4096)
		close(started)
		go func() { <-ctx.Done(); life.Cancel() }()
		time.AfterFunc(30*time.Millisecond, cancel)
		block := strings.Repeat("N", 1<<20)
		for i := 0; i < 128; i++ {
			if _, err := io.WriteString(raw, block); err != nil {
				break
			}
		}
		life.NoForward()
		close(returned)
	}))
	defer downstream.Close()
	resp, err := downstream.Client().Get(downstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-started
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("original writer deadline did not interrupt blocked write")
	}
}

func TestNEWTESTNativeLifetimeSecondCallDoesNotReenterHTTP(t *testing.T) {
	var entries atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entries.Add(1); _, _ = io.WriteString(w, "NEWTEST") }))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer life.finish()
	if !life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("original lifetime was not admitted")
	}
	wrapped, _ := NewGatewayNativeLifetimeUpstream(&NEWTESTLifetimeHTTP{client: upstream.Client()})
	invoke := func() bool {
		var freshCallCAS atomic.Bool
		requestCtx := WithGatewayNativeLifetime(ctx, life)
		if !gatewayNativeEntered(requestCtx, &freshCallCAS) {
			return false
		}
		req, _ := http.NewRequestWithContext(requestCtx, http.MethodPost, upstream.URL, strings.NewReader("NEWTEST"))
		resp, err := wrapped.Do(req, "", 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return true
	}
	if !invoke() || invoke() || entries.Load() != 1 {
		t.Fatal("a second call reused one admitted lifetime", entries.Load())
	}
}

// Exercise the existing native response parser and the physical body wrapper
// against a local HTTP endpoint, with no native row, provider key or SQL claim.
// Encrypted native assembly remains the separate primary fixture gate.
func TestNEWTESTNativeLifetimeActualSSEParser(t *testing.T) {
	terminal := "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"
	for _, tc := range []struct {
		name, wire string
		cap        int64
		success    bool
	}{
		{"terminal", terminal, 4096, true},
		{"partial", strings.TrimSuffix(terminal, "\n\n"), 4096, false},
		{"overcap", terminal, 4, false},
		{"duplicateType", "data: {\"type\":\"response.completed\",\"type\":\"response.created\",\"response\":{\"status\":\"completed\"}}\n\n", 4096, false},
		{"invalidUTF8", "data: {\"type\":\"response.created\",\"value\":\"\xff\"}\n\n", 4096, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/responses" {
					t.Error("unexpected native response endpoint", r.URL.Path)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tc.wire)
			}))
			defer upstream.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, tc.cap)
			if err != nil {
				t.Fatal(err)
			}
			defer life.finish()
			wrapped, _ := NewGatewayNativeLifetimeUpstream(&NEWTESTLifetimeHTTP{client: upstream.Client()})
			svc := &OpenAIGatewayService{httpUpstream: wrapped, cfg: rawChatCompletionsTestConfig()}
			a := &Account{ID: 7, Name: "NEWTESTparser", Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"base_url": upstream.URL}}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			requestCtx := WithGatewayNativeLifetime(ctx, life)
			_, err = svc.forwardGatewayNativeResponses(requestCtx, c, a, []byte(`{"model":"NEWTESTmodel","input":"NEWTEST","store":false,"stream":true,"service_tier":"default"}`))
			if tc.success {
				if err != nil || rec.Body.String() != terminal {
					t.Fatal("successful terminal delivery failed", err, rec.Body.String())
				}
			} else if !errors.Is(err, ErrGatewayNativeEffectUnknown) {
				t.Fatal("unqualified output was not unknown", err)
			}
			life.finish()
			s := life.Snapshot()
			if !s.ContextDone || !s.ForwardingReturned || !s.BodyClosed || s.CloseFailed || s.Completed {
				t.Fatal("parser/body observation invented effect or lost physical closure", s)
			}
		})
	}
}
