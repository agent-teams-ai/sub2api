//go:build unit

package gatewaytransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var fixtureProviderKey = gatewayIngressGuardFixtureOpaque()
var fixtureExecutionToken = gatewayIngressGuardFixtureOpaque()
var fixtureCallbackToken = gatewayIngressGuardFixtureOpaque()
var fixtureCleanupToken = gatewayIngressGuardFixtureOpaque()
var fixtureForeignToken = gatewayIngressGuardFixtureOpaque()

// Assert the specified source bounds over HTTP, independently of the
// implementation's channel capacities (changing those must change the result).
const fixtureExecutionAdmissionCap = 32
const fixtureControlAdmissionCap = 8

const (
	ownerExecution   = "11111111-1111-4111-8111-111111111111"
	ownerIssuer      = "22222222-2222-4222-8222-222222222222"
	ownerGeneration  = "33333333-3333-4333-8333-333333333333"
	ownerWorker      = "44444444-4444-4444-8444-444444444444"
	ownerIncarnation = "55555555-5555-4555-8555-555555555555"
	ownerAccount     = "66666666-6666-4666-8666-666666666666"
)

// Concrete disposable fixtures use the accepted registry wire, without
// asserting durable SQL authority or depending on unfinished helper names.
func ownerRequest() Request {
	return Request{RequestRef: "fixture-request", Worker: ownerWorker,
		Admission: Admission{ExecutionRef: ownerExecution, IssuerEpoch: ownerIssuer,
			InvocationRef: "fixture-invocation", AttemptRef: "fixture-attempt", AccountRef: ownerAccount,
			AuthorizationEpoch: 3, SubjectRef: "fixture-subject", PolicyRevision: 4, BindingRevision: 5,
			ProfileID: service.GatewayMiMoResponsesProfile,
			Limits:    Limits{Requests: 2, Concurrency: 1, RequestBytes: 4096, OutputBytes: 4096, Tokens: 100},
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)},
		Descriptor: service.GatewayNativeRoute{AccountID: 7, Generation: ownerGeneration,
			CreatedAt: time.Date(2026, 10, 3, 1, 2, 3, 123456789, time.UTC),
			Profile:   service.GatewayMiMoResponsesProfile, BaseURL: "https://fixture.invalid", Model: "fixture-model"},
		Payload: json.RawMessage(`{"model":"fixture-model","input":"fixture","store":false,"stream":true,"service_tier":"default"}`)}
}

func ownerReply(req admitRequest) admitReply {
	p := Proof{ExecutionRef: req.Admission.ExecutionRef, RequestRef: req.RequestRef,
		Worker: req.Worker, Token: "fixture-proof", Native: req.Native}
	d := req.Descriptor
	return admitReply{ConsumerID: req.ConsumerID, Admission: req.Admission,
		Status: requestStatus{RequestRef: req.RequestRef, Effect: "dispatch_started"},
		Dispatch: &dispatch{Descriptor: kernelDescriptor{d.Generation, d.Generation, d.Profile},
			ExecutionRef: p.ExecutionRef, RequestRef: p.RequestRef, Limits: req.Admission.Limits,
			Deadline: req.Admission.ExpiresAt, Closure: p},
		NativeDescriptor: &d, LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
}

// Sealed lost-ACK state fixture never admits or enters a provider. Other tests
// below run the real constructor and actual HTTP/TLS forwarding boundaries.
func ownerRegistry() *Handler {
	return &Handler{cfg: Config{MaxEntries: 1, CleanupTimeout: time.Second,
		Enrollment: Enrollment{"fixture-origin", ownerIncarnation, "fixture-qualification"}},
		entries: make(map[transportKey]*reservation), requests: make(map[requestKey]transportKey)}
}

func ownerReserve(t *testing.T, h *Handler, r Request) *reservation {
	t.Helper()
	deadline, err := parseInstant(r.Admission.ExpiresAt)
	if err != nil {
		t.Fatal("invalid fixture deadline", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	e, first, err := h.reserve("fixture-consumer", r, ctx, cancel, func() {})
	if err != nil || !first {
		cancel()
		t.Fatal("original reservation failed", err)
	}
	t.Cleanup(func() { h.seal(e); e.life.NoForward() })
	return e
}

type ownerHTTPResult struct {
	code     int
	receipt  Receipt
	err      error
	body     []byte
	duration time.Duration
}

// No testing.Fatal in the forwarding goroutine; cancellation can interrupt
// the stream, but control responses must arrive and decode without ambiguity.
func ownerPOST(client *http.Client, origin, path, token string, input any) ownerHTTPResult {
	start := time.Now()
	raw, err := json.Marshal(input)
	if err != nil {
		return ownerHTTPResult{err: err}
	}
	req, err := http.NewRequest("POST", origin+transportsPath+path, bytes.NewReader(raw))
	if err != nil {
		return ownerHTTPResult{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return ownerHTTPResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	result := ownerHTTPResult{code: resp.StatusCode, err: err, body: data, duration: time.Since(start)}
	if len(data) > 65536 {
		result.err = errors.New("fixture response exceeded cap")
	} else if err == nil && resp.StatusCode == http.StatusAccepted {
		result.err = json.Unmarshal(data, &result.receipt)
	}
	return result
}

// Controlled storage is not SQL qualification. The actual service, AEAD
// Authorization boundary, TLS provider, registry and private HTTP paths run.
type ownerFixtureRepo struct {
	service.AccountRepository
	row *service.Account
	mu  sync.Mutex
}

func (r *ownerFixtureRepo) GetByID(context.Context, int64) (*service.Account, error) {
	return r.row, nil
}
func (r *ownerFixtureRepo) LockGatewayNativeAccount(context.Context, int64) (*service.Account, func(), error) {
	r.mu.Lock()
	return r.row, r.mu.Unlock, nil
}

type ownerFixtureHTTP struct {
	client       *http.Client
	closeFails   bool
	closeGate    <-chan struct{}
	closeStarted chan<- struct{}
}

func (u *ownerFixtureHTTP) Do(r *http.Request, _ string, _ int64, concurrency int) (*http.Response, error) {
	if concurrency != 0 {
		return nil, errors.New("ordinary limiter entered")
	}
	resp, err := u.client.Do(r)
	if err == nil && u.closeGate != nil {
		resp.Body = &ownerBlockedClose{ReadCloser: resp.Body, gate: u.closeGate, started: u.closeStarted}
	}
	if err == nil && u.closeFails {
		resp.Body = &ownerCloseFailure{ReadCloser: resp.Body}
	}
	return resp, err
}
func (u *ownerFixtureHTTP) DoWithTLS(r *http.Request, proxy string, id int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(r, proxy, id, concurrency)
}

// Regression: cancellation does not certify closure while the physical Close
// is delayed, even when the HTTP request itself has already been interrupted.
type ownerBlockedClose struct {
	io.ReadCloser
	gate    <-chan struct{}
	started chan<- struct{}
}

func (b *ownerBlockedClose) Close() error {
	b.started <- struct{}{}
	<-b.gate
	return b.ReadCloser.Close()
}

type ownerCloseFailure struct{ io.ReadCloser }

func (b *ownerCloseFailure) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("fixture physical close failure")
}

func TestGatewayNativeOwnerHTTPClosureOnActualCompletedTransport(t *testing.T) {
	// Regression: partial provider output stalls forever despite server IdleTimeout;
	// timeout is mistaken for completion or releases unknown occupied evidence.
	for _, mode := range []string{"completed", "paused", "held", "closeFailed", "idle", "idleCloseFailed", "idleBlockedClose"} {
		t.Run(mode, func(t *testing.T) {
			var entries, admits, acks atomic.Int32
			closeGate := make(chan struct{})
			closeStarted := make(chan struct{}, 1)
			var releaseClose sync.Once
			defer releaseClose.Do(func() { close(closeGate) })
			providerEntered := make(chan struct{}, 1)
			providerClosed := make(chan struct{}, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entries.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+fixtureProviderKey || r.URL.Path != "/v1/responses" {
					t.Error("native provider authority changed")
				}
				select {
				case providerEntered <- struct{}{}:
				default:
				}
				w.Header().Set("Content-Type", "text/event-stream")
				if mode == "held" || strings.HasPrefix(mode, "idle") || mode == "paused" {
					_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
				} else {
					_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
				}
				flusher, ok := w.(http.Flusher)
				if !ok {
					t.Error("fixture response cannot flush")
					return
				}
				flusher.Flush()
				if mode == "paused" {
					// A legitimate reasoning pause longer than the old hardcoded
					// second must survive the trusted two-second fixture policy.
					select {
					case <-time.After(1200 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
					_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")
					flusher.Flush()
				}
				// Completion must close the live body without waiting for EOF.
				<-r.Context().Done()
				select {
				case providerClosed <- struct{}{}:
				default:
				}
			}))
			defer upstream.Close()
			custodyKey := make([]byte, 32)
			if _, err := rand.Read(custodyKey); err != nil {
				t.Fatal(err)
			}
			custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": custodyKey})
			if err != nil {
				t.Fatal(err)
			}
			scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: ownerAccount, Generation: ownerGeneration, Purpose: service.GatewayCredentialPurpose}
			envelope, err := custody.Seal(scope, fixtureProviderKey)
			if err != nil {
				t.Fatal(err)
			}
			row := &service.Account{ID: 7, Name: "fixture", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, CreatedAt: time.Now().UTC(),
				Credentials: map[string]any{"api_key": envelope, "base_url": upstream.URL}, Extra: map[string]any{service.GatewayGenerationExtraKey: ownerGeneration, service.GatewayProfileExtraKey: service.GatewayMiMoResponsesProfile,
					service.GatewayModelExtraKey: "fixture-model", service.GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses", "openai_passthrough": true,
					"native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
			repo := &ownerFixtureRepo{row: row}
			providerHTTP := &ownerFixtureHTTP{client: upstream.Client(), closeFails: mode == "closeFailed" || mode == "idleCloseFailed"}
			if mode == "idleBlockedClose" {
				providerHTTP.closeGate, providerHTTP.closeStarted = closeGate, closeStarted
			}
			u, err := service.NewGatewayNativeLifetimeUpstream(providerHTTP)
			if err != nil {
				t.Fatal(err)
			}
			svcCfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}}
			gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, svcCfg, nil, nil, nil, nil, nil, u, nil, nil, nil, nil, nil, nil, nil, nil)
			proofCh := make(chan Proof, 1)
			callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				admits.Add(1)
				var input admitRequest
				if r.URL.Path != "/private/native/v1/admit" || r.Header.Get("Authorization") != "Bearer "+fixtureCallbackToken {
					t.Error("wrong fixed admission authority")
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil {
					t.Error("invalid admit")
					w.WriteHeader(400)
					return
				}
				reply := ownerReply(input)
				select {
				case proofCh <- reply.Dispatch.Closure:
				default:
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer callback.Close()
			var denyAuthority atomic.Bool
			cfg := Config{Gateway: gateway, Custody: custody, Enrollment: Enrollment{"fixture-origin", ownerIncarnation, "fixture-qualification"},
				Profile:    QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: "fixture-model", BaseURL: upstream.URL, QualificationRef: "fixture-qualification", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 200},
				MaxEntries: 4, EnvelopeBytes: 8192, CallbackBytes: 65536, CallbackOrigin: callback.URL, CallbackCredential: fixtureCallbackToken, CallbackTimeout: time.Second, IOTimeout: 5 * time.Second, ProviderReadIdle: time.Second, CleanupTimeout: time.Second,
				Authorize: func(r *http.Request) (Peer, error) {
					switch r.Header.Get("Authorization") {
					case "Bearer " + fixtureExecutionToken:
						return Peer{"fixture-consumer", "execution"}, nil
					case "Bearer " + fixtureCleanupToken:
						return Peer{"fixture-consumer", "cleanup"}, nil
					case "Bearer " + fixtureForeignToken:
						return Peer{"fixture-foreign", "execution"}, nil
					default:
						return Peer{}, errDenied
					}
				},
				VerifyEnrollment:   func(context.Context, Enrollment) error { return nil },
				VerifyDispatch:     func(context.Context, string, Proof, time.Time) error { return nil },
				AuthorizeCleanup:   func(context.Context, string, Proof, CleanupLease) error { return errDenied },
				AcknowledgeClosure: func(context.Context, string, Proof, CleanupLease, Receipt) error { return errDenied },
				AuthorizeOwnerClosure: func(_ context.Context, consumer string, p Proof) error {
					if denyAuthority.Load() || consumer != "fixture-consumer" || p.Worker != ownerWorker || p.Token != "fixture-proof" {
						return errDenied
					}
					return nil
				},
				AcknowledgeOwnerClosure: func(_ context.Context, _ string, _ Proof, r Receipt) error {
					if r.Phase != "closed" || !closed(r.Lifetime) {
						return errDenied
					}
					acks.Add(1)
					return nil
				},
			}
			if mode == "paused" {
				cfg.ProviderReadIdle = 2 * time.Second
			}
			h, err := New(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(h)
			defer server.Close()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = h.Stop(ctx)
			}()
			client := &http.Client{Timeout: 3 * time.Second}
			call := func(path, token string, input any) (int, Receipt) {
				t.Helper()
				result := ownerPOST(client, server.URL, path, token, input)
				if result.err != nil {
					t.Fatal("private control response failed", result.err)
				}
				return result.code, result.receipt
			}
			input := ownerRequest()
			input.Descriptor, err = service.GatewayNativeDescriptor(row)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan ownerHTTPResult, 1)
			go func() { done <- ownerPOST(client, server.URL, "", fixtureExecutionToken, input) }()
			var proof Proof
			select {
			case proof = <-proofCh:
			case <-time.After(3 * time.Second):
				t.Fatal("actual admit missing")
			}
			select {
			case <-providerEntered:
			case <-time.After(3 * time.Second):
				t.Fatal("actual provider entry missing")
			}
			request := ownerClosureRequest{proof}
			if code, _ := call("/read-owner", fixtureCleanupToken, request); code != 403 {
				t.Fatal("delegate entered owner route")
			}
			if code, _ := call("/read-owner", fixtureForeignToken, request); code != 409 {
				t.Fatal("foreign consumer read original transport")
			}
			for _, mutate := range []func(*Proof){
				func(p *Proof) { p.ExecutionRef = ownerIssuer },
				func(p *Proof) { p.RequestRef = "fixture-foreign" },
				func(p *Proof) { p.Worker = ownerIssuer },
				func(p *Proof) { p.Token = "fixture-foreign" },
				func(p *Proof) { p.Native.OriginRef = "fixture-foreign" },
				func(p *Proof) { p.Native.EngineIncarnation = ownerIssuer },
				func(p *Proof) { p.Native.Generation = ownerIssuer },
				func(p *Proof) { p.Native.RequestNonce = ownerWorker },
			} {
				wrong := request
				mutate(&wrong.Proof)
				if code, _ := call("/ack-owner", fixtureExecutionToken, wrong); code != 409 {
					t.Fatal("foreign original/native proof acknowledged")
				}
			}
			if code, _ := call("/ack-owner", fixtureExecutionToken, cleanupRequest{Proof: proof}); code != 400 {
				t.Fatal("owner path accepted delegated wire")
			}
			if code, _ := call("/ack", fixtureExecutionToken, cleanupRequest{Proof: proof}); code != 403 {
				t.Fatal("owner entered delegated route")
			}
			if mode == "held" {
				if code, _ := call("/ack-owner", fixtureExecutionToken, request); code != 409 || acks.Load() != 0 {
					t.Fatal("unclosed transport acknowledged")
				}
				if code, _ := call("/cancel-owner", fixtureExecutionToken, request); code != 202 {
					t.Fatal("original cancel failed")
				}
			}
			if mode == "idleBlockedClose" {
				select {
				case <-closeStarted:
				case <-time.After(2 * time.Second):
					t.Fatal("idle did not cancel then attempt Close")
				}
				code, retained := call("/read-owner", fixtureExecutionToken, request)
				if code != 202 || retained.Phase == "closed" || retained.Effect != "effect_unknown" ||
					!retained.Lifetime.ContextDone || retained.Lifetime.BodyClosed || retained.Lifetime.ForwardingReturned || retained.Lifetime.Completed || retained.Acknowledged {
					t.Fatal("blocked Close invented closure/completion", retained)
				}
				if code, _ := call("/ack-owner", fixtureExecutionToken, request); code != 409 || acks.Load() != 0 {
					t.Fatal("blocked Close released occupancy")
				}
				call("", fixtureExecutionToken, input)
				if entries.Load() != 1 || admits.Load() != 1 {
					t.Fatal("blocked Close reentered provider")
				}
				select {
				case <-done:
					t.Fatal("forward returned before physical Close")
				default:
				}
				releaseClose.Do(func() { close(closeGate) })
			}
			select {
			case result := <-done:
				if (mode == "completed" || mode == "paused") && (result.err != nil || result.code != 200) {
					t.Fatal("actual completed stream failed", result.code, result.err)
				}
				if strings.HasPrefix(mode, "idle") && bytes.Contains(result.body, []byte("response.completed")) {
					t.Fatal("read-idle delivered a false completed event")
				}
				if strings.HasPrefix(mode, "idle") {
					// Distinguish the native 1s read-idle from this client's
					// independent 3s timeout and the handler's 5s I/O deadline.
					if result.duration < 800*time.Millisecond || result.duration >= 2*time.Second || !bytes.Contains(result.body, []byte("response.created")) {
						t.Fatal("partial stream did not return at native read-idle before client/absolute timeout", result.duration)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native forward did not return")
			}
			select {
			case <-providerClosed:
			case <-time.After(time.Second):
				t.Fatal("native lifetime did not close live provider body")
			}
			code, receipt := call("/read-owner", fixtureExecutionToken, request)
			settleBy := time.Now().Add(2 * time.Second)
			for {
				if code != 202 || receipt.Proof == nil || *receipt.Proof != proof {
					t.Fatal("original receipt unavailable")
				}
				if receipt.Lifetime.ForwardingReturned && (receipt.Lifetime.BodyClosed || receipt.Lifetime.CloseFailed) {
					break
				}
				if time.Now().After(settleBy) {
					t.Fatal("native physical lifetime did not settle")
				}
				time.Sleep(10 * time.Millisecond)
				code, receipt = call("/read-owner", fixtureExecutionToken, request)
			}
			if (mode == "closeFailed" || mode == "idleCloseFailed") && !receipt.Lifetime.CloseFailed {
				t.Fatal("physical Close failure observation lost")
			}
			if strings.HasPrefix(mode, "idle") {
				if receipt.Effect != "effect_unknown" || receipt.Lifetime.Completed || receipt.Acknowledged || acks.Load() != 0 || !receipt.Lifetime.ContextDone {
					t.Fatal("read-idle changed unknown effect or acknowledged occupancy before closure ACK")
				}
				if mode == "idleCloseFailed" && receipt.Phase == "closed" {
					t.Fatal("failed Close certified closure after read-idle")
				}
			}
			code, receipt = call("/ack-owner", fixtureExecutionToken, request)
			if mode == "closeFailed" || mode == "idleCloseFailed" {
				if code != 409 || acks.Load() != 0 {
					t.Fatal("failed physical Close acknowledged")
				}
			} else {
				if code != 202 || !receipt.Acknowledged || receipt.Phase != "closed" || acks.Load() != 1 {
					t.Fatal("original closed proof not acknowledged")
				}
				if (mode == "completed" || mode == "paused") && (receipt.Effect != "completed" || !receipt.Lifetime.Completed) {
					t.Fatal("completed native outcome lost")
				}
				if code, _ := call("/ack-owner", fixtureExecutionToken, request); code != 202 {
					t.Fatal("exact original ACK not idempotent")
				}
			}
			call("", fixtureExecutionToken, input)
			if entries.Load() != 1 || admits.Load() != 1 {
				t.Fatal("closure reentered provider or issued another claim")
			}
			denyAuthority.Store(true)
			if code, _ := call("/read-owner", fixtureExecutionToken, request); code != 409 {
				t.Fatal("current owner authority denial bypassed by retained receipt")
			}
		})
	}
}

func TestOwnerClosureMissingPortsAndSealedLostAck(t *testing.T) {
	h := ownerRegistry()
	e := ownerReserve(t, h, ownerRequest())
	p := Proof{ExecutionRef: ownerExecution, RequestRef: e.request.RequestRef, Worker: ownerWorker, Token: "fixture-original", Native: e.native}
	if _, err := h.ownerClosure(context.Background(), "fixture-consumer", "read-owner", p); err == nil {
		t.Fatal("missing authority allowed owner closure")
	}
	h.cfg.AuthorizeOwnerClosure = func(context.Context, string, Proof) error { return nil }
	if _, err := h.ownerClosure(context.Background(), "fixture-consumer", "read-owner", p); err == nil || e.proof != nil {
		t.Fatal("unsealed reservation attached proof")
	}
	h.seal(e)
	e.life.NoForward()
	r, err := h.ownerClosure(context.Background(), "fixture-consumer", "read-owner", p)
	if err != nil || r.Proof == nil || *r.Proof != p || r.Lifetime.Entered || e.life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("lost ACK owner read rearmed dispatch")
	}
	changed := p
	changed.Token = "fixture-replacement"
	if _, err := h.ownerClosure(context.Background(), "fixture-consumer", "read-owner", changed); err == nil {
		t.Fatal("recovered original proof was replaced")
	}
	if _, err := h.ownerClosure(context.Background(), "fixture-consumer", "ack-owner", p); err == nil {
		t.Fatal("missing ACK authority allowed closure")
	}
}

// Controlled storage plus real private HTTP, callback and TLS provider. No DB
// claim/occupancy qualification is inferred from these boundary tests.
func ownerIngressFixture(t *testing.T, provider http.Handler) (*Handler, *httptest.Server, *atomic.Int32, <-chan Proof) {
	t.Helper()
	upstream := httptest.NewTLSServer(provider)
	t.Cleanup(upstream.Close)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.Repeat("K", 32))})
	if err != nil {
		t.Fatal(err)
	}
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: ownerAccount, Generation: ownerGeneration, Purpose: service.GatewayCredentialPurpose}
	envelope, err := custody.Seal(scope, fixtureProviderKey)
	if err != nil {
		t.Fatal(err)
	}
	row := &service.Account{ID: 7, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, CreatedAt: ownerRequest().Descriptor.CreatedAt,
		Credentials: map[string]any{"api_key": envelope, "base_url": upstream.URL}, Extra: map[string]any{
			service.GatewayGenerationExtraKey: ownerGeneration, service.GatewayProfileExtraKey: service.GatewayMiMoResponsesProfile,
			service.GatewayModelExtraKey: "fixture-model", service.GatewayCredentialScopeExtraKey: scope.Metadata(),
			"openai_responses_mode": "force_responses", "openai_passthrough": true,
			"native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	u, err := service.NewGatewayNativeLifetimeUpstream(&ownerFixtureHTTP{client: upstream.Client()})
	if err != nil {
		t.Fatal(err)
	}
	gateway := service.NewOpenAIGatewayService(&ownerFixtureRepo{row: row}, nil, nil, nil, nil, nil, nil,
		&config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
		nil, nil, nil, nil, nil, u, nil, nil, nil, nil, nil, nil, nil, nil)
	admits := &atomic.Int32{}
	proofs := make(chan Proof, 1)
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admits.Add(1)
		var input admitRequest
		if r.URL.Path != "/private/native/v1/admit" || r.Header.Get("Authorization") != "Bearer "+fixtureCallbackToken || json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("invalid authenticated callback")
			w.WriteHeader(400)
			return
		}
		reply := ownerReply(input)
		proofs <- reply.Dispatch.Closure
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(callback.Close)
	cfg := Config{Gateway: gateway, Custody: custody, Enrollment: Enrollment{"fixture-origin", ownerIncarnation, "fixture-qualification"},
		Profile: QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: "fixture-model", BaseURL: upstream.URL, QualificationRef: "fixture-qualification",
			RequestBytes: 4096, OutputBytes: 8 << 20, Tokens: 100, ProviderTokenUpperBound: 200},
		MaxEntries: 4, EnvelopeBytes: 8192, CallbackBytes: 65536, CallbackOrigin: callback.URL, CallbackCredential: fixtureCallbackToken,
		CallbackTimeout: time.Second, IOTimeout: 15 * time.Second, CleanupTimeout: time.Second,
		Authorize: func(r *http.Request) (Peer, error) {
			switch r.Header.Get("Authorization") {
			case "Bearer " + fixtureExecutionToken:
				return Peer{"fixture-consumer", "execution"}, nil
			case "Bearer " + fixtureCleanupToken:
				return Peer{"fixture-consumer", "cleanup"}, nil
			case "Bearer " + gatewayIngressGuardFixture1:
				return Peer{"fixture-consumer", "management"}, nil
			}
			return Peer{}, errDenied
		},
		VerifyEnrollment:      func(context.Context, Enrollment) error { return nil },
		VerifyDispatch:        func(context.Context, string, Proof, time.Time) error { return nil },
		AuthorizeCleanup:      func(context.Context, string, Proof, CleanupLease) error { return errDenied },
		AcknowledgeClosure:    func(context.Context, string, Proof, CleanupLease, Receipt) error { return errDenied },
		AuthorizeOwnerClosure: func(context.Context, string, Proof) error { return nil },
		AcknowledgeOwnerClosure: func(_ context.Context, _ string, _ Proof, r Receipt) error {
			if !closed(r.Lifetime) {
				return errDenied
			}
			return nil
		},
	}
	h, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	// Real kernel socket bounds make downstream backpressure deterministic;
	// this is fixture listener configuration, not a production handler hook.
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			if err := conn.(*net.TCPConn).SetWriteBuffer(1024); err != nil {
				t.Error(err)
			}
		}
	}
	server.Start()
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h.Stop(ctx)
	})
	return h, server, admits, proofs
}

// Expect: 100-continue observes the REAL first request body Read. No body is
// supplied, so accepted handlers remain blocked before decode/reserve/callback.
func ownerHeldBody(t *testing.T, origin, path, token string, want int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(origin, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n", transportsPath+path, token)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal("held body did not receive immediate admission decision", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("held %s: got %d want %d", path, resp.StatusCode, want)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// Regression: body buffering precedes execution admission, so authenticated
// slow bodies exhaust the listener and cleanup cannot get a bounded response.
func TestGatewayNativeIngressHeldBodiesReserveControlAndReleaseOnAbort(t *testing.T) {
	var upstreams atomic.Int32
	h, server, admits, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreams.Add(1)
		w.WriteHeader(500)
	}))
	var held []net.Conn
	for i := 0; i < fixtureExecutionAdmissionCap; i++ {
		held = append(held, ownerHeldBody(t, server.URL, "", fixtureExecutionToken, 100))
	}
	ownerHeldBody(t, server.URL, "", fixtureExecutionToken, 503)
	// Wrong-purpose credentials remain forbidden, including at saturation.
	ownerHeldBody(t, server.URL, "/read", fixtureExecutionToken, 403)
	for i := 0; i < fixtureControlAdmissionCap; i++ {
		ownerHeldBody(t, server.URL, "/read", fixtureCleanupToken, 100)
	}
	ownerHeldBody(t, server.URL, "/read", fixtureCleanupToken, 503)
	ownerHeldBody(t, server.URL, "/read-owner", fixtureExecutionToken, 503)
	management := httptest.NewServer(h.ManagementHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("saturated management entered handler")
	})))
	defer management.Close()
	req, _ := http.NewRequest("POST", management.URL, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+gatewayIngressGuardFixture1)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal("management did not share the bounded reserved control budget")
	}
	_ = held[0].Close()
	by := time.Now().Add(2 * time.Second)
	for {
		result := ownerPOST(&http.Client{Timeout: time.Second}, server.URL, "", fixtureExecutionToken, map[string]string{})
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.code == 400 {
			break // Invalid envelope is read only AFTER the aborted slot releases.
		}
		if result.code != 503 || time.Now().After(by) {
			t.Fatal("aborted held execution did not release its handler slot", result.code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if admits.Load() != 0 || upstreams.Load() != 0 || len(h.entries) != 0 {
		t.Fatal("pre-body saturation created callback/claim/upstream or retained occupancy")
	}
}

// Regression: releasing execution admission after body decode/first flush lets
// blocked downstream output multiply executions and starve exact cleanup.
func TestGatewayNativeIngressBlockedOutputRetainsSlotAndAllowsCleanup(t *testing.T) {
	var upstreams atomic.Int32
	providerReady := make(chan struct{}, 1)
	h, server, admits, proofs := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreams.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		frame := ": " + strings.Repeat("x", 16380) + "\n\n"
		// More than the unread downstream TCP window; remain alive without a
		// terminal event. Cleanup must interrupt the actual blocked HTTP writer.
		for i := 0; i < 440; i++ {
			if _, err := io.WriteString(w, frame); err != nil {
				return
			}
			if http.NewResponseController(w).Flush() != nil {
				return
			}
			if i == 64 {
				providerReady <- struct{}{}
			}
		}
		<-r.Context().Done()
	}))
	input := ownerRequest()
	input.Descriptor.BaseURL = h.cfg.Profile.BaseURL
	input.Admission.Limits.OutputBytes = 8 << 20
	raw, _ := json.Marshal(input)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.(*net.TCPConn).SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", transportsPath, fixtureExecutionToken, len(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "POST"})
	if err != nil || response.StatusCode != 200 {
		t.Fatal("live private stream did not start", err)
	}
	// Leave response.Body unread throughout saturation and cleanup.
	var proof Proof
	select {
	case proof = <-proofs:
	case <-time.After(2 * time.Second):
		t.Fatal("sole authenticated admit missing")
	}
	select {
	case <-providerReady:
	case <-time.After(3 * time.Second):
		t.Fatal("controlled provider did not fill unread downstream output")
	}
	for i := 1; i < fixtureExecutionAdmissionCap; i++ {
		ownerHeldBody(t, server.URL, "", fixtureExecutionToken, 100)
	}
	ownerHeldBody(t, server.URL, "", fixtureExecutionToken, 503)
	client := &http.Client{Timeout: 2 * time.Second}
	request := ownerClosureRequest{Proof: proof}
	read := ownerPOST(client, server.URL, "/read-owner", fixtureExecutionToken, request)
	if read.err != nil || read.code != 202 || read.receipt.Phase != "entered" || read.receipt.Lifetime.ForwardingReturned {
		t.Fatal("blocked output released lifetime or starved control", read.code, read.err, read.receipt)
	}
	ack := ownerPOST(client, server.URL, "/ack-owner", fixtureExecutionToken, request)
	if ack.err != nil || ack.code != 409 {
		t.Fatal("blocked output falsely acknowledged closure")
	}
	cancel := ownerPOST(client, server.URL, "/cancel-owner", fixtureExecutionToken, request)
	if cancel.err != nil || cancel.code != 202 {
		t.Fatal("reserved control could not cancel blocked writer")
	}
	by := time.Now().Add(2 * time.Second)
	for {
		read = ownerPOST(client, server.URL, "/read-owner", fixtureExecutionToken, request)
		if read.err != nil || read.code != 202 {
			t.Fatal("exact closure readback unavailable")
		}
		if read.receipt.Phase == "closed" {
			break
		}
		if time.Now().After(by) {
			t.Fatal("cancellation did not interrupt the blocked writer and close provider body")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if read.receipt.Effect != "effect_unknown" || read.receipt.Acknowledged || admits.Load() != 1 || upstreams.Load() != 1 {
		t.Fatal("local handler cleanup certified durable occupancy/effect or replayed inference")
	}
	// Closed but unacknowledged evidence stays retained after the HTTP slot frees.
	if len(h.entries) != 1 {
		t.Fatal("handler release evicted unacknowledged closure")
	}
	result := ownerPOST(client, server.URL, "", fixtureExecutionToken, map[string]string{})
	if result.err != nil || result.code != 400 {
		t.Fatal("forward return did not release execution slot", result.code, result.err)
	}
}

func gatewayIngressGuardFixtureOpaque() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("synthetic fixture entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var gatewayIngressGuardFixture1 = gatewayIngressGuardFixtureOpaque()
