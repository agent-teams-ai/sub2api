//go:build unit

package gatewaytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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

const fixtureProviderKey = "test-fixture-literal"
const fixtureExecutionToken = "example-fixture-literal"
const fixtureCallbackToken = "fixture-callback"
const fixtureCleanupToken = "fixture-cleanup"
const fixtureForeignToken = "fixture-foreign"

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
	code    int
	receipt Receipt
	err     error
}

// No testing.Fatal in the forwarding goroutine; cancellation can interrupt
// the stream, but control responses must arrive and decode without ambiguity.
func ownerPOST(client *http.Client, origin, path, token string, input any) ownerHTTPResult {
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
	result := ownerHTTPResult{code: resp.StatusCode, err: err}
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
	client     *http.Client
	closeFails bool
}

func (u *ownerFixtureHTTP) Do(r *http.Request, _ string, _ int64, concurrency int) (*http.Response, error) {
	if concurrency != 0 {
		return nil, errors.New("ordinary limiter entered")
	}
	resp, err := u.client.Do(r)
	if err == nil && u.closeFails {
		resp.Body = &ownerCloseFailure{ReadCloser: resp.Body}
	}
	return resp, err
}
func (u *ownerFixtureHTTP) DoWithTLS(r *http.Request, proxy string, id int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(r, proxy, id, concurrency)
}

type ownerCloseFailure struct{ io.ReadCloser }

func (b *ownerCloseFailure) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("fixture physical close failure")
}

func TestOwnerHTTPClosureOnActualCompletedTransport(t *testing.T) {
	for _, mode := range []string{"completed", "held", "closeFailed"} {
		t.Run(mode, func(t *testing.T) {
			var entries, admits, acks atomic.Int32
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
				if mode == "held" {
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
				// Completion must close the live body without waiting for EOF.
				<-r.Context().Done()
				select {
				case providerClosed <- struct{}{}:
				default:
				}
			}))
			defer upstream.Close()
			custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.Repeat("K", 32))})
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
			u, err := service.NewGatewayNativeLifetimeUpstream(&ownerFixtureHTTP{client: upstream.Client(), closeFails: mode == "closeFailed"})
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
				MaxEntries: 4, EnvelopeBytes: 8192, CallbackBytes: 65536, CallbackOrigin: callback.URL, CallbackCredential: fixtureCallbackToken, CallbackTimeout: time.Second, IOTimeout: 5 * time.Second, CleanupTimeout: time.Second,
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
			select {
			case result := <-done:
				if mode == "completed" && (result.err != nil || result.code != 200) {
					t.Fatal("actual completed stream failed", result.code, result.err)
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
			if mode == "closeFailed" && !receipt.Lifetime.CloseFailed {
				t.Fatal("physical Close failure observation lost")
			}
			code, receipt = call("/ack-owner", fixtureExecutionToken, request)
			if mode == "closeFailed" {
				if code != 409 || acks.Load() != 0 {
					t.Fatal("failed physical Close acknowledged")
				}
			} else {
				if code != 202 || !receipt.Acknowledged || receipt.Phase != "closed" || acks.Load() != 1 {
					t.Fatal("original closed proof not acknowledged")
				}
				if mode == "completed" && (receipt.Effect != "completed" || !receipt.Lifetime.Completed) {
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
