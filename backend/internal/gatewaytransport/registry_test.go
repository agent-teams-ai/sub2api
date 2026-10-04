//go:build unit

package gatewaytransport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const NEWTESTExecution = "11111111-1111-4111-8111-111111111111"
const NEWTESTIssuer = "22222222-2222-4222-8222-222222222222"
const NEWTESTGeneration = "33333333-3333-4333-8333-333333333333"
const NEWTESTWorker = "44444444-4444-4444-8444-444444444444"
const NEWTESTIncarnation = "55555555-5555-4555-8555-555555555555"
const NEWTESTAccount = "66666666-6666-4666-8666-666666666666"
const NEWTESTCleanup = "77777777-7777-4777-8777-777777777777"

func NEWTESTRequest() Request {
	return Request{RequestRef: "NEWTESTrequest", Worker: NEWTESTWorker,
		Admission: Admission{ExecutionRef: NEWTESTExecution, IssuerEpoch: NEWTESTIssuer, InvocationRef: "NEWTESTinvocation", AttemptRef: "NEWTESTattempt", AccountRef: NEWTESTAccount,
			AuthorizationEpoch: 3, SubjectRef: "NEWTESTsubject", PolicyRevision: 4, BindingRevision: 5, ProfileID: service.GatewayMiMoResponsesProfile,
			Limits: Limits{Requests: 2, Concurrency: 1, RequestBytes: 4096, OutputBytes: 4096, Tokens: 100}, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)},
		Descriptor: service.GatewayNativeRoute{AccountID: 7, Generation: NEWTESTGeneration, CreatedAt: time.Date(2026, 10, 3, 1, 2, 3, 123456789, time.UTC), Profile: service.GatewayMiMoResponsesProfile, BaseURL: "https://NEWTEST.invalid", Model: "NEWTESTmodel"},
		Payload:    json.RawMessage(`{"model":"NEWTESTmodel","input":"NEWTEST","store":false,"stream":true,"service_tier":"default"}`)}
}

// Explicit component harness, deliberately not New: no fake custody, enrollment
// certificate, provider credential or assertion of actual SQL integration.
func NEWTESTRegistry(callback *httptest.Server, cap int) *Handler {
	return &Handler{cfg: Config{MaxEntries: cap, CallbackOrigin: callback.URL, CallbackCredential: "NEWTESTcallback", CallbackTimeout: 200 * time.Millisecond, CallbackBytes: 65536,
		CleanupTimeout: time.Second, Enrollment: Enrollment{"NEWTESTorigin", NEWTESTIncarnation, "NEWTESTqualification"},
		VerifyDispatch: func(_ context.Context, _ string, p Proof, _ time.Time) error {
			if p.Token != "NEWTESTproof" {
				return errDenied
			}
			return nil
		},
		AuthorizeCleanup:   func(context.Context, string, Proof, CleanupLease) error { return nil },
		AcknowledgeClosure: func(context.Context, string, Proof, CleanupLease, Receipt) error { return nil }}, entries: make(map[transportKey]*reservation), requests: make(map[requestKey]transportKey), callback: callback.Client()}
}
func NEWTESTReserve(t *testing.T, h *Handler, r Request) (*reservation, bool, error) {
	t.Helper()
	deadline, _ := parseInstant(r.Admission.ExpiresAt)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	e, first, err := h.reserve("NEWTESTconsumer", r, ctx, cancel, func() {})
	if !first {
		cancel()
	}
	if first {
		t.Cleanup(func() { h.seal(e); e.life.NoForward() })
	}
	return e, first, err
}
func NEWTESTReply(req admitRequest) admitReply {
	p := Proof{ExecutionRef: req.Admission.ExecutionRef, RequestRef: req.RequestRef, Worker: req.Worker, Token: "NEWTESTproof", Native: req.Native}
	d := req.Descriptor
	return admitReply{ConsumerID: req.ConsumerID, Admission: req.Admission, Status: requestStatus{RequestRef: req.RequestRef, Effect: "dispatch_started"},
		Dispatch:         &dispatch{Descriptor: kernelDescriptor{d.Generation, d.Generation, d.Profile}, ExecutionRef: p.ExecutionRef, RequestRef: p.RequestRef, Limits: req.Admission.Limits, Deadline: req.Admission.ExpiresAt, Closure: p},
		NativeDescriptor: &d, LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
}

func TestNEWTESTConcurrentReservationsOneHTTPCallback(t *testing.T) {
	var callbacks atomic.Int32
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks.Add(1)
		if r.URL.Path != "/private/native/v1/admit" || r.Header.Get("Authorization") != "Bearer NEWTESTcallback" {
			t.Error("wrong fixed callback origin/auth")
		}
		var req admitRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NEWTESTReply(req))
	}))
	defer callback.Close()
	h := NEWTESTRegistry(callback, 4)
	input := NEWTESTRequest()
	var firsts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, first, err := NEWTESTReserve(t, h, input)
			if err != nil {
				t.Error(err)
				return
			}
			if first {
				firsts.Add(1)
				ok, err := h.admit(context.Background(), "NEWTESTconsumer", e)
				if err != nil || !ok {
					t.Error("exact permission rejected", err)
				}
			}
		}()
	}
	wg.Wait()
	if firsts.Load() != 1 || callbacks.Load() != 1 {
		t.Fatalf("duplicate issued claim callback: first=%d callback=%d", firsts.Load(), callbacks.Load())
	}
}

func TestNEWTESTSaturationBeforeHTTPCallbackAndChangedIntent(t *testing.T) {
	var callbacks atomic.Int32
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { callbacks.Add(1) }))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	input := NEWTESTRequest()
	e, first, err := NEWTESTReserve(t, h, input)
	if err != nil || !first {
		t.Fatal(err)
	}
	h.seal(e)
	e.life.NoForward()
	changed := input
	changed.RequestRef = "NEWTESTother"
	if _, _, err := NEWTESTReserve(t, h, changed); err == nil {
		t.Fatal("unacknowledged receipt evicted")
	}
	changed = input
	changed.Admission.BindingRevision++
	if _, _, err := NEWTESTReserve(t, h, changed); err == nil {
		t.Fatal("changed full envelope accepted as retry")
	}
	if callbacks.Load() != 0 {
		t.Fatal("saturation reached callback")
	}
}

func TestNEWTESTHeldAndLostAdmitACKNeverRearms(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "held", true: "lost"}[lost], func(t *testing.T) {
			reached := make(chan struct{})
			release := make(chan struct{})
			cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req admitRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				close(reached)
				<-release
				if lost {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(NEWTESTReply(req))
			}))
			defer cb.Close()
			h := NEWTESTRegistry(cb, 1)
			e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
			result := make(chan bool, 1)
			go func() { ok, _ := h.admit(context.Background(), "NEWTESTconsumer", e); result <- ok }()
			<-reached
			h.seal(e)
			close(release)
			if <-result {
				t.Fatal("late permission admitted sealed reservation")
			}
			e.life.NoForward()
			r := h.receipt("NEWTESTconsumer", e)
			if !r.Sealed || r.Phase != "closed" || r.Lifetime.Entered || r.Effect != "effect_unknown" {
				t.Fatalf("wrong lost-ACK facts: %+v", r)
			}
		})
	}
}

func TestNEWTESTCallbackFullBindingMutationsDeny(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*admitReply)
	}{
		{"consumer", func(r *admitReply) { r.ConsumerID = "NEWTESTforeign" }},
		{"issuer", func(r *admitReply) { r.Admission.IssuerEpoch = NEWTESTWorker }},
		{"execution", func(r *admitReply) { r.Admission.ExecutionRef = NEWTESTWorker }},
		{"invocation", func(r *admitReply) { r.Admission.InvocationRef = "NEWTESTforeign" }},
		{"attempt", func(r *admitReply) { r.Admission.AttemptRef = "NEWTESTforeign" }},
		{"logicalAccount", func(r *admitReply) { r.Admission.AccountRef = NEWTESTWorker }},
		{"authorizationEpoch", func(r *admitReply) { r.Admission.AuthorizationEpoch++ }},
		{"subject", func(r *admitReply) { r.Admission.SubjectRef = "NEWTESTforeign" }},
		{"policyRevision", func(r *admitReply) { r.Admission.PolicyRevision++ }},
		{"bindingRevision", func(r *admitReply) { r.Admission.BindingRevision++ }},
		{"profile", func(r *admitReply) { r.Admission.ProfileID = "NEWTESTforeign" }},
		{"requestAllowance", func(r *admitReply) { r.Dispatch.Limits.Requests++ }},
		{"concurrency", func(r *admitReply) { r.Dispatch.Limits.Concurrency++ }},
		{"outputBytes", func(r *admitReply) { r.Dispatch.Limits.OutputBytes++ }},
		{"requestBytes", func(r *admitReply) { r.Dispatch.Limits.RequestBytes++ }},
		{"tokens", func(r *admitReply) { r.Admission.Limits.Tokens++ }},
		{"deadline", func(r *admitReply) { r.Dispatch.Deadline = time.Now().Add(time.Hour).Format(time.RFC3339Nano) }},
		{"row", func(r *admitReply) { r.NativeDescriptor.AccountID++ }},
		{"model", func(r *admitReply) { r.NativeDescriptor.Model = "NEWTESTforeign" }},
		{"birthInstant", func(r *admitReply) { r.NativeDescriptor.CreatedAt = r.NativeDescriptor.CreatedAt.Add(time.Nanosecond) }},
		{"endpoint", func(r *admitReply) { r.NativeDescriptor.BaseURL = "https://NEWTESTforeign.invalid" }},
		{"generation", func(r *admitReply) { r.Dispatch.Closure.Native.Generation = NEWTESTWorker }},
		{"origin", func(r *admitReply) { r.Dispatch.Closure.Native.OriginRef = "NEWTESTforeign" }},
		{"incarnation", func(r *admitReply) { r.Dispatch.Closure.Native.EngineIncarnation = NEWTESTWorker }},
		{"nonce", func(r *admitReply) { r.Dispatch.Closure.Native.RequestNonce = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }},
		{"worker", func(r *admitReply) { r.Dispatch.Closure.Worker = NEWTESTIssuer }},
		{"missingToken", func(r *admitReply) { r.Dispatch.Closure.Token = "" }},
		{"wrongToken", func(r *admitReply) { r.Dispatch.Closure.Token = "NEWTESTforeign" }},
		{"lease", func(r *admitReply) { r.LeaseExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req admitRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				reply := NEWTESTReply(req)
				mutation.change(&reply)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer cb.Close()
			h := NEWTESTRegistry(cb, 1)
			e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
			if ok, _ := h.admit(context.Background(), "NEWTESTconsumer", e); ok {
				t.Fatal("wrong binding entered")
			}
		})
	}
}

func TestNEWTESTReadbackCallbackNoPermission(t *testing.T) {
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req admitRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(admitReply{ConsumerID: req.ConsumerID, Admission: req.Admission, Status: requestStatus{RequestRef: req.RequestRef, Effect: "completed"}})
	}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
	if ok, err := h.admit(context.Background(), "NEWTESTconsumer", e); err != nil || ok {
		t.Fatal("readback became permission", err)
	}
}

func TestNEWTESTCleanupRecoveredOriginalProofRepeatedReceipt(t *testing.T) {
	cb := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
	h.seal(e)
	e.life.NoForward()
	p := Proof{ExecutionRef: NEWTESTExecution, RequestRef: e.request.RequestRef, Worker: NEWTESTWorker, Token: "NEWTESToriginal", Native: e.native}
	lease := CleanupLease{CleanupRef: NEWTESTCleanup, Worker: NEWTESTWorker, Token: "NEWTESTlease", LeaseExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	for _, action := range []string{"read", "cancel", "ack", "read", "ack"} {
		r, err := h.cleanup(context.Background(), "NEWTESTconsumer", action, cleanupRequest{p, lease})
		if err != nil || r.Proof == nil || *r.Proof != p || r.Phase != "closed" || !r.Sealed || r.Lifetime.Entered || r.Effect != "effect_unknown" {
			t.Fatalf("cleanup changed original unknown/non-entry binding: %+v %v", r, err)
		}
	}
	wrong := p
	wrong.Token = "NEWTESTreplacement"
	if _, err := h.cleanup(context.Background(), "NEWTESTconsumer", "cancel", cleanupRequest{wrong, lease}); err == nil {
		t.Fatal("replacement proof accepted")
	}
	if e.life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("cleanup rearmed dispatch")
	}
	lease.LeaseExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := h.cleanup(context.Background(), "NEWTESTconsumer", "read", cleanupRequest{p, lease}); err == nil {
		t.Fatal("expired cleanup lease accepted")
	}
}

func TestNEWTESTPrivateHTTPConcurrentDuplicatesAndConsumerBodyRejected(t *testing.T) {
	var callbacks atomic.Int32
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks.Add(1)
		var req admitRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(admitReply{ConsumerID: req.ConsumerID, Admission: req.Admission, Status: requestStatus{RequestRef: req.RequestRef, Effect: "effect_unknown"}})
	}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 4)
	h.cfg.Authorize = func(r *http.Request) (Peer, error) { return Peer{"NEWTESTconsumer", "execution"}, nil }
	h.cfg.IOTimeout = time.Second
	h.cfg.EnvelopeBytes = 8192
	h.cfg.Profile = QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: "NEWTESTmodel", BaseURL: "https://NEWTEST.invalid", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 200}
	server := httptest.NewServer(h)
	defer server.Close()
	input := NEWTESTRequest()
	body, _ := json.Marshal(input)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := server.Client().Post(server.URL+transportsPath, "application/json", strings.NewReader(string(body)))
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 202 {
				t.Error("duplicate/readback denied", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if callbacks.Load() != 1 {
		t.Fatal("HTTP duplicates caused multiple callback claims", callbacks.Load())
	}
	// Public callers cannot supply a consumer in this protected private envelope.
	foreign := append([]byte(`{"consumerId":"NEWTESTforeign",`), body[1:]...)
	resp, err := server.Client().Post(server.URL+transportsPath, "application/json", strings.NewReader(string(foreign)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 400 || callbacks.Load() != 1 {
		t.Fatal("body consumer reached callback")
	}
}

func TestNEWTESTDuplicateCallbackInvocationNoSecondPermission(t *testing.T) {
	var calls atomic.Int32
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req admitRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NEWTESTReply(req))
	}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
	if ok, err := h.admit(context.Background(), "NEWTESTconsumer", e); !ok || err != nil {
		t.Fatal("original permission rejected", err)
	}
	if ok, err := h.admit(context.Background(), "NEWTESTconsumer", e); ok || err != nil {
		t.Fatal("duplicate callback returned permission", err)
	}
	r := h.receipt("NEWTESTconsumer", e)
	if calls.Load() != 1 || r.Status == nil || r.Status.Effect != "dispatch_started" {
		t.Fatal("duplicate callback lost readback or reissued claim")
	}
}

func TestNEWTESTCallbackAmbiguousBytesAndBoundedFailure(t *testing.T) {
	for _, kind := range []string{"duplicate", "alias", "invalidUTF8", "bounded", "timeout", "http4xx", "missingDispatchFields"} {
		t.Run(kind, func(t *testing.T) {
			cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req admitRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				reply := NEWTESTReply(req)
				raw, _ := json.Marshal(reply)
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "duplicate":
					raw = append([]byte(`{"consumerId":"NEWTESTconsumer",`), raw[1:]...)
				case "alias":
					raw = []byte(strings.Replace(string(raw), `"consumerId"`, `"ConsumerId"`, 1))
				case "invalidUTF8":
					raw = append(raw, 0xff)
				case "bounded":
					raw = []byte(strings.Repeat("N", 70000))
				case "timeout":
					<-r.Context().Done()
					return
				case "http4xx":
					w.WriteHeader(http.StatusForbidden)
				case "missingDispatchFields":
					reply.LeaseExpiresAt = ""
					raw, _ = json.Marshal(reply)
				}
				_, _ = w.Write(raw)
			}))
			defer cb.Close()
			h := NEWTESTRegistry(cb, 1)
			e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
			start := time.Now()
			if ok, err := h.admit(context.Background(), "NEWTESTconsumer", e); ok || err == nil {
				t.Fatal("ambiguous callback yielded permission")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("callback lifetime not bounded")
			}
			h.seal(e)
			e.life.NoForward()
			r := h.receipt("NEWTESTconsumer", e)
			if r.Effect != "effect_unknown" || r.Lifetime.Entered {
				t.Fatal("HTTP failure inferred durable no-effect")
			}
		})
	}
}

func TestNEWTESTConstructorAbsentAuthorityDenied(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("absent private composition accepted")
	}
	if _, err := New(nil, Config{}); err == nil { //nolint:staticcheck // Deliberately verify rejection of a nil bootstrap context.
		t.Fatal("nil bootstrap context accepted")
	}
}

func TestNEWTESTContextCancellationSealVisibleAndProofRecoverable(t *testing.T) {
	cb := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	e, _, err := NEWTESTReserve(t, h, NEWTESTRequest())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate request cancellation while a handler is still waiting on its ACK.
	// The registry must report the observer's permanent latch before Forward ends.
	e.life.Cancel()
	r := h.receipt("NEWTESTconsumer", e)
	if !r.Sealed || r.Lifetime.ForwardingReturned {
		t.Fatal("cancel latch depended on handler return")
	}
	p := Proof{ExecutionRef: NEWTESTExecution, RequestRef: e.request.RequestRef, Worker: NEWTESTWorker, Token: "NEWTESToriginal", Native: e.native}
	lease := CleanupLease{CleanupRef: NEWTESTCleanup, Worker: NEWTESTWorker, Token: "NEWTESTlease", LeaseExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	recovered, err := h.cleanup(context.Background(), "NEWTESTconsumer", "read", cleanupRequest{p, lease})
	if err != nil || recovered.Proof == nil || *recovered.Proof != p || !recovered.Sealed || recovered.Lifetime.Entered {
		t.Fatalf("sealed lost-ACK cleanup recovery failed: %+v %v", recovered, err)
	}
	if e.life.Admit(time.Now().Add(time.Minute)) {
		t.Fatal("readback rearmed cancelled lifetime")
	}
	h.mu.Lock()
	full, ok := h.requests[requestKey{"NEWTESTconsumer", NEWTESTExecution, e.request.RequestRef}]
	bindingMatches := ok && full.native == p.Native && h.entries[full] == e
	h.mu.Unlock()
	if !bindingMatches {
		t.Fatal("registry is not indexed by the original full binding")
	}
}

// Losing the current cleanup lifetime while SQL returns an ACK is ambiguous to
// this hop. Retain the exact original receipt for a fresh leased read/ACK.
func TestNEWTESTCleanupLostACKRetainsExactReceipt(t *testing.T) {
	cb := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cb.Close()
	h := NEWTESTRegistry(cb, 1)
	e, _, _ := NEWTESTReserve(t, h, NEWTESTRequest())
	h.seal(e)
	e.life.NoForward()
	p := Proof{ExecutionRef: NEWTESTExecution, RequestRef: e.request.RequestRef, Worker: NEWTESTWorker, Token: "NEWTESToriginal", Native: e.native}
	lease := CleanupLease{CleanupRef: NEWTESTCleanup, Worker: NEWTESTWorker, Token: "NEWTESTlease", LeaseExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
	ctx, cancel := context.WithCancel(context.Background())
	h.cfg.AcknowledgeClosure = func(context.Context, string, Proof, CleanupLease, Receipt) error { cancel(); return nil }
	if _, err := h.cleanup(ctx, "NEWTESTconsumer", "ack", cleanupRequest{p, lease}); err == nil {
		t.Fatal("lost cleanup ACK discarded retained evidence")
	}
	r, err := h.cleanup(context.Background(), "NEWTESTconsumer", "read", cleanupRequest{p, lease})
	if err != nil || r.Acknowledged || r.Proof == nil || *r.Proof != p || !r.Sealed {
		t.Fatal("lost ACK changed original receipt", r, err)
	}
}
