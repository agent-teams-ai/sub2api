//go:build unit

package gatewaytransport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Real loopback HTTP/TLS + custody + native CAS/lifetime. The control callback is
// an explicit authority fixture; durable SQL fences are qualified by joined CI.
func TestPublicIngressStreamsReplaysEvictsAndPreservesPrivateBoundary(t *testing.T) {
	var entries, settled atomic.Int32
	var original Request
	capability := "synthetic-execution-capability-only"
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+fixtureCallbackToken, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, capability, input.ExecutionBearer)
			require.NotContains(t, string(input.Admission), "payload")
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			var input struct {
				admitRequest
				ExecutionBearer string `json:"executionBearer"`
				RequestedModel  string `json:"requestedModel"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, capability, input.ExecutionBearer)
			require.Equal(t, "fixture-model", input.RequestedModel)
			_ = json.NewEncoder(w).Encode(ownerReply(input.admitRequest))
		case "/private/native/v1/execution-settle":
			var input struct {
				ConsumerID     string  `json:"consumerId"`
				Proof          Proof   `json:"proof"`
				Receipt        Receipt `json:"receipt"`
				RequestedModel string  `json:"requestedModel"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, "fixture-consumer", input.ConsumerID)
			require.Equal(t, "fixture-model", input.RequestedModel)
			require.True(t, closed(input.Receipt.Lifetime))
			require.True(t, input.Receipt.Lifetime.Completed)
			settled.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Errorf("unexpected callback path %s", r.URL.Path)
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "Bearer "+fixtureProviderKey, r.Header.Get("Authorization"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Contains(t, string(raw), `"input":"fixture"`)
		require.NotContains(t, string(raw), capability)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
	}), func(cfg *Config, _ *ownerFixtureRepo) {
		original = ownerRequest()
		original.Descriptor.BaseURL = cfg.Profile.BaseURL
		original.Payload = json.RawMessage(`{"model":"fixture-model","stream":true,"input":"fixture"}`)
		cfg.CallbackOrigin = authority.URL
		cfg.MaxEntries = 2
	})
	public := httptest.NewServer(h.PublicHandler(4))
	defer public.Close()
	call := func(ref, path string) (int, []byte) {
		req, err := http.NewRequest(http.MethodPost, public.URL+path, bytes.NewReader(original.Payload))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+capability)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Gateway-Request-Id", ref)
		if strings.Contains(path, "/executions/") {
			a := original.Admission
			raw, _ := json.Marshal(map[string]any{"invocationRef": a.InvocationRef, "attemptRef": a.AttemptRef, "accountRef": a.AccountRef, "authorizationEpoch": a.AuthorizationEpoch, "subjectRef": a.SubjectRef, "policyRevision": a.PolicyRevision, "bindingRevision": a.BindingRevision, "profileId": a.ProfileID, "limits": a.Limits, "expiresAt": a.ExpiresAt})
			req.Header.Set("X-Gateway-Admission", string(raw))
		}
		response, err := public.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, ref, response.Header.Get("X-Gateway-Request-Ref"))
		require.NotContains(t, string(data), "issuerEpoch")
		require.NotContains(t, string(data), "fixture-proof")
		require.NotContains(t, string(data), fixtureExecutionToken)
		return response.StatusCode, data
	}
	status, body := call("first-public", "/v1/responses")
	require.Equal(t, 200, status)
	require.Contains(t, string(body), "response.completed")
	status, body = call("first-public", "/v1/responses")
	require.Equal(t, 202, status)
	require.Contains(t, string(body), `"effect":"completed"`)
	require.Equal(t, int32(1), entries.Load())
	original.Payload = ownerRequest().Payload
	for _, ref := range []string{"second-public", "third-public", "fourth-public", "fifth-public"} {
		status, _ = call(ref, "/v1/executions/"+original.Admission.ExecutionRef+"/requests")
		require.Equal(t, 200, status)
	}
	require.Equal(t, int32(5), entries.Load())
	require.Equal(t, int32(5), settled.Load())
	h.mu.Lock()
	require.LessOrEqual(t, len(h.entries), 2)
	h.mu.Unlock()
}

func TestPublicIngressDisconnectClosesBodyAndSettlesWithoutClientContext(t *testing.T) {
	var original Request
	settled := make(chan Receipt, 1)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			var input admitRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(ownerReply(input))
		case "/private/native/v1/execution-settle":
			var input struct {
				Receipt Receipt `json:"receipt"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			settled <- input.Receipt
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), func(cfg *Config, _ *ownerFixtureRepo) {
		original = ownerRequest()
		original.Descriptor.BaseURL = cfg.Profile.BaseURL
		cfg.CallbackOrigin = authority.URL
	})
	public := httptest.NewServer(h.PublicHandler(2))
	defer public.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer synthetic-capability-123")
	req.Header.Set("Content-Type", "application/json")
	response, err := public.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode)
	require.NotEmpty(t, response.Header.Get("X-Gateway-Request-Ref"))
	cancel()
	_ = response.Body.Close()
	select {
	case r := <-settled:
		require.True(t, closed(r.Lifetime))
		require.True(t, r.Lifetime.Entered)
		require.False(t, r.Lifetime.Completed)
	case <-time.After(3 * time.Second):
		t.Fatal("client disconnect failed independent physical closure settlement")
	}
}

func TestStandardResponsesDefaultsPreserveBytesAndDenyDuplicateAuthority(t *testing.T) {
	raw := []byte("{\"model\":\"fixture-model\",\"stream\":true,\"input\":[{\"content\":\"escaped } key\"}]} \n")
	normalized, err := standardResponsesDefaults(raw)
	require.NoError(t, err)
	require.Equal(t, string(raw[:len(raw)-3])+`,"store":false,"service_tier":"default"} `+"\n", string(normalized))
	_, err = qualifyPayloadWithDefaultTier(normalized, "fixture-model", 100, 1000, true)
	require.NoError(t, err)
	for _, raw := range []string{
		`{"model":"fixture-model","stream":true,"store":false,"\u0073tore":true}`,
		`{"model":"fixture-model","stream":true,"input":{"value":1,"\u0076alue":2}}`,
		`{"model":"fixture-model","stream":true,"STORE":true}`,
		strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),
	} {
		_, err := standardResponsesDefaults([]byte(raw))
		require.Error(t, err)
	}
	for _, raw := range []string{`{"model":"fixture-model","stream":true,"store":true}`, `{"model":"fixture-model","stream":true,"service_tier":"priority"}`} {
		normalized, err := standardResponsesDefaults([]byte(raw))
		require.NoError(t, err)
		_, err = qualifyPayloadWithDefaultTier(normalized, "fixture-model", 100, 1000, true)
		require.Error(t, err)
	}
}

func TestBoundReservationNonceSharedVectorAndScope(t *testing.T) {
	nonce, valid := boundReservationNonce("fixture-consumer", "sandbox-native-origin", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "request-A")
	require.True(t, valid)
	require.Equal(t, "207e4967-3dea-824e-abbe-b2bcb615b123", nonce.String())
	changed, valid := boundReservationNonce("fixture-consumer", "sandbox-native-origin", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "request-B")
	require.True(t, valid)
	require.NotEqual(t, nonce, changed)
	_, valid = boundReservationNonce("fixture-consumer", "sandbox-native-origin", "not-an-incarnation", "22222222-2222-4222-8222-222222222222", "request-A")
	require.False(t, valid)
}

func TestPublicStatusOnlyReceiptsDisposeButAmbiguousAdmissionRemainsBounded(t *testing.T) {
	var original Request
	var ambiguous atomic.Bool
	var admits, entries atomic.Int32
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			admits.Add(1)
			if ambiguous.Load() {
				w.WriteHeader(503)
				return
			}
			var input admitRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(admitReply{ConsumerID: input.ConsumerID, Admission: input.Admission, Status: requestStatus{RequestRef: input.RequestRef, Effect: "not_dispatched"}})
		default:
			t.Errorf("status-only attempt must not attest SQL closure: %s", r.URL.Path)
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entries.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) {
		original = ownerRequest()
		original.Descriptor.BaseURL = cfg.Profile.BaseURL
		cfg.CallbackOrigin = authority.URL
		cfg.MaxEntries = 2
	})
	public := httptest.NewServer(h.PublicHandler(4))
	defer public.Close()
	call := func(id string) int {
		req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer synthetic-capability-123")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Gateway-Request-Id", id)
		response, err := public.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		_, err = io.ReadAll(response.Body)
		require.NoError(t, err)
		return response.StatusCode
	}
	for _, id := range []string{"denied-one", "denied-two", "denied-three", "denied-four", "denied-five"} {
		require.Equal(t, 202, call(id))
	}
	require.Equal(t, int32(5), admits.Load())
	require.Zero(t, entries.Load())
	h.mu.Lock()
	require.Len(t, h.entries, 2)
	for _, e := range h.entries {
		require.True(t, e.statusOnly)
		require.False(t, e.acknowledged)
		require.True(t, closed(e.life.Snapshot()))
	}
	h.mu.Unlock()
	ambiguous.Store(true)
	require.Equal(t, 202, call("ambiguous-one"))
	require.Equal(t, 202, call("ambiguous-two"))
	require.Equal(t, 409, call("must-stay-bounded"))
	require.Equal(t, int32(7), admits.Load())
	require.Zero(t, entries.Load())
	h.mu.Lock()
	for _, e := range h.entries {
		require.False(t, e.statusOnly)
		require.False(t, e.acknowledged)
	}
	h.mu.Unlock()
}

func TestPublicTerminalEventAndEOFWaitForDurableSettlementAndFailureTruncates(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "durable", false: "callback-failed"}[success], func(t *testing.T) {
			var original Request
			entered, release := make(chan struct{}), make(chan struct{})
			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/private/native/v1/execution-authority":
					var input publicAuthorizationRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
				case "/private/native/v1/public-admit":
					var input admitRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					_ = json.NewEncoder(w).Encode(ownerReply(input))
				case "/private/native/v1/execution-settle":
					close(entered)
					<-release
					if !success {
						w.WriteHeader(503)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				default:
					w.WriteHeader(403)
				}
			}))
			defer authority.Close()
			h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
			}), func(cfg *Config, _ *ownerFixtureRepo) {
				original = ownerRequest()
				original.Descriptor.BaseURL = cfg.Profile.BaseURL
				cfg.CallbackOrigin = authority.URL
			})
			public := httptest.NewServer(h.PublicHandler(2))
			defer public.Close()
			req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer synthetic-capability-123")
			req.Header.Set("Content-Type", "application/json")
			response, err := public.Client().Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, 200, response.StatusCode)
			type result struct {
				data string
				err  error
			}
			finished := make(chan result, 1)
			firstLine := make(chan string, 1)
			go func() {
				reader := bufio.NewReader(response.Body)
				line, err := reader.ReadString('\n')
				firstLine <- line
				if err != nil {
					finished <- result{line, err}
					return
				}
				rest, err := io.ReadAll(reader)
				finished <- result{line + string(rest), err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("terminal callback not reached")
			}
			select {
			case line := <-firstLine:
				t.Fatalf("terminal-aware client observed completion before durable callback: %q", line)
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			select {
			case result := <-finished:
				if success {
					require.NoError(t, result.err)
					require.Contains(t, result.data, "response.completed")
				} else {
					require.Error(t, result.err)
					require.NotContains(t, result.data, "response.completed")
				}
			case <-time.After(time.Second):
				t.Fatal("stream did not finish after settlement")
			}
			h.mu.Lock()
			for _, e := range h.entries {
				require.Equal(t, success, e.acknowledged)
				require.False(t, e.statusOnly)
			}
			h.mu.Unlock()
		})
	}
}

func TestPublicTerminalBurstPacesTwelveCallbacksAndRetainsAbortedQueuedOwner(t *testing.T) {
	var original Request
	var active, maximum, settlements, entries atomic.Int32
	release := make(chan struct{})
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			var input admitRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(ownerReply(input))
		case "/private/native/v1/execution-settle":
			current := active.Add(1)
			defer active.Add(-1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			<-release
			settlements.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entries.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
	}), func(cfg *Config, _ *ownerFixtureRepo) {
		original = ownerRequest()
		original.Descriptor.BaseURL = cfg.Profile.BaseURL
		cfg.CallbackOrigin = authority.URL
		cfg.MaxEntries = 32
	})
	public := httptest.NewServer(h.PublicHandler(12))
	defer public.Close()
	type opened struct {
		index  int
		cancel context.CancelFunc
	}
	openedRequests := make(chan opened, 12)
	finished := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func(i int) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
			if err != nil {
				finished <- err
				return
			}
			req.Header.Set("Authorization", "Bearer synthetic-capability-123")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Gateway-Request-Id", uuid.NewString())
			response, err := public.Client().Do(req)
			if err != nil {
				finished <- err
				return
			}
			defer response.Body.Close()
			openedRequests <- opened{i, cancel}
			_, err = io.ReadAll(response.Body)
			finished <- err
		}(i)
	}
	var abort context.CancelFunc
	for i := 0; i < 12; i++ {
		select {
		case opened := <-openedRequests:
			if opened.index == 11 {
				abort = opened.cancel
			}
		case <-time.After(2 * time.Second):
			t.Fatal("not all public streams reached response headers")
		}
	}
	require.Eventually(t, func() bool { return active.Load() == 4 }, time.Second, time.Millisecond)
	require.Equal(t, int32(4), maximum.Load())
	require.Equal(t, int32(12), entries.Load())
	// The 13th request cannot borrow protected callback or extra handler capacity.
	req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer synthetic-capability-123")
	req.Header.Set("Content-Type", "application/json")
	denied, err := public.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, 503, denied.StatusCode)
	_ = denied.Body.Close()
	require.NotNil(t, abort)
	abort()
	close(release)
	failed := 0
	for i := 0; i < 12; i++ {
		select {
		case err := <-finished:
			if err != nil {
				failed++
			}
		case <-time.After(2 * time.Second):
			t.Fatal("paced terminal queue did not drain")
		}
	}
	require.Equal(t, 1, failed)
	require.Eventually(t, func() bool { return settlements.Load() == 12 }, time.Second, time.Millisecond)
	require.LessOrEqual(t, maximum.Load(), int32(4))
	h.mu.Lock()
	for _, e := range h.entries {
		require.True(t, e.acknowledged)
		require.True(t, closed(e.life.Snapshot()))
	}
	h.mu.Unlock()
}

func TestPublicTerminalAggregateBudgetWithholdsOnSaturationAndReleases(t *testing.T) {
	frame := []byte("event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
	budget := &publicTerminalBudget{maximum: len(frame)}
	first := httptest.NewRecorder()
	first.Header().Set("Content-Type", "text/event-stream")
	one := &publicTerminalWriter{ResponseWriter: first, budget: budget, maximum: 1024}
	_, err := one.Write(frame)
	require.NoError(t, err)
	require.Empty(t, first.Body.String())
	second := httptest.NewRecorder()
	second.Header().Set("Content-Type", "text/event-stream")
	two := &publicTerminalWriter{ResponseWriter: second, budget: budget, maximum: 1024}
	_, err = two.Write(frame)
	require.Error(t, err)
	require.Empty(t, second.Body.String())
	require.Error(t, two.release())
	two.dispose()
	require.NoError(t, one.release())
	require.Equal(t, string(frame), first.Body.String())
	one.dispose()
	require.Zero(t, budget.used)
	third := httptest.NewRecorder()
	third.Header().Set("Content-Type", "text/event-stream")
	three := &publicTerminalWriter{ResponseWriter: third, budget: budget, maximum: 1024}
	_, err = three.Write(frame)
	require.NoError(t, err)
	require.NoError(t, three.release())
	three.dispose()
	require.Zero(t, budget.used)
}

func TestPublicPreclaimAuthorityCapacityIsDistinctFromAuthenticationAndProtocolFailure(t *testing.T) {
	var status atomic.Int32
	var providerEntries, callbacks atomic.Int32
	status.Store(503)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks.Add(1)
		require.Equal(t, "/private/native/v1/execution-authority", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, "{}")
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { providerEntries.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) { cfg.CallbackOrigin = authority.URL })
	public := httptest.NewServer(h.PublicHandler(2))
	defer public.Close()
	call := func(expectedStatus int, expectedCode string) {
		req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(ownerRequest().Payload))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer synthetic-capability-123")
		req.Header.Set("Content-Type", "application/json")
		response, err := public.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, expectedStatus, response.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
		require.Equal(t, expectedCode, body["code"])
		require.Equal(t, "not_dispatched", body["effect"])
		require.Zero(t, providerEntries.Load())
		h.mu.Lock()
		require.Empty(t, h.entries)
		h.mu.Unlock()
	}
	for _, testcase := range []struct {
		upstream, status int
		code             string
	}{{503, 503, "admission_limited"}, {429, 503, "admission_limited"}, {403, 403, "forbidden"}, {401, 403, "forbidden"}, {500, 502, "upstream_failure"}, {200, 502, "upstream_failure"}} {
		status.Store(int32(testcase.upstream))
		call(testcase.status, testcase.code)
	}
	require.Equal(t, int32(6), callbacks.Load())
	authority.Close()
	call(503, "admission_limited")
	require.Equal(t, int32(6), callbacks.Load())
}
