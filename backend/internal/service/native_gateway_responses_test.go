//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test exercises real HTTP entry and native Responses bytes. Repository
// state is controlled; it does NOT establish PostgreSQL locking/trigger behavior.
func TestGatewayNativeResponses_PhysicalAccountAndTools(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var dispatches atomic.Int32
	var fail atomic.Bool
	var partial atomic.Bool
	first := []byte(`{"model":"mimo-test","input":"sandbox","store":false,"service_tier":"default","tools":[{"type":"custom","name":"exec","format":{"type":"text"}}]}`)
	firstWire := []byte(`{"model":"mimo-test","input":"sandbox","store":false,"tools":[{"type":"custom","name":"exec","format":{"type":"text"}}]}`)
	second := []byte(`{"model":"mimo-test","input":[{"type":"custom_tool_call_output","call_id":"call_1","output":"sandbox result"}],"store":false}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatches.Add(1)
		assert.Equal(t, "/v1/responses", r.URL.Path)
		assert.Equal(t, "Bearer fixture-key", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Codex-Turn-State"))
		payload, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(payload, firstWire) || bytes.Equal(payload, second) || strings.Contains(string(payload), `"stream":true`), "native custom-tool payload must survive unchanged")
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":{"message":"private-vendor-body"}}`)
			return
		}
		if partial.Load() {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"sandbox_resp","status":"completed","output":[{"type":"custom_tool_call","call_id":"call_1","name":"exec","input":"sandbox"}],"usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	defer upstream.Close()
	a := &Account{ID: 17, CreatedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
		Credentials: map[string]any{"api_key": "fixture-key", "base_url": upstream.URL},
		Extra:       map[string]any{GatewayGenerationExtraKey: "33333333-3333-4333-8333-333333333333", GatewayProfileExtraKey: GatewayMiMoResponsesProfile, GatewayModelExtraKey: "mimo-test", "openai_responses_mode": "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	nativeFixtureSealAccount(t, a)
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	repo := &gatewayIdentityRepoFixture{row: a}
	svc := &OpenAIGatewayService{accountRepo: repo, httpUpstream: &gatewayIdentityRealHTTP{client: upstream.Client()}, cfg: rawChatCompletionsTestConfig()}
	call := func(r GatewayNativeRoute, payload []byte) (*httptest.ResponseRecorder, bool, error) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
		c.Request.Header.Set("X-Codex-Turn-State", "foreign")
		_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, r, payload)
		return recorder, entered, err
	}
	t.Run("deleted integer reused for a different physical generation", func(t *testing.T) {
		reused := *a
		reused.CreatedAt = a.CreatedAt.Add(time.Second)
		repo.row = &reused
		_, entered, err := call(route, first)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.row = a
	})
	t.Run("transport fresh row is a foreign generation", func(t *testing.T) {
		foreign := *a
		foreign.Extra = map[string]any{}
		for k, v := range a.Extra {
			foreign.Extra[k] = v
		}
		foreign.Extra[GatewayGenerationExtraKey] = "44444444-4444-4444-8444-444444444444"
		repo.fresh = &foreign
		_, entered, err := call(route, first)
		require.Error(t, err)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.fresh = nil
	})
	t.Run("inert and grouped rows deny", func(t *testing.T) {
		inert := *a
		inert.Status = StatusDisabled
		repo.row = &inert
		_, entered, err := call(route, first)
		require.Error(t, err)
		require.False(t, entered)
		grouped := *a
		grouped.GroupIDs = []int64{99}
		repo.row = &grouped
		_, entered, err = call(route, first)
		require.Error(t, err)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.row = a
	})
	t.Run("erased tombstone cannot execute stale descriptor", func(t *testing.T) {
		erased := *a
		erased.Status = StatusDisabled
		erased.Credentials = map[string]any{"base_url": upstream.URL}
		repo.row = &erased
		_, entered, err := call(route, first)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.row = a
	})
	t.Run("custom tool and output stay on the same physical account", func(t *testing.T) {
		for i, payload := range [][]byte{first, second} {
			rec, entered, err := call(route, payload)
			require.NoError(t, err)
			require.True(t, entered)
			require.EqualValues(t, i+1, dispatches.Load())
			require.Contains(t, rec.Body.String(), `"type":"custom_tool_call"`)
		}
	})
	t.Run("upstream error is one possible effect without bridge fallback or body leak", func(t *testing.T) {
		fail.Store(true)
		rec, entered, err := call(route, first)
		require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
		require.True(t, entered)
		require.EqualValues(t, 3, dispatches.Load())
		require.NotContains(t, rec.Body.String(), "private-vendor-body")
		fail.Store(false)
	})
	t.Run("partial SSE is unknown without replay", func(t *testing.T) {
		partial.Store(true)
		_, entered, err := call(route, []byte(`{"model":"mimo-test","stream":true,"store":false}`))
		require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
		require.True(t, entered)
		require.EqualValues(t, 4, dispatches.Load())
		partial.Store(false)
	})
	t.Run("ordinary account keeps its scheduling behavior", func(t *testing.T) {
		ordinary := &Account{Status: StatusActive, Schedulable: true}
		require.True(t, ordinary.IsSchedulable())
		require.False(t, a.IsSchedulable())
	})
}

// Regression: a provider body returning (0,nil) repeatedly keeps a stuck stream
// alive by refreshing its timer despite making no byte progress.
type nativeZeroProgressBody struct {
	ctx   context.Context
	reads atomic.Int32
}

func (b *nativeZeroProgressBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return 0, nil
	}
}
func TestGatewayNativeIdleZeroByteReadsCannotRenewTolerance(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body := &nativeZeroProgressBody{ctx: ctx}
	reader := &gatewayNativeIdleReader{reader: body, idle: 50 * time.Millisecond, cancel: cancel}
	start := time.Now()
	n, err := reader.Read(make([]byte, 1))
	require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
	require.Zero(t, n)
	require.Greater(t, body.reads.Load(), int32(1))
	require.Less(t, time.Since(start), time.Second)
	require.Error(t, ctx.Err())
}

// Admission's internal tier policy remains default. Only the trusted MiMo wire
// omits that field; the real peer must receive all unrelated bytes unchanged.
func TestGatewayNativeMiMoWireDefaultTier(t *testing.T) {
	const opaque = `"input":[{"type":"additional_tools","role":"developer","tools":[],"service_tier":"nested","n":9007199254740993,"v":1.2300,"s":"\u0061"}],"store":false,"stream":false`
	cases := []struct {
		name, payload, expected string
		denied                  bool
	}{
		{"first", `{ "service_tier" : "default", "model":"mimo-test",` + opaque + ` }`, `{ "model":"mimo-test",` + opaque + ` }`, false},
		{"middle escaped", `{"model":"mimo-test", "service\u005ftier":"default",` + opaque + `}`, `{"model":"mimo-test",` + opaque + `}`, false},
		{"last", `{"model":"mimo-test",` + opaque + `, "service_tier":"default" }`, `{"model":"mimo-test",` + opaque + ` }`, false},
		{"nondefault", `{"model":"mimo-test","service_tier":"priority",` + opaque + `}`, "", true},
		{"duplicate", `{"model":"mimo-test","service_tier":"default","service\u005ftier":"default",` + opaque + `}`, "", true},
		{"alias", `{"model":"mimo-test","Service_Tier":"default",` + opaque + `}`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			wire := make(chan []byte, 1)
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
				if err != nil {
					t.Error(err)
				}
				wire <- body
				assert.Equal(t, "true", r.Header.Get("x-openai-internal-codex-responses-lite"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
			}))
			defer peer.Close()
			account := nativeReviewStreamAccount(t, peer.URL, GatewayMiMoResponsesProfile)
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: &gatewayIdentityRealHTTP{client: peer.Client()}, cfg: rawChatCompletionsTestConfig()}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(tc.payload))
			original := []byte(tc.payload)
			payload := append([]byte(nil), original...)
			_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			require.Equal(t, original, payload, "internal normalized payload must not mutate")
			if tc.denied {
				require.Same(t, ErrGatewayNativeIdentity, err)
				require.False(t, entered)
				require.Zero(t, calls.Load())
				return
			}
			require.NoError(t, err)
			require.True(t, entered)
			require.EqualValues(t, 1, calls.Load())
			require.Equal(t, []byte(tc.expected), <-wire, "provider wire must differ only by the approved tier span")
		})
	}
}

func TestGatewayNativeOpenRouterWireDefaultTierUnchanged(t *testing.T) {
	payload := []byte(`{"model":"` + GatewayOpenRouterModel + `","service_tier":"default", "input":[{"n":9007199254740993,"v":1.2300}],"stream":false}`)
	transport := &nativeDiagnosticHTTP{response: &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"completed","output":[]}`)), Header: http.Header{}}}
	account := nativeReviewStreamAccount(t, GatewayOpenRouterBaseURL, GatewayOpenRouterResponsesProfile)
	account.Extra[GatewayModelExtraKey] = GatewayOpenRouterModel
	route, err := GatewayNativeDescriptor(account)
	require.NoError(t, err)
	svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
	_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
	require.NoError(t, err)
	require.True(t, entered)
	require.Equal(t, 1, transport.requests)
	actual, err := io.ReadAll(transport.lastRequest.Body)
	require.NoError(t, err)
	require.Equal(t, payload, actual)
}
