//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const claudeResponsesFixtureBody = `{"model":"claude-sonnet-4-6","instructions":"Fixture system instructions stay at system priority.","input":"fixture input","store":false,"stream":true,"service_tier":"default","max_output_tokens":100}`
const claudeMessagesFixtureSSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"usage\":{\"input_tokens\":7,\"output_tokens\":0,\"cache_read_input_tokens\":2,\"cache_creation_input_tokens\":1}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"fixture answer\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

type claudeTransportStore struct {
	GatewayNativeClaudeRepository
	physical                  GatewayNativeOAuthPhysical
	envelope                  string
	locks, releases, captures int
	limits                    GatewayClaudeRawLimits
	observed                  time.Time
}

func (r *claudeTransportStore) ResolveGatewayClaudeCanonical(ctx context.Context, route GatewayNativeRoute, account string) (GatewayNativeCredentialScope, string, error) {
	consumer, err := GatewayNativeConsumer(ctx)
	if err != nil || consumer != r.physical.Scope.Consumer || account != r.physical.Scope.Account || !SameGatewayNativeDescriptor(route, r.physical.Route) {
		return GatewayNativeCredentialScope{}, "", ErrGatewayNativeIdentity
	}
	return r.physical.Scope, r.physical.Operation, nil
}
func (r *claudeTransportStore) LockGatewayClaudePhysical(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error) {
	r.locks++
	if !GatewayNativeOAuthScopeAuthorized(ctx, scope) || scope != r.physical.Scope || operation != r.physical.Operation || route != nil && !SameGatewayNativeDescriptor(*route, r.physical.Route) {
		return GatewayNativeOAuthPhysical{}, "", nil, ErrGatewayNativeIdentity
	}
	return r.physical, r.envelope, func() { r.releases++ }, nil
}
func (r *claudeTransportStore) StoreGatewayClaudeLimits(_ context.Context, p GatewayNativeOAuthPhysical, limits GatewayClaudeRawLimits, observed time.Time) error {
	if p.Scope != r.physical.Scope || p.CredentialRevision != r.physical.CredentialRevision {
		return ErrGatewayNativeIdentity
	}
	r.captures++
	r.limits, r.observed = limits, observed
	return nil
}

type claudeTransportHTTP struct {
	HTTPUpstream
	calls    int
	body     string
	status   int
	headers  http.Header
	closeErr error
	doErr    error
	closed   atomic.Bool
	inspect  func(*http.Request)
	onRead   func()
}
type claudeTransportBody struct {
	io.Reader
	closed *atomic.Bool
	err    error
	onRead func()
}

func (b *claudeTransportBody) Close() error { b.closed.Store(true); return b.err }
func (b *claudeTransportBody) Read(p []byte) (int, error) {
	if b.onRead != nil {
		b.onRead()
	}
	return b.Reader.Read(p)
}
func (u *claudeTransportHTTP) Do(r *http.Request, proxy string, id int64, concurrency int) (*http.Response, error) {
	u.calls++
	if u.inspect != nil {
		u.inspect(r)
	}
	return &http.Response{StatusCode: u.status, Header: u.headers, Body: &claudeTransportBody{strings.NewReader(u.body), &u.closed, u.closeErr, u.onRead}, Request: r}, u.doErr
}

// The real source seam, AEAD bundle opening, one-use/lifetime CAS, converter,
// passive snapshot writer and physical body close run with controlled storage.
// PostgreSQL locking and OAuth exchange are separately covered by native tests.
func TestGatewayNativeClaudeResponsesDispatchLifecycle(t *testing.T) {
	for _, mode := range []string{"complete", "truncated", "rate-limit", "close-failure", "output-cap", "sealed", "invalid-media", "transport-error"} {
		t.Run(mode, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			scope := GatewayNativeCredentialScope{Consumer: "claude-consumer", Owner: "claude-owner", Account: "claude-account", Generation: uuid.NewString(), Purpose: GatewayOAuthBundlePurpose}
			route := GatewayNativeRoute{AccountID: 31, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Generation: scope.Generation, Profile: GatewayClaudeOAuthMessagesProfile, Model: GatewayClaudeOAuthModel, BaseURL: GatewayClaudeOAuthBaseURL}
			store := &claudeTransportStore{physical: GatewayNativeOAuthPhysical{Scope: scope, Operation: "claude-connect", Route: route, Issuer: GatewayClaudeOAuthIssuer, Subject: uuid.NewString(), ProviderAccount: uuid.NewString(), CredentialRevision: 1}}
			dispatch, err := NewGatewayNativeClaudeOAuth(store, nativeFixtureCustody(t), nil)
			require.NoError(t, err)
			store.envelope, err = dispatch.seal(scope, gatewayClaudeBundle{Kind: "claude-oauth/v1", Revision: 1, AccessToken: "fixture-claude-access", RefreshToken: "fixture-claude-refresh", Account: store.physical.Subject, Organization: store.physical.ProviderAccount, ExpiresAt: time.Now().Add(time.Hour)})
			require.NoError(t, err)
			upstream := &claudeTransportHTTP{status: http.StatusOK, body: claudeMessagesFixtureSSE, headers: http.Header{"Content-Type": {"text/event-stream"}, "Anthropic-Ratelimit-Unified-5h-Utilization": {"0.25"}, "Anthropic-Ratelimit-Unified-5h-Reset": {"1792700000"}, "X-Secret-Provider-Diagnostic": {"must-not-escape"}}}
			upstream.inspect = func(r *http.Request) {
				require.Zero(t, store.releases, "credential identity must remain fenced through provider entry")
				require.Equal(t, "https://api.anthropic.com/v1/messages?beta=true", r.URL.String())
				require.Equal(t, "Bearer fixture-claude-access", r.Header.Get("Authorization"))
				require.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
				for _, beta := range []string{"claude-code-20250219", "oauth-2025-04-20", "context-management-2025-06-27", "effort-2025-11-24", "extended-cache-ttl-2025-04-11"} {
					require.Contains(t, strings.Split(r.Header.Get("anthropic-beta"), ","), beta)
				}
				require.Regexp(t, `^claude-cli/[0-9]+\.[0-9]+\.[0-9]+ \(external, cli\)$`, r.Header.Get("User-Agent"))
				require.Equal(t, "cli", r.Header.Get("X-App"))
				require.Equal(t, "js", r.Header.Get("X-Stainless-Lang"))
				require.Equal(t, "node", r.Header.Get("X-Stainless-Runtime"))
				require.Equal(t, "0", r.Header.Get("X-Stainless-Retry-Count"))
				require.Empty(t, r.Header.Get("Cookie"))
				require.Empty(t, r.Header.Get("X-Caller-Only"))
				require.Nil(t, r.GetBody)
				var body map[string]json.RawMessage
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.JSONEq(t, `[{"role":"user","content":"fixture input"}]`, string(body["messages"]))
				require.Equal(t, "100", string(body["max_tokens"]))
				require.Nil(t, body["input"])
				require.Nil(t, body["store"])
				require.JSONEq(t, `[]`, string(body["tools"]))
				require.Equal(t, "1", string(body["temperature"]))
				var system []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}
				require.NoError(t, json.Unmarshal(body["system"], &system))
				require.Len(t, system, 4)
				version := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("User-Agent"), "claude-cli/"), " (external, cli)")
				require.Contains(t, system[0].Text, "cc_version="+version+".")
				require.Contains(t, system[0].Text, "cc_entrypoint=cli;")
				require.Equal(t, "You are Claude Code, Anthropic's official CLI for Claude.", system[1].Text)
				require.Contains(t, system[2].Text, "You are an interactive agent")
				require.Equal(t, "Fixture system instructions stay at system priority.", system[3].Text)

			}
			upstream.onRead = func() {
				require.Equal(t, store.locks, store.releases, "SQL identity guard must release before the first SSE body read")
				require.Equal(t, 1, store.captures, "passive limits publish after releasing SQL and before streaming")
			}
			if mode == "truncated" {
				upstream.body = strings.Split(claudeMessagesFixtureSSE, "event: message_stop")[0]
			}
			if mode == "rate-limit" {
				upstream.status, upstream.body = http.StatusTooManyRequests, `{"error":{"message":"must-not-escape"}}`
			}
			if mode == "close-failure" {
				upstream.closeErr = errors.New("fixture close failed")
			}
			if mode == "invalid-media" {
				upstream.headers.Set("Content-Type", "application/json")
			}
			if mode == "transport-error" {
				upstream.doErr = errors.New("fixture transport failed after response ownership")
			}
			wrapped, err := NewGatewayNativeLifetimeUpstream(upstream)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{httpUpstream: wrapped}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			ctx, err = WithGatewayNativeConsumer(ctx, scope.Consumer)
			require.NoError(t, err)
			cap := int64(8192)
			if mode == "output-cap" {
				cap = 100
			}
			life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, cap)
			require.NoError(t, err)
			life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
			require.True(t, life.Admit(time.Now().Add(time.Minute)))
			ctx = WithGatewayNativeLifetime(ctx, life)
			ctx, err = dispatch.BindApproved(ctx, route, scope.Account, 3, 4096, 100)
			require.NoError(t, err)
			var usage GatewayNativeUsage
			ctx = WithGatewayNativeUsageObserver(ctx, func(u GatewayNativeUsage) { usage = u })
			if mode == "sealed" {
				life.Cancel()
			}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/transports", nil)
			c.Request.Header.Set("Cookie", "foreign")
			c.Request.Header.Set("X-Caller-Only", "foreign")
			result, entered, err := svc.ForwardGatewayRoute(ctx, c, route, []byte(claudeResponsesFixtureBody))
			if mode == "complete" || mode == "close-failure" {
				require.NoError(t, err)
				require.True(t, entered)
				require.NotNil(t, result)
				require.Contains(t, recorder.Body.String(), "event: response.completed")
				require.Contains(t, recorder.Body.String(), "fixture answer")
				require.Equal(t, "complete", usage.State)
				require.True(t, usage.Finalized)
				require.EqualValues(t, 10, *usage.InputTokens)
				require.EqualValues(t, 3, *usage.OutputTokens)
				require.EqualValues(t, 2, *usage.CachedInputTokens)
			} else {
				require.Error(t, err)
				require.NotContains(t, recorder.Body.String(), "event: response.completed")
				if mode == "sealed" {
					require.False(t, entered)
					require.Equal(t, 0, upstream.calls)
				} else {
					require.True(t, entered)
					require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
					require.Equal(t, "unknown", usage.State)
				}
			}
			if mode != "sealed" {
				require.Equal(t, 1, upstream.calls)
				require.Eventually(t, upstream.closed.Load, time.Second, time.Millisecond)
				if mode == "transport-error" {
					require.Zero(t, store.captures)
				} else {
					require.Equal(t, 1, store.captures)
					require.Len(t, store.limits.Windows, 1)
					require.Equal(t, GatewayClaudeFiveHour, store.limits.Windows[0].ID)
					require.False(t, store.observed.IsZero())
				}
			}
			require.Equal(t, store.locks, store.releases)
			snapshot := life.Snapshot()
			require.True(t, snapshot.ForwardingReturned)
			require.True(t, snapshot.ContextDone)
			require.True(t, snapshot.BodyKnown)
			if mode == "close-failure" {
				require.True(t, snapshot.CloseFailed)
				require.False(t, snapshot.BodyClosed)
			} else {
				require.True(t, snapshot.BodyClosed)
			}
			require.NotContains(t, recorder.Body.String(), "fixture-claude-access")
			require.NotContains(t, recorder.Body.String(), "must-not-escape")
		})
	}
}

// Unsupported modalities or aliases must fail before credential/provider entry;
// the converter's permissive fallback must never silently drop caller intent.
func TestGatewayNativeClaudeResponsesRejectsLossyInput(t *testing.T) {
	require.NoError(t, ValidateGatewayNativeClaudeResponses([]byte(claudeResponsesFixtureBody)))
	require.Error(t, ValidateGatewayNativeClaudeResponsesBounded([]byte(claudeResponsesFixtureBody), int64(len(claudeResponsesFixtureBody))))
	for _, addition := range []string{`,"previous_response_id":"resp_old"`, `,"text":{"format":{"type":"json_schema"}}`, `,"tools":[{"type":"custom","name":"shell"}]`, `,"temperature":null`, `,"MODEL":"claude-sonnet-4-6"`} {
		body := strings.TrimSuffix(claudeResponsesFixtureBody, "}") + addition + "}"
		require.Error(t, ValidateGatewayNativeClaudeResponses([]byte(body)), body)
	}
	for _, input := range []string{`[{"role":"user","content":[{"type":"input_image","image_url":"https://fixture.invalid/image"}]}]`, `[{"role":"user","content":"text","output":"silently ignored"}]`, `[{"type":"function_call_output","call_id":"missing","output":"orphan"}]`, `[{"role":"system","content":"no user message"}]`} {
		body := bytes.ReplaceAll([]byte(claudeResponsesFixtureBody), []byte(`"fixture input"`), []byte(input))
		require.Error(t, ValidateGatewayNativeClaudeResponses(body), input)
	}
}

// OAuth attribution may supply defaults, but never rename tools, replace an
// explicit sampling choice, inject conversation turns or demote system text.
func TestGatewayNativeClaudeOAuthAttributionPreservesCanonicalIntent(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","instructions":"Preserve system priority.","input":"fixture tool input","store":false,"stream":true,"service_tier":"default","max_output_tokens":20000,"temperature":0.25,"top_p":0.9,"parallel_tool_calls":false,"tools":[{"type":"function","name":"read_fixture","description":"Read the fixture.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}],"tool_choice":{"type":"function","name":"read_fixture"}}`)
	wire, _, err := gatewayClaudePrepareResponses(body)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &fields))
	require.Equal(t, "0.25", string(fields["temperature"]))
	require.Equal(t, "0.9", string(fields["top_p"]))
	require.Equal(t, "20000", string(fields["max_tokens"]))
	require.JSONEq(t, `[{"role":"user","content":"fixture tool input"}]`, string(fields["messages"]))
	require.JSONEq(t, `[{"name":"read_fixture","description":"Read the fixture.","input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}]`, string(fields["tools"]))
	require.JSONEq(t, `{"type":"tool","name":"read_fixture","disable_parallel_tool_use":true}`, string(fields["tool_choice"]))
	thinking := bytes.ReplaceAll(body, []byte(`"temperature":0.25,"top_p":0.9,`), []byte(`"reasoning":{"effort":"medium"},`))
	// Forced tools are incompatible with enabled thinking, so this rejects
	// before Enter instead of silently changing the caller's tool choice.
	require.Error(t, ValidateGatewayNativeClaudeResponses(thinking))
	thinking = bytes.ReplaceAll(thinking, []byte(`"tool_choice":{"type":"function","name":"read_fixture"}`), []byte(`"tool_choice":"auto"`))
	wire, _, err = gatewayClaudePrepareResponses(thinking)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(wire, &fields))
	require.Equal(t, "1", string(fields["temperature"]))
	require.JSONEq(t, `{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}`, string(fields["context_management"]))
	require.Error(t, ValidateGatewayNativeClaudeResponses(bytes.ReplaceAll(thinking, []byte(`"reasoning":{"effort":"medium"}`), []byte(`"reasoning":{"effort":"medium"},"temperature":0.25`))))
}
