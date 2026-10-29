//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const claudeNativeRequest = `{"model":"claude-sonnet-4-6","max_tokens":4096,"stream":true,"system":[{"type":"text","text":"Preserve native system priority.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Inspect fixture"},{"role":"assistant","content":[{"type":"thinking","thinking":"Prior thought","signature":"opaque-history-signature"},{"type":"tool_use","id":"tool_history","name":"read_fixture","input":{"path":"fixture","Path":"case-sensitive property"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool_history","content":[{"type":"text","text":"Native result"}]}]}],"tools":[{"name":"read_fixture","description":"Read fixture","input_schema":{"type":"object","properties":{"path":{"type":"string"}}},"cache_control":{"type":"ephemeral"}}],"thinking":{"type":"enabled","budget_tokens":1024},"metadata":{"user_id":"native-fixture-user"},"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]},"output_config":{"effort":"high"}}`

const claudeNativeSSEStart = ": native keepalive\r\n\r\nevent: ping\ndata: {\"type\":\"ping\"}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_native\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":7,\"output_tokens\":0,\"cache_read_input_tokens\":2,\"cache_creation_input_tokens\":1}}}\n\n"
const claudeNativeSSEBlocks = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Native thought\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"opaque-output-signature\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Native answer\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool_native\",\"name\":\"read_fixture\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"native\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n"
const claudeNativeSSEDelta = "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"input_tokens\":8,\"output_tokens\":5,\"cache_read_input_tokens\":3,\"cache_creation_input_tokens\":1}}\n\n"
const claudeNativeSSEStop = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

func claudeNativeFixture(t *testing.T, upstream *claudeTransportHTTP, native bool, outputBytes int64) (context.Context, *OpenAIGatewayService, GatewayNativeRoute, *claudeTransportStore, *GatewayNativeLifetime) {
	t.Helper()
	scope := GatewayNativeCredentialScope{Consumer: "native-consumer", Owner: "native-owner", Account: "native-account", Generation: uuid.NewString(), Purpose: GatewayOAuthBundlePurpose}
	route := GatewayNativeRoute{AccountID: 32, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Generation: scope.Generation, Profile: GatewayClaudeOAuthMessagesProfile, Model: GatewayClaudeOAuthModel, BaseURL: GatewayClaudeOAuthBaseURL}
	store := &claudeTransportStore{physical: GatewayNativeOAuthPhysical{Scope: scope, Operation: "native-connect", Route: route, Issuer: GatewayClaudeOAuthIssuer, Subject: uuid.NewString(), ProviderAccount: uuid.NewString(), CredentialRevision: 1}}
	dispatch, err := NewGatewayNativeClaudeOAuth(store, nativeFixtureCustody(t), nil)
	require.NoError(t, err)
	store.envelope, err = dispatch.seal(scope, gatewayClaudeBundle{Kind: "claude-oauth/v1", Revision: 1, AccessToken: "native-fixture-access", RefreshToken: "native-fixture-refresh", Account: store.physical.Subject, Organization: store.physical.ProviderAccount, ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	wrapped, err := NewGatewayNativeLifetimeUpstream(upstream)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	ctx, err = WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, outputBytes)
	require.NoError(t, err)
	life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
	require.True(t, life.Admit(time.Now().Add(time.Minute)))
	ctx = WithGatewayNativeLifetime(ctx, life)
	if native {
		ctx = WithGatewayNativeClaudeMessages(ctx)
	}
	ctx, err = dispatch.BindApproved(ctx, route, scope.Account, 1, 16384, 4096)
	require.NoError(t, err)
	return ctx, &OpenAIGatewayService{httpUpstream: wrapped}, route, store, life
}

func TestGatewayNativeClaudeMessagesPreservesNativeWireAndUsage(t *testing.T) {
	complete := claudeNativeSSEStart + claudeNativeSSEBlocks + claudeNativeSSEDelta + claudeNativeSSEStop
	for _, mode := range []string{"complete", "truncated", "truncated-stop", "missing-delta", "output-cap", "max_tokens", "pause_turn", "refusal", "model_context_window_exceeded"} {
		t.Run(mode, func(t *testing.T) {
			wire := complete
			cap := int64(16384)
			switch mode {
			case "truncated":
				wire = strings.TrimSuffix(wire, claudeNativeSSEStop)
			case "truncated-stop":
				wire = strings.TrimSuffix(wire, "\n")
			case "missing-delta":
				wire = strings.Replace(wire, claudeNativeSSEDelta, "", 1)
			case "output-cap":
				cap = 100
			case "complete":
			default:
				wire = strings.Replace(wire, `"stop_reason":"tool_use"`, `"stop_reason":"`+mode+`"`, 1)
			}
			upstream := &claudeTransportHTTP{status: 200, body: wire, headers: http.Header{"Content-Type": {"text/event-stream"}}}
			ctx, gateway, route, store, life := claudeNativeFixture(t, upstream, true, cap)
			upstream.inspect = func(r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.True(t, bytes.Equal([]byte(claudeNativeRequest), raw), "native signed history and tool schema must reach HTTP unchanged")
				require.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
				require.Nil(t, r.GetBody)
				require.Zero(t, store.releases)
			}
			upstream.onRead = func() { require.Equal(t, store.locks, store.releases) }
			var usage GatewayNativeUsage
			ctx = WithGatewayNativeUsageObserver(ctx, func(u GatewayNativeUsage) { usage = u })
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			_, entered, err := gateway.ForwardGatewayRoute(ctx, c, route, []byte(claudeNativeRequest))
			require.True(t, entered)
			require.Equal(t, 1, upstream.calls)
			require.True(t, upstream.closed.Load())
			require.True(t, life.Snapshot().BodyClosed)
			require.True(t, usage.Finalized)
			if mode == "truncated" || mode == "truncated-stop" || mode == "missing-delta" || mode == "output-cap" {
				require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
				require.Equal(t, "unknown", usage.State)
				require.False(t, life.Snapshot().Completed)
				require.NotContains(t, recorder.Body.String(), "event: message_stop")
				if mode == "truncated" || mode == "truncated-stop" {
					require.EqualValues(t, 12, *usage.InputTokens)
					require.EqualValues(t, 5, *usage.OutputTokens)
				}
			} else {
				require.NoError(t, err)
				require.True(t, bytes.Equal([]byte(wire), recorder.Body.Bytes()), "native frames, signatures, comments and tool deltas must retain exact bytes")
				require.Equal(t, "complete", usage.State)
				require.EqualValues(t, 12, *usage.InputTokens)
				require.EqualValues(t, 5, *usage.OutputTokens)
				require.EqualValues(t, 3, *usage.CachedInputTokens)
			}
		})
	}
}

func TestGatewayNativeClaudeMessagesRejectsBeforeProviderEntry(t *testing.T) {
	cases := map[string]string{
		"invalid-json":      strings.TrimSuffix(claudeNativeRequest, "}"),
		"foreign-model":     strings.Replace(claudeNativeRequest, "claude-sonnet-4-6", "foreign-model", 1),
		"over-token-budget": strings.Replace(claudeNativeRequest, `"max_tokens":4096`, `"max_tokens":4097`, 1),
		"fractional-tokens": strings.Replace(claudeNativeRequest, `"max_tokens":4096`, `"max_tokens":4.096e3`, 1),
		"model-alias":       strings.Replace(claudeNativeRequest, `"model":`, `"MODEL":`, 1),
		"duplicate-model":   strings.Replace(claudeNativeRequest, `"model":`, `"model":"foreign","model":`, 1),
		"nested-duplicate":  strings.Replace(claudeNativeRequest, `"path":"fixture"`, `"path":"first","path":"fixture"`, 1),
		"nested-alias":      strings.Replace(claudeNativeRequest, `"signature":`, `"Signature":`, 1),
		"unknown-control":   strings.TrimSuffix(claudeNativeRequest, "}") + `,"base_url":"https://foreign.invalid"}`,
		"private-mode":      strings.TrimSuffix(claudeNativeRequest, "}") + `,"gateway_native_messages":true}`,
		"nonstream":         strings.Replace(claudeNativeRequest, `"stream":true`, `"stream":false`, 1),
		"malformed-content": strings.Replace(claudeNativeRequest, `"content":"Inspect fixture"`, `"content":42`, 1),
		"missing-signature": strings.Replace(claudeNativeRequest, `,"signature":"opaque-history-signature"`, ``, 1),
		"unknown-tool":      strings.Replace(claudeNativeRequest, `"name":"read_fixture","description"`, `"type":"hosted-unknown","name":"read_fixture","description"`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			upstream := &claudeTransportHTTP{}
			ctx, gateway, route, store, life := claudeNativeFixture(t, upstream, true, 16384)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			_, entered, err := gateway.ForwardGatewayRoute(ctx, c, route, []byte(body))
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.False(t, entered)
			require.Zero(t, upstream.calls)
			require.Zero(t, store.locks)
			require.True(t, life.Snapshot().BodyClosed)
		})
	}
	require.NoError(t, ValidateGatewayNativeClaudeMessagesBounded([]byte(claudeNativeRequest), int64(len(claudeNativeRequest)), 4096))
	require.Error(t, ValidateGatewayNativeClaudeMessagesBounded([]byte(claudeNativeRequest), int64(len(claudeNativeRequest)-1), 4096))
	require.Error(t, ValidateGatewayNativeClaudeMessagesBounded([]byte(claudeNativeRequest), 16384, 4095))
	upstream := &claudeTransportHTTP{}
	ctx, gateway, route, store, _ := claudeNativeFixture(t, upstream, false, 16384)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	_, entered, err := gateway.ForwardGatewayRoute(ctx, c, route, []byte(claudeNativeRequest))
	require.Error(t, err)
	require.False(t, entered, "a caller path alone must never select trusted native mode")
	require.Zero(t, store.locks)
	require.Zero(t, upstream.calls)
}
