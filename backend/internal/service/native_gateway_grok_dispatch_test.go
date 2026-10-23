//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type grokTransportStore struct {
	GatewayNativeGrokRepository
	physical        GatewayNativeOAuthPhysical
	envelope        string
	locks, releases atomic.Int32
}

func (r *grokTransportStore) LockGatewayGrokPhysical(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error) {
	r.locks.Add(1)
	if !GatewayNativeOAuthScopeAuthorized(ctx, scope) || scope != r.physical.Scope || operation != r.physical.Operation || route == nil || !SameGatewayNativeDescriptor(*route, r.physical.Route) {
		return GatewayNativeOAuthPhysical{}, "", nil, ErrGatewayNativeIdentity
	}
	return r.physical, r.envelope, func() { r.releases.Add(1) }, nil
}

type grokPassiveLimitsStore struct {
	GatewayAccountLimitsRepositoryV2
	writes   int
	physical GatewayNativeOAuthPhysical
	snapshot GatewayAccountLimitsSnapshotV2
	observed time.Time
	released *atomic.Int32
}

func (r *grokPassiveLimitsStore) StoreGatewayAccountLimitsV2(ctx context.Context, p GatewayNativeOAuthPhysical, snapshot GatewayAccountLimitsSnapshotV2, observed time.Time) error {
	if ctx.Err() != nil || r.released.Load() < 1 {
		return ErrGatewayNativeIdentity
	}
	r.writes++
	r.physical = p
	r.snapshot = snapshot
	r.observed = observed
	return nil
}

// Real fixed-origin HTTP transport, scoped AEAD custody and the existing
// finite reader run together. This is protocol proof, not a live qualification.
func TestGatewayGrokFiniteHTTPToolsAndSingleEntry(t *testing.T) {
	for _, mode := range []string{"tools", "400", "422", "redirect", "idle", "deadline", "output-bound"} {
		t.Run(mode, func(t *testing.T) {
			_, _, base, scope := connectPureFixture(t)
			route := GatewayNativeRoute{AccountID: 71, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Generation: scope.Generation, Profile: GatewayGrokOAuthResponsesProfile, BaseURL: GatewayGrokOAuthBaseURL, Model: GatewayGrokOAuthModel}
			store := &grokTransportStore{physical: GatewayNativeOAuthPhysical{CredentialRevision: 1, Scope: scope, Operation: "grok-connect", Route: route, Issuer: GatewayGrokOAuthIssuer, Subject: "owner-subject", ProviderAccount: "personal:owner-subject"}}
			dispatch, err := NewGatewayNativeGrokOAuth(store, nativeFixtureCustody(t), nil, GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
			require.NoError(t, err)
			store.envelope, err = dispatch.seal(scope, gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: "fixture-access", RefreshToken: "fixture-refresh", Subject: store.physical.Subject, Team: store.physical.ProviderAccount, ExpiresAt: time.Now().Add(time.Hour), Nonce: strings.Repeat("n", 43), ClientID: "qualified-client"})
			require.NoError(t, err)
			limits := &grokPassiveLimitsStore{released: &store.releases}
			var entries atomic.Int32
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				turn := entries.Add(1)
				require.Equal(t, "cli-chat-proxy.grok.com", r.Host)
				require.Equal(t, "/v1/responses", r.URL.Path)
				require.Equal(t, "Bearer fixture-access", r.Header.Get("Authorization"))
				require.Equal(t, xai.CLITokenAuth, r.Header.Get("X-XAI-Token-Auth"))
				require.Empty(t, r.Header.Get("x-grok-client-version"))
				require.Equal(t, xai.ProtectedClientIdentifier, r.Header.Get("x-grok-client-identifier"))
				require.Empty(t, r.Header.Get("x-grok-client-mode"))
				require.Equal(t, xai.ProtectedUserAgent, r.Header.Get("User-Agent"))
				require.Empty(t, r.Header.Get("Cookie"))
				require.Empty(t, r.Header.Get("Idempotency-Key"))
				require.Empty(t, r.Header.Get("X-Caller-Only"))
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, "grok-4.7", gjson.GetBytes(body, "model").String())
				require.Equal(t, "function", gjson.GetBytes(body, "tools.0.type").String())
				require.Equal(t, "exec", gjson.GetBytes(body, "tools.0.name").String())
				require.Equal(t, "function", gjson.GetBytes(body, "tools.1.type").String())
				if turn == 2 {
					require.Equal(t, "function_call", gjson.GetBytes(body, "input.0.type").String())
					require.Equal(t, "function_call_output", gjson.GetBytes(body, "input.1.type").String())
					require.Equal(t, "preserved result", gjson.GetBytes(body, "input.1.output").String())
				}
				switch mode {
				case "400":
					w.WriteHeader(400)
					return
				case "422":
					w.WriteHeader(422)
					return
				case "redirect":
					w.Header().Set("Location", "https://api.x.ai/v1/responses")
					w.WriteHeader(307)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("x-ratelimit-limit-requests", "100")
				w.Header().Set("x-ratelimit-remaining-requests", "75")
				if mode == "idle" || mode == "deadline" {
					_, _ = io.WriteString(w, ": heartbeat\n\n")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				if mode == "output-bound" {
					_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":%q}\n\n", strings.Repeat("x", 5000))
					return
				}
				// Vendor billing pings must never leak to strict Responses consumers.
				_, _ = io.WriteString(w, "event: ping\ndata: {\"cost\":999}\n\n")
				if turn == 1 {
					for _, event := range []string{
						`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"i1","call_id":"c1","name":"exec","arguments":"","status":"in_progress"}}`,
						`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"i1","delta":"{\"input\":\"echo preserved\"}"}`,
						`{"type":"response.function_call_arguments.done","output_index":0,"item_id":"i1","arguments":"{\"input\":\"echo preserved\"}"}`,
						`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"i1","call_id":"c1","name":"exec","arguments":"{\"input\":\"echo preserved\"}","status":"completed"}}`,
					} {
						_, _ = fmt.Fprintf(w, "data: %s\n\n", event)
					}
				}
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"function_call\",\"id\":\"i1\",\"call_id\":\"c1\",\"name\":\"exec\",\"arguments\":\"{\\\"input\\\":\\\"echo preserved\\\"}\"}],\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n")
			}))
			defer provider.Close()
			local := provider.Client().Transport.(*http.Transport).Clone()
			local.Proxy = nil
			local.TLSClientConfig.ServerName = "example.com"
			local.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "cli-chat-proxy.grok.com:443" {
					return nil, ErrGatewayNativeIdentity
				}
				return (&net.Dialer{}).DialContext(ctx, network, provider.Listener.Addr().String())
			}
			defer local.CloseIdleConnections()
			owned, err := NewGatewayNativeLifetimeUpstream(&gatewayIdentityRealHTTP{client: &http.Client{Transport: local, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{}, httpUpstream: owned}
			payload := []byte(`{"model":"grok-4.7","input":"controlled text","store":false,"stream":true,"service_tier":"default","max_output_tokens":100,"tools":[{"type":"custom","name":"exec","format":{"type":"text"}},{"type":"function","name":"read","parameters":{"type":"object"}}]}`)
			call := func(route GatewayNativeRoute, payload []byte) (*httptest.ResponseRecorder, bool, error, *GatewayNativeLifetime, GatewayNativeUsage) {
				timeout := time.Second
				if mode == "deadline" {
					timeout = 50 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(base, timeout)
				defer cancel()
				life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
				require.NoError(t, err)
				life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
				require.True(t, life.Admit(time.Now().Add(time.Second)))
				ctx = WithGatewayNativeLifetime(ctx, life)
				ctx = WithGatewayProviderLimitsWriter(ctx, limits)
				idle := 40 * time.Millisecond
				if mode == "deadline" {
					idle = time.Second
				}
				ctx = WithGatewayNativeProviderReadIdle(ctx, idle)
				var usage GatewayNativeUsage
				ctx = WithGatewayNativeUsageObserver(ctx, func(u GatewayNativeUsage) { usage = u })
				ctx, err = WithGatewayNativeGrokDispatch(ctx, dispatch, scope, store.physical.Operation, 4096, 100)
				require.NoError(t, err)
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
				for _, header := range []string{"Cookie", "User-Agent", "Authorization", "Idempotency-Key", "X-Caller-Only"} {
					c.Request.Header.Set(header, "caller-must-not-leak")
				}
				_, entered, err := svc.ForwardGatewayRoute(ctx, c, route, payload)
				return rec, entered, err, life, usage
			}
			for _, bad := range []string{strings.Replace(string(payload), `"controlled text"`, `[{"role":"user","content":[{"type":"input_image","image_url":"https://forbidden.invalid"}]}]`, 1), strings.Replace(string(payload), `"custom"`, `"web_search"`, 1)} {
				_, entered, err, _, _ := call(route, []byte(bad))
				require.Error(t, err)
				require.False(t, entered)
			}
			wrong := route
			wrong.BaseURL = "https://api.x.ai"
			_, entered, err, _, _ := call(wrong, payload)
			require.Error(t, err)
			require.False(t, entered)
			require.Zero(t, store.locks.Load())
			require.Zero(t, entries.Load())
			rec, entered, err, life, usage := call(route, payload)
			require.True(t, entered)
			require.EqualValues(t, 1, entries.Load())
			require.EqualValues(t, 1, store.locks.Load())
			require.EqualValues(t, 1, store.releases.Load())
			if mode != "tools" {
				require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
				require.False(t, life.Snapshot().Completed)
				return
			}
			require.NoError(t, err)
			require.True(t, life.Snapshot().Completed)
			require.NotContains(t, rec.Body.String(), "999")
			require.Contains(t, rec.Body.String(), "response.custom_tool_call_input.done")
			require.Contains(t, rec.Body.String(), "custom_tool_call")
			require.Contains(t, rec.Body.String(), "echo preserved")
			require.Equal(t, 1, limits.writes)
			require.Equal(t, route, limits.physical.Route)
			require.Equal(t, scope, limits.physical.Scope)
			require.EqualValues(t, 25, *limits.snapshot.Windows[0].UsedPercent)
			require.Equal(t, limits.observed.Format(time.RFC3339Nano), *limits.snapshot.Windows[0].ObservedAt)
			require.True(t, usage.Finalized)
			require.NotNil(t, usage.InputTokens)
			require.EqualValues(t, 7, *usage.InputTokens)
			require.EqualValues(t, 3, *usage.OutputTokens)
			var second map[string]any
			require.NoError(t, json.Unmarshal(payload, &second))
			second["input"] = []any{map[string]any{"type": "custom_tool_call", "call_id": "c1", "name": "exec", "input": "echo preserved"}, map[string]any{"type": "custom_tool_call_output", "call_id": "c1", "output": "preserved result"}, map[string]any{"type": "function_call", "call_id": "c2", "name": "read", "arguments": "{}"}, map[string]any{"type": "function_call_output", "call_id": "c2", "output": "read result"}}
			payload, err = json.Marshal(second)
			require.NoError(t, err)
			_, entered, err, life, _ = call(route, payload)
			require.NoError(t, err)
			require.True(t, entered)
			require.True(t, life.Snapshot().Completed)
			require.EqualValues(t, 2, entries.Load())
			require.EqualValues(t, 2, store.releases.Load())
		})
	}
}
