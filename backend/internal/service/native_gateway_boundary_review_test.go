//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Count the actual native transport entry, as well as local server requests.
// Repository state is controlled; no provider request or PostgreSQL proof.
type gatewayBoundaryReviewHTTP struct {
	gatewayIdentityRealHTTP
	entries atomic.Int32
}

func (h *gatewayBoundaryReviewHTTP) Do(r *http.Request, proxy string, id int64, concurrency int) (*http.Response, error) {
	h.entries.Add(1)
	return h.gatewayIdentityRealHTTP.Do(r, proxy, id, concurrency)
}

func TestGatewayNativeReviewAmbiguousPolicyFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var requests atomic.Int32
	var expected []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		if expected != nil {
			assert.True(t, bytes.Equal(body, expected), "native noncritical bytes must survive unchanged")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer upstream.Close()
	cases := []struct{ name, field, first, last, pair string }{
		{"model", "model", `"mimo-test"`, `"foreign-model"`, `"model":"mimo-test","model":"foreign-model"`},
		{"store", "store", `false`, `true`, `"store":false,"store":true`},
		{"previous response", "previous_response_id", `""`, `"foreign-response"`, `"previous_response_id":"","previous_response_id":"foreign-response"`},
		{"service tier", "service_tier", `"default"`, `"priority"`, `"service_tier":"default","service_tier":"priority"`},
		{"escaped model", "model", `"mimo-test"`, `"foreign-model"`, `"model":"mimo-test","mo\u0064el":"foreign-model"`},
	}
	for _, profile := range []string{GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile} {
		t.Run(profile, func(t *testing.T) {
			mode, passthrough := "force_responses", true
			if profile == GatewayLegacyBridgeProfile {
				mode, passthrough = "force_chat_completions", false
			}
			a := &Account{ID: 17, CreatedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
				Credentials: map[string]any{"api_key": "sandbox-fixture", "base_url": upstream.URL},
				Extra:       map[string]any{GatewayGenerationExtraKey: "33333333-3333-4333-8333-333333333333", GatewayProfileExtraKey: profile, GatewayModelExtraKey: "mimo-test", "openai_responses_mode": mode, "openai_passthrough": passthrough, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
			nativeFixtureSealAccount(t, a)
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			transport := &gatewayBoundaryReviewHTTP{gatewayIdentityRealHTTP: gatewayIdentityRealHTTP{client: upstream.Client()}}
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			call := func(body []byte) (bool, error) {
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
				_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, body)
				return entered, err
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					prefix := `{"input":[] ,`
					if tc.field != "model" {
						prefix += `"model":"mimo-test",`
					}
					payload := []byte(prefix + tc.pair + `}`)
					// Independently demonstrate the parser disagreement on these exact bytes.
					var standard map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(payload, &standard))
					require.True(t, bytes.Equal(standard[tc.field], []byte(tc.last)), "standard JSON selects the last policy value")
					require.Equal(t, tc.first, gjson.GetBytes(payload, tc.field).Raw, "native preflight selects the first policy value")
					before := requests.Load()
					entered, err := call(payload)
					assert.Zero(t, transport.entries.Load(), "ambiguous policy must reach zero transport entries")
					assert.False(t, entered)
					assert.ErrorIs(t, err, ErrGatewayNativeIdentity)
					assert.Equal(t, before, requests.Load())
				})
			}
			t.Run("identical duplicate policy is still ambiguous", func(t *testing.T) {
				entered, err := call([]byte(`{"model":"mimo-test","store":false,"store":false}`))
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
				require.Zero(t, transport.entries.Load())
			})
			if profile == GatewayMiMoResponsesProfile {
				t.Run("nested and noncritical duplicates preserve all native bytes", func(t *testing.T) {
					expected = []byte(" {\n\"model\":\"mimo-test\",\"store\":false,\"metadata\":{\"model\":\"nested\",\"model\":\"nested-last\"},\"input\":[],\"metadata\":{\"store\":true}} ")
					entered, err := call(expected)
					require.NoError(t, err)
					require.True(t, entered)
					require.EqualValues(t, 1, transport.entries.Load())
				})
			}
		})
	}
}
