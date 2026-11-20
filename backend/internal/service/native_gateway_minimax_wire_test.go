//go:build unit

package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeMiniMaxWireDefaultTierAndReasoningHistory(t *testing.T) {
	// Codex 0.133 serializes an absent encrypted value as null while retaining
	// clear reasoning_text content and omitting the output-only reasoning ID.
	const history = `"input":[{"type":"reasoning","summary":[],"content":[{"type":"reasoning_text","text":"opaque \u0061 thought"}],"encrypted_content":null},{"type":"function_call","call_id":"call_1","name":"add_integers","arguments":"{\"a\":2,\"b\":3}"},{"type":"function_call_output","call_id":"call_1","output":"5"}],"tools":[{"type":"function","name":"add_integers","parameters":{"type":"object","properties":{"service_tier":{"const":"nested-preserved"},"n":{"const":9007199254740993}}},"strict":true}],"tool_choice":"auto","stream":true,"store":false,"max_output_tokens":4096`
	for _, tier := range []string{`"default"`, `"\u0064efault"`, `"priority"`} {
		t.Run(tier, func(t *testing.T) {
			payload := []byte(`{"model":"MiniMax-M3.1-Flash","service_tier":` + tier + `,` + history + `}`)
			want := []byte(`{"model":"MiniMax-M3.1-Flash",` + history + `}`)
			var calls atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, "/v1/responses", r.URL.Path)
				require.Equal(t, "ReviewRouter/native-account-gateway", r.Header.Get("User-Agent"))
				wire, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, want, wire, "only the top-level validated tier may be removed")
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			defer peer.Close()
			target, err := url.Parse(peer.URL)
			require.NoError(t, err)
			a := nativeReviewStreamAccount(t, GatewayMiniMaxMPlanResponsesBaseURL, GatewayMiniMaxMPlanResponsesProfile)
			a.Extra[GatewayModelExtraKey] = GatewayMiniMaxMPlanResponsesModel
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: &gatewayIdentityRealHTTP{client: &http.Client{Transport: kimiTierPeerTransport{peer: target}}}, cfg: rawChatCompletionsTestConfig()}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
			original := append([]byte(nil), payload...)
			_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			require.Equal(t, original, payload, "the admitted request must remain unchanged")
			if tier == `"priority"` {
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
				require.Zero(t, calls.Load())
			} else {
				require.NoError(t, err)
				require.True(t, entered)
				require.EqualValues(t, 1, calls.Load())
			}
		})
	}
}

// A malformed clear-reasoning history must fail before custody/provider entry.
// Other qualified providers retain their existing narrower history contract.
func TestGatewayNativeMiniMaxReasoningHistoryBounded(t *testing.T) {
	for _, test := range []struct{ name, profile, model, item string }{
		{"clear-without-encrypted", GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel, `{"type":"reasoning","id":"reasoning_1","summary":[],"content":[{"type":"reasoning_text","text":"thought"}]}`},
		{"clear-with-null-encrypted", GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel, `{"type":"reasoning","summary":[],"content":[{"type":"reasoning_text","text":"thought"}],"encrypted_content": null }`},
		{"null-content", GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel, `{"type":"reasoning","summary":[],"content":null}`},
		{"both-null", GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel, `{"type":"reasoning","summary":[],"content":null,"encrypted_content":null}`},
		{"gemini-encrypted-only", GatewayGeminiAPIKeyProfile, GatewayGeminiAPIModel, `{"type":"reasoning","summary":[],"content": null ,"encrypted_content":"opaque-carrier"}`},
		{"gemini-plain", GatewayGeminiAPIKeyProfile, GatewayGeminiAPIModel, `{"type":"reasoning","summary":[],"content":null,"encrypted_content":null}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"model":%q,"stream":true,"store":false,"max_output_tokens":100,"input":[%s]}`, test.model, test.item))
			original := append([]byte(nil), body...)
			wire, _, err := gatewayNativePrepareProviderResponses(test.profile, body, 4096)
			require.NoError(t, err)
			require.Equal(t, original, body, "admission must not mutate the caller's history")
			require.Equal(t, original, wire, "optional nulls must remain opaque on the admitted wire")
		})
	}
	for _, content := range []string{`{}`, `[{"type":"input_text","text":"wrong kind"}]`, `[{"type":"reasoning_text","text":null}]`, `[{"type":"reasoning_text","text":"ok","image_url":"forbidden"}]`, `[{"type":"reasoning_text","text":"ok","text":"duplicate"}]`} {
		body := []byte(fmt.Sprintf(`{"model":"MiniMax-M3.1-Flash","stream":true,"store":false,"max_output_tokens":100,"input":[{"type":"reasoning","summary":[],"content":%s}]}`, content))
		require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(GatewayMiniMaxMPlanResponsesProfile, body, 4096), ErrGatewayNativeIdentity)
	}
	for _, item := range []string{
		`{"type":"reasoning","content":null,"encrypted_content":{}}`,
		`{"type":"reasoning","content":null,"encrypted_content":[]}`,
		`{"type":"reasoning","content":null,"encrypted_content":false}`,
		`{"type":"reasoning","content":null,"encrypted_content":1}`,
		`{"type":"reasoning","content":null,"unknown":null}`,
		`{"type":"reasoning","content":null,"summary":null}`,
		`{"type":"reasoning","content":null,"status":null}`,
		`{"type":"reasoning","content":null,"id":null}`,
		`{"type":"reasoning","content":null,"content":null}`,
		`{"type":"reasoning","Content":null}`,
		`{"type":"reasoning","encrypted_content":null,"encrypted_content":"opaque"}`,
		`{"type":"reasoning","encrypted_content":null,"encrypted_\u0063ontent":null}`,
		`{"type":"reasoning","Encrypted_content":null}`,
	} {
		body := []byte(fmt.Sprintf(`{"model":"MiniMax-M3.1-Flash","stream":true,"store":false,"max_output_tokens":100,"input":[%s]}`, item))
		require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(GatewayMiniMaxMPlanResponsesProfile, body, 4096), ErrGatewayNativeIdentity, item)
	}
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
		{GatewayGeminiAPIKeyProfile, GatewayGeminiAPIModel},
	} {
		body := []byte(fmt.Sprintf(`{"model":%q,"stream":true,"store":false,"max_output_tokens":100,"input":[{"type":"reasoning","content":[{"type":"reasoning_text","text":"thought"}]}]}`, tuple.model))
		require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, body, 4096), ErrGatewayNativeIdentity)
	}
}
