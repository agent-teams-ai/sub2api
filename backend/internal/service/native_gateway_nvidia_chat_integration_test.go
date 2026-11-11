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
	"github.com/stretchr/testify/require"
)

// Real native dispatch and Responses->Chat conversion, fake network only.
// The Chat target is still the exact fixed NVIDIA origin; this test never
// contacts NVIDIA and never uses a real credential.
func TestGatewayNVIDIABuildProtectedChatModelsAndToolCall(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, model := range []string{GatewayNVIDIABuildAnchorModel, GatewayNVIDIABuildGLMModel} {
		t.Run(model, func(t *testing.T) {
			a := &Account{
				ID:        17,
				CreatedAt: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
				Platform:  PlatformOpenAI,
				Type:      AccountTypeAPIKey,
				Status:    StatusActive,
				Credentials: map[string]any{
					"api_key":  "nvidia-synthetic-credential",
					"base_url": GatewayNVIDIABuildBaseURL,
				},
				Extra: map[string]any{
					GatewayGenerationExtraKey:              "12345678-1234-4234-8234-123456789abc",
					GatewayProfileExtraKey:                 GatewayNVIDIABuildChatProfile,
					GatewayModelExtraKey:                   GatewayNVIDIABuildAnchorModel,
					"openai_responses_mode":                "force_chat_completions",
					"openai_passthrough":                   false,
					"native_api_key_cancel_on_disconnect":  true,
					"openai_preserve_compatible_reasoning": true,
				},
			}
			nativeFixtureSealAccount(t, a)
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			syntheticSSE := "data: {\"id\":\"chat-synthetic\",\"model\":\"" + model + "\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_synthetic\",\"type\":\"function\",\"function\":{\"name\":\"echo_status\",\"arguments\":\"{\\\"item\\\":\\\"alpha\\\"}\"}}]},\"finish_reason\":null}]}\n\n" +
				"data: {\"id\":\"chat-synthetic\",\"model\":\"" + model + "\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" +
				"data: [DONE]\n\n"
			upstream := &nativeDiagnosticHTTP{response: &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(syntheticSSE)),
			}}
			svc := &OpenAIGatewayService{
				accountRepo:  &gatewayIdentityRepoFixture{row: a},
				httpUpstream: upstream,
				cfg:          rawChatCompletionsTestConfig(),
			}
			payload := []byte(`{"model":"` + model + `","input":"synthetic only","store":false,"stream":true,"max_output_tokens":128,"tools":[{"type":"function","name":"echo_status","description":"synthetic","parameters":{"type":"object","properties":{"item":{"type":"string"}},"required":["item"]}}],"tool_choice":"auto"}`)
			call := func(wire []byte) (*httptest.ResponseRecorder, bool, error) {
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(wire))
				_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, wire)
				return rec, entered, err
			}
			rec, entered, err := call(payload)
			require.NoError(t, err)
			require.True(t, entered)
			require.Equal(t, 1, upstream.requests)
			require.Contains(t, rec.Body.String(), "response.completed", "a tool call must have a full terminal event")
			require.Contains(t, rec.Body.String(), "[DONE]", "a native stream cannot silently finish on EOF")
			require.Contains(t, rec.Body.String(), "function_call")
			require.Equal(t, "https://integrate.api.nvidia.com/v1/chat/completions", upstream.lastRequest.URL.String())
			require.Equal(t, "Bearer nvidia-synthetic-credential", upstream.lastRequest.Header.Get("Authorization"))
			actual, err := io.ReadAll(upstream.lastRequest.Body)
			require.NoError(t, err)
			require.Contains(t, string(actual), `"model":"`+model+`"`)
			require.Contains(t, string(actual), `"function":{"name":"echo_status"`)
			require.NotContains(t, string(actual), "gcn1.")
			for _, unsupported := range []string{"vendor/mismatched", GatewayNVIDIABuildGLMModel + ":free"} {
				wrong := []byte(strings.Replace(string(payload), model, unsupported, 1))
				_, entered, err := call(wrong)
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
				require.Equal(t, 1, upstream.requests)
			}
		})
	}
}
