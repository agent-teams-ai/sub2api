//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	for _, model := range []string{GatewayNVIDIABuildAnchorModel} {
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

			// A real second Responses turn must replay the assistant call and
			// the client tool result through the same native bridge. No
			// previous_response_id, untrusted account affinity or secret reuse.
			nextSSE := "data: {\"id\":\"chat-next\",\"model\":\"" + model + "\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"synthetic done\"},\"finish_reason\":null}]}\n\n" +
				"data: {\"id\":\"chat-next\",\"model\":\"" + model + "\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
				"data: [DONE]\n\n"
			upstream.response = &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(nextSSE)),
			}
			nextPayload := []byte(`{"model":"` + model + `","input":[{"type":"function_call","name":"echo_status","call_id":"call_synthetic","arguments":"{\"item\":\"alpha\"}"},{"type":"function_call_output","call_id":"call_synthetic","output":"{\"status\":\"ok\"}"}],"store":false,"stream":true,"max_output_tokens":128,"tools":[{"type":"function","name":"echo_status","description":"synthetic","parameters":{"type":"object","properties":{"item":{"type":"string"}},"required":["item"]}}],"tool_choice":"auto"}`)
			next, nextEntered, nextErr := call(nextPayload)
			require.NoError(t, nextErr)
			require.True(t, nextEntered)
			require.Equal(t, 2, upstream.requests)
			require.Contains(t, next.Body.String(), "response.completed")
			require.Contains(t, next.Body.String(), "[DONE]")
			secondWire, err := io.ReadAll(upstream.lastRequest.Body)
			require.NoError(t, err)
			require.Contains(t, string(secondWire), `"tool_call_id":"call_synthetic"`)
			require.Contains(t, string(secondWire), `"role":"tool"`)
			// A known token-limit terminal closes the provider request, but its
			// response must remain incomplete and cannot qualify a lifecycle result.
			for _, terminal := range []struct {
				name, stream string
				known        bool
			}{
				{"text length", strings.Replace(nextSSE, `"finish_reason":"stop"`, `"finish_reason":"length"`, 1), true},
				{"empty length", strings.Replace(nativeReviewCCFinish, "stop", "length", 1) + nativeReviewDone, true},
				{"missing terminal", nativeReviewCCDelta + nativeReviewDone, false},
				{"tool length", strings.Replace(syntheticSSE, `"finish_reason":"tool_calls"`, `"finish_reason":"length"`, 1), false},
				{"partial tool length", `data: {"id":"sandbox","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_truncated","type":"function","function":{"name":"echo_status","arguments":"{"}}]},"finish_reason":null}]}` + "\n\n" + strings.Replace(nativeReviewCCFinish, "stop", "length", 1) + nativeReviewDone, false},
			} {
				t.Run(terminal.name, func(t *testing.T) {
					upstream.response.Body = io.NopCloser(strings.NewReader(terminal.stream))
					rec, entered, err := call(payload)
					require.True(t, entered)
					if terminal.known {
						require.NoError(t, err)
						require.Contains(t, rec.Body.String(), `"status":"incomplete"`)
						require.Contains(t, rec.Body.String(), `"reason":"max_output_tokens"`)
						require.Contains(t, rec.Body.String(), "[DONE]")
					} else {
						require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
						require.NotContains(t, rec.Body.String(), "response.completed")
						require.NotContains(t, rec.Body.String(), "response.function_call_arguments.done")
						require.NotContains(t, rec.Body.String(), "[DONE]")
					}
				})
			}
			// NVIDIA's streaming-only admission remains unchanged, independently
			// of the historical bridge's buffered incomplete-result support.
			_, bufferedEntered, bufferedErr := call([]byte(strings.Replace(string(payload), `"stream":true`, `"stream":false`, 1)))
			require.False(t, bufferedEntered)
			require.ErrorIs(t, bufferedErr, ErrGatewayNativeIdentity)
			for _, unsupported := range []string{"vendor/mismatched", GatewayNVIDIABuildAnchorModel + ":free"} {
				wrong := []byte(strings.Replace(string(payload), model, unsupported, 1))
				_, entered, err := call(wrong)
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
				require.Equal(t, 7, upstream.requests)
			}
		})
	}
}

// Exercise the real protected NVIDIA failure path in a fresh process, where
// native stderr is the existing bounded Gateway diagnostic input.
func TestGatewayNVIDIABuildTerminalDiagnostics(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGatewayNVIDIABuildProtectedChatModelsAndToolCall$")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), `{"event":"gateway_native_response_failure","phase":"invalid_final"}`)
	require.NotContains(t, string(output), "nvidia-synthetic-credential")
	require.NotContains(t, string(output), "call_truncated")
}
