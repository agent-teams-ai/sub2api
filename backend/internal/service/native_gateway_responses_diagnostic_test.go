//go:build unit

package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type nativeDiagnosticBody struct {
	io.Reader
	reads, closes, bytesRead int
	readErr                  error
}

func (b *nativeDiagnosticBody) Read(p []byte) (int, error) {
	b.reads++
	if b.readErr != nil {
		return 0, b.readErr
	}
	n, err := b.Reader.Read(p)
	b.bytesRead += n
	return n, err
}

func (b *nativeDiagnosticBody) Close() error {
	b.closes++
	return nil
}

type nativeDiagnosticHTTP struct {
	HTTPUpstream
	response    *http.Response
	err         error
	requests    int
	lastRequest *http.Request
}

func (h *nativeDiagnosticHTTP) Do(request *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	h.requests++
	h.lastRequest = request
	return h.response, h.err
}

// Red on the previous code: an entered HTTP rejection has no safe phase/status
// diagnostic. The same boundary must still return the exact unknown singleton,
// bound HTTP400 reads, never retry or disclose supplied private content.
func TestGatewayNativeResponsesFailureDiagnostics(t *testing.T) {
	// One fresh process reproduces the private bootstrap's uninitialized logger
	// and isolates stderr replacement from all other tests (including parallel
	// tests). No generic logger is initialized just to make diagnostics visible.
	if os.Getenv("RR_NATIVE_DIAGNOSTIC_TEST_CHILD") != "1" {
		child := exec.Command(os.Args[0], "-test.run=^TestGatewayNativeResponsesFailureDiagnostics$")
		child.Env = append(os.Environ(), "RR_NATIVE_DIAGNOSTIC_TEST_CHILD=1")
		output, err := child.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	require.False(t, logger.L().Core().Enabled(zap.WarnLevel), "private composition starts without the generic logger")
	const sentinel = "PRIVATE_NATIVE_DIAGNOSTIC_SENTINEL"
	cases := []struct {
		name, contentType, wire, phase, category string
		status                                   int
		stream, success, unread                  bool
		transportErr, readErr                    error
	}{
		{name: "http400", status: 400, phase: "http_status", category: "invalid_error_json", wire: sentinel},
		{name: "http400 unknown private", status: 400, phase: "http_status", category: "unknown", wire: `{"error":{"code":"` + sentinel + `","message":"` + sentinel + `","param":"` + sentinel + `"}}`},
		{name: "http400 parameter", status: 400, phase: "http_status", category: "parameter_service_tier", wire: `{"error":{"code":"invalid_request_error","message":"` + sentinel + `","param":"service_tier"}}`},
		{name: "http400 code mode", status: 400, phase: "http_status", category: "code_mode_rejected", wire: `{"error":{"code":"code_mode_only","message":"` + sentinel + `"}}`},
		{name: "http400 lite", status: 400, phase: "http_status", category: "responses_lite_required", wire: `{"error":{"message":"custom tools require MiMo freeform Responses lite mode. ` + sentinel + `"}}`},
		{name: "http400 authentication precedence", status: 400, phase: "http_status", category: "authentication_rejected", wire: `{"error":{"code":"invalid_api_key","message":"Invalid API key supplied while code_mode is enabled"}}`},
		{name: "http400 model precedence", status: 400, phase: "http_status", category: "model_rejected", wire: `{"error":{"code":"invalid_model","message":"Invalid model while code_mode is required"}}`},
		{name: "http400 incidental code mode", status: 400, phase: "http_status", category: "unknown", wire: `{"error":{"message":"Invalid API key supplied while code_mode is enabled"}}`},
		{name: "http400 direct code mode", status: 400, phase: "http_status", category: "code_mode_rejected", wire: `{"error":{"message":"code_mode is required"}}`},
		{name: "http400 numeric code known message", status: 400, phase: "http_status", category: "code_mode_rejected", wire: `{"error":{"code":400,"message":"code_mode is required. ` + sentinel + `"}}`},
		{name: "http400 numeric code known param", status: 400, phase: "http_status", category: "parameter_service_tier", wire: `{"error":{"code":400,"message":{"private":"` + sentinel + `"},"param":"service_tier"}}`},
		{name: "http400 typed code nonstring param", status: 400, phase: "http_status", category: "authentication_rejected", wire: `{"error":{"code":"invalid_api_key","param":["` + sentinel + `"]}}`},
		{name: "http400 unrecognized object fields", status: 400, phase: "http_status", category: "unknown", wire: `{"error":{"code":{"private":"` + sentinel + `"},"message":false,"param":400,"detail":{"message":"code_mode is required"}}}`},
		{name: "http400 scalar error", status: 400, phase: "http_status", category: "unknown", wire: `{"error":"code_mode is required. ` + sentinel + `"}`},
		{name: "http400 array error", status: 400, phase: "http_status", category: "unknown", wire: `{"error":[{"message":"code_mode is required"}]}`},
		{name: "http400 root array", status: 400, phase: "http_status", category: "unknown", wire: `[{"error":{"code":"invalid_api_key"}}]`},
		{name: "http400 null error", status: 400, phase: "http_status", category: "unknown", wire: `{"error":null}`},
		{name: "http400 malformed JSON", status: 400, phase: "http_status", category: "invalid_error_json", wire: `{"error":{"code":400},`},
		{name: "http400 empty body", status: 400, phase: "http_status", category: "invalid_error_json"},
		{name: "http400 bound", status: 400, phase: "http_status", category: "body_limit", wire: strings.Repeat(sentinel, 1024)},
		{name: "http401", status: 401, phase: "http_status", unread: true, wire: sentinel},
		{name: "http429", status: 429, phase: "http_status", unread: true, wire: sentinel},
		{name: "out of range status", status: 999, phase: "http_status", unread: true, wire: sentinel},
		{name: "transport", phase: "transport", transportErr: errors.New(sentinel)},
		{name: "missing response", phase: "invalid_response"},
		{name: "body read", status: 200, phase: "body_read", readErr: errors.New(sentinel)},
		{name: "SSE read", status: 200, stream: true, phase: "sse_read", contentType: "text/event-stream", readErr: errors.New(sentinel)},
		{name: "invalid final", status: 200, phase: "invalid_final", wire: `{"status":"incomplete","private":"` + sentinel + `"}`},
		{name: "invalid content type", status: 200, stream: true, phase: "invalid_content_type", contentType: sentinel, unread: true, wire: sentinel},
		{name: "invalid SSE event", status: 200, stream: true, phase: "sse_invalid_event", contentType: "text/event-stream", wire: "data: " + sentinel + "\n\n"},
		{name: "incomplete SSE", status: 200, stream: true, phase: "sse_incomplete", contentType: "text/event-stream", wire: "data: {\"type\":\"response.created\"}\n\n"},
		{name: "completed JSON", status: 200, success: true, wire: `{"status":"completed","output":[]}`},
		{name: "completed SSE", status: 200, stream: true, success: true, contentType: "text/event-stream", wire: nativeReviewCompleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr, err := os.CreateTemp(t.TempDir(), "private-native-stderr")
			require.NoError(t, err)
			originalStderr := os.Stderr
			os.Stderr = stderr
			t.Cleanup(func() {
				os.Stderr = originalStderr
				_ = stderr.Close()
			})
			body := &nativeDiagnosticBody{Reader: strings.NewReader(tc.wire), readErr: tc.readErr}
			transport := &nativeDiagnosticHTTP{err: tc.transportErr}
			if tc.status != 0 {
				transport.response = &http.Response{StatusCode: tc.status, Body: body, Header: http.Header{"Content-Type": {tc.contentType}, "X-Private": {sentinel}}}
			}
			a := nativeReviewStreamAccount(t, "http://127.0.0.1", GatewayMiMoResponsesProfile)
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			payload := []byte(`{"model":"mimo-test","input":"` + sentinel + `","stream":` + strconv.FormatBool(tc.stream) + `}`)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
			result, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			require.True(t, entered)
			require.Equal(t, 1, transport.requests)
			if tc.status == 400 {
				require.LessOrEqual(t, body.bytesRead, 8193, "HTTP400 body read is bounded")
			}
			if tc.unread {
				require.Zero(t, body.reads, "a rejected response must not be consumed")
			}
			if transport.response != nil {
				require.Positive(t, body.closes, "physical response body must still close")
			}
			logs, readErr := os.ReadFile(stderr.Name())
			require.NoError(t, readErr)
			if tc.success {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.Equal(t, tc.wire, rec.Body.String())
				require.Empty(t, logs, "successful private forwarding emits no failure diagnostic")
				return
			}
			require.Same(t, ErrGatewayNativeEffectUnknown, err)
			require.Nil(t, result)
			require.Equal(t, 1, strings.Count(string(logs), "\n"), "one bounded diagnostic line per failed call")
			var event map[string]any
			require.NoError(t, json.Unmarshal(logs, &event))
			require.Equal(t, "gateway_native_response_failure", event["event"])
			require.Equal(t, tc.phase, event["phase"])
			if tc.status >= 100 && tc.status <= 599 {
				require.EqualValues(t, tc.status, event["http_status"])
			} else {
				require.NotContains(t, event, "http_status")
			}
			if tc.category != "" {
				require.Equal(t, tc.category, event["provider_error_category"])
			} else {
				require.NotContains(t, event, "provider_error_category")
			}
			for field := range event {
				require.Contains(t, []string{"event", "phase", "http_status", "provider_error_category"}, field)
			}
			for _, private := range []string{sentinel, "sandbox-fixture", "99999999-9999-4999-8999-999999999999", "http://127.0.0.1", "account_id"} {
				require.NotContains(t, string(logs), private)
			}
		})
	}
}

// Codex 0.147 sends this static protocol header when its MiMo catalog selects
// Responses Lite. The trusted profile must restore it after caller headers are
// discarded; other profiles must never inherit it from the caller.
func TestGatewayNativeResponsesLiteHeaderIsProfileScoped(t *testing.T) {
	cases := []struct{ name, profile, expected string }{
		{"MiMo", GatewayMiMoResponsesProfile, "true"},
		{"OpenRouter", GatewayOpenRouterResponsesProfile, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"model":"mimo-test","input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"functions","tools":[]}]}],"stream":false}`)
			responseBody := &nativeDiagnosticBody{Reader: strings.NewReader(`{"status":"completed","output":[]}`)}
			transport := &nativeDiagnosticHTTP{response: &http.Response{StatusCode: 200, Body: responseBody, Header: http.Header{}}}
			account := nativeReviewStreamAccount(t, "http://127.0.0.1", tc.profile)
			if tc.profile == GatewayOpenRouterResponsesProfile {
				account.Credentials["base_url"] = GatewayOpenRouterBaseURL
				account.Extra[GatewayModelExtraKey] = GatewayOpenRouterModel
				payload = []byte(strings.Replace(string(payload), "mimo-test", GatewayOpenRouterModel, 1))
			}
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
			c.Request.Header.Set("x-openai-internal-codex-responses-lite", "caller-controlled")
			c.Request.Header.Set("X-Private-Routing", "must-not-forward")
			result, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			require.True(t, entered)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, 1, transport.requests)
			require.Equal(t, tc.expected, transport.lastRequest.Header.Get("x-openai-internal-codex-responses-lite"))
			require.Empty(t, transport.lastRequest.Header.Get("X-Private-Routing"))
			require.Equal(t, "Bearer sandbox-fixture", transport.lastRequest.Header.Get("Authorization"))
			actual, err := io.ReadAll(transport.lastRequest.Body)
			require.NoError(t, err)
			require.Equal(t, payload, actual, "MCP/tool/input bytes stay unchanged")
		})
	}
}
