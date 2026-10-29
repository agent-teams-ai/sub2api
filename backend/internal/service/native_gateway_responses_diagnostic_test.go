//go:build unit

package service

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type nativeDiagnosticBody struct {
	io.Reader
	reads, closes, bytesRead int
	readErr                  error
	waitForCancel            bool
	ctx                      context.Context
}

func (b *nativeDiagnosticBody) Read(p []byte) (int, error) {
	b.reads++
	if b.waitForCancel {
		<-b.ctx.Done()
		return 0, b.ctx.Err()
	}
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
	if h.response != nil {
		if body, ok := h.response.Body.(*nativeDiagnosticBody); ok {
			body.ctx = request.Context()
		}
	}
	return h.response, h.err
}

// Retain the controlled TLS fixture's protected request checks, then supply
// the missing declaration and selected wire bytes at that same response seam.
type nativeDiagnosticCodexStream struct {
	HTTPUpstream
	body *nativeDiagnosticBody
}

func (h *nativeDiagnosticCodexStream) Do(r *http.Request, proxy string, id int64, concurrency int) (*http.Response, error) {
	resp, err := h.HTTPUpstream.Do(r, proxy, id, concurrency)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
		resp.Header.Del("Content-Type")
		resp.Body = h.body
	}
	return resp, err
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
	t.Run("codex request shape private scalars", func(t *testing.T) {
		for _, tc := range []struct {
			body                                     string
			present, stringValue, nonblank, metadata bool
		}{
			{`{"instructions":"` + sentinel + `", "metadata":{"private":"` + sentinel + `"}, "input":[{"content":"` + sentinel + `"}]}`, true, true, true, true},
			{`{"instructions":"  ", "input":[]}`, true, true, false, false},
			{`{"instructions":null, "input":[]}`, true, false, false, false},
			{`{"input":[]}`, false, false, false, false},
		} {
			raw, err := json.Marshal(gatewayNativeCodexRequestShape([]byte(tc.body)))
			require.NoError(t, err)
			require.NotContains(t, string(raw), sentinel)
			var got struct {
				Event       string          `json:"event"`
				Canonical   bool            `json:"canonical_object"`
				Present     bool            `json:"instructions_present"`
				StringValue bool            `json:"instructions_string"`
				Nonblank    bool            `json:"instructions_nonblank"`
				Fields      map[string]bool `json:"unsupported_fields_present"`
			}
			require.NoError(t, json.Unmarshal(raw, &got))
			require.Equal(t, "gateway_native_codex_request_shape", got.Event)
			require.True(t, got.Canonical)
			require.Equal(t, tc.present, got.Present)
			require.Equal(t, tc.stringValue, got.StringValue)
			require.Equal(t, tc.nonblank, got.Nonblank)
			require.Equal(t, tc.metadata, got.Fields["metadata"])
			require.Len(t, got.Fields, 14)
			require.False(t, got.Fields["max_output_tokens"])
		}
	})
	t.Run("protected codex HTTP400 emits private shape", func(t *testing.T) {
		f := newOAuthDispatchFixture(t)
		route := f.qualify(t)
		f.mode = "badrequest"
		stderr, err := os.CreateTemp(t.TempDir(), "protected-shape-")
		require.NoError(t, err)
		previous := os.Stderr
		os.Stderr = stderr
		defer func() { os.Stderr = previous; _ = stderr.Close() }()
		_, entered, err, life := f.call(t, route, oauthDispatchPayload())
		require.True(t, entered)
		require.Same(t, ErrGatewayNativeEffectUnknown, err)
		require.EqualValues(t, 1, f.entries.Load())
		require.True(t, life.Snapshot().BodyClosed)
		raw, err := os.ReadFile(stderr.Name())
		require.NoError(t, err)
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		require.Len(t, lines, 2)
		var shape map[string]any
		require.NoError(t, json.Unmarshal(lines[0], &shape))
		require.Equal(t, "gateway_native_codex_request_shape", shape["event"])
		require.Equal(t, false, shape["instructions_present"])
		require.Equal(t, false, shape["instructions_string"])
		require.Equal(t, false, shape["instructions_nonblank"])
		require.Equal(t, false, shape["unsupported_fields_present"].(map[string]any)["max_output_tokens"])
		require.NotContains(t, string(raw), f.bundle.AccessToken)
		require.NotContains(t, string(raw), f.bundle.IDToken)
		var failure map[string]any
		require.NoError(t, json.Unmarshal(lines[1], &failure))
		require.Equal(t, "invalid_request", failure["provider_error_category"])
		require.Equal(t, "instructions", failure["provider_error_parameter"])
	})
	t.Run("protected codex missing media requires complete protocol", func(t *testing.T) {
		for _, tc := range []struct {
			name, wire string
			success    bool
		}{
			{"comments and large first frame", ": keepalive\r\n\r\nevent: response.created\r\ndata: {\"type\":\"response.created\",\"response\":{\"status\":\"in_progress\",\"private\":\"" + strings.Repeat(sentinel, 512) + "\"}}\r\n\r\n" + nativeReviewCompleted, true},
			{"non SSE first frame", ": keepalive\n\n<html>" + sentinel + "\n\n" + nativeReviewCompleted, false},
			{"truncated non SSE", ": keepalive\n\n{\"private\":\"" + sentinel, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newOAuthDispatchFixture(t)
				route := f.qualify(t)
				body := &nativeDiagnosticBody{Reader: strings.NewReader(tc.wire)}
				owned := f.svc.httpUpstream.(*gatewayNativeLifetimeUpstream)
				owned.HTTPUpstream = &nativeDiagnosticCodexStream{HTTPUpstream: owned.HTTPUpstream, body: body}
				ctx, cancel := context.WithTimeout(f.ctx, time.Second)
				defer cancel()
				life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, gatewayNativeResponseLimit)
				require.NoError(t, err)
				life.BindAccount(f.scope.Consumer, f.scope.Account, f.scope.Generation)
				require.True(t, life.Admit(time.Now().Add(time.Second)))
				ctx = WithGatewayNativeProviderReadIdle(WithGatewayNativeLifetime(ctx, life), 50*time.Millisecond)
				ctx, err = WithGatewayNativeOAuthDispatch(ctx, f.dispatch, f.scope, f.store.physical.Operation, 4096, 128)
				require.NoError(t, err)
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(oauthDispatchPayload()))
				stderr, err := os.CreateTemp(t.TempDir(), "codex-missing-media-")
				require.NoError(t, err)
				previous := os.Stderr
				os.Stderr = stderr
				defer func() { os.Stderr = previous; _ = stderr.Close() }()
				result, entered, err := f.svc.ForwardGatewayRoute(ctx, c, route, oauthDispatchPayload())
				require.True(t, entered)
				require.EqualValues(t, 1, f.entries.Load(), "one protected provider request, no replay")
				require.True(t, life.Snapshot().BodyClosed)
				require.Equal(t, 1, body.closes)
				require.LessOrEqual(t, body.bytesRead, gatewayNativeResponseLimit+1)
				logs, readErr := os.ReadFile(stderr.Name())
				require.NoError(t, readErr)
				if tc.success {
					require.NoError(t, err)
					require.NotNil(t, result)
					require.Equal(t, tc.wire, rec.Body.String(), "original comments and complete SSE bytes are preserved")
					require.Greater(t, body.bytesRead, 8193, "the first complete frame uses the existing frame bound")
					require.Empty(t, logs)
				} else {
					require.Same(t, ErrGatewayNativeEffectUnknown, err)
					require.Nil(t, result)
					require.Empty(t, rec.Body.String(), "no bytes before a valid protocol frame")
					require.NotContains(t, string(logs), sentinel)
				}
			})
		}
	})
	const cappedSSE = ": sandbox comment\n\n" + nativeReviewCompleted
	const cappedJSON = `{"status":"completed","output":[]}`
	cases := []struct {
		name, contentType, wire, phase, category, encoding, shape, parameter string
		readReason, mediaCategory, bodyShape, bodyPrefix, transportReason    string
		idle, deadline                                                       time.Duration
		outputCap                                                            int64
		status                                                               int
		stream, success, unread                                              bool
		transportErr, readErr                                                error
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
		{name: "http400 canonical detail", status: 400, phase: "http_status", category: "invalid_request", shape: "flat_error_object", parameter: "max_output_tokens", wire: `{"detail":"Unsupported parameter: max_output_tokens. ` + sentinel + `"}`},
		{name: "http400 plan gated detail", status: 400, phase: "http_status", category: "model_rejected", shape: "flat_error_object", parameter: "model", wire: `{"detail":"The 'gpt-6.1-sol' model is not supported when using Codex with a ChatGPT account."}`},
		{name: "http400 instructions detail", status: 400, phase: "http_status", category: "invalid_request", shape: "flat_error_object", parameter: "instructions", wire: `{"detail":"Instructions are required"}`},
		{name: "http400 private detail", status: 400, phase: "http_status", category: "unknown", shape: "flat_error_object", parameter: "missing", wire: `{"detail":"` + sentinel + ` Unsupported parameter: max_output_tokens"}`},
		{name: "http400 null detail", status: 400, phase: "http_status", category: "unknown", shape: "unrecognized_object", wire: `{"detail":null}`},
		{name: "http400 object detail", status: 400, phase: "http_status", category: "unknown", shape: "unrecognized_object", wire: `{"detail":{"message":"Unsupported parameter: max_output_tokens"}}`},
		{name: "http400 duplicate detail", status: 400, phase: "http_status", category: "unknown", shape: "ambiguous", wire: `{"detail":"Unsupported parameter: max_output_tokens","detail":"` + sentinel + `"}`},
		{name: "http400 alias detail", status: 400, phase: "http_status", category: "unknown", shape: "ambiguous", wire: `{"Detail":"Unsupported parameter: max_output_tokens"}`},
		{name: "http400 root array", shape: "non_object", status: 400, phase: "http_status", category: "unknown", wire: `[{"error":{"code":"invalid_api_key"}}]`},
		{name: "http400 null error", status: 400, phase: "http_status", category: "unknown", wire: `{"error":null}`},
		{name: "http400 malformed JSON", status: 400, phase: "http_status", category: "invalid_error_json", wire: `{"error":{"code":400},`},
		{name: "http400 empty body", status: 400, phase: "http_status", category: "empty_error_body"},
		{name: "http400 whitespace", status: 400, phase: "http_status", category: "empty_error_body", wire: " \t\r\n"},
		{name: "http400 HTML", status: 400, phase: "http_status", category: "html_error_body", wire: "<!DOCTYPE html><html><body>" + sentinel + "</body></html>"},
		{name: "http400 residual encoding", status: 400, phase: "http_status", category: "unhandled_error_encoding", encoding: sentinel, wire: sentinel},
		{name: "http400 encoded valid JSON", status: 400, phase: "http_status", category: "authentication_rejected", encoding: "gzip", wire: `{"error":{"code":"invalid_api_key"}}`},
		{name: "http400 SSE known envelope", status: 400, phase: "http_status", category: "code_mode_rejected", wire: "event: error\ndata: {\"error\":{\"message\":\"code_mode is required. " + sentinel + "\"}}\n\n"},
		{name: "http400 SSE direct multiline CRLF", status: 400, phase: "http_status", category: "parameter_service_tier", wire: ": private " + sentinel + "\r\nevent: error\r\nid: " + sentinel + "\r\nretry: 10\r\ndata: {\"code\":400,\r\ndata: \"param\":\"service_tier\"}\r\n\r\n"},
		{name: "http400 SSE typed error", shape: "flat_error_object", parameter: "missing", status: 400, phase: "http_status", category: "authentication_rejected", wire: "data: {\"type\":\"error\",\"code\":\"invalid_api_key\"}\n\n"},
		{name: "http400 SSE unknown", status: 400, phase: "http_status", category: "sse_error_body", wire: "event: " + sentinel + "\ndata: {\"error\":{\"message\":\"" + sentinel + "\"}}\n\n"},
		{name: "http400 SSE incomplete", status: 400, phase: "http_status", category: "invalid_error_json", wire: "event: error\ndata: {\"error\":{\"code\":\"invalid_api_key\"}}\n"},
		{name: "http400 SSE multiple frames", status: 400, phase: "http_status", category: "invalid_error_json", wire: "data: {}\n\ndata: {\"error\":{\"code\":\"invalid_api_key\"}}\n\n"},
		{name: "http400 SSE malformed data", status: 400, phase: "http_status", category: "invalid_error_json", wire: "event: error\ndata: {\"error\":\n\n"},
		{name: "http400 pseudo SSE", status: 400, phase: "http_status", category: "invalid_error_json", wire: sentinel + "\ndata: {\"error\":{\"code\":\"invalid_api_key\"}}\n\n"},
		{name: "http400 SSE duplicate event", status: 400, phase: "http_status", category: "invalid_error_json", wire: "event: error\nevent: private\ndata: {\"code\":\"invalid_api_key\"}\n\n"},
		{name: "http400 SSE invalid retry", status: 400, phase: "http_status", category: "invalid_error_json", wire: "retry: -1\ndata: {\"error\":{\"code\":\"invalid_api_key\"}}\n\n"},
		{name: "http400 SSE invalid UTF8", status: 400, phase: "http_status", category: "invalid_error_json", wire: ": \xff\ndata: {}\n\n"},
		{name: "http400 read failure precedence", status: 400, phase: "http_status", category: "body_read_failed", encoding: "gzip", readErr: errors.New(sentinel)},
		{name: "http400 encoded bound", status: 400, phase: "http_status", category: "body_limit", encoding: "gzip", wire: strings.Repeat(sentinel, 1024)},
		{name: "http400 failed response envelope", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "response_error_object", parameter: "tools", wire: `{"type":"response.failed","response":{"error":{"type":"invalid_request_error","code":"unknown_parameter","param":"tools[0].function.parameters","message":"` + sentinel + `"}}}`},
		{name: "http400 failed status envelope", status: 400, phase: "http_status", category: "invalid_request", shape: "response_error_object", parameter: "input", wire: `{"response":{"status":"failed","error":{"type":"invalid_request_error","param":"input[0].content"}}}`},
		{name: "http400 guarded response path", status: 400, phase: "http_status", category: "unknown", shape: "unrecognized_object", wire: `{"response":{"error":{"code":"invalid_api_key"}},"echo":{"error":{"param":"tools"}}}`},
		{name: "http400 numeric code type fallback", status: 400, phase: "http_status", category: "invalid_request", shape: "root_error_object", parameter: "missing", wire: `{"error":{"code":400,"type":"invalid_request_error","message":"` + sentinel + `"}}`},
		{name: "http400 explicit unknown param blocks message", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"unknown_parameter","param":"` + sentinel + `","message":"Unsupported parameter: tools"}}`},
		{name: "http400 nonstring param blocks message", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"unknown_parameter","param":["tools"],"message":"Unsupported parameter: tools"}}`},
		{name: "http400 null param anchored message", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "prompt_cache_retention", wire: `{"error":{"code":"unknown_parameter","param":null,"message":"Unsupported parameter: 'prompt_cache_retention'. ` + sentinel + `"}}`},
		{name: "http400 incidental message not inferred", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "missing", wire: `{"error":{"code":"unknown_parameter","message":"` + sentinel + ` says Unsupported parameter: tools"}}`},
		{name: "http400 validation phrase boundary", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "missing", wire: `{"error":{"code":"unknown_parameter","message":"Unsupported parametertools"}}`},
		{name: "http400 unguarded message not inferred", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "missing", wire: `{"error":{"code":"` + sentinel + `","message":"Unsupported parameter: tools"}}`},
		{name: "http400 malformed message path", status: 400, phase: "http_status", category: "unsupported_parameter", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"unknown_parameter","message":"Unsupported parameter: tools.` + sentinel + `!"}}`},
		{name: "http400 duplicate selected param", status: 400, phase: "http_status", category: "unknown", shape: "ambiguous", wire: `{"error":{"code":"invalid_api_key","param":"tools","param":"input"}}`},
		{name: "http400 aliased response field", status: 400, phase: "http_status", category: "unknown", shape: "ambiguous", wire: `{"type":"response.failed","response":{"Error":{"code":"invalid_api_key"}}}`},
		{name: "http400 authentication and parameter", status: 400, phase: "http_status", category: "authentication_rejected", shape: "root_error_object", parameter: "service_tier", wire: `{"error":{"code":"invalid_api_key","param":"service_tier"}}`},
		{name: "http400 MiMo text sentence SSE", status: 400, phase: "http_status", category: "invalid_request", shape: "root_error_object", parameter: "text", wire: "data: {\"error\":{\"code\":\"400\",\"message\":\"Param Incorrect\",\"param\":\"`text` is not set\"}}\n\n"},
		{name: "http400 MiMo reasoning sentence numeric code", status: 400, phase: "http_status", category: "invalid_request", shape: "root_error_object", parameter: "reasoning", wire: `{"error":{"code":400,"message":"Param Incorrect","param":"The reasoning_content in the thinking mode must be passed back to the API."}}`},
		{name: "http400 MiMo unknown sentence", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"400","message":"Param Incorrect","param":"` + sentinel + ` ` + "`text` is not set" + `"}}`},
		{name: "http400 MiMo sentence wrong code", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"` + sentinel + `","message":"Param Incorrect","param":"` + "`text` is not set" + `"}}`},
		{name: "http400 MiMo sentence wrong message", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"400","message":"` + sentinel + `","param":"` + "`text` is not set" + `"}}`},
		{name: "http400 public schema SSE empty param", status: 400, phase: "http_status", category: "invalid_request", shape: "root_error_object", parameter: "text", wire: "data: {\"error\":{\"code\":\"responses_feature_not_supported\",\"message\":\"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed.\",\"param\":\"\"}}\n\n"},
		{name: "http400 public schema absent param", status: 400, phase: "http_status", category: "invalid_request", shape: "root_error_object", parameter: "text", wire: `{"error":{"code":"responses_feature_not_supported","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed."}}`},
		{name: "http400 schema unknown param", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"responses_feature_not_supported","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed.","param":"private-unrecognized"}}`},
		{name: "http400 schema nonstring param", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"responses_feature_not_supported","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed.","param":{}}}`},
		{name: "http400 schema null param", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "missing", wire: `{"error":{"code":"responses_feature_not_supported","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed.","param":null}}`},
		{name: "http400 schema wrong code", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"private-unrecognized","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed.","param":""}}`},
		{name: "http400 schema message not exact", status: 400, phase: "http_status", category: "unknown", shape: "root_error_object", parameter: "other", wire: `{"error":{"code":"responses_feature_not_supported","message":"text.format type 'json_schema' is not supported, only 'text' and 'json_object' are allowed. private-unrecognized","param":""}}`},
		{name: "http400 bound", status: 400, phase: "http_status", category: "body_limit", wire: strings.Repeat(sentinel, 1024)},
		{name: "http401", status: 401, phase: "http_status", unread: true, wire: sentinel},
		{name: "http429", status: 429, phase: "http_status", unread: true, wire: sentinel},
		{name: "out of range status", status: 999, phase: "http_status", unread: true, wire: sentinel},
		{name: "transport", phase: "transport", transportErr: errors.New(sentinel), transportReason: "other"},
		{name: "transport entered wrapped EOF", phase: "transport", transportErr: fmt.Errorf("%s: %w", sentinel, io.EOF), transportReason: "eof", outputCap: 4096},
		{name: "missing response", phase: "invalid_response"},
		{name: "body read", status: 200, phase: "body_read", readErr: errors.New(sentinel)},
		// Red if scanner overflow keeps the generic read phase, or read failures
		// omit the closed reason. The shared unknown singleton is not idle proof.
		{name: "SSE read", status: 200, stream: true, phase: "sse_read", readReason: "other", contentType: "text/event-stream", readErr: errors.New(sentinel)},
		{name: "SSE nonidle unknown singleton", status: 200, stream: true, phase: "sse_read", readReason: "other", contentType: "text/event-stream", readErr: ErrGatewayNativeEffectUnknown},
		{name: "SSE wrapped context canceled", status: 200, stream: true, phase: "sse_read", readReason: "context_canceled", contentType: "text/event-stream", readErr: fmt.Errorf("%s: %w", sentinel, context.Canceled)},
		{name: "SSE upstream context deadline", status: 200, stream: true, phase: "sse_read", readReason: "context_deadline", contentType: "text/event-stream", readErr: context.DeadlineExceeded},
		{name: "SSE unexpected EOF", status: 200, stream: true, phase: "sse_read", readReason: "unexpected_eof", contentType: "text/event-stream", readErr: io.ErrUnexpectedEOF},
		{name: "SSE body after close", status: 200, stream: true, phase: "sse_read", readReason: "body_after_close", contentType: "text/event-stream", readErr: http.ErrBodyReadAfterClose},
		{name: "SSE wrapped connection closed", status: 200, stream: true, phase: "sse_read", readReason: "connection_closed", contentType: "text/event-stream", readErr: fmt.Errorf("%s: %w", sentinel, net.ErrClosed)},
		{name: "SSE typed timeout", status: 200, stream: true, phase: "sse_read", readReason: "transport_timeout", contentType: "text/event-stream", readErr: &net.DNSError{Name: sentinel, IsTimeout: true}},
		{name: "SSE typed network nontimeout", status: 200, stream: true, phase: "sse_read", readReason: "other", contentType: "text/event-stream", readErr: &net.DNSError{Name: sentinel}},
		{name: "SSE gzip checksum", status: 200, stream: true, phase: "sse_read", readReason: "compression_error", contentType: "text/event-stream", readErr: gzip.ErrChecksum},
		{name: "SSE gzip header", status: 200, stream: true, phase: "sse_read", readReason: "compression_error", contentType: "text/event-stream", readErr: gzip.ErrHeader},
		{name: "SSE wrapped deflate corruption", status: 200, stream: true, phase: "sse_read", readReason: "compression_error", contentType: "text/event-stream", readErr: fmt.Errorf("%s: %w", sentinel, flate.CorruptInputError(7))},
		{name: "SSE wrapped zstd checksum", status: 200, stream: true, phase: "sse_read", readReason: "compression_error", contentType: "text/event-stream", readErr: fmt.Errorf("%s: %w", sentinel, zstd.ErrCRCMismatch)},
		{name: "SSE zstd encoder counterexample", status: 200, stream: true, phase: "sse_read", readReason: "other", contentType: "text/event-stream", readErr: zstd.ErrEncoderClosed},
		{name: "SSE text counterexample", status: 200, stream: true, phase: "sse_read", readReason: "other", contentType: "text/event-stream", readErr: errors.New("unexpected EOF gzip: invalid header " + sentinel)},
		{name: "SSE exact cap includes comments", status: 200, stream: true, success: true, contentType: "text/event-stream", wire: cappedSSE, outputCap: int64(len(cappedSSE))},
		{name: "SSE cap plus one", status: 200, stream: true, phase: "body_limit", contentType: "text/event-stream", wire: cappedSSE, outputCap: int64(len(cappedSSE) - 1)},
		{name: "JSON exact cap", status: 200, success: true, wire: cappedJSON, outputCap: int64(len(cappedJSON))},
		{name: "JSON cap plus one", status: 200, phase: "body_limit", wire: cappedJSON, outputCap: int64(len(cappedJSON) - 1)},
		{name: "SSE oversized line", status: 200, stream: true, phase: "sse_frame_limit", contentType: "text/event-stream", wire: ":" + strings.Repeat("x", (1<<20)+1) + "\n\n"},
		{name: "SSE idle expired", status: 200, stream: true, phase: "sse_read", readReason: "idle_expired", contentType: "text/event-stream", idle: 20 * time.Millisecond, deadline: time.Second},
		{name: "SSE deadline omits read reason", status: 200, stream: true, phase: "deadline", contentType: "text/event-stream", idle: time.Second, deadline: 100 * time.Millisecond},
		{name: "invalid final", status: 200, phase: "invalid_final", wire: `{"status":"incomplete","private":"` + sentinel + `"}`},
		{name: "invalid content type", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "other", contentType: sentinel, unread: true, wire: sentinel},
		{name: "invalid content type missing", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "other", bodyPrefix: "text", wire: sentinel},
		{name: "missing media empty", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "empty", bodyPrefix: "empty"},
		{name: "missing media JSON", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "json", bodyPrefix: "json_prefix", category: "model_rejected", shape: "root_error_object", parameter: "model", wire: `{"error":{"code":"invalid_model","param":"model","message":"` + sentinel + `"}}`},
		{name: "missing media HTML", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "html", bodyPrefix: "html_prefix", wire: "<!DOCTYPE html><html><body>" + sentinel + "</body></html>"},
		{name: "missing media SSE", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "sse", bodyPrefix: "sse_prefix", wire: "event: response.created\r\ndata: {\"type\":\"response.created\",\"private\":\"" + sentinel + "\"}\r\n\r\n" + nativeReviewCompleted},
		{name: "missing media malformed SSE", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "other", bodyPrefix: "sse_prefix", wire: "event: error\ndata: " + sentinel + "\n\n"},
		{name: "missing media bound", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "sse", bodyPrefix: "sse_prefix", category: "body_limit", wire: "event: response.created\ndata: {\"type\":\"response.created\"}\n\n" + strings.Repeat(sentinel, 1024)},
		{name: "missing media truncated JSON prefix", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "other", bodyPrefix: "json_prefix", category: "body_limit", wire: `{"private":"` + strings.Repeat(sentinel, 1024)},
		{name: "missing media large first SSE prefix", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "other", bodyPrefix: "sse_prefix", category: "body_limit", wire: "event: response.created\ndata: {\"private\":\"" + strings.Repeat(sentinel, 1024)},
		{name: "missing media gzip prefix", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "missing", bodyShape: "other", bodyPrefix: "gzip_prefix", category: "body_limit", wire: "\x1f\x8b" + strings.Repeat(sentinel, 1024)},
		{name: "missing media deadline", status: 200, stream: true, phase: "deadline", category: "body_read_failed", idle: time.Second, deadline: 100 * time.Millisecond},
		{name: "invalid content type HTML", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "html", contentType: `text/html; private="` + sentinel + `"`, unread: true, wire: sentinel},
		{name: "invalid content type SSE formatting", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "sse", contentType: " text/event-stream", unread: true, wire: sentinel},
		{name: "invalid content type malformed", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "other", contentType: "application/json; " + sentinel, unread: true, wire: sentinel},
		{name: "invalid content type JSON", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "json", contentType: `Application/JSON; private="` + sentinel + `"`, category: "model_rejected", shape: "root_error_object", parameter: "model", wire: `{"error":{"code":"invalid_model","type":"invalid_request_error","param":"model","message":"` + sentinel + `"}}`},
		{name: "invalid content type JSON suffix", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "json", contentType: "application/problem+json", category: "authentication_rejected", wire: `{"error":{"code":"invalid_api_key","message":"` + sentinel + `"}}`},
		{name: "invalid content type JSON bound", status: 200, stream: true, phase: "invalid_content_type", mediaCategory: "json", contentType: "application/json", category: "body_limit", wire: strings.Repeat(sentinel, 1024)},
		{name: "invalid content type JSON deadline", status: 200, stream: true, phase: "deadline", contentType: "application/json", category: "body_read_failed", idle: time.Second, deadline: 100 * time.Millisecond},
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
			body := &nativeDiagnosticBody{Reader: strings.NewReader(tc.wire), readErr: tc.readErr, waitForCancel: tc.idle != 0}
			transport := &nativeDiagnosticHTTP{err: tc.transportErr}
			if tc.status != 0 {
				transport.response = &http.Response{StatusCode: tc.status, Body: body, Header: http.Header{"Content-Type": {tc.contentType}, "X-Private": {sentinel}, "Content-Encoding": {tc.encoding}}}
			}
			a := nativeReviewStreamAccount(t, "http://127.0.0.1", GatewayMiMoResponsesProfile)
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			payload := []byte(`{"model":"mimo-test","input":"` + sentinel + `","stream":` + strconv.FormatBool(tc.stream) + `}`)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
			ctx := nativeFixtureContext(t, context.Background())
			if tc.idle != 0 || tc.outputCap != 0 {
				deadline, outputCap := tc.deadline, tc.outputCap
				if deadline == 0 {
					deadline = time.Second
				}
				if outputCap == 0 {
					outputCap = gatewayNativeResponseLimit
				}
				bounded, cancel := context.WithTimeout(ctx, deadline)
				t.Cleanup(cancel)
				life, err := NewGatewayNativeLifetime(bounded, cancel, func() {}, outputCap)
				require.NoError(t, err)
				scope := nativeFixtureScope(a)
				life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
				require.True(t, life.Admit(time.Now().Add(time.Second)))
				ctx = WithGatewayNativeProviderReadIdle(WithGatewayNativeLifetime(bounded, life), tc.idle)
				if tc.outputCap != 0 {
					svc.httpUpstream, err = NewGatewayNativeLifetimeUpstream(transport)
					require.NoError(t, err)
				}
			}
			result, entered, err := svc.ForwardGatewayRoute(ctx, c, route, payload)
			require.True(t, entered)
			require.Equal(t, 1, transport.requests)
			if tc.status == 400 || tc.mediaCategory == "json" || tc.mediaCategory == "missing" {
				require.LessOrEqual(t, body.bytesRead, 8193, "diagnostic body read is bounded")
			}
			if tc.unread {
				require.Zero(t, body.reads, "a rejected response must not be consumed")
			}
			if transport.response != nil {
				require.Positive(t, body.closes, "physical response body must still close")
			}
			if tc.outputCap != 0 && transport.response != nil {
				require.Equal(t, 1, body.closes, "cap boundary keeps physical closure exactly once")
				require.LessOrEqual(t, int64(body.bytesRead), tc.outputCap+1, "owned body keeps its one-byte cap probe")
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
			if tc.phase == "invalid_content_type" || tc.name == "invalid content type JSON deadline" || tc.name == "missing media deadline" {
				require.Empty(t, rec.Body.String(), "a wrong-media response is never forwarded")
			}
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
			if tc.shape != "" {
				require.Equal(t, tc.shape, event["provider_error_shape"])
			}
			if tc.parameter != "" {
				require.Equal(t, tc.parameter, event["provider_error_parameter"])
			}
			if tc.shape == "ambiguous" || tc.shape == "non_object" || tc.shape == "unrecognized_object" || tc.status != 400 && tc.mediaCategory != "json" && tc.bodyShape != "json" {
				require.NotContains(t, event, "provider_error_parameter")
			}
			if tc.status != 400 && tc.mediaCategory != "json" && tc.bodyShape != "json" {
				require.NotContains(t, event, "provider_error_shape")
			}
			if tc.mediaCategory != "" {
				require.Equal(t, tc.mediaCategory, event["upstream_media_category"])
			} else {
				require.NotContains(t, event, "upstream_media_category")
			}
			if tc.bodyShape != "" {
				require.Equal(t, tc.bodyShape, event["upstream_body_shape"])
			} else {
				require.NotContains(t, event, "upstream_body_shape")
			}
			if tc.bodyPrefix != "" {
				require.Equal(t, tc.bodyPrefix, event["upstream_body_prefix"])
			} else {
				require.NotContains(t, event, "upstream_body_prefix")
			}
			if tc.readReason != "" {
				require.Equal(t, tc.readReason, event["read_error_reason"])
			} else {
				require.NotContains(t, event, "read_error_reason")
			}
			transportFields := []string{"transport_error_reason", "upstream_connection", "upstream_request_written", "upstream_response_started", "native_entered"}
			if tc.phase == "transport" {
				require.Equal(t, tc.transportReason, event["transport_error_reason"])
				require.Equal(t, "not_obtained", event["upstream_connection"])
				require.Equal(t, false, event["upstream_request_written"])
				require.Equal(t, false, event["upstream_response_started"])
				if tc.outputCap != 0 {
					require.Equal(t, true, event["native_entered"])
				} else {
					require.NotContains(t, event, "native_entered")
				}
			} else {
				for _, field := range transportFields {
					require.NotContains(t, event, field, "transport metadata belongs only to transport failures")
				}
			}
			for field := range event {
				require.Contains(t, append([]string{"event", "phase", "http_status", "provider_error_category", "provider_error_shape", "provider_error_parameter", "read_error_reason", "upstream_media_category", "upstream_body_shape", "upstream_body_prefix"}, transportFields...), field)
			}
			for _, private := range []string{sentinel, "gateway native output limit", "sandbox-fixture", "99999999-9999-4999-8999-999999999999", "http://127.0.0.1", "account_id"} {
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
				// additional_tools is MiMo's Responses Lite extension. The header
				// isolation check uses a valid plain-text request for OpenRouter.
				payload = []byte(`{"model":"` + GatewayOpenRouterModel + `","input":"preserved text","stream":false}`)
			}
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			if tc.profile == GatewayOpenRouterResponsesProfile {
				modelsBody := `{"data":[` + openRouterModelRow(GatewayOpenRouterModel, true) + `]}`
				require.NoError(t, svc.SetGatewayOpenRouterModels(openRouterModelsFixture(t, &modelsBody)))
			}
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
