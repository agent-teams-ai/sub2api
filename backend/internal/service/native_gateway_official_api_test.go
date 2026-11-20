//go:build unit

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func officialAPIWireFixture(t *testing.T, profile, base, model string, handler http.HandlerFunc) (*OpenAIGatewayService, GatewayNativeRoute, func([]byte) (*httptest.ResponseRecorder, bool, error)) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DisableKeepAlives = true
	t.Cleanup(transport.CloseIdleConnections)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "api.anthropic.com:443" && address != "generativelanguage.googleapis.com:443" {
			return nil, ErrGatewayNativeIdentity
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	a := nativeReviewStreamAccount(t, base, profile)
	a.Extra[GatewayModelExtraKey] = model
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	s := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: &gatewayIdentityRealHTTP{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}}, cfg: rawChatCompletionsTestConfig()}
	call := func(body []byte) (*httptest.ResponseRecorder, bool, error) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
		c.Request.Header.Set("Authorization", "Bearer caller-must-not-reach-provider")
		_, entered, err := s.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, body)
		if profile == GatewayGeminiAPIKeyProfile && entered {
			require.Equal(t, "/v1beta/openai/chat/completions", GetActualOpenAIUpstreamEndpoint(c))
		}
		return rec, entered, err
	}
	return s, route, call
}

func officialAPICompletedOutput(t *testing.T, wire string) []json.RawMessage {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(wire))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "data: ")
		var event struct {
			Type     string `json:"type"`
			Response struct {
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(line), &event) == nil && event.Type == "response.completed" {
			return event.Response.Output
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatal("no successful final Responses event")
	return nil
}

func TestGatewayNativeOfficialGeminiActualTLSContinuationAndSchema(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const signature = "fixture-google-thought-signature"
	requests := 0
	_, _, call := officialAPIWireFixture(t, GatewayGeminiAPIKeyProfile, GatewayGeminiAPIBaseURL, GatewayGeminiAPIModel, func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "generativelanguage.googleapis.com", r.Host)
		require.Equal(t, "/v1beta/openai/chat/completions", r.URL.Path)
		require.Equal(t, "Bearer sandbox-fixture", r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var request map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &request))
		require.JSONEq(t, `{"type":"json_schema","json_schema":{"name":"codex_output_schema","strict":true,"schema":{"type":"object","properties":{"findings":{"type":"array","items":{"type":"string"}}},"required":["findings"],"additionalProperties":false}}}`, string(request["response_format"]))
		w.Header().Set("Content-Type", "text/event-stream")
		if requests == 1 {
			fmt.Fprintf(w, "data: {\"id\":\"first\",\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_review\",\"type\":\"function\",\"function\":{\"name\":\"read_source\",\"arguments\":\"{\\\"path\\\":\\\"file.go\\\"}\"}}]},\"finish_reason\":null}]}\n\n", GatewayGeminiAPIModel)
			// Signature can arrive later than its call name/arguments.
			fmt.Fprintf(w, "data: {\"id\":\"first\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"extra_content\":{\"google\":{\"thought_signature\":%q}}}]},\"finish_reason\":null}]}\n\n", signature)
			io.WriteString(w, "data: {\"id\":\"first\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
		} else {
			require.Contains(t, string(request["messages"]), signature)
			require.Contains(t, string(request["messages"]), `"tool_call_id":"call_review"`)
			io.WriteString(w, "data: {\"id\":\"second\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"{\\\"findings\\\":[]}\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"second\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		}
	})
	request := map[string]any{"model": GatewayGeminiAPIModel, "input": "Review file.go", "store": false, "stream": true, "max_output_tokens": 512, "tools": []any{map[string]any{"type": "function", "name": "read_source", "parameters": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]string{"type": "string"}}}}}, "text": map[string]any{"format": map[string]any{"type": "json_schema", "name": "codex_output_schema", "strict": true, "schema": map[string]any{"type": "object", "properties": map[string]any{"findings": map[string]any{"type": "array", "items": map[string]string{"type": "string"}}}, "required": []string{"findings"}, "additionalProperties": false}}}}
	raw, err := json.Marshal(request)
	require.NoError(t, err)
	first, entered, err := call(raw)
	require.NoError(t, err)
	require.True(t, entered)
	require.NotContains(t, first.Body.String(), signature)
	output := officialAPICompletedOutput(t, first.Body.String())
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)
	require.Contains(t, string(outputJSON), "gemini-thoughts-v1.")
	output = append(output, json.RawMessage(`{"type":"function_call_output","call_id":"call_review","output":"synthetic file contents"}`))
	request["input"] = output
	raw, err = json.Marshal(request)
	require.NoError(t, err)
	second, entered, err := call(raw)
	require.NoError(t, err)
	require.True(t, entered)
	finalOutput := officialAPICompletedOutput(t, second.Body.String())
	require.Len(t, finalOutput, 2, "reserved continuation slot plus final message")
	require.NotContains(t, string(finalOutput[0]), "encrypted_content")
	require.Contains(t, string(finalOutput[1]), `"type":"message"`)
	require.Equal(t, 2, requests)
	// A corrupted opaque proof is refused before another provider entry.
	for i, item := range output {
		var m map[string]any
		require.NoError(t, json.Unmarshal(item, &m))
		if encrypted, ok := m["encrypted_content"].(string); ok {
			m["encrypted_content"] = encrypted + "!"
			output[i], err = json.Marshal(m)
			require.NoError(t, err)
		}
	}
	request["input"] = output
	raw, err = json.Marshal(request)
	require.NoError(t, err)
	_, entered, err = call(raw)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.False(t, entered)
	require.Equal(t, 2, requests)
}

func TestGatewayNativeOfficialGeminiRejectsBufferedChunksAfterInvalidSignature(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, _, call := officialAPIWireFixture(t, GatewayGeminiAPIKeyProfile, GatewayGeminiAPIBaseURL, GatewayGeminiAPIModel, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Keep every line in one small write, so the scanner has later chunks
		// buffered when the second, conflicting signature closes the body.
		chunks := []string{
			`{"id":"first","choices":[{"index":0,"delta":{"role":"assistant","content":"before","extra_content":{"google":{"thought_signature":"first-signature"}}},"finish_reason":null}]}`,
			`{"id":"first","choices":[{"index":0,"delta":{"extra_content":{"google":{"thought_signature":"conflicting-signature"}}},"finish_reason":null}]}`,
			`{"id":"first","choices":[{"index":0,"delta":{"content":"buffered-after-invalid-signature"},"finish_reason":null}]}`,
			`{"id":"first","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			`[DONE]`,
		}
		io.WriteString(w, "data: "+strings.Join(chunks, "\n\ndata: ")+"\n\n")
	})
	body, err := json.Marshal(map[string]any{"model": GatewayGeminiAPIModel, "input": "Review", "store": false, "stream": true, "max_output_tokens": 512})
	require.NoError(t, err)
	rec, entered, err := call(body)
	require.True(t, entered)
	require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
	require.Contains(t, rec.Body.String(), "before")
	require.NotContains(t, rec.Body.String(), "buffered-after-invalid-signature")
	require.NotContains(t, rec.Body.String(), "response.completed")
}

func TestGatewayNativeOfficialAnthropicActualTLSHeadersToolsAndSchema(t *testing.T) {
	gin.SetMode(gin.TestMode)
	requests := 0
	_, _, call := officialAPIWireFixture(t, GatewayAnthropicAPIKeyProfile, GatewayAnthropicAPIBaseURL, GatewayAnthropicAPIModel, func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "api.anthropic.com", r.Host)
		require.Equal(t, "/v1/messages", r.URL.Path)
		require.Equal(t, "sandbox-fixture", r.Header.Get("x-api-key"))
		require.Empty(t, r.Header.Get("Authorization"))
		require.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		require.Empty(t, r.Header.Get("anthropic-beta"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var request map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &request))
		require.JSONEq(t, `{"format":{"type":"json_schema","schema":{"type":"object","properties":{"findings":{"type":"array","items":{"type":"string"}}},"required":["findings"],"additionalProperties":false}}}`, string(request["output_config"]))
		require.Nil(t, request["thinking"])
		require.NotContains(t, string(body), "claude-code")
		if requests == 2 {
			require.Contains(t, string(request["messages"]), `"type":"tool_result"`)
			require.Contains(t, string(request["messages"]), `"tool_use_id":"toolu_review"`)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_review\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n", GatewayAnthropicAPIModel)
		if requests == 1 {
			io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_review\",\"name\":\"read_source\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\"file.go\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		} else {
			io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"{\\\"findings\\\":[]}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		}
	})
	raw := []byte(`{"model":"claude-sonnet-4-6","input":"Review file.go","store":false,"stream":true,"max_output_tokens":512,"tools":[{"type":"function","name":"read_source","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}],"text":{"format":{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":{"type":"object","properties":{"findings":{"type":"array","items":{"type":"string"}}},"required":["findings"],"additionalProperties":false}}}}`)
	first, entered, err := call(raw)
	require.NoError(t, err)
	require.True(t, entered)
	output := officialAPICompletedOutput(t, first.Body.String())
	var tool struct {
		CallID string `json:"call_id"`
	}
	require.NoError(t, json.Unmarshal(output[0], &tool))
	require.NotEmpty(t, tool.CallID)
	result, err := json.Marshal(map[string]string{"type": "function_call_output", "call_id": tool.CallID, "output": "synthetic file contents"})
	require.NoError(t, err)
	output = append(output, result)
	var request map[string]any
	require.NoError(t, json.Unmarshal(raw, &request))
	request["input"] = output
	raw, err = json.Marshal(request)
	require.NoError(t, err)
	second, entered, err := call(raw)
	require.NoError(t, err)
	require.True(t, entered)
	require.NotEmpty(t, officialAPICompletedOutput(t, second.Body.String()))
	require.Equal(t, 2, requests)
}
