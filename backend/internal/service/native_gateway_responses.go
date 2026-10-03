package service

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// Only the explicit private native Responses profile uses this byte-preserving
// path. Stock passthrough performs custom-tool conversion and error retries;
// neither is appropriate for MiMo's officially documented native Responses lite.
// Ordinary callers, the historical bridge and their handlers stay unchanged.
func (s *OpenAIGatewayService) gatewayNativeTargetURL(a *Account) (string, error) {
	if a.Extra[GatewayProfileExtraKey] == GatewayLegacyBridgeProfile {
		return s.openAIChatCompletionsTargetURL(a)
	}
	base, err := s.validateUpstreamBaseURL(a.GetCredential("base_url"))
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	return buildOpenAIResponsesURLForPlatform(PlatformOpenAI, base), nil
}

// These are hard bounds for the draft profile, NOT a capacity qualification.
const gatewayNativeResponseLimit = 8 << 20
const gatewayNativeSSEFrameLimit = 1 << 20

func (s *OpenAIGatewayService) forwardGatewayNativeResponses(ctx context.Context, c *gin.Context, a *Account, body []byte) (*OpenAIForwardResult, error) {
	target, err := s.gatewayNativeTargetURL(a)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	request, err := http.NewRequestWithContext(WithHTTPUpstreamProfile(ctx, HTTPUpstreamProfileOpenAI), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	request.Header.Set("Authorization", "Bearer "+a.GetCredential("api_key"))
	request.Header.Set("Content-Type", "application/json")
	// No caller affinity, turn-state, auth or routing headers. No invented
	// vendor protocol switch: the official model catalog drives CLI tool shapes.
	request.Header.Set("Accept", "application/json")
	if gjson.GetBytes(body, "stream").Bool() {
		request.Header.Set("Accept", "text/event-stream")
	}
	start := time.Now()
	resp, err := s.doOpenAIUpstream(request, "", a)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if err == ErrGatewayNativeIdentity || err == ErrGatewayNativeReplay {
			return nil, err
		}
		return nil, ErrGatewayNativeEffectUnknown
	}
	if resp == nil || resp.Body == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Never read, export or log a vendor error body or return failover metadata.
		return nil, ErrGatewayNativeEffectUnknown
	}
	stream := gjson.GetBytes(body, "stream").Bool()
	result := &OpenAIForwardResult{Stream: stream, Model: gjson.GetBytes(body, "model").String(), UpstreamEndpoint: "/v1/responses"}
	if !stream {
		output, err := io.ReadAll(io.LimitReader(resp.Body, gatewayNativeResponseLimit+1))
		if err != nil || len(output) > gatewayNativeResponseLimit {
			return nil, ErrGatewayNativeEffectUnknown
		}
		fields, ok := gatewayNativeCanonicalObject(output, "status")
		if !ok || gjson.ParseBytes(fields["status"]).String() != "completed" {
			return nil, ErrGatewayNativeEffectUnknown
		}
		result.Usage = OpenAIUsage{InputTokens: int(gjson.GetBytes(output, "usage.input_tokens").Int()), OutputTokens: int(gjson.GetBytes(output, "usage.output_tokens").Int())}
		c.Header("Content-Type", "application/json")
		if n, err := c.Writer.Write(output); err != nil || n != len(output) {
			return nil, ErrGatewayNativeEffectUnknown
		}
		if gatewayNativeFlush(c.Writer) != nil {
			return nil, ErrGatewayNativeEffectUnknown
		}
		result.Duration = time.Since(start)
		return result, nil
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return nil, ErrGatewayNativeEffectUnknown
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	// One bounded event at a time; no producer goroutine, unbounded queue, history,
	// error-body cache or stream reconstruction. Cancellation uses the request ctx.
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, gatewayNativeResponseLimit+1))
	// Include original LF/CRLF bytes in each token for bounds and forwarding.
	scanner.Split(gatewayNativeRawSSELine)
	scanner.Buffer(make([]byte, 4096), gatewayNativeSSEFrameLimit+1)
	var event bytes.Buffer
	var data []string
	total := 0
	for scanner.Scan() {
		raw := scanner.Bytes()
		total += len(raw)
		if total > gatewayNativeResponseLimit || event.Len()+len(raw) > gatewayNativeSSEFrameLimit {
			return nil, ErrGatewayNativeEffectUnknown
		}
		_, _ = event.Write(raw) // bytes.Buffer.Write cannot fail.
		line := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\r'})
		if len(line) > 0 {
			if bytes.HasPrefix(line, []byte("data:")) {
				value := line[5:]
				if len(value) > 0 && value[0] == ' ' {
					value = value[1:]
				}
				data = append(data, string(value))
			} else if bytes.Equal(line, []byte("data")) {
				data = append(data, "")
			}
			continue
		}
		// Comments and other forwarded SSE fields also belong to the UTF-8 frame.
		if !utf8.Valid(event.Bytes()) {
			return nil, ErrGatewayNativeEffectUnknown
		}
		completed := false
		if len(data) > 0 {
			// SSE joins all data fields in an event before JSON interpretation.
			payload := []byte(strings.Join(data, "\n"))
			if bytes.Equal(payload, []byte("[DONE]")) {
				return nil, ErrGatewayNativeEffectUnknown
			}
			fields, ok := gatewayNativeCanonicalObject(payload, "type", "response")
			if !ok {
				return nil, ErrGatewayNativeEffectUnknown
			}
			kind := gjson.ParseBytes(fields["type"]).String()
			// Check only the protocol response object, never tool/user payloads.
			var status string
			if response := fields["response"]; response != nil {
				responseFields, ok := gatewayNativeCanonicalObject(response, "status")
				if !ok {
					return nil, ErrGatewayNativeEffectUnknown
				}
				status = gjson.ParseBytes(responseFields["status"]).String()
			}
			if kind == "error" || kind == "response.failed" || kind == "response.incomplete" {
				return nil, ErrGatewayNativeEffectUnknown
			}
			if kind == "response.completed" {
				if status != "completed" {
					return nil, ErrGatewayNativeEffectUnknown
				}
				completed = true
				result.Usage = OpenAIUsage{InputTokens: int(gjson.GetBytes(payload, "response.usage.input_tokens").Int()), OutputTokens: int(gjson.GetBytes(payload, "response.usage.output_tokens").Int())}
			}
		}
		if n, err := c.Writer.Write(event.Bytes()); err != nil || n != event.Len() {
			return nil, ErrGatewayNativeEffectUnknown
		}
		if gatewayNativeFlush(c.Writer) != nil {
			return nil, ErrGatewayNativeEffectUnknown
		}
		if completed {
			// Protocol completion and successful delivery settle the accepted effect.
			// A keepalive/EOF/read failure after this point cannot revise that outcome.
			_ = resp.Body.Close()
			result.Duration = time.Since(start)
			return result, nil
		}
		event.Reset()
		data = nil
	}
	return nil, ErrGatewayNativeEffectUnknown
}

func gatewayNativeRawSSELine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Go's response controller observes FlushError on the actual HTTP writer.
// Skip Unwrap-capable wrappers with only a void Flush, but retain an outer
// writer's explicit FlushError contract (for delivery-aware middleware).
func gatewayNativeFlush(writer http.ResponseWriter) error {
	for {
		if _, ok := writer.(interface{ FlushError() error }); ok {
			break
		}
		unwrap, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		writer = unwrap.Unwrap()
	}
	return http.NewResponseController(writer).Flush()
}
