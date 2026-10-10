package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
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
	if a.Type == AccountTypeOAuth && a.Extra[GatewayProfileExtraKey] == GatewayOAuthStagingProfile {
		return GatewayCodexOAuthBaseURL + "/responses", nil
	}
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

// Draft fallback for direct private service callers. The dedicated handler
// supplies its trusted IOTimeout-aligned policy; the approved context deadline
// always wins. This is provider BODY inactivity, not listener idle or H2 PING.
const gatewayNativeUpstreamReadIdle = 30 * time.Second

type gatewayNativeProviderReadIdleKey struct{}

// WithGatewayNativeProviderReadIdle is set by trusted private composition only,
// never decoded from the request. Cancellation still observes the saved deadline.
func WithGatewayNativeProviderReadIdle(ctx context.Context, idle time.Duration) context.Context {
	return context.WithValue(ctx, gatewayNativeProviderReadIdleKey{}, idle)
}

// GatewayNativeResponseHeaderBytes marks the actual owned private transport.
// Ordinary requests, including ordinary OpenAI profiles, keep their policy.
func GatewayNativeResponseHeaderBytes(ctx context.Context) int64 {
	if ctx == nil || gatewayNativeLifetime(ctx) == nil {
		return 0
	}
	return 16 << 10
}

// Closed operational vocabulary: never derive diagnostics from provider content.
type gatewayNativeResponseFailurePhase string

const (
	gatewayNativeFailureTransport   gatewayNativeResponseFailurePhase = "transport"
	gatewayNativeFailureResponse    gatewayNativeResponseFailurePhase = "invalid_response"
	gatewayNativeFailureHTTP        gatewayNativeResponseFailurePhase = "http_status"
	gatewayNativeFailureRead        gatewayNativeResponseFailurePhase = "body_read"
	gatewayNativeFailureLimit       gatewayNativeResponseFailurePhase = "body_limit"
	gatewayNativeFailureFinal       gatewayNativeResponseFailurePhase = "invalid_final"
	gatewayNativeFailureContentType gatewayNativeResponseFailurePhase = "invalid_content_type"
	gatewayNativeFailureFrameLimit  gatewayNativeResponseFailurePhase = "sse_frame_limit"
	gatewayNativeFailureFrame       gatewayNativeResponseFailurePhase = "sse_invalid_frame"
	gatewayNativeFailureEvent       gatewayNativeResponseFailurePhase = "sse_invalid_event"
	gatewayNativeFailureProvider    gatewayNativeResponseFailurePhase = "sse_provider_failure"
	gatewayNativeFailureIncomplete  gatewayNativeResponseFailurePhase = "sse_incomplete"
	gatewayNativeFailureSSERead     gatewayNativeResponseFailurePhase = "sse_read"
	gatewayNativeFailureDeadline    gatewayNativeResponseFailurePhase = "deadline"
	gatewayNativeFailureWrite       gatewayNativeResponseFailurePhase = "downstream_write"
	gatewayNativeFailureFlush       gatewayNativeResponseFailurePhase = "downstream_flush"
)

// Only fixed categories escape this bounded, request-deadline-controlled read.
func gatewayNativeHTTPErrorCategory(reader io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(reader, 8193))
	if err != nil {
		return "body_read_failed"
	}
	if len(body) > 8192 {
		return "body_limit"
	}
	if !json.Valid(body) {
		return "invalid_error_json"
	}
	var envelope struct {
		Error struct {
			Code    json.RawMessage `json:"code"`
			Message json.RawMessage `json:"message"`
			Param   json.RawMessage `json:"param"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return "unknown"
	}
	// Provider field types vary. Only strings can match the fixed vocabulary;
	// other valid JSON values must neither mask sibling fields nor be coerced.
	var code, message, param string
	_ = json.Unmarshal(envelope.Error.Code, &code)
	_ = json.Unmarshal(envelope.Error.Message, &message)
	_ = json.Unmarshal(envelope.Error.Param, &param)
	switch code {
	case "code_mode_only":
		return "code_mode_rejected"
	case "invalid_api_key":
		return "authentication_rejected"
	case "model_not_found", "invalid_model":
		return "model_rejected"
	}
	switch param {
	case "service_tier":
		return "parameter_service_tier"
	case "max_output_tokens":
		return "parameter_max_output_tokens"
	case "parallel_tool_calls":
		return "parameter_parallel_tool_calls"
	case "context_management":
		return "parameter_context_management"
	}
	message = strings.ToLower(message)
	if strings.Contains(message, "custom tools require mimo freeform responses lite mode") {
		return "responses_lite_required"
	}
	if strings.Contains(message, "code_mode is required") || strings.Contains(message, "code_mode must be enabled") || strings.Contains(message, "invalid code_mode") {
		return "code_mode_rejected"
	}
	switch code {
	case "unsupported_parameter":
		return "unsupported_parameter"
	case "invalid_request_error":
		return "invalid_request"
	}
	return "unknown"
}

func (s *OpenAIGatewayService) forwardGatewayNativeResponses(ctx context.Context, c *gin.Context, a *Account, body []byte) (*OpenAIForwardResult, error) {
	target, err := s.gatewayNativeTargetURL(a)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	upstreamCtx, stopUpstream := context.WithCancel(ctx)
	defer stopUpstream()
	request, err := http.NewRequestWithContext(WithHTTPUpstreamProfile(upstreamCtx, HTTPUpstreamProfileOpenAI), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	if a.Type != AccountTypeOAuth {
		request.Header.Set("Authorization", "Bearer "+a.GetCredential("api_key"))
	}
	request.Header.Set("Content-Type", "application/json")
	if a.Extra[GatewayProfileExtraKey] == GatewayMiMoResponsesProfile {
		request.Header.Set("x-openai-internal-codex-responses-lite", "true")
	}
	// Only trusted profile protocol headers; no caller affinity, turn-state,
	// auth or routing headers.
	request.Header.Set("Accept", "application/json")
	if gjson.GetBytes(body, "stream").Bool() {
		request.Header.Set("Accept", "text/event-stream")
	}
	// This seam has no effect on return identity, dispatch or settlement. Only
	// bounded status and static phases reach the private process stderr channel.
	// It works without initializing the general logger and leaves readiness on
	// stdout intact. Never include context fields, headers, bodies or error text.
	status := 0
	providerErrorCategory := ""
	fail := func(phase gatewayNativeResponseFailurePhase) error {
		if ctx.Err() == context.DeadlineExceeded {
			phase = gatewayNativeFailureDeadline
		}
		event := struct {
			Event                 string                            `json:"event"`
			Phase                 gatewayNativeResponseFailurePhase `json:"phase"`
			HTTPStatus            int                               `json:"http_status,omitempty"`
			ProviderErrorCategory string                            `json:"provider_error_category,omitempty"`
		}{Event: "gateway_native_response_failure", Phase: phase, ProviderErrorCategory: providerErrorCategory}
		if status >= 100 && status <= 599 {
			event.HTTPStatus = status
		}
		line, _ := json.Marshal(event) // fixed strings and integer cannot fail.
		_, _ = fmt.Fprintln(os.Stderr, string(line))
		return ErrGatewayNativeEffectUnknown
	}
	start := time.Now()
	resp, err := s.doOpenAIUpstream(request, "", a)
	if resp != nil {
		status = resp.StatusCode
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if err == ErrGatewayNativeIdentity || err == ErrGatewayNativeReplay {
			return nil, err
		}
		return nil, fail(gatewayNativeFailureTransport)
	}
	if resp == nil || resp.Body == nil {
		return nil, fail(gatewayNativeFailureResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// HTTP400 diagnostics never export vendor content or alter settlement.
		if resp.StatusCode == http.StatusBadRequest {
			providerErrorCategory = gatewayNativeHTTPErrorCategory(resp.Body)
		}
		return nil, fail(gatewayNativeFailureHTTP)
	}
	var reader io.Reader = resp.Body
	if life := gatewayNativeLifetime(ctx); life != nil {
		idle, _ := ctx.Value(gatewayNativeProviderReadIdleKey{}).(time.Duration)
		if idle <= 0 || idle > gatewayNativeUpstreamReadIdle {
			idle = gatewayNativeUpstreamReadIdle
		}
		reader = &gatewayNativeIdleReader{reader: resp.Body, idle: idle, cancel: func() {
			// Cancel the real HTTP request to interrupt its blocked Read BEFORE
			// requesting physical Close. Cancellation alone proves no closure.
			stopUpstream()
			life.Cancel()
		}}
	}
	stream := gjson.GetBytes(body, "stream").Bool()
	result := &OpenAIForwardResult{Stream: stream, Model: gjson.GetBytes(body, "model").String(), UpstreamEndpoint: "/v1/responses"}
	if !stream {
		output, err := io.ReadAll(io.LimitReader(reader, gatewayNativeResponseLimit+1))
		if err != nil {
			return nil, fail(gatewayNativeFailureRead)
		}
		if len(output) > gatewayNativeResponseLimit {
			return nil, fail(gatewayNativeFailureLimit)
		}
		fields, ok := gatewayNativeCanonicalObject(output, "status")
		if !ok || gjson.ParseBytes(fields["status"]).String() != "completed" {
			return nil, fail(gatewayNativeFailureFinal)
		}
		result.Usage = OpenAIUsage{InputTokens: int(gjson.GetBytes(output, "usage.input_tokens").Int()), OutputTokens: int(gjson.GetBytes(output, "usage.output_tokens").Int())}
		c.Header("Content-Type", "application/json")
		if n, err := c.Writer.Write(output); err != nil || n != len(output) {
			return nil, fail(gatewayNativeFailureWrite)
		}
		if gatewayNativeFlush(c.Writer) != nil {
			return nil, fail(gatewayNativeFailureFlush)
		}
		result.Duration = time.Since(start)
		return result, nil
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return nil, fail(gatewayNativeFailureContentType)
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	// One bounded event at a time; no producer goroutine, unbounded queue, history,
	// error-body cache or stream reconstruction. Cancellation uses the request ctx.
	scanner := bufio.NewScanner(io.LimitReader(reader, gatewayNativeResponseLimit+1))
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
			return nil, fail(gatewayNativeFailureFrameLimit)
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
			return nil, fail(gatewayNativeFailureFrame)
		}
		completed := false
		if len(data) > 0 {
			// SSE joins all data fields in an event before JSON interpretation.
			payload := []byte(strings.Join(data, "\n"))
			if bytes.Equal(payload, []byte("[DONE]")) {
				return nil, fail(gatewayNativeFailureIncomplete)
			}
			fields, ok := gatewayNativeCanonicalObject(payload, "type", "response")
			if !ok {
				return nil, fail(gatewayNativeFailureEvent)
			}
			kind := gjson.ParseBytes(fields["type"]).String()
			// Check only the protocol response object, never tool/user payloads.
			var status string
			if response := fields["response"]; response != nil {
				responseFields, ok := gatewayNativeCanonicalObject(response, "status")
				if !ok {
					return nil, fail(gatewayNativeFailureEvent)
				}
				status = gjson.ParseBytes(responseFields["status"]).String()
			}
			if kind == "error" || kind == "response.failed" || kind == "response.incomplete" {
				return nil, fail(gatewayNativeFailureProvider)
			}
			if kind == "response.completed" {
				if status != "completed" {
					return nil, fail(gatewayNativeFailureFinal)
				}
				completed = true
				result.Usage = OpenAIUsage{InputTokens: int(gjson.GetBytes(payload, "response.usage.input_tokens").Int()), OutputTokens: int(gjson.GetBytes(payload, "response.usage.output_tokens").Int())}
			}
		}
		if n, err := c.Writer.Write(event.Bytes()); err != nil || n != event.Len() {
			return nil, fail(gatewayNativeFailureWrite)
		}
		if gatewayNativeFlush(c.Writer) != nil {
			return nil, fail(gatewayNativeFailureFlush)
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
	if scanner.Err() != nil {
		return nil, fail(gatewayNativeFailureSSERead)
	}
	return nil, fail(gatewayNativeFailureIncomplete)
}

// The forwarding goroutine is the sole reader. One timer per pending Read,
// no reader goroutine/queue. The lock orders timeout against Read return: a
// timer that loses that race cannot cancel later downstream work or reads.
type gatewayNativeIdleReader struct {
	reader  io.Reader
	idle    time.Duration
	cancel  func()
	mu      sync.Mutex
	expired bool
}

func (r *gatewayNativeIdleReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	if r.expired {
		r.mu.Unlock()
		return 0, ErrGatewayNativeEffectUnknown
	}
	pending := true
	timerDone := make(chan struct{})
	timer := time.AfterFunc(r.idle, func() {
		defer close(timerDone)
		r.mu.Lock()
		if !pending {
			r.mu.Unlock()
			return
		}
		r.expired = true
		r.mu.Unlock()
		r.cancel()
	})
	r.mu.Unlock()
	var n int
	var err error
	for {
		n, err = r.reader.Read(p)
		if n != 0 || err != nil {
			break
		}
		// A zero-byte nil-error read is not provider progress and cannot reset
		// the pending read-idle clock.
		r.mu.Lock()
		expired := r.expired
		r.mu.Unlock()
		if expired {
			break
		}
	}
	r.mu.Lock()
	pending = false
	stopped := timer.Stop()
	expired := r.expired
	r.mu.Unlock()
	if !stopped {
		// Join an already fired callback before another Read can arm a timer.
		// Only cancellation is joined, never physical body Close.
		<-timerDone
	}
	if expired {
		return 0, ErrGatewayNativeEffectUnknown
	}
	return n, err
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
