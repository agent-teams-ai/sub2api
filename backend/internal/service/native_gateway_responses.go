package service

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
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

// Actual provider body-read inactivity on the owned private Responses path.
// Independent of the approved absolute lifetime and downstream write deadline.
const gatewayNativeUpstreamReadIdle = time.Second

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
	var reader io.Reader = resp.Body
	if life := gatewayNativeLifetime(ctx); life != nil {
		reader = &gatewayNativeIdleReader{reader: resp.Body, cancel: func() {
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

// The forwarding goroutine is the sole reader. One timer per pending Read,
// no reader goroutine/queue. The lock orders timeout against Read return: a
// timer that loses that race cannot cancel later downstream work or reads.
type gatewayNativeIdleReader struct {
	reader  io.Reader
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
	timer := time.AfterFunc(gatewayNativeUpstreamReadIdle, func() {
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
