package gatewaytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

var errAuthorityUnavailable = errors.New("native execution authority unavailable")

type authorityHTTPError struct{ status int }

func (e authorityHTTPError) Error() string { return "native execution authority status" }

var publicExecutionRoute = regexp.MustCompile(`^/v1/executions/([A-Za-z0-9_-]{1,128})/requests$`)
var publicReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var publicToken = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type publicAuthorizationRequest struct {
	ExecutionBearer string          `json:"executionBearer"`
	RequestRef      string          `json:"requestRef"`
	ExecutionRef    string          `json:"executionRef,omitempty"`
	Admission       json.RawMessage `json:"admission,omitempty"`
}
type publicAuthorizationReply struct {
	ConsumerID string                     `json:"consumerId"`
	RequestRef string                     `json:"requestRef"`
	Worker     string                     `json:"worker"`
	Admission  Admission                  `json:"admission"`
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
}

// PublicHandler belongs on its own bounded listener. Only execution capabilities
// cross this boundary; the fixed private execution peer credential never does.
// Prompt/output bytes remain in Go; callbacks carry bounded authority metadata.
func (h *Handler) PublicHandler(maxActive int) http.Handler {
	if maxActive < 1 || maxActive > 2048 {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { publicError(w, 503, "admission_limited", "") })
	}
	slots := make(chan struct{}, maxActive)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		match := publicExecutionRoute.FindStringSubmatch(r.URL.Path)
		validQuery := r.URL.RawQuery == "" && !r.URL.ForceQuery || r.URL.Path == "/v1/messages" && r.URL.RawQuery == "beta=true" && !r.URL.ForceQuery
		if r.Method != http.MethodPost || !validQuery || r.URL.RawPath != "" ||
			r.URL.Path != "/v1/responses" && r.URL.Path != "/v1/messages" && match == nil || len(r.RequestURI) > 2048 {
			publicError(w, http.StatusNotFound, "not_found", "")
			return
		}
		requestRef, valid := publicSingleton(r, "X-Gateway-Request-Id")
		if !valid || requestRef != "" && !publicReference.MatchString(requestRef) {
			publicError(w, 400, "invalid_request", "")
			return
		}
		if requestRef == "" {
			requestRef = uuid.NewString()
		}
		// Rejection occurs before callback or body read, using the shared bounded
		// public execution budget; privileged admission has independent slots.
		select {
		case slots <- struct{}{}:
		default:
			r.Close = true
			w.Header().Set("Connection", "close")
			publicError(w, 503, "admission_limited", requestRef)
			return
		}
		defer func() { <-slots }()
		controller := http.NewResponseController(w)
		if controller.SetReadDeadline(time.Now().Add(h.cfg.IOTimeout)) != nil || controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout)) != nil {
			publicError(w, 503, "admission_limited", requestRef)
			return
		}
		authorization, single := publicSingleton(r, "Authorization")
		apiKey, apiSingle := publicSingleton(r, "X-Api-Key")
		if !apiSingle || apiKey != "" && (r.URL.Path != "/v1/messages" || authorization != "") {
			publicError(w, 401, "unauthenticated", requestRef)
			return
		}
		if r.URL.Path == "/v1/messages" && authorization == "" && apiKey != "" {
			authorization = "Bearer " + apiKey
		}
		contentType, contentSingle := publicSingleton(r, "Content-Type")
		encoding, encodingSingle := publicSingleton(r, "Content-Encoding")
		media, params, mediaErr := mime.ParseMediaType(contentType)
		if !single || !strings.HasPrefix(authorization, "Bearer ") || len(authorization) < 23 || len(authorization) > 1031 || !publicToken.MatchString(strings.TrimPrefix(authorization, "Bearer ")) {
			publicError(w, 401, "unauthenticated", requestRef)
			return
		}
		if !contentSingle || mediaErr != nil || media != "application/json" || len(params) > 1 ||
			len(params) == 1 && params["charset"] != "utf-8" || !encodingSingle || encoding != "" || len(r.Header) > 32 {
			publicError(w, 400, "invalid_request", requestRef)
			return
		}
		lookup := publicAuthorizationRequest{ExecutionBearer: strings.TrimPrefix(authorization, "Bearer "), RequestRef: requestRef}
		if match != nil {
			lookup.ExecutionRef = match[1]
			supplied, single := publicSingleton(r, "X-Gateway-Admission")
			if !single || supplied == "" || len(supplied) > 4096 || !json.Valid([]byte(supplied)) {
				publicError(w, 400, "invalid_request", requestRef)
				return
			}
			lookup.Admission = json.RawMessage(supplied)
		} else if supplied, single := publicSingleton(r, "X-Gateway-Admission"); !single || supplied != "" {
			publicError(w, 400, "invalid_request", requestRef)
			return
		}
		var approved publicAuthorizationReply
		if err := h.publicPost(r.Context(), "/private/native/v1/execution-authority", lookup, &approved); err != nil {
			// This callback cannot claim or enter a provider. Only here can a
			// transient authority failure truthfully mean admission-limited.
			var status authorityHTTPError
			if errors.Is(err, errAuthorityUnavailable) || errors.As(err, &status) && (status.status == 503 || status.status == 429) {
				publicError(w, 503, "admission_limited", requestRef)
			} else if errors.As(err, &status) && (status.status == 403 || status.status == 401) {
				publicError(w, 403, "forbidden", requestRef)
			} else {
				publicError(w, 502, "upstream_failure", requestRef)
			}
			return
		}
		if !identifier.MatchString(approved.ConsumerID) || approved.RequestRef != requestRef || !canonicalUUID.MatchString(approved.Worker) ||
			!approved.Admission.valid(time.Now()) || lookup.ExecutionRef != "" && lookup.ExecutionRef != approved.Admission.ExecutionRef {
			publicError(w, 502, "upstream_failure", requestRef)
			return
		}
		if r.URL.Path == "/v1/messages" && approved.Admission.ProfileID != service.GatewayClaudeOAuthMessagesProfile {
			publicError(w, 403, "forbidden", requestRef)
			return
		}
		if r.ContentLength > approved.Admission.Limits.RequestBytes {
			publicError(w, 413, "invalid_request", requestRef)
			return
		}
		payload, err := io.ReadAll(io.LimitReader(r.Body, approved.Admission.Limits.RequestBytes+1))
		if err != nil || int64(len(payload)) > approved.Admission.Limits.RequestBytes {
			publicError(w, 413, "invalid_request", requestRef)
			return
		}
		if r.URL.Path == "/v1/responses" {
			payload, err = standardResponsesDefaults(payload)
			if err != nil || int64(len(payload)) > approved.Admission.Limits.RequestBytes {
				publicError(w, 400, "invalid_request", requestRef)
				return
			}
		}
		input := Request{RequestRef: requestRef, Worker: approved.Worker, Admission: approved.Admission, Descriptor: approved.Descriptor, Payload: payload}
		h.serveRequest(w, r, Peer{ConsumerID: approved.ConsumerID, Role: "execution"}, input, lookup.ExecutionBearer)
	})
}

func publicSingleton(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func publicError(w http.ResponseWriter, status int, code, requestRef string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]any{"code": code, "traceRef": uuid.NewString(), "effect": "not_dispatched", "retry": map[string]string{"kind": "never"}}
	if requestRef != "" {
		body["requestRef"] = requestRef
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeExecutionError(w http.ResponseWriter, public bool, status int, ref string) {
	if public {
		publicError(w, status, "invalid_request", ref)
		return
	}
	http.Error(w, "private native transport denied", status)
}

func (h *Handler) writeExecutionReceipt(w http.ResponseWriter, consumer string, e *reservation, public bool) {
	r := h.receipt(consumer, e)
	h.mu.Lock()
	refused := e.preclaimRefused
	h.mu.Unlock()
	if public && refused {
		publicError(w, http.StatusServiceUnavailable, "admission_limited", r.RequestRef)
		return
	}
	if !public {
		writeReceipt(w, r)
		return
	}
	effect := "effect_unknown"
	if r.Status != nil {
		effect = r.Status.Effect
	}
	if r.Lifetime.Completed {
		effect = "completed"
	} else if closed(r.Lifetime) && r.Lifetime.Entered {
		effect = "effect_unknown"
	}
	status := "unknown"
	switch effect {
	case "not_dispatched", "rejected_before_dispatch":
		status = "failed"
	case "dispatch_started", "response_started":
		status = "pending"
	case "completed":
		status = "completed"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Gateway-Request-Ref", r.RequestRef)
	w.WriteHeader(http.StatusAccepted)
	body := map[string]any{"requestRef": r.RequestRef, "effect": effect, "status": status}
	if effect == "rejected_before_dispatch" {
		body["error"] = map[string]any{"code": "upstream_failure", "traceRef": uuid.NewString(), "requestRef": r.RequestRef, "effect": effect, "retry": map[string]string{"kind": "never"}}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// Fixed origin, one attempt, no environment proxy/redirect and bounded metadata.
func (h *Handler) publicPost(ctx context.Context, path string, body, reply any) error {
	raw, err := json.Marshal(body)
	if err != nil || int64(len(raw)) > h.cfg.CallbackBytes {
		return errDenied
	}
	bounded, cancel := context.WithTimeout(ctx, h.cfg.CallbackTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, strings.TrimSuffix(h.cfg.CallbackOrigin, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return errDenied
	}
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+h.cfg.CallbackCredential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := h.callback.Do(req)
	if err != nil {
		return errAuthorityUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return authorityHTTPError{response.StatusCode}
	}
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" {
		return errDenied
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, h.cfg.CallbackBytes+1))
	if err != nil || bounded.Err() != nil {
		return errAuthorityUnavailable
	}
	if int64(len(data)) > h.cfg.CallbackBytes || strictJSON(data, reply) != nil {
		return errDenied
	}
	return nil
}

// Physical closure and terminal delivery are independent of client disconnect.
// Failed callbacks retain the original registry evidence for protected cleanup.
func (h *Handler) settlePublic(consumer string, e *reservation) bool {
	h.seal(e)
	h.mu.Lock()
	refused := e.preclaimRefused && e.proof == nil
	h.mu.Unlock()
	if refused && closed(e.life.Snapshot()) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Queue is bounded by active public handlers, with no SQL checkout or
	// callback socket held while waiting. Terminal metadata never retries.
	select {
	case h.terminalCallbacks <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-h.terminalCallbacks }()
	var r Receipt
	timer := time.NewTicker(5 * time.Millisecond)
	defer timer.Stop()
	for {
		r = h.receipt(consumer, e)
		if closed(r.Lifetime) {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
		}
	}
	if r.Proof == nil {
		return false
	}
	body := struct {
		ConsumerID string  `json:"consumerId"`
		Proof      Proof   `json:"proof"`
		Receipt    Receipt `json:"receipt"`
	}{consumer, *r.Proof, r}
	var reply struct {
		OK bool `json:"ok"`
	}
	if h.publicPost(ctx, "/private/native/v1/execution-settle", body, &reply) != nil || !reply.OK {
		return false
	}
	h.mu.Lock()
	e.acknowledged = true
	h.mu.Unlock()
	return true
}

// Standard Responses clients may omit the safe server defaults. Supplied values
// remain untouched and the common qualifier still rejects store=true or a paid
// tier. SDK ingress keeps its exact existing explicit-field contract.
func standardResponsesDefaults(raw []byte) ([]byte, error) {
	if uniquePayloadJSON(raw) != nil {
		return nil, errDenied
	}
	fields, valid := service.GatewayNativePayloadFields(raw, "model", "stream", "store", "service_tier", "previous_response_id", "max_output_tokens")
	if !valid {
		return nil, errDenied
	}
	suffix := ""
	if fields["store"] == nil {
		suffix += `,"store":false`
	}
	if fields["service_tier"] == nil {
		suffix += `,"service_tier":"default"`
	}
	if suffix == "" {
		return raw, nil
	}
	end := bytes.LastIndexByte(raw, '}')
	if end < 0 {
		return nil, errDenied
	}
	out := make([]byte, 0, len(raw)+len(suffix))
	out = append(out, raw[:end]...)
	out = append(out, suffix...)
	out = append(out, raw[end:]...)
	return out, nil
}

// Decode names before normalization. This bounded scanner rejects duplicate
// decoded keys at every depth while leaving opaque numbers and body bytes alone.
func uniquePayloadJSON(raw []byte) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errDenied
		}
		token, err := decoder.Token()
		if err != nil {
			return errDenied
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]bool)
			for decoder.More() {
				token, err = decoder.Token()
				if err != nil {
					return errDenied
				}
				key, ok := token.(string)
				if !ok || keys[key] {
					return errDenied
				}
				keys[key] = true
				if value(depth+1) != nil {
					return errDenied
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim('}') {
				return errDenied
			}
		case '[':
			for decoder.More() {
				if value(depth+1) != nil {
					return errDenied
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim(']') {
				return errDenied
			}
		default:
			return errDenied
		}
		return nil
	}
	if value(0) != nil {
		return errDenied
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errDenied
	}
	return nil
}

// Public clients can finish as soon as their terminal SSE event arrives. Hold
// that bounded frame until the provider effect, configured usage and physical
// closure are durable; preceding frames retain their exact original bytes.
type publicTerminalBudget struct {
	mu            sync.Mutex
	used, maximum int
}

func (b *publicTerminalBudget) reserve(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || size > b.maximum-b.used {
		return false
	}
	b.used += size
	return true
}
func (b *publicTerminalBudget) release(size int) { b.mu.Lock(); defer b.mu.Unlock(); b.used -= size }

type publicTerminalWriter struct {
	budget   *publicTerminalBudget
	reserved int
	http.ResponseWriter
	pending, terminal []byte
	held, failed      bool
	maximum           int
}

func (w *publicTerminalWriter) dispose() {
	if w.reserved > 0 {
		w.budget.release(w.reserved)
		w.reserved = 0
	}
	w.pending = nil
	w.terminal = nil
}
func (w *publicTerminalWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *publicTerminalWriter) Write(data []byte) (int, error) {
	if strings.Split(w.Header().Get("Content-Type"), ";")[0] != "text/event-stream" {
		return w.ResponseWriter.Write(data)
	}
	if w.failed {
		return 0, errDenied
	}
	if w.held {
		if len(w.terminal)+len(data) > w.maximum || !w.budget.reserve(len(data)) {
			w.failed = true
			return 0, errDenied
		}
		w.reserved += len(data)
		w.terminal = append(w.terminal, data...)
		return len(data), nil
	}
	w.pending = append(w.pending, data...)
	for {
		end := publicSSEFrameEnd(w.pending)
		if end == 0 {
			if len(w.pending) > w.maximum {
				w.failed = true
				return 0, errDenied
			}
			return len(data), nil
		}
		frame := w.pending[:end]
		if end > w.maximum {
			w.failed = true
			return 0, errDenied
		}
		if publicTerminalFrame(frame) {
			if len(w.pending) > w.maximum {
				w.failed = true
				return 0, errDenied
			}
			if !w.budget.reserve(len(w.pending)) {
				w.failed = true
				return 0, errDenied
			}
			w.reserved += len(w.pending)
			w.terminal = bytes.Clone(w.pending)
			w.pending = nil
			w.held = true
			return len(data), nil
		}
		if _, err := w.ResponseWriter.Write(frame); err != nil {
			w.failed = true
			return 0, err
		}
		w.pending = w.pending[end:]
	}
}
func (w *publicTerminalWriter) Flush() { _ = w.FlushError() }
func (w *publicTerminalWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *publicTerminalWriter) release() error {
	if w.failed || !w.held || len(w.pending) != 0 {
		return errDenied
	}
	if _, err := w.ResponseWriter.Write(w.terminal); err != nil {
		return err
	}
	w.terminal = nil
	return w.FlushError()
}
func publicSSEFrameEnd(raw []byte) int {
	start := 0
	for i, b := range raw {
		if b != '\n' {
			continue
		}
		line := bytes.TrimSuffix(raw[start:i], []byte{'\r'})
		if len(line) == 0 {
			return i + 1
		}
		start = i + 1
	}
	return 0
}
func publicTerminalFrame(frame []byte) bool {
	var data []byte
	for _, line := range bytes.Split(frame, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.HasPrefix(line, []byte("data:")) {
			v := line[5:]
			v = bytes.TrimPrefix(v, []byte{' '})
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, v...)
		}
	}
	var event struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(data, &event) == nil && (event.Type == "response.completed" || event.Type == "message_stop")
}
