package gatewaytransport

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

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
