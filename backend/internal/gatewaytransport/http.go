package gatewaytransport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Mount on a dedicated private listener, explicitly. This handler does not
// install stock server, scheduler, admin, probe or logging middleware.
func (h *Handler) ServeHTTP(raw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	owner := r.URL.Path == transportsPath+"/read-owner" || r.URL.Path == transportsPath+"/cancel-owner" || r.URL.Path == transportsPath+"/ack-owner"
	if r.URL.Path != transportsPath && r.URL.Path != transportsPath+"/cancel" && r.URL.Path != transportsPath+"/read" && r.URL.Path != transportsPath+"/ack" && !owner {
		http.NotFound(raw, r)
		return
	}
	peer, err := h.cfg.Authorize(r)
	if err != nil || !identifier.MatchString(peer.ConsumerID) ||
		(r.URL.Path == transportsPath || owner) && peer.Role != "execution" || r.URL.Path != transportsPath && !owner && peer.Role != "cleanup" {
		http.Error(raw, "private native transport denied", http.StatusForbidden)
		return
	}
	slots := h.controls
	if r.URL.Path == transportsPath {
		slots = h.executions
	}
	if !h.acquireHTTP(raw, r, slots) {
		return
	}
	// Includes envelope reads, callback, Forward/physical Close and all writes.
	// Local handler release never acknowledges upstream or durable closure.
	defer func() { <-slots }()
	controller := http.NewResponseController(raw)
	if controller.SetReadDeadline(time.Now().Add(h.cfg.IOTimeout)) != nil || controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout)) != nil {
		http.Error(raw, "private native transport denied", http.StatusServiceUnavailable)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.EnvelopeBytes+1))
	if err != nil || int64(len(data)) > h.cfg.EnvelopeBytes {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	if r.URL.Path != transportsPath {
		if owner {
			var input ownerClosureRequest
			if strictJSON(data, &input) != nil {
				http.Error(raw, "private native transport denied", http.StatusBadRequest)
				return
			}
			result, err := h.ownerClosure(r.Context(), peer.ConsumerID, strings.TrimPrefix(r.URL.Path, transportsPath+"/"), input.Proof)
			if err != nil {
				http.Error(raw, "private native transport denied", http.StatusConflict)
				return
			}
			writeReceipt(raw, result)
			return
		}
		var input cleanupRequest
		if strictJSON(data, &input) != nil {
			http.Error(raw, "private native transport denied", http.StatusBadRequest)
			return
		}
		result, err := h.cleanup(r.Context(), peer.ConsumerID, r.URL.Path[len(transportsPath)+1:], input)
		if err != nil {
			http.Error(raw, "private native transport denied", http.StatusConflict)
			return
		}
		writeReceipt(raw, result)
		return
	}
	var input Request
	if strictJSON(data, &input) != nil {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	profile, configured := h.profile(input.Admission.ProfileID)
	if !configured || !input.Admission.valid(time.Now()) || !identifier.MatchString(input.RequestRef) || !canonicalUUID.MatchString(input.Worker) ||
		input.Descriptor.AccountID < 1 || !canonicalUUID.MatchString(input.Descriptor.Generation) || input.Descriptor.CreatedAt.IsZero() ||
		input.Descriptor.Profile != profile.Profile || input.Descriptor.Model != profile.Model || input.Descriptor.BaseURL != profile.BaseURL ||
		input.Admission.Limits.RequestBytes > profile.RequestBytes || input.Admission.Limits.OutputBytes > profile.OutputBytes || input.Admission.Limits.Tokens > profile.Tokens ||
		int64(len(input.Payload)) > input.Admission.Limits.RequestBytes {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	payload, err := qualifyPayload(input.Payload, input.Descriptor.Model, input.Admission.Limits.Tokens, profile.ProviderTokenUpperBound)
	if err != nil || int64(len(payload)) > input.Admission.Limits.RequestBytes {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	deadline, _ := parseInstant(input.Admission.ExpiresAt)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	// The original writer implements deadlines even when the Gin writer does not
	// implement Unwrap. Cancellation interrupts both a blocked write and read.
	interrupt := func() { _ = controller.SetWriteDeadline(time.Now()); _ = controller.SetReadDeadline(time.Now()) }
	e, first, err := h.reserve(peer.ConsumerID, input, ctx, cancel, interrupt)
	if err != nil || !first {
		// Do not interrupt the response writer for this duplicate's own receipt.
		cancel()
		if err != nil {
			http.Error(raw, "private native transport denied", http.StatusConflict)
			return
		}
		_ = controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout))
		writeReceipt(raw, h.receipt(peer.ConsumerID, e))
		return
	}
	permitted, err := h.admit(ctx, peer.ConsumerID, e)
	if err != nil || !permitted {
		// Positive no Forward/body entry, independently of whether SQL claimed.
		// Record it before cancellation so the original keepalive connection is
		// not interrupted when there is no forwarding I/O to unblock.
		h.finishNoEntry(e)
		h.seal(e)
		_ = controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout))
		writeReceipt(raw, h.receipt(peer.ConsumerID, e))
		return
	}
	ctx, err = service.WithGatewayNativeConsumer(ctx, peer.ConsumerID)
	if err != nil {
		h.finishNoEntry(e)
		h.seal(e)
		return
	}
	ctx = service.WithGatewayNativeCustody(ctx, h.cfg.Custody)
	ctx = service.WithGatewayNativeLifetime(ctx, e.life)
	ctx = service.WithGatewayNativeProviderReadIdle(ctx, h.cfg.ProviderReadIdle)
	if profile.Profile == service.GatewayCodexOAuthResponsesProfile {
		ctx, err = h.cfg.OAuth.BindApproved(ctx, input.Descriptor, input.Admission.AccountRef, input.Admission.AuthorizationEpoch, input.Admission.Limits.RequestBytes, input.Admission.Limits.Tokens)
		if err != nil {
			h.finishNoEntry(e)
			h.seal(e)
			_ = controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout))
			writeReceipt(raw, h.receipt(peer.ConsumerID, e))
			return
		}
	}
	c, _ := gin.CreateTestContext(raw)
	c.Writer = &privateGinWriter{ResponseWriter: c.Writer, raw: raw}
	c.Request = r.Clone(ctx)
	// Deadline writes are bounded from the original approved request lifetime.
	writeDeadline := time.Now().Add(h.cfg.IOTimeout)
	if deadline.Before(writeDeadline) {
		writeDeadline = deadline
	}
	_ = controller.SetWriteDeadline(writeDeadline)
	raw.Header().Set("X-Gateway-Request-Ref", input.RequestRef)
	_, _, _ = h.cfg.Gateway.ForwardGatewayRoute(ctx, c, input.Descriptor, payload)
	// Service observation records forward return/physical Close and terminal
	// delivery. HTTP completion itself never acknowledges kernel settlement.
	h.mu.Lock()
	e.sealed = true
	h.mu.Unlock()
}

// Management uses the SAME reserved control budget as transport cleanup and
// owner read/cancel/ack. Authentication precedes admission and body buffering;
// the existing management router still establishes protected consumer scope.
func (h *Handler) ManagementHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := h.cfg.Authorize(r)
		if err != nil || peer.Role != "management" || !identifier.MatchString(peer.ConsumerID) {
			http.Error(w, "private native transport denied", http.StatusForbidden)
			return
		}
		if !h.acquireHTTP(w, r, h.controls) {
			return
		}
		defer func() { <-h.controls }()
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) acquireHTTP(w http.ResponseWriter, r *http.Request, slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		// Do not let net/http drain a held rejected body before sending the
		// rejection. No envelope read, registry reservation or callback occurs.
		r.Close = true
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout))
		http.Error(w, "private native transport busy", http.StatusServiceUnavailable)
		return false
	}
}

func (h *Handler) finishNoEntry(e *reservation) { e.life.NoForward() }
func writeReceipt(w http.ResponseWriter, r Receipt) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(r)
}

type privateGinWriter struct {
	gin.ResponseWriter
	raw http.ResponseWriter
}

func (w *privateGinWriter) Unwrap() http.ResponseWriter { return w.raw }
func (w *privateGinWriter) FlushError() error           { return http.NewResponseController(w.raw).Flush() }

// The persisted one-use callback capability is its sole authorization. It still
// consumes the same eight management/cleanup slots, never execution capacity.
func (h *Handler) NativeOAuthCallbackHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/auth/callback" || r.URL.RawPath != "" {
			http.Error(w, "private native transport denied", http.StatusBadRequest)
			return
		}
		if !h.acquireHTTP(w, r, h.controls) {
			return
		}
		defer func() { <-h.controls }()
		next.ServeHTTP(w, r)
	})
}
