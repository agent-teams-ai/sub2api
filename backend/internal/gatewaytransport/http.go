package gatewaytransport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	if r.URL.Path != transportsPath && r.URL.Path != transportsPath+"/cancel" && r.URL.Path != transportsPath+"/read" && r.URL.Path != transportsPath+"/ack" {
		http.NotFound(raw, r)
		return
	}
	peer, err := h.cfg.Authorize(r)
	if err != nil || !identifier.MatchString(peer.ConsumerID) ||
		r.URL.Path == transportsPath && peer.Role != "execution" || r.URL.Path != transportsPath && peer.Role != "cleanup" {
		http.Error(raw, "private native transport denied", http.StatusForbidden)
		return
	}
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
	if strictJSON(data, &input) != nil || !input.Admission.valid(time.Now()) || !identifier.MatchString(input.RequestRef) || !canonicalUUID.MatchString(input.Worker) ||
		input.Descriptor.AccountID < 1 || !canonicalUUID.MatchString(input.Descriptor.Generation) || input.Descriptor.CreatedAt.IsZero() ||
		input.Descriptor.Profile != h.cfg.Profile.Profile || input.Admission.ProfileID != h.cfg.Profile.Profile || input.Descriptor.Model != h.cfg.Profile.Model || input.Descriptor.BaseURL != h.cfg.Profile.BaseURL ||
		input.Admission.Limits.RequestBytes > h.cfg.Profile.RequestBytes || input.Admission.Limits.OutputBytes > h.cfg.Profile.OutputBytes || input.Admission.Limits.Tokens > h.cfg.Profile.Tokens ||
		int64(len(input.Payload)) > input.Admission.Limits.RequestBytes {
		http.Error(raw, "private native transport denied", http.StatusBadRequest)
		return
	}
	payload, err := qualifyPayload(input.Payload, input.Descriptor.Model, input.Admission.Limits.Tokens, h.cfg.Profile.ProviderTokenUpperBound)
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
		h.seal(e)
		// Positive no Forward/body entry, independently of whether SQL claimed.
		h.finishNoEntry(e)
		_ = controller.SetWriteDeadline(time.Now().Add(h.cfg.IOTimeout))
		writeReceipt(raw, h.receipt(peer.ConsumerID, e))
		return
	}
	ctx, err = service.WithGatewayNativeConsumer(ctx, peer.ConsumerID)
	if err != nil {
		h.seal(e)
		h.finishNoEntry(e)
		return
	}
	ctx = service.WithGatewayNativeCustody(ctx, h.cfg.Custody)
	ctx = service.WithGatewayNativeLifetime(ctx, e.life)
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
