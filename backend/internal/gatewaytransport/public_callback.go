package gatewaytransport

// Private authority and settlement callbacks, with independent queue and RPC budgets.
import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Preclaim queueing owns no callback socket. The original caller (including
// admission expiry) bounds both stages, but queue time does not consume the
// independent active RPC budget shared by authority and public claim producers.
func (h *Handler) preclaimRPCContext(ctx context.Context, queueBudget, activeBudget time.Duration) (context.Context, context.CancelFunc, error) {
	queueCtx, cancelQueue := context.WithTimeout(ctx, queueBudget)
	select {
	case h.preclaimCallbacks <- struct{}{}:
	case <-queueCtx.Done():
		err := queueCtx.Err()
		cancelQueue()
		return nil, nil, err
	}
	// Acquisition and cancellation can become ready together. A permit must
	// never turn an expired queued producer into a new callback attempt.
	if err := queueCtx.Err(); err != nil {
		cancelQueue()
		<-h.preclaimCallbacks
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		cancelQueue()
		<-h.preclaimCallbacks
		return nil, nil, err
	}
	cancelQueue()
	activeCtx, cancelActive := context.WithTimeout(ctx, activeBudget)
	if err := activeCtx.Err(); err != nil {
		cancelActive()
		<-h.preclaimCallbacks
		return nil, nil, err
	}
	var once sync.Once
	return activeCtx, func() {
		once.Do(func() {
			cancelActive()
			<-h.preclaimCallbacks
		})
	}, nil
}

// Fixed origin, one attempt, no environment proxy/redirect and bounded metadata.
func (h *Handler) publicPost(ctx context.Context, path string, body, reply any) error {
	return h.publicPostWithin(ctx, path, body, reply, h.cfg.CallbackTimeout, h.cfg.CallbackTimeout)
}

func (h *Handler) publicPostWithin(ctx context.Context, path string, body, reply any, queueBudget, activeBudget time.Duration) error {
	raw, err := json.Marshal(body)
	if err != nil || int64(len(raw)) > h.cfg.CallbackBytes {
		return errDenied
	}
	var bounded context.Context
	var cancel context.CancelFunc
	if path == "/private/native/v1/execution-authority" {
		bounded, cancel, err = h.preclaimRPCContext(ctx, queueBudget, activeBudget)
		if err != nil {
			return errAuthorityUnavailable
		}
	} else {
		bounded, cancel = context.WithTimeout(ctx, activeBudget)
	}
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

// Production public reservations capture the qualified request model before
// admission. Direct fixture reservations retain their canonical descriptor model.
func (h *Handler) publicRequestedModel(e *reservation) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e.requestedModel != "" {
		return e.requestedModel
	}
	return e.request.Descriptor.Model
}

// Physical closure and terminal delivery are independent of client disconnect.
// Failed callbacks retain the original registry evidence for protected cleanup.
func (h *Handler) settlePublic(consumer string, e *reservation) bool {
	return h.settlePublicWithin(consumer, e, 20*time.Second, 10*time.Second)
}

func (h *Handler) settlePublicWithin(consumer string, e *reservation, queueBudget, activeBudget time.Duration) bool {
	h.seal(e)
	h.mu.Lock()
	refused := e.preclaimRefused && e.proof == nil
	h.mu.Unlock()
	if refused && closed(e.life.Snapshot()) {
		return true
	}
	// Queue is bounded by active public handlers, with no SQL checkout or
	// callback socket held while waiting. Queue time must not consume the
	// independent active settlement budget. Terminal metadata never retries.
	queueCtx, cancelQueue := context.WithTimeout(context.Background(), queueBudget)
	defer cancelQueue()
	select {
	case h.terminalCallbacks <- struct{}{}:
	case <-queueCtx.Done():
		return false
	}
	if queueCtx.Err() != nil {
		<-h.terminalCallbacks
		return false
	}
	cancelQueue()
	defer func() { <-h.terminalCallbacks }()
	ctx, cancel := context.WithTimeout(context.Background(), activeBudget)
	defer cancel()
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
		ConsumerID     string  `json:"consumerId"`
		Proof          Proof   `json:"proof"`
		Receipt        Receipt `json:"receipt"`
		RequestedModel string  `json:"requestedModel"`
	}{consumer, *r.Proof, r, h.publicRequestedModel(e)}
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
