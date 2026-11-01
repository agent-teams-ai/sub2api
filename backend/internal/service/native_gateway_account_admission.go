package service

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// A private projection of Sub2API policy, not a second scheduler. The caller
// receives no raw quota windows and never interprets provider thresholds.
type GatewayAccountAdmissionResult struct {
	Status             string `json:"status"`
	PhysicalGeneration string `json:"physicalGeneration,omitempty"`
	RetryAt            string `json:"retryAt,omitempty"`
}

func (s *GatewayAccountLimitsReader) ReadAdmission(ctx context.Context, in GatewayAccountLimitsInput) GatewayAccountAdmissionResult {
	// Reuse both owner-authority checks and durable principal/generation fences.
	snapshot := s.Read(ctx, in)
	return gatewayAccountAdmission(snapshot, time.Now().UTC())
}

func gatewayAccountAdmission(snapshot GatewayAccountLimitsResult, now time.Time) GatewayAccountAdmissionResult {
	if snapshot.Status != "snapshot" {
		return GatewayAccountAdmissionResult{Status: snapshot.Status}
	}
	headers := http.Header{}
	for _, w := range snapshot.Windows {
		if w.Family != "codex" {
			return GatewayAccountAdmissionResult{Status: "unsupported"}
		}
		if w.UsedPercent == nil || w.ResetAt == nil {
			continue
		}
		reset, err := time.Parse(time.RFC3339Nano, *w.ResetAt)
		if err != nil || !reset.After(now) {
			continue
		}
		prefix := "x-codex-" + w.ID + "-"
		headers.Set(prefix+"used-percent", strconv.FormatFloat(*w.UsedPercent, 'f', -1, 64))
		if w.DurationSeconds != nil {
			headers.Set(prefix+"window-minutes", strconv.FormatInt(*w.DurationSeconds/60, 10))
		}
		headers.Set(prefix+"reset-after-seconds", strconv.FormatInt(int64(reset.Sub(now)/time.Second), 10))
	}
	// The exact stock rule chooses the exhausted normalized 7d window before 5h.
	// Reconstruct remaining time from the fenced observation, never restart its
	// original reset-after duration when a cached snapshot is read again.
	reset := calculateOpenAI429ResetTimeAt(headers, now)
	if reset == nil || !reset.After(now) {
		return GatewayAccountAdmissionResult{Status: "available"}
	}
	return GatewayAccountAdmissionResult{Status: "limited", PhysicalGeneration: snapshot.PhysicalGeneration, RetryAt: reset.UTC().Format(time.RFC3339Nano)}
}
