package service

import (
	"context"
	"time"
)

// A private cached admission hint, not a second scheduler or a total-spend
// eligibility decision. The caller receives no raw quota windows.
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
	status := "available"
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
		if *w.UsedPercent >= 100 {
			// Subscription exhaustion is not total-spend exhaustion: Codex may
			// still accept paid credits. Cached windows contain neither credit
			// eligibility nor an authoritative refusal, so they must never
			// become a limited decision, even when the reset is in the future.
			// The admitted request's real upstream 429 remains authoritative.
			status = "unknown"
		}
	}
	return GatewayAccountAdmissionResult{Status: status}
}
