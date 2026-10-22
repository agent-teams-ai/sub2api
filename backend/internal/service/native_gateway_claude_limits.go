package service

import (
	"math"
	"net/http"
	"time"
)

// These IDs name the provider's actual buckets. A model-specific weekly bucket
// must not be merged with the subscription-wide weekly bucket.
const (
	GatewayClaudeFiveHour       = "claude-5h"
	GatewayClaudeSevenDay       = "claude-7d"
	GatewayClaudeSonnetSevenDay = "claude-7d-sonnet"
	GatewayClaudeFableSevenDay  = "claude-7d-fable"
)

type GatewayClaudeRawWindow struct {
	ID          string  `json:"id"`
	Utilization *string `json:"utilization,omitempty"`
	Reset       *string `json:"reset,omitempty"`
	ObservedAt  string  `json:"observedAt"`
}

type GatewayClaudeRawLimits struct {
	Windows []GatewayClaudeRawWindow `json:"windows"`
}

// Capture only a fixed response-header allowlist. Do not turn local request
// costs, inferred session starts, Extra, or absent values into provider quota.
func CaptureGatewayClaudeLimits(headers http.Header, observed time.Time) GatewayClaudeRawLimits {
	raw := GatewayClaudeRawLimits{}
	for _, bucket := range []struct{ id, header string }{
		{GatewayClaudeFiveHour, "5h"},
		{GatewayClaudeSevenDay, "7d"},
		{GatewayClaudeFableSevenDay, "7d_oi"},
	} {
		read := func(field string) *string {
			values := headers.Values("anthropic-ratelimit-unified-" + bucket.header + "-" + field)
			if len(values) == 0 {
				return nil
			}
			value := "invalid"
			if len(values) == 1 && len(values[0]) <= 128 {
				value = values[0]
			}
			return &value
		}
		w := GatewayClaudeRawWindow{ID: bucket.id, Utilization: read("utilization"), Reset: read("reset"), ObservedAt: observed.UTC().Format(time.RFC3339Nano)}
		if w.Utilization != nil || w.Reset != nil {
			raw.Windows = append(raw.Windows, w)
		}
	}
	return raw
}

func NormalizeGatewayClaudeLimits(raw GatewayClaudeRawLimits) []GatewayAccountLimitWindow {
	if len(raw.Windows) > 4 {
		return nil
	}
	seen := make(map[string]bool, len(raw.Windows))
	out := make([]GatewayAccountLimitWindow, 0, len(raw.Windows))
	for _, w := range raw.Windows {
		duration := int64(7 * 24 * 60 * 60)
		switch w.ID {
		case GatewayClaudeFiveHour:
			duration = 5 * 60 * 60
		case GatewayClaudeSevenDay, GatewayClaudeSonnetSevenDay, GatewayClaudeFableSevenDay:
		default:
			return nil
		}
		if seen[w.ID] {
			return nil
		}
		seen[w.ID] = true
		n := GatewayAccountLimitWindow{ID: w.ID, Family: "claude", DurationSeconds: &duration, Basis: "duration"}
		if fraction := limitsNumber(w.Utilization); fraction != nil {
			percent := *fraction * 100
			if !math.IsInf(percent, 0) {
				n.UsedPercent = &percent
			}
		}
		if observed, err := time.Parse(time.RFC3339Nano, w.ObservedAt); err == nil {
			n.ObservedAt = limitsISO(limitsInstant(observed.UTC().Format(time.RFC3339Nano)))
		}
		// Header reset is Unix seconds. Millisecond-looking values fail the
		// canonical upper bound instead of silently changing units.
		if seconds := limitsInteger(w.Reset); seconds != nil && *seconds <= 253402300799 {
			reset := time.Unix(*seconds, 0).UTC()
			n.ResetAt = limitsISO(&reset)
		}
		out = append(out, n)
	}
	return out
}
