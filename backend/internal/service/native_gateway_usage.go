package service

import (
	"context"
	"encoding/json"
	"regexp"
)

// GatewayNativeUsage is a closed scalar projection of provider usage at the
// native request seam. It is evidence, not a billing ledger or cost estimate.
type GatewayNativeUsage struct {
	Source                string `json:"source"`
	State                 string `json:"state"`
	InputTokens           *int64 `json:"inputTokens,omitempty"`
	OutputTokens          *int64 `json:"outputTokens,omitempty"`
	CachedInputTokens     *int64 `json:"cachedInputTokens,omitempty"`
	ReasoningOutputTokens *int64 `json:"reasoningOutputTokens,omitempty"`
	CostState             string `json:"costState"`
	Finalized             bool   `json:"finalized"`
}

type gatewayNativeUsageObserverKey struct{}

// WithGatewayNativeUsageObserver is wired by the trusted private transport only.
// Observations never carry payload, provider identifiers, headers or credentials.
func WithGatewayNativeUsageObserver(ctx context.Context, observe func(GatewayNativeUsage)) context.Context {
	return context.WithValue(ctx, gatewayNativeUsageObserverKey{}, observe)
}

var gatewayNativeUsageInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func gatewayNativeUsageCount(raw json.RawMessage) *int64 {
	var count int64
	if !gatewayNativeUsageInteger.Match(raw) || json.Unmarshal(raw, &count) != nil || count > 9007199254740991 {
		return nil
	}
	return &count
}

// Reject ambiguous protocol keys rather than deriving numbers from tool/user data.
func gatewayNativeObserveUsage(output []byte, observation *GatewayNativeUsage, complete bool) {
	fields, ok := gatewayNativeCanonicalObject(output, "usage")
	if !ok || fields["usage"] == nil {
		return
	}
	usage, ok := gatewayNativeCanonicalObject(fields["usage"], "input_tokens", "output_tokens", "input_tokens_details", "output_tokens_details")
	if !ok {
		return
	}
	input, out := gatewayNativeUsageCount(usage["input_tokens"]), gatewayNativeUsageCount(usage["output_tokens"])
	if input == nil && out == nil {
		return
	}
	observation.InputTokens, observation.OutputTokens = input, out
	observation.CachedInputTokens, observation.ReasoningOutputTokens = nil, nil
	if details, valid := gatewayNativeCanonicalObject(usage["input_tokens_details"], "cached_tokens"); valid {
		n := gatewayNativeUsageCount(details["cached_tokens"])
		if n != nil && input != nil && *n <= *input {
			observation.CachedInputTokens = n
		}
	}
	if details, valid := gatewayNativeCanonicalObject(usage["output_tokens_details"], "reasoning_tokens"); valid {
		n := gatewayNativeUsageCount(details["reasoning_tokens"])
		if n != nil && out != nil && *n <= *out {
			observation.ReasoningOutputTokens = n
		}
	}
	observation.State = "partial"
	if complete && input != nil && out != nil {
		observation.State = "complete"
	}
}
