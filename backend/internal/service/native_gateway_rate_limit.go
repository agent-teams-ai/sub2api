package service

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
)

// Only fixed classifications and bounded numeric headers leave the provider boundary.
// Vendor messages, raw metadata and response bodies can contain credentials or prompts.
type gatewayNativeRateLimitDiagnostic struct {
	Source  string            `json:"limit_source,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

var gatewayNativeRateLimitNumber = regexp.MustCompile(`^[0-9]{1,16}(\.[0-9]{1,3})?$`)

func gatewayNativeRateLimitEvidence(body io.Reader, headers http.Header) gatewayNativeRateLimitDiagnostic {
	result := gatewayNativeRateLimitDiagnostic{}
	for _, name := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Limit-Requests", "X-RateLimit-Remaining-Requests", "X-RateLimit-Reset-Requests"} {
		values := headers.Values(name)
		if len(values) == 1 && gatewayNativeRateLimitNumber.MatchString(values[0]) {
			if result.Headers == nil {
				result.Headers = make(map[string]string)
			}
			result.Headers[name] = values[0]
		}
	}
	if body == nil || headers.Get("Content-Encoding") != "" {
		return result
	}
	raw, err := io.ReadAll(io.LimitReader(body, 16385))
	if err != nil || len(raw) > 16384 {
		return result
	}
	var envelope struct {
		Error struct {
			Metadata struct {
				LimitSource string `json:"limit_source"`
			} `json:"metadata"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return result
	}
	switch envelope.Error.Metadata.LimitSource {
	case "openrouter_free_models_per_day", "openrouter_free_models_per_minute", "free-models-per-day", "free-models-per-min", "upstream_provider_shared_pool", "upstream_provider", "openrouter_rate_limit", "openrouter_ddos_protection":
		result.Source = envelope.Error.Metadata.LimitSource
	}
	return result
}
