package service

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

func gatewayKimiQuota(root gjson.Result, observed time.Time) ([]GatewayAccountLimitWindowV2, bool) {
	var windows []GatewayAccountLimitWindowV2
	usages, limits, usage := root.Get("usages"), root.Get("limits"), root.Get("usage")
	recognized := usages.IsObject() || limits.IsArray() || usage.IsObject()
	// These are the explicit, observed quota identities. The coding share of
	// monthly total is intentionally not merged into the total quota.
	for _, item := range []struct{ key, id string }{
		{"limit_5h", "five_hour"}, {"limit_7d", "weekly"}, {"limit_month_total", "monthly"},
	} {
		node := usages.Get(item.key)
		if !node.IsObject() {
			continue
		}
		w := quotaWindow("kimi", item.id, "unknown", observed)
		if ratio := quotaNumber(node.Get("used_ratio")); ratio != nil && !math.IsInf(*ratio*100, 0) {
			percent := *ratio * 100
			w.UsedPercent = &percent
		}
		w.ResetAt = quotaReset(node.Get("reset_time"))
		windows = quotaAppendWindow(windows, w)
	}
	if limits.IsArray() {
		limits.ForEach(func(_, node gjson.Result) bool {
			detail := node.Get("detail")
			if !detail.IsObject() {
				return true
			}
			w := quotaWindow("kimi", kimiQuotaWindowID(node.Get("window")), "unknown", observed)
			w.UsedPercent = quotaUsed(detail.Get("limit"), detail.Get("used"), detail.Get("remaining"))
			w.ResetAt = quotaReset(detail.Get("resetTime"))
			windows = quotaAppendWindow(windows, w)
			return true
		})
	}
	if usage.IsObject() {
		// Legacy top-level usage has no invariant period. Only an explicit
		// window supplies its identity; matching reset times are not authority.
		id := kimiQuotaWindowID(usage.Get("window"))
		reset := quotaReset(usage.Get("resetTime"))
		w := quotaWindow("kimi", id, "unknown", observed)
		w.UsedPercent, w.ResetAt = quotaUsed(usage.Get("limit"), usage.Get("used"), usage.Get("remaining")), reset
		windows = quotaAppendWindow(windows, w)
	}
	return windows, recognized
}

func kimiQuotaWindowID(window gjson.Result) string {
	duration := quotaNumber(window.Get("duration"))
	if duration == nil {
		return "unknown"
	}
	seconds := *duration
	switch window.Get("timeUnit").String() {
	case "TIME_UNIT_SECOND":
	case "TIME_UNIT_MINUTE":
		seconds *= 60
	case "TIME_UNIT_HOUR":
		seconds *= 3600
	case "TIME_UNIT_DAY":
		seconds *= 86400
	case "TIME_UNIT_MONTH":
		if *duration == 1 {
			return "monthly"
		}
		return "unknown"
	default:
		return "unknown"
	}
	switch seconds {
	case 5 * 3600:
		return "five_hour"
	case 7 * 86400:
		return "weekly"
	default:
		return "unknown"
	}
}

func gatewayGLMQuota(root gjson.Result, observed time.Time) ([]GatewayAccountLimitWindowV2, bool) {
	limits := root.Get("data.limits")
	var windows []GatewayAccountLimitWindowV2
	limits.ForEach(func(_, item gjson.Result) bool {
		unit := ""
		switch item.Get("type").String() {
		case "CREDIT_LIMIT":
			unit = "credits"
		case "TOKENS_LIMIT":
			unit = "tokens"
		default:
			return true
		}
		id := "unknown"
		if n := quotaNumber(item.Get("unit")); n != nil {
			switch *n {
			case 3:
				id = "five_hour"
			case 6:
				id = "weekly"
			}
		}
		w := quotaWindow("glm", id, unit, observed)
		w.UsedPercent = quotaNumber(item.Get("percentage"))
		w.ResetAt = quotaReset(item.Get("nextResetTime"))
		windows = quotaAppendWindow(windows, w)
		return true
	})
	return windows, limits.IsArray()
}

func gatewayMiniMaxQuota(root gjson.Result, observed time.Time) ([]GatewayAccountLimitWindowV2, bool) {
	remains := root.Get("model_remains")
	var windows []GatewayAccountLimitWindowV2
	remains.ForEach(func(_, item gjson.Result) bool {
		if item.Get("model_name").String() != "general" {
			return true
		}
		for _, bucket := range []struct{ id, percent, reset string }{
			{"five_hour", "current_interval_remaining_percent", "end_time"},
			{"weekly", "current_weekly_remaining_percent", "weekly_end_time"},
		} {
			if bucket.id == "weekly" && item.Get("current_weekly_status").Int() != 1 {
				continue
			}
			remaining := item.Get(bucket.percent)
			if !remaining.Exists() {
				continue
			}
			w := quotaWindow("minimax", bucket.id, "unknown", observed)
			if n := quotaNumber(remaining); n != nil && *n <= 100 {
				used := 100 - *n
				w.UsedPercent = &used
			}
			w.ResetAt = quotaReset(item.Get(bucket.reset))
			windows = quotaAppendWindow(windows, w)
		}
		return true
	})
	return windows, remains.IsArray()
}

func gatewayGrokBillingQuota(root gjson.Result, observed time.Time) ([]GatewayAccountLimitWindowV2, bool) {
	config := root.Get("config")
	if !config.IsObject() {
		return nil, false
	}
	var windows []GatewayAccountLimitWindowV2
	if strings.EqualFold(strings.TrimSpace(config.Get("currentPeriod.type").String()), "weekly") {
		w := quotaWindow("grok", "weekly", "credits", observed)
		w.UsedPercent = quotaNumber(config.Get("creditUsagePercent"))
		w.ResetAt = quotaReset(config.Get("currentPeriod.end"))
		windows = quotaAppendWindow(windows, w)
	}
	if config.Get("monthlyLimit").Exists() || config.Get("used").Exists() || config.Get("billingPeriodEnd").Exists() {
		w := quotaWindow("grok", "monthly", "unknown", observed)
		// Monthly fields are monetary cents, which are not tokens or credits.
		// Keep the ratio but do not claim a unit absent from the wire contract.
		amount := func(node gjson.Result) gjson.Result {
			if node.IsObject() {
				return node.Get("val")
			}
			return node
		}
		w.UsedPercent = quotaUsed(amount(config.Get("monthlyLimit")), amount(config.Get("used")), gjson.Result{})
		w.ResetAt = quotaReset(config.Get("billingPeriodEnd"))
		windows = quotaAppendWindow(windows, w)
	}
	return windows, true
}

// Duplicate observations are collapsed by semantic identity, never by reset
// order. Conflicting numbers become unknown rather than selecting a convenient
// source. Valid neighboring buckets survive malformed or conflicting values.
func quotaAppendWindow(windows []GatewayAccountLimitWindowV2, incoming GatewayAccountLimitWindowV2) []GatewayAccountLimitWindowV2 {
	for i := range windows {
		w := &windows[i]
		if w.ID != incoming.ID || w.Provider != incoming.Provider || w.Unit != incoming.Unit || w.Dimension != incoming.Dimension {
			continue
		}
		if w.UsedPercent != nil && incoming.UsedPercent != nil && math.Abs(*w.UsedPercent-*incoming.UsedPercent) > 0.000001 {
			w.UsedPercent = nil
		}
		if w.ResetAt != nil && incoming.ResetAt != nil && *w.ResetAt != *incoming.ResetAt {
			w.ResetAt = nil
		}
		return windows
	}
	if len(windows) < 8 {
		windows = append(windows, incoming)
	}
	return windows
}

// CaptureGatewayGrokRateLimits captures only actual passive response headers.
// It requires the response observation instant rather than inventing a new one
// during cached reads. Rate reset instants do not establish a plan period.
func CaptureGatewayGrokRateLimits(headers http.Header, observed time.Time) GatewayAccountLimitsSnapshotV2 {
	out := GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []GatewayAccountLimitWindowV2{}}
	if observed.IsZero() || observed.Year() < 1 || observed.Year() > 9999 {
		return out
	}
	for _, dimension := range []struct{ suffix, id, unit string }{{"requests", "request_rate", "requests"}, {"tokens", "token_rate", "tokens"}} {
		read := func(field string) (string, bool) {
			var values []string
			for _, prefix := range []string{"x-ratelimit-", "x-rate-limit-"} {
				values = append(values, headers.Values(prefix+field+"-"+dimension.suffix)...)
			}
			if len(values) != 1 || len(values[0]) > 128 {
				return "", len(values) != 0
			}
			return values[0], true
		}
		limit, hasLimit := read("limit")
		remaining, hasRemaining := read("remaining")
		reset, hasReset := read("reset")
		if !hasLimit && !hasRemaining && !hasReset {
			continue
		}
		w := quotaWindow("grok", dimension.id, dimension.unit, observed)
		w.Dimension = "rate_limit"
		// Headers are integer counters; fractional/nonfinite values cannot
		// manufacture a known percentage.
		l, le := strconv.ParseInt(limit, 10, 64)
		r, re := strconv.ParseInt(remaining, 10, 64)
		if le == nil && re == nil && l > 0 && r >= 0 && r <= l {
			n := float64(l-r) / float64(l) * 100
			w.UsedPercent = &n
		}
		w.ResetAt = grokQuotaHeaderReset(reset, observed)
		out.Windows = append(out.Windows, w)
	}
	return out
}

func grokQuotaHeaderReset(raw string, observed time.Time) *string {
	if raw == "" {
		return nil
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n >= 0 {
		if n >= 1_000_000_000 {
			return quotaReset(gjson.Parse(strconv.Quote(raw)))
		}
		if n <= 253402300799-observed.Unix() {
			reset := observed.Add(time.Duration(n) * time.Second)
			return limitsISO(&reset)
		}
		return nil
	}
	if reset := quotaReset(gjson.Parse(strconv.Quote(raw))); reset != nil {
		return reset
	}
	if duration, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && duration >= 0 {
		reset := observed.Add(duration)
		if reset.Year() >= 1 && reset.Year() <= 9999 {
			return limitsISO(&reset)
		}
	}
	return nil
}
