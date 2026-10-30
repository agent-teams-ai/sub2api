package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/tidwall/gjson"
)

const gatewayProviderQuotaMaxBytes = 256 * 1024

// Errors deliberately contain no upstream body, URL, credential, or transport
// diagnostic. A provider's error body may echo authentication material.
var ErrGatewayProviderQuota = errors.New("provider quota observation unavailable")

// GatewayProviderQuotaCollector is the read-only HTTP leaf. Its caller owns the
// protected custody lease, generation fence, cadence and atomic replacement of
// the complete snapshot. It never enumerates ordinary accounts or writes Extra.
type GatewayProviderQuotaCollector struct{ client *http.Client }

func NewGatewayProviderQuotaCollector(transport http.RoundTripper) *GatewayProviderQuotaCollector {
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 2, DisableKeepAlives: true}
	}
	return &GatewayProviderQuotaCollector{client: &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Fetch accepts only the credential furnished by the current scoped custody
// lease. All endpoints are source-owned; no account headers/base URL can alter
// the request. In particular there is no OAuth refresh or inference fallback.
func (c *GatewayProviderQuotaCollector) Fetch(ctx context.Context, provider string, credential []byte) (GatewayAccountLimitsSnapshotV2, error) {
	snapshot, _, err := c.FetchObserved(ctx, provider, credential)
	return snapshot, err
}

// FetchObserved also returns the observation identity required by the canonical
// CAS writer, including successful observations containing no quota windows.
func (c *GatewayProviderQuotaCollector) FetchObserved(ctx context.Context, provider string, credential []byte) (GatewayAccountLimitsSnapshotV2, time.Time, error) {
	empty := GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []GatewayAccountLimitWindowV2{}}
	if c == nil || c.client == nil || len(credential) == 0 || len(credential) > 16384 || strings.TrimSpace(string(credential)) != string(credential) || strings.ContainsAny(string(credential), "\r\n") {
		return empty, time.Time{}, ErrGatewayProviderQuota
	}
	urls := []string{}
	switch provider {
	case "kimi":
		urls = append(urls, "https://api.kimi.ai/coding/v1/usages")
	case "glm":
		urls = append(urls, "https://api.z.ai/api/monitor/usage/quota/limit")
	case "minimax":
		urls = append(urls, "https://www.minimax.io/v1/token_plan/remains")
	case "grok":
		urls = append(urls, xai.BuildBillingURL(true), xai.BuildBillingURL(false))
	default:
		return empty, time.Time{}, ErrGatewayProviderQuota
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// One observation identifies this bounded fetch batch, including Grok's two
	// independent billing domains. Cached projections preserve this instant.
	observed := time.Now().UTC()
	observedAny := false
	for _, target := range urls {
		body, err := c.get(bounded, target, provider, credential)
		if err != nil {
			continue
		}
		snapshot, err := NormalizeGatewayProviderQuota(provider, body, observed)
		if err != nil {
			continue
		}
		observedAny = true
		for _, w := range snapshot.Windows {
			// Billing has independently qualified weekly and monthly reads. Each
			// endpoint contributes only its own domain; never carry old windows.
			if provider == "grok" && (strings.Contains(target, "?format=credits") && w.ID != "weekly" || !strings.Contains(target, "?format=credits") && w.ID != "monthly") {
				continue
			}
			empty.Windows = append(empty.Windows, w)
		}
	}
	if !observedAny || ctx.Err() != nil {
		return GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []GatewayAccountLimitWindowV2{}}, time.Time{}, ErrGatewayProviderQuota
	}
	return empty, observed, nil
}

func (c *GatewayProviderQuotaCollector) get(ctx context.Context, target, provider string, credential []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, ErrGatewayProviderQuota
	}
	if provider == "grok" {
		req.Header.Set("Authorization", "Bearer "+string(credential))
		req.Header.Set("Accept", "application/json")
		req.Header.Set(xai.CLITokenAuthHeader, xai.CLITokenAuthValue)
		req.Header.Set("x-grok-client-identifier", xai.ProtectedClientIdentifier)
	} else {
		auth := string(credential)
		if provider != "glm" {
			auth = "Bearer " + auth
		}
		req.Header.Set("Authorization", auth)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", xai.ProtectedUserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ErrGatewayProviderQuota
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrGatewayProviderQuota
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gatewayProviderQuotaMaxBytes+1))
	if err != nil || len(body) > gatewayProviderQuotaMaxBytes || ctx.Err() != nil {
		return nil, ErrGatewayProviderQuota
	}
	return body, nil
}

// NormalizeGatewayProviderQuota preserves absent/malformed numbers as null and
// validates each window independently. An empty recognized provider envelope can
// clear a previous snapshot; an empty HTTP 200 or arbitrary JSON cannot.
func NormalizeGatewayProviderQuota(provider string, body []byte, observed time.Time) (GatewayAccountLimitsSnapshotV2, error) {
	out := GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []GatewayAccountLimitWindowV2{}}
	if len(body) > gatewayProviderQuotaMaxBytes || !gjson.ValidBytes(body) || !gjson.ParseBytes(body).IsObject() || observed.IsZero() || observed.Year() < 1 || observed.Year() > 9999 {
		return out, ErrGatewayProviderQuota
	}
	root := gjson.ParseBytes(body)
	var recognized bool
	switch provider {
	case "kimi":
		out.Windows, recognized = gatewayKimiQuota(root, observed)
	case "glm":
		if success := root.Get("success"); success.Exists() && (success.Type != gjson.True) {
			return out, ErrGatewayProviderQuota
		}
		out.Windows, recognized = gatewayGLMQuota(root, observed)
	case "minimax":
		if code := root.Get("base_resp.status_code"); code.Exists() && (quotaNumber(code) == nil || *quotaNumber(code) != 0) {
			return out, ErrGatewayProviderQuota
		}
		out.Windows, recognized = gatewayMiniMaxQuota(root, observed)
	case "grok":
		out.Windows, recognized = gatewayGrokBillingQuota(root, observed)
	}
	if !recognized {
		return out, ErrGatewayProviderQuota
	}
	if out.Windows == nil {
		out.Windows = []GatewayAccountLimitWindowV2{}
	}
	return out, nil
}

func quotaWindow(provider, id, unit string, observed time.Time) GatewayAccountLimitWindowV2 {
	w := GatewayAccountLimitWindowV2{ID: id, Provider: provider, Dimension: "plan_quota", Unit: unit, Period: GatewayAccountLimitPeriodV2{Kind: "unknown"}, ObservedAt: limitsISO(&observed)}
	var label string
	var seconds int64
	switch id {
	case "five_hour":
		label, seconds = "5h", 5*60*60
	case "weekly":
		label, seconds = "Week", 7*24*60*60
	case "monthly":
		label, w.Period.Kind = "Month", "monthly_billing_cycle"
	}
	if label != "" {
		w.Label = &label
	}
	if seconds != 0 {
		w.Period = GatewayAccountLimitPeriodV2{Kind: "duration", DurationSeconds: &seconds}
	}
	return w
}

func quotaNumber(v gjson.Result) *float64 {
	if v.Type != gjson.Number && v.Type != gjson.String {
		return nil
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(v.String()), 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return nil
	}
	return &n
}

func quotaUsed(limit, used, remaining gjson.Result) *float64 {
	l := quotaNumber(limit)
	if l == nil || *l == 0 {
		return nil
	}
	u := quotaNumber(used)
	if u == nil {
		if r := quotaNumber(remaining); r != nil && *r <= *l {
			n := *l - *r
			u = &n
		}
	}
	if u == nil {
		return nil
	}
	n := *u / *l * 100
	if math.IsInf(n, 0) || math.IsNaN(n) {
		return nil
	}
	return &n
}

func quotaReset(v gjson.Result) *string {
	if !v.Exists() || v.Type != gjson.Number && v.Type != gjson.String {
		return nil
	}
	if v.Type == gjson.String {
		if parsed, err := time.Parse(time.RFC3339Nano, v.String()); err == nil && parsed.Year() >= 1 && parsed.Year() <= 9999 {
			return limitsISO(&parsed)
		}
	}
	n := quotaNumber(v)
	if n == nil || math.Trunc(*n) != *n || *n <= 0 || *n > 253402300799999 {
		return nil
	}
	value := int64(*n)
	var reset time.Time
	if value >= 1_000_000_000_000 {
		reset = time.UnixMilli(value).UTC()
	} else {
		reset = time.Unix(value, 0).UTC()
	}
	if reset.Year() < 1 || reset.Year() > 9999 {
		return nil
	}
	return limitsISO(&reset)
}
