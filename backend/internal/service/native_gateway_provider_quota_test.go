package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayProviderQuotaKimiExplicitWindows(t *testing.T) {
	observed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	// Current response shape: monthly total is a billing cycle, not 30 days;
	// absent legacy weekly must not reappear from an unmarked top-level usage.
	snapshot, err := NormalizeGatewayProviderQuota("kimi", []byte(`{
	  "usages":{"limit_5h":{"used_ratio":0,"reset_time":"2026-10-23T18:00:00+02:00"},
	    "limit_month_total":{"used_ratio":0.42,"reset_time":"2026-11-01T00:00:00Z"},
	    "limit_month_code":{"used_ratio":0.18}},
	  "limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},
	    "detail":{"limit":"100","remaining":"100"}}]
	}`), observed)
	require.NoError(t, err)
	require.Len(t, snapshot.Windows, 2)
	require.Equal(t, "five_hour", snapshot.Windows[0].ID)
	require.Equal(t, 0.0, *snapshot.Windows[0].UsedPercent)
	require.Equal(t, "2026-10-23T16:00:00Z", *snapshot.Windows[0].ResetAt)
	require.Equal(t, "monthly", snapshot.Windows[1].ID)
	require.Equal(t, "monthly_billing_cycle", snapshot.Windows[1].Period.Kind)
	require.Nil(t, snapshot.Windows[1].Period.DurationSeconds)
	require.Equal(t, "unknown", snapshot.Windows[1].Unit)
	require.InDelta(t, 42, *snapshot.Windows[1].UsedPercent, 0.00001)
	require.True(t, ValidateGatewayAccountLimitWindowsV2(snapshot.Windows))

	legacy, err := NormalizeGatewayProviderQuota("kimi", []byte(`{
	 "limits":[{"detail":{"limit":100,"remaining":20}},
	 {"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":100,"remaining":75}},
	 {"window":{"duration":7,"timeUnit":"TIME_UNIT_DAY"},"detail":{"limit":200,"remaining":100}}],
	 "usage":{"limit":1000,"remaining":800}
	}`), observed)
	require.NoError(t, err)
	require.Len(t, legacy.Windows, 3)
	require.Equal(t, "unknown", legacy.Windows[0].ID)
	require.Equal(t, "unknown", legacy.Windows[0].Period.Kind)
	require.Nil(t, legacy.Windows[0].Label)
	require.Equal(t, "five_hour", legacy.Windows[1].ID)
	require.Equal(t, 25.0, *legacy.Windows[1].UsedPercent)
	require.Equal(t, "weekly", legacy.Windows[2].ID)
	require.Equal(t, 50.0, *legacy.Windows[2].UsedPercent)

	// A malformed bucket and an absent coding entitlement do not invent 0%.
	partial, err := NormalizeGatewayProviderQuota("kimi", []byte(`{"usages":{"limit_5h":{"used_ratio":"NaN"},"limit_month_total":{"used_ratio":0.5}}}`), observed)
	require.NoError(t, err)
	require.Nil(t, partial.Windows[0].UsedPercent)
	require.Equal(t, 50.0, *partial.Windows[1].UsedPercent)
	goPlan, err := NormalizeGatewayProviderQuota("kimi", []byte(`{"user":{"membership":{"level":"LEVEL_GO"}},"usages":{}}`), observed)
	require.NoError(t, err)
	require.Empty(t, goPlan.Windows)
	conflict, err := NormalizeGatewayProviderQuota("kimi", []byte(`{"usages":{"limit_5h":{"used_ratio":0}},"limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":100,"remaining":0}}]}`), observed)
	require.NoError(t, err)
	require.Len(t, conflict.Windows, 1)
	require.Nil(t, conflict.Windows[0].UsedPercent)
	matchingReset, err := NormalizeGatewayProviderQuota("kimi", []byte(`{"usages":{"limit_7d":{"used_ratio":0.25,"reset_time":"2026-10-25T00:00:00Z"}},"usage":{"limit":100,"used":25,"resetTime":"2026-10-25T00:00:00Z"}}`), observed)
	require.NoError(t, err)
	require.Len(t, matchingReset.Windows, 2)
	require.Equal(t, "unknown", matchingReset.Windows[1].ID)
}

func TestGatewayProviderQuotaGLMUnitsAndUnknown(t *testing.T) {
	snapshot, err := NormalizeGatewayProviderQuota("glm", []byte(`{"success":true,"data":{"limits":[
	 {"type":"CREDIT_LIMIT","unit":6,"percentage":60,"nextResetTime":1792756800000},
	 {"type":"TOKENS_LIMIT","unit":3,"percentage":0,"nextResetTime":1792774800000},
	 {"type":"CREDIT_LIMIT","unit":3},
	 {"type":"TOKENS_LIMIT","unit":99,"percentage":"NaN","nextResetTime":1792756800000},
	 {"type":"REQUEST_LIMIT","unit":3,"percentage":99}
	]}}`), time.Now().UTC())
	require.NoError(t, err)
	require.Len(t, snapshot.Windows, 4)
	require.Equal(t, "weekly", snapshot.Windows[0].ID) // reset order cannot rename windows
	require.Equal(t, "credits", snapshot.Windows[0].Unit)
	require.Equal(t, "five_hour", snapshot.Windows[1].ID)
	require.Equal(t, "tokens", snapshot.Windows[1].Unit)
	require.Equal(t, 0.0, *snapshot.Windows[1].UsedPercent)
	require.Nil(t, snapshot.Windows[2].UsedPercent)
	require.Equal(t, "unknown", snapshot.Windows[3].ID)
	require.Nil(t, snapshot.Windows[3].Label)
	require.Nil(t, snapshot.Windows[3].Period.DurationSeconds)
	require.True(t, ValidateGatewayAccountLimitWindowsV2(snapshot.Windows))
}

func TestGatewayProviderQuotaMiniMaxWeeklyReplacementAndBusinessError(t *testing.T) {
	observed := time.Now().UTC()
	withWeek, err := NormalizeGatewayProviderQuota("minimax", []byte(`{"base_resp":{"status_code":0},"model_remains":[
	 {"model_name":"video","current_interval_remaining_percent":0},
	 {"model_name":"general","current_interval_remaining_percent":80,"end_time":1792774800000,
	 "current_weekly_status":1,"current_weekly_remaining_percent":0,"weekly_end_time":1793000000000}]}`), observed)
	require.NoError(t, err)
	require.Len(t, withWeek.Windows, 2)
	require.Equal(t, 20.0, *withWeek.Windows[0].UsedPercent)
	require.Equal(t, 100.0, *withWeek.Windows[1].UsedPercent)
	withoutWeek, err := NormalizeGatewayProviderQuota("minimax", []byte(`{"base_resp":{"status_code":0},"model_remains":[{"model_name":"general","current_interval_remaining_percent":100,"current_weekly_status":0,"current_weekly_remaining_percent":80}]}`), observed)
	require.NoError(t, err)
	require.Len(t, withoutWeek.Windows, 1)
	require.Equal(t, 0.0, *withoutWeek.Windows[0].UsedPercent)
	_, err = NormalizeGatewayProviderQuota("minimax", []byte(`{"base_resp":{"status_code":1004,"status_msg":"secret echo"},"model_remains":[]}`), observed)
	require.ErrorIs(t, err, ErrGatewayProviderQuota)
	require.NotContains(t, err.Error(), "secret")
}

func TestGatewayProviderQuotaGrokBillingAndPassiveHeaders(t *testing.T) {
	observed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	snapshot, err := NormalizeGatewayProviderQuota("grok", []byte(`{"config":{
	 "currentPeriod":{"type":"weekly","end":"2026-10-25T00:00:00Z"},"creditUsagePercent":35,
	 "monthlyLimit":{"val":15000},"used":{"val":7500},"billingPeriodEnd":"2026-11-01T00:00:00Z"}}`), observed)
	require.NoError(t, err)
	require.Len(t, snapshot.Windows, 2)
	require.Equal(t, "credits", snapshot.Windows[0].Unit)
	require.Equal(t, 35.0, *snapshot.Windows[0].UsedPercent)
	require.Equal(t, "monthly_billing_cycle", snapshot.Windows[1].Period.Kind)
	require.Equal(t, "unknown", snapshot.Windows[1].Unit)
	require.Equal(t, 50.0, *snapshot.Windows[1].UsedPercent)
	require.Empty(t, CaptureGatewayGrokRateLimits(nil, observed).Windows)
	headers := http.Header{}
	headers.Set("x-ratelimit-limit-requests", "100")
	headers.Set("x-ratelimit-remaining-requests", "75")
	headers.Set("x-ratelimit-reset-requests", "60")
	headers.Set("x-ratelimit-limit-tokens", "500000")
	headers.Set("x-ratelimit-remaining-tokens", "broken")
	rate := CaptureGatewayGrokRateLimits(headers, observed)
	require.Len(t, rate.Windows, 2)
	require.Equal(t, "rate_limit", rate.Windows[0].Dimension)
	require.Equal(t, "request_rate", rate.Windows[0].ID)
	require.Equal(t, "unknown", rate.Windows[0].Period.Kind)
	require.Nil(t, rate.Windows[0].Label)
	require.Equal(t, 25.0, *rate.Windows[0].UsedPercent)
	require.Equal(t, "2026-10-23T12:01:00Z", *rate.Windows[0].ResetAt)
	require.Equal(t, "2026-10-23T12:00:00Z", *rate.Windows[0].ObservedAt)
	require.Nil(t, rate.Windows[1].UsedPercent) // no nominal Free allowance fallback
	require.True(t, ValidateGatewayAccountLimitWindowsV2(rate.Windows))
}

type gatewayQuotaFixtureTransport struct {
	server *url.URL
	check  func(*http.Request)
}

func (f gatewayQuotaFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.check(req)
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme, u.Host = f.server.Scheme, f.server.Host
	clone.URL = &u
	return http.DefaultTransport.RoundTrip(clone)
}

func TestGatewayProviderQuotaCollectorHTTPFixtures(t *testing.T) {
	for _, tc := range []struct{ provider, target, auth, fixture string }{
		{"kimi", "https://api.kimi.ai/coding/v1/usages", "Bearer scoped-secret", `{"usages":{"limit_5h":{"used_ratio":0.25}}}`},
		{"glm", "https://api.z.ai/api/monitor/usage/quota/limit", "scoped-secret", `{"success":true,"data":{"limits":[{"type":"CREDIT_LIMIT","unit":3,"percentage":25}]}}`},
		{"minimax", "https://www.minimax.io/v1/token_plan/remains", "Bearer scoped-secret", `{"base_resp":{"status_code":0},"model_remains":[{"model_name":"general","current_interval_remaining_percent":75}]}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, tc.auth, r.Header.Get("Authorization"))
				body, _ := io.ReadAll(r.Body)
				require.Empty(t, body)
				_, _ = io.WriteString(w, tc.fixture)
			}))
			defer server.Close()
			local, err := url.Parse(server.URL)
			require.NoError(t, err)
			collector := NewGatewayProviderQuotaCollector(gatewayQuotaFixtureTransport{local, func(r *http.Request) { require.Equal(t, tc.target, r.URL.String()) }})
			snapshot, err := collector.Fetch(context.Background(), tc.provider, []byte("scoped-secret"))
			require.NoError(t, err)
			require.EqualValues(t, 1, count.Load())
			require.Len(t, snapshot.Windows, 1)
			require.Equal(t, 25.0, *snapshot.Windows[0].UsedPercent)
		})
	}
}

func TestGatewayProviderQuotaCollectorBoundsAndNoFallback(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"redirect", `secret echo`, http.StatusFound},
		{"auth", `secret echo`, http.StatusUnauthorized},
		{"oversize", strings.Repeat(" ", gatewayProviderQuotaMaxBytes+1), http.StatusOK},
		{"empty", ``, http.StatusOK},
		{"arbitrary-json", `{}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Location", "/inference-must-not-run")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			local, _ := url.Parse(server.URL)
			collector := NewGatewayProviderQuotaCollector(gatewayQuotaFixtureTransport{local, func(*http.Request) {}})
			_, err := collector.Fetch(context.Background(), "minimax", []byte("scoped-secret"))
			require.ErrorIs(t, err, ErrGatewayProviderQuota)
			require.NotContains(t, err.Error(), "secret")
			require.EqualValues(t, 1, count.Load())
		})
	}
	// The weekly billing domain survives a failed monthly GET; no model POST,
	// refresh or previous monthly window is used to fill the missing result.
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer scoped-secret", r.Header.Get("Authorization"))
		if r.URL.RawQuery != "" {
			_, _ = io.WriteString(w, `{"config":{"currentPeriod":{"type":"weekly"},"creditUsagePercent":10}}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	local, _ := url.Parse(server.URL)
	collector := NewGatewayProviderQuotaCollector(gatewayQuotaFixtureTransport{local, func(r *http.Request) { paths = append(paths, r.URL.String()) }})
	snapshot, err := collector.Fetch(context.Background(), "grok", []byte("scoped-secret"))
	require.NoError(t, err)
	require.Equal(t, []string{"https://cli-chat-proxy.grok.com/v1/billing?format=credits", "https://cli-chat-proxy.grok.com/v1/billing"}, paths)
	require.Len(t, snapshot.Windows, 1)
	require.Equal(t, "weekly", snapshot.Windows[0].ID)
}

func TestGatewayProviderQuotaEmptyObservationHasIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"usages":{}}`)
	}))
	defer server.Close()
	local, _ := url.Parse(server.URL)
	collector := NewGatewayProviderQuotaCollector(gatewayQuotaFixtureTransport{local, func(*http.Request) {}})
	snapshot, observed, err := collector.FetchObserved(context.Background(), "kimi", []byte("scoped-secret"))
	require.NoError(t, err)
	require.Empty(t, snapshot.Windows)
	require.False(t, observed.IsZero())
	require.Equal(t, time.UTC, observed.Location())
}
