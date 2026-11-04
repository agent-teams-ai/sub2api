//go:build unit

package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type quotaRefreshTransport func(*http.Request) (*http.Response, error)

func (f quotaRefreshTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayCodexQuotaProjection(t *testing.T) {
	observed := time.Now().UTC()
	for _, tc := range []struct {
		name, body  string
		valid, used bool
	}{
		{"ordinary wham with credits", `{"account_id":"qualified-account","plan_type":"plus","credits":{"has_credits":true,"balance":"25"},"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":0,"limit_window_seconds":18000},"secondary_window":null},"additional_rate_limits":[{"limit_name":"spark","rate_limit":{"primary_window":{"used_percent":100,"limit_window_seconds":60}}}]}`, true, true},
		{"zero", `{"rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_after_seconds":0}}}`, true, true},
		{"missing percent", `{"rate_limit":{"primary_window":{"limit_window_seconds":18000}}}`, true, false},
		{"null percent", `{"rate_limit":{"primary_window":{"used_percent":null,"limit_window_seconds":18000}}}`, true, false},
		{"credits only", `{"credits":{"has_credits":true}}`, false, false},
		{"null windows", `{"rate_limit":{"primary_window":null,"secondary_window":null}}`, false, false},
		{"spark only", `{"additional_rate_limits":[{"rate_limit":{"primary_window":{"used_percent":0}}}]}`, false, false},
		{"quoted percent", `{"rate_limit":{"primary_window":{"used_percent":"0"}}}`, false, false},
		{"negative", `{"rate_limit":{"primary_window":{"used_percent":-1}}}`, false, false},
		{"overflow", `{"rate_limit":{"primary_window":{"used_percent":1e999}}}`, false, false},
		{"over 100", `{"rate_limit":{"primary_window":{"used_percent":101}}}`, false, false},
		{"duplicate percent", `{"rate_limit":{"primary_window":{"used_percent":0,"used_percent":100}}}`, false, false},
		{"wrong account", `{"account_id":"other","rate_limit":{"primary_window":{"used_percent":1}}}`, false, false},
		{"huge reset", `{"rate_limit":{"primary_window":{"reset_at":9007199254740992}}}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := projectGatewayCodexQuota([]byte(tc.body), "qualified-account", observed)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, raw.Windows, 1)
			require.Equal(t, "primary", raw.Windows[0].ID)
			require.Equal(t, tc.used, raw.Windows[0].Used != nil)
			require.Equal(t, observed.Format(time.RFC3339Nano), raw.Windows[0].ObservedAt)
			if tc.used {
				require.Equal(t, 0.0, *NormalizeGatewayCodexLimits(raw)[0].UsedPercent)
			}
		})
	}
}

// This test crosses custody, authority, the actual GET transport and cache
// writer. It fails if refresh calls inference, fabricates a missing percentage,
// or overwrites stale evidence after a failed/foreign/revoked observation.
func TestGatewayAccountLimitsExplicitRefresh(t *testing.T) {
	for _, mode := range []string{"new account", "success", "missing percent", "upstream error", "redirect", "overflow", "malformed", "revoked before", "revoked at entry", "revoked after", "refresh before", "refresh after", "principal after"} {
		t.Run(mode, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			source := &limitsFixtureRepository{oauthDispatchStore: f.store}
			f.dispatch.repository = source
			oldObserved := time.Now().Add(-time.Hour)
			old := CaptureGatewayCodexLimits(http.Header{"X-Codex-Primary-Used-Percent": {"75"}}, oldObserved)
			source.stored = GatewayAccountLimitsStored{Revision: 1, Raw: &old}
			if mode == "new account" {
				source.stored = GatewayAccountLimitsStored{}
			}
			calls, authorityCalls := 0, 0
			f.dispatch.client = &http.Client{Transport: quotaRefreshTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, chatGPTUsageURL, r.URL.String())
				require.Equal(t, "Bearer "+f.bundle.AccessToken, r.Header.Get("Authorization"))
				require.Equal(t, f.store.physical.ProviderAccount, r.Header.Get("ChatGPT-Account-Id"))
				deadline, ok := r.Context().Deadline()
				require.True(t, ok)
				require.LessOrEqual(t, time.Until(deadline), 5*time.Second)
				body := `{"rate_limit":{"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_after_seconds":60}}}`
				status := http.StatusOK
				switch mode {
				case "missing percent":
					body = `{"rate_limit":{"primary_window":{"limit_window_seconds":18000}}}`
				case "upstream error":
					status = 429
				case "redirect":
					status = 302
				case "overflow":
					body = strings.Repeat(" ", 65537)
				case "malformed":
					body = `{"rate_limit":{"primary_window":{"used_percent":"bad"}}}`
				case "refresh after":
					f.store.fenceEntered = true
				case "principal after":
					f.store.physical.Subject = "foreign"
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
			}), CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}
			authorize := func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				authorityCalls++
				if mode == "revoked before" || mode == "revoked at entry" && authorityCalls > 1 || mode == "revoked after" && authorityCalls > 2 {
					return GatewayNativeRoute{}, ErrGatewayNativeIdentity
				}
				return route, nil
			}
			refresher, err := NewGatewayAccountLimitsRefresher(f.dispatch, source, authorize)
			require.NoError(t, err)
			if mode == "refresh before" {
				f.store.fenceEntered = true
			}
			in := GatewayAccountLimitsInput{f.scope.Owner, f.scope.Account, GatewayCodexOAuthResponsesProfile, 7}
			out := refresher.Refresh(f.ctx, in)
			if mode == "new account" || mode == "success" || mode == "missing percent" {
				require.Equal(t, "snapshot", out.Status)
				require.Equal(t, 1, source.writes)
				if mode == "new account" {
					require.Equal(t, int64(1), out.Revision)
				} else {
					require.Equal(t, int64(2), out.Revision)
				}
				require.NotEqual(t, old.Windows[0].ObservedAt, source.stored.Raw.Windows[0].ObservedAt)
				if mode == "success" || mode == "new account" {
					require.Equal(t, 0.0, *out.Windows[0].UsedPercent)
				} else {
					require.Nil(t, out.Windows[0].UsedPercent)
				}
			} else {
				require.Equal(t, "unavailable", out.Status)
				require.Zero(t, source.writes)
				require.Equal(t, int64(1), source.stored.Revision)
				require.Equal(t, old.Windows[0].ObservedAt, source.stored.Raw.Windows[0].ObservedAt)
			}
			if mode == "revoked before" || mode == "revoked at entry" || mode == "refresh before" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
			require.Zero(t, f.entries.Load())
		})
	}
}
