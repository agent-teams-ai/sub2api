package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type accountInfoRoundTripper func(*http.Request) (*http.Response, error)

func (f accountInfoRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayQuotaAndInfoUseOneAuthenticatedObservation(t *testing.T) {
	calls := 0
	collector := NewGatewayProviderQuotaCollector(accountInfoRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, "https://api.z.ai/api/monitor/usage/quota/limit", req.URL.String())
		require.Equal(t, "synthetic-key", req.Header.Get("Authorization"))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"data":{"level":"GLM Max","limits":[{"type":"TOKENS_LIMIT","unit":3,"percentage":25}]}}`)), Request: req}, nil
	}))
	out, err := collector.FetchWithAccountInfo(context.Background(), "glm", []byte("synthetic-key"))
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.NotNil(t, out.Info)
	require.Equal(t, "GLM Max", out.Info.Subscription.Value.Label)
	require.Equal(t, out.ObservedAt.Format(time.RFC3339Nano), out.Info.Subscription.ObservedAt)
	require.Equal(t, out.Info.Subscription.ObservedAt, *out.Limits.Windows[0].ObservedAt)
	cleared := gatewayQuotaAccountInfo("glm", []byte(`{"success":true,"data":{"limits":[]}}`), out.ObservedAt)
	require.Equal(t, "unknown", cleared.Subscription.Status)
}

func TestGatewayCodexInfoKeepsSelectedScopeAndNativePlanLabels(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	var claims map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{"email":"fixture@example.invalid","https://api.openai.com/auth":{"chatgpt_plan_type":"pro"}}`), &claims))
	f := gatewayVerifiedCodexInfo(claims, at)
	require.Equal(t, "fixture@example.invalid", *f.Email.Value)
	require.Equal(t, "Pro 200", f.Subscription.Value.Label)
	raw := []byte(`{"accounts":{"personal":{"account":{"account_id":"personal","account_structure":"personal","plan_type":"plus","name":"Personal"},"entitlement":{"expires_at":"2026-12-06T05:00:00Z"}},"workspace":{"account":{"account_id":"workspace","account_structure":"workspace","plan_type":"business"},"entitlement":{"expires_at":"2026-12-10T05:00:00Z"}}}}`)
	selected := gatewayCodexAccountInfo(raw, "workspace", at)
	require.Equal(t, "workspace", selected.Subscription.Value.Scope)
	require.Equal(t, "Enterprise", selected.Subscription.Value.Label)
	require.Equal(t, "2026-12-10T05:00:00Z", selected.Subscription.Value.EndsAt.Value)
	require.Equal(t, "unknown", selected.Email.Status, "account-check must not copy unrelated identity")
}

func TestGatewayAccountCapabilitiesHavePerMethodSupportAndQualifiedAnchor(t *testing.T) {
	openrouter, ok := GatewayNativeAccountCapability(GatewayOpenRouterResponsesProfile, GatewayOpenRouterModel, true, false)
	require.True(t, ok)
	require.Equal(t, GatewayOpenRouterModel, openrouter.Models[0].ModelID)
	require.Equal(t, "openrouter", openrouter.Provider.ID)
	codex, ok := GatewayNativeAccountCapability(GatewayCodexOAuthResponsesProfile, GatewayCodexOAuthModel, true, false)
	require.True(t, ok)
	require.Len(t, codex.Methods, 2)
	for _, m := range codex.Methods {
		require.True(t, m.Create)
		require.True(t, m.Reconnect)
		require.NotEqual(t, "credential_import", m.Kind)
	}
	glm, ok := GatewayNativeAccountCapability(GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel, true, false)
	require.True(t, ok)
	require.Len(t, glm.Models, 2, "reuse native static lower bound")
	_, ok = GatewayNativeAccountCapability("unmounted-profile", "model", true, false)
	require.False(t, ok)
}

func TestGatewayAccountInfoInvalidSubscriptionDateDoesNotPoisonPlan(t *testing.T) {
	for _, expiry := range []string{"0000-01-01T00:00:00Z", "0000-01-01", "2026-02-30", "not-a-date"} {
		plan := gatewayInfoSubscription("plus", "personal", expiry)
		require.NotNil(t, plan)
		require.Equal(t, "Plus", plan.Label)
		require.Nil(t, plan.EndsAt)
	}
}

type accountInfoCancelBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (b accountInfoCancelBody) Close() error { b.cancel(); return nil }

func TestGatewayQuotaAndInfoRejectsObservationWhenContextClosesAfterRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector := NewGatewayProviderQuotaCollector(accountInfoRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: accountInfoCancelBody{Reader: strings.NewReader(`{"success":true,"data":{"level":"GLM Max","limits":[{"type":"TOKENS_LIMIT","unit":3,"percentage":25}]}}`), cancel: cancel}, Request: req}, nil
	}))
	observation, err := collector.FetchWithAccountInfo(ctx, "glm", []byte("synthetic-key"))
	require.Error(t, err)
	require.Equal(t, GatewayProviderQuotaObservation{}, observation, "no partial facts may escape an unsuccessful observation")
}
