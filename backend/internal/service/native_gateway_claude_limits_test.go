//go:build unit

package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type claudeLimitsCache struct {
	stored GatewayAccountLimitsStored
	reads  int
}

func (c *claudeLimitsCache) ReadGatewayAccountLimits(context.Context, GatewayAccountLimitsInput, GatewayNativeRoute) (GatewayAccountLimitsStored, error) {
	c.reads++
	return c.stored, nil
}
func TestGatewayClaudePassiveHeaderTruthAndInertRead(t *testing.T) {
	observed := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	raw := CaptureGatewayClaudeLimits(http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0"}, "Anthropic-Ratelimit-Unified-5h-Reset": {"1792650000"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"1.25"}, "Anthropic-Ratelimit-Unified-7d-Reset": {"1792650000000"},
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": {"NaN"},
		"X-Codex-Primary-Used-Percent":                  {"100"}, "Anthropic-Ratelimit-Requests-Remaining": {"99"},
	}, observed)
	windows := NormalizeGatewayClaudeLimits(raw)
	require.Len(t, windows, 3)
	require.Equal(t, GatewayClaudeFiveHour, windows[0].ID)
	require.Equal(t, float64(0), *windows[0].UsedPercent)
	require.Equal(t, int64(18000), *windows[0].DurationSeconds)
	require.Equal(t, float64(125), *windows[1].UsedPercent)
	require.Nil(t, windows[1].ResetAt, "millisecond-looking reset must stay unknown under seconds contract")
	require.Equal(t, GatewayClaudeFableSevenDay, windows[2].ID)
	require.Nil(t, windows[2].UsedPercent)
	for _, w := range windows {
		require.Equal(t, "claude", w.Family)
		require.Equal(t, observed.Format(time.RFC3339Nano), *w.ObservedAt)
		require.NotEqual(t, GatewayClaudeSonnetSevenDay, w.ID)
	}
	duplicate := CaptureGatewayClaudeLimits(http.Header{"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.2", "0.3"}}, observed)
	require.Nil(t, NormalizeGatewayClaudeLimits(duplicate)[0].UsedPercent)
	none := CaptureGatewayClaudeLimits(http.Header{"Retry-After": {"10"}}, observed)
	require.Empty(t, none.Windows)
	cache := &claudeLimitsCache{stored: GatewayAccountLimitsStored{PrincipalVersion: strings.Repeat("a", 64), Revision: 2, Claude: &raw}}
	route := GatewayNativeRoute{AccountID: 42, CreatedAt: observed, Generation: uuid.NewString(), Profile: GatewayClaudeOAuthMessagesProfile, BaseURL: GatewayClaudeOAuthBaseURL, Model: GatewayClaudeOAuthModel}
	reader, err := NewGatewayAccountLimitsReader(cache, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) { return route, nil })
	require.NoError(t, err)
	ctx, err := WithGatewayNativeConsumer(context.Background(), "consumer")
	require.NoError(t, err)
	result := reader.Read(ctx, GatewayAccountLimitsInput{OwnerRef: "owner", AccountRef: "account", ProfileID: GatewayClaudeOAuthMessagesProfile, ExpectedAuthorizationEpoch: 1})
	require.Equal(t, "snapshot", result.Status)
	require.Equal(t, windows, result.Windows)
	require.Equal(t, 2, cache.reads)
	require.Equal(t, observed.Format(time.RFC3339Nano), *result.Windows[0].ObservedAt)
}

type claudeOAuthEmptyRepository struct{ GatewayNativeClaudeRepository }
type claudeOAuthFixtureTransport func(*http.Request) (*http.Response, error)

func (f claudeOAuthFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGatewayClaudeOAuthSourceIdentityAndCustody(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	custody, err := NewGatewayNativeCredentialCustody("claude-test", map[string][]byte{"claude-test": key})
	require.NoError(t, err)
	account, org := uuid.NewString(), uuid.NewString()
	reply := func() map[string]any {
		return map[string]any{"access_token": "private-access", "refresh_token": "private-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "user:profile user:inference", "account": map[string]string{"uuid": account}, "organization": map[string]string{"uuid": org}}
	}
	payload, _ := json.Marshal(reply())
	calls := 0
	s, err := NewGatewayNativeClaudeOAuth(claudeOAuthEmptyRepository{}, custody, claudeOAuthFixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Empty(t, r.Header.Get("Authorization"))
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(payload))), Request: r}, nil
	}))
	require.NoError(t, err)
	bundle, err := s.exchange(context.Background(), map[string]any{"grant_type": "authorization_code"}, nil)
	require.NoError(t, err)
	require.Equal(t, account, bundle.Account)
	require.Equal(t, org, bundle.Organization)
	scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "logical", Generation: uuid.NewString(), Purpose: GatewayOAuthBundlePurpose}
	envelope, err := s.seal(scope, bundle)
	require.NoError(t, err)
	require.NotContains(t, envelope, "private-access")
	physical := GatewayNativeOAuthPhysical{CredentialRevision: 1, Scope: scope, Issuer: GatewayClaudeOAuthIssuer, Subject: account, ProviderAccount: org}
	_, err = s.bundle(scope, envelope, physical)
	require.NoError(t, err)
	replay := physical
	replay.CredentialRevision = 2
	_, err = s.bundle(scope, envelope, replay)
	require.Error(t, err, "prior encrypted revision must not open as rotated custody")
	foreign := scope
	foreign.Generation = uuid.NewString()
	_, err = s.bundle(foreign, envelope, physical)
	require.Error(t, err)
	for _, scenario := range []string{"missing_account", "missing_org", "wrong_uuid", "missing_inference", "wrong_type", "wrong_account_refresh", "duplicate_identity", "id_token_without_identity"} {
		t.Run(scenario, func(t *testing.T) {
			m := reply()
			previous := (*gatewayClaudeBundle)(nil)
			switch scenario {
			case "missing_account":
				delete(m, "account")
			case "missing_org":
				delete(m, "organization")
			case "wrong_uuid":
				m["account"] = map[string]string{"uuid": "not-uuid"}
			case "missing_inference":
				m["scope"] = "user:profile"
			case "wrong_type":
				m["token_type"] = "Basic"
			case "wrong_account_refresh":
				m["account"] = map[string]string{"uuid": uuid.NewString()}
				previous = &bundle
			case "id_token_without_identity":
				delete(m, "account")
				delete(m, "organization")
				m["id_token"] = "opaque-cannot-qualify"
			}
			payload, _ = json.Marshal(m)
			if scenario == "duplicate_identity" {
				payload = []byte(strings.Replace(string(payload), `"account":{`, `"account":{"uuid":"`+uuid.NewString()+`",`, 1))
			}
			_, e := s.exchange(context.Background(), map[string]any{"grant_type": "authorization_code"}, previous)
			require.Error(t, e)
		})
	}
	require.Equal(t, 9, calls)
	// Refresh may omit identity only while preserving the authenticated prior pair.
	m := reply()
	delete(m, "account")
	delete(m, "organization")
	payload, _ = json.Marshal(m)
	refreshed, err := s.exchange(context.Background(), map[string]any{"grant_type": "refresh_token"}, &bundle)
	require.NoError(t, err)
	require.Equal(t, account, refreshed.Account)
	require.Equal(t, org, refreshed.Organization)
}

func TestGatewayClaudeCustodyContainedFromOrdinaryAccounts(t *testing.T) {
	for _, key := range []string{"gateway_claude_profile_v1", "gateway_claude_generation_v1", "gateway_claude_scope_v1"} {
		row := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Extra: map[string]any{key: "malformed"}}
		require.True(t, HasGatewayNativeIdentity(row))
		require.False(t, row.IsSchedulable())
	}
}
