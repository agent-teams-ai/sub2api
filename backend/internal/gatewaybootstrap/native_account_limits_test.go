package gatewaybootstrap

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Real bounded callback HTTP: selectors carry only the logical account and
// expected owner epoch; malformed/duplicate principal routes cannot authorize.
func TestGatewayAccountLimitsAuthorityHTTP(t *testing.T) {
	valid := `{"ok":true,"native":{"account_id":1,"generation":"00000000-0000-4000-8000-000000000001","created_at":"2026-10-22T00:00:00.123456Z","profile":"openai-codex-oauth-responses-v1","base_url":"https://chatgpt.com/backend-api/codex","model":"gpt-5.6-sol"}}`
	for _, tc := range []struct {
		name, body string
		allowed    bool
	}{
		{"valid", valid, true},
		{"duplicate", strings.Replace(valid, `"ok":true`, `"ok":true,"ok":true`, 1), false},
		{"alias", strings.Replace(valid, `"account_id":1`, `"Account_id":1`, 1), false},
		{"unknown", strings.Replace(valid, `"account_id":1`, `"account_id":1,"providerAccount":"not-exported"`, 1), false},
		{"wrong profile", strings.Replace(valid, service.GatewayCodexOAuthResponsesProfile, "wrong-profile", 1), false},
		{"unsafe birth", strings.Replace(valid, "123456Z", "123456789Z", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				require.Equal(t, "/private/native/v1/account-limits-authority", r.URL.Path)
				require.Equal(t, "POST", r.Method)
				require.Equal(t, "Bearer fixture-authority-credential", r.Header.Get("Authorization"))
				var body map[string]any
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				require.Equal(t, map[string]any{"consumerId": "fixture-consumer", "ownerRef": "fixture-owner", "accountRef": "fixture-account", "profileId": service.GatewayCodexOAuthResponsesProfile, "expectedAuthorizationEpoch": float64(3)}, body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			authority, err := newAuthority(AuthorityConfig{server.URL, "fixture-authority-credential"}, nil)
			require.NoError(t, err)
			defer authority.client.CloseIdleConnections()
			route, err := authority.AuthorizeNativeAccountLimits(context.Background(), "fixture-consumer", service.GatewayAccountLimitsInput{OwnerRef: "fixture-owner", AccountRef: "fixture-account", ProfileID: service.GatewayCodexOAuthResponsesProfile, ExpectedAuthorizationEpoch: 3})
			if tc.allowed {
				require.NoError(t, err)
				require.Equal(t, int64(1), route.AccountID)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, 1, calls, "callback refusal must never retry")
		})
	}
}
