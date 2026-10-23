//go:build unit

package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Disabling or expiring a candidate between enumeration and the fresh custody
// lease must prevent the collector callback, even though its sealed shape is valid.
func TestGatewayProviderQuotaLeaseRechecksEligibility(t *testing.T) {
	a := &Account{ID: 17, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
		Credentials: map[string]any{"api_key": "quota-test-private-key", "base_url": GatewayKimiCodeResponsesBaseURL},
		Extra:       map[string]any{GatewayGenerationExtraKey: "11111111-1111-4111-8111-111111111111", GatewayProfileExtraKey: GatewayKimiCodeResponsesProfile, GatewayModelExtraKey: GatewayKimiCodeResponsesModel, "openai_responses_mode": "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	nativeFixtureSealAccount(t, a)
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	scope, err := GatewayNativeCredentialScopeForAccount(a)
	require.NoError(t, err)
	repo := &gatewayIdentityRepoFixture{row: a}
	gateway := &OpenAIGatewayService{accountRepo: repo}
	for _, mode := range []string{"active", "disabled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			fresh := *a
			if mode == "disabled" {
				fresh.Status = StatusDisabled
			}
			if mode == "expired" {
				past := time.Now().Add(-time.Minute)
				fresh.ExpiresAt = &past
			}
			repo.fresh = &fresh
			calls := 0
			err := gateway.WithGatewayNativeQuotaCredential(nativeFixtureContext(t, context.Background()), scope, route, nativeFixtureCustody(t), func(key []byte, p GatewayNativeOAuthPhysical) error {
				calls++
				require.Equal(t, "quota-test-private-key", string(key))
				return nil
			})
			if mode == "active" {
				require.NoError(t, err)
				require.Equal(t, 1, calls)
			} else {
				require.Error(t, err)
				require.Zero(t, calls)
			}
		})
	}
}
