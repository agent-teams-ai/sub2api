//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type limitsV2Fixture struct {
	stored GatewayAccountLimitsStoredV2
	reads  int
	reject bool
}

func (r *limitsV2Fixture) ReadGatewayAccountLimitsV2(context.Context, GatewayAccountLimitsInput, GatewayNativeRoute) (GatewayAccountLimitsStoredV2, error) {
	r.reads++
	if r.reject {
		return GatewayAccountLimitsStoredV2{}, ErrGatewayNativeIdentity
	}
	return r.stored, nil
}
func limitsV2Window() GatewayAccountLimitWindowV2 {
	used := 0.0
	observed := "2026-10-23T00:00:00Z"
	label := "Month"
	return GatewayAccountLimitWindowV2{ID: "monthly", Provider: "grok", Dimension: "plan_quota", Unit: "credits", Period: GatewayAccountLimitPeriodV2{Kind: "monthly_billing_cycle"}, Label: &label, UsedPercent: &used, ObservedAt: &observed}
}
func limitsV2Route() GatewayNativeRoute {
	return GatewayNativeRoute{AccountID: 41, Generation: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), Profile: GatewayGrokOAuthResponsesProfile, BaseURL: GatewayGrokOAuthBaseURL, Model: GatewayGrokOAuthModel}
}

// These checks fail on an authorization/principal/birth loss during either
// await, or when an empty newer observation resurrects removed quota windows.
func TestGatewayAccountLimitsV2ReadFences(t *testing.T) {
	for _, scenario := range []string{"snapshot", "no_observation", "empty_observation", "owner_revoked", "birth_changed", "deleted", "principal_changed", "revision_rollback", "snapshot_removed", "cancelled", "new_empty_observation"} {
		t.Run(scenario, func(t *testing.T) {
			route := limitsV2Route()
			snapshot := GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []GatewayAccountLimitWindowV2{limitsV2Window()}}
			source := &limitsV2Fixture{stored: GatewayAccountLimitsStoredV2{PrincipalVersion: "principal-v2", Revision: 7, Snapshot: &snapshot}}
			if scenario == "no_observation" {
				source.stored.Snapshot = nil
				source.stored.Revision = 0
			}
			if scenario == "empty_observation" {
				snapshot.Windows = nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			reader, err := NewGatewayAccountLimitsReaderV2(source, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				calls++
				if calls == 2 {
					switch scenario {
					case "owner_revoked":
						return GatewayNativeRoute{}, ErrGatewayNativeIdentity
					case "birth_changed":
						changed := route
						changed.CreatedAt = changed.CreatedAt.Add(time.Microsecond)
						return changed, nil
					case "deleted":
						source.reject = true
					case "principal_changed":
						source.stored.PrincipalVersion = "replacement"
					case "revision_rollback":
						source.stored.Revision = 6
					case "snapshot_removed":
						source.stored.Snapshot = nil
					case "cancelled":
						cancel()
					case "new_empty_observation":
						source.stored.Snapshot = &GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []GatewayAccountLimitWindowV2{}}
						source.stored.Revision = 8
					}
				}
				return route, nil
			})
			require.NoError(t, err)
			out := reader.Read(ctx, GatewayAccountLimitsInput{OwnerRef: "owner", AccountRef: "account", ProfileID: route.Profile, ExpectedAuthorizationEpoch: 7})
			switch scenario {
			case "snapshot":
				require.Equal(t, "snapshot", out.Status)
				require.Equal(t, int64(7), out.Revision)
				require.Equal(t, 0.0, *out.Windows[0].UsedPercent)
				require.Nil(t, out.Windows[0].Period.DurationSeconds)
			case "no_observation", "empty_observation", "new_empty_observation":
				require.Equal(t, GatewayAccountLimitsResultV2{Status: "unknown"}, out)
			default:
				require.Equal(t, GatewayAccountLimitsResultV2{Status: "unavailable"}, out)
			}
			require.Equal(t, 2, calls)
		})
	}
}

// Units/monthly periods and absent fields are independent facts. This fails if
// unknown gets coerced to zero or monthly billing is relabeled as 30 days.
func TestGatewayAccountLimitsV2WindowContract(t *testing.T) {
	base := limitsV2Window()
	require.True(t, ValidateGatewayAccountLimitWindowsV2([]GatewayAccountLimitWindowV2{base}))
	unknown := base
	unknown.UsedPercent = nil
	unknown.ObservedAt = nil
	unknown.Label = nil
	unknown.Period = GatewayAccountLimitPeriodV2{Kind: "unknown"}
	require.True(t, ValidateGatewayAccountLimitWindowsV2([]GatewayAccountLimitWindowV2{unknown}))
	credit := base
	credit.Provider = "glm"
	token := credit
	token.Unit = "tokens"
	require.True(t, ValidateGatewayAccountLimitWindowsV2([]GatewayAccountLimitWindowV2{credit, token}))
	for _, change := range []func(*GatewayAccountLimitWindowV2){
		func(w *GatewayAccountLimitWindowV2) { w.ID = "provider-raw-id" },
		func(w *GatewayAccountLimitWindowV2) { w.Provider = "codex" },
		func(w *GatewayAccountLimitWindowV2) { w.Dimension = "balance" },
		func(w *GatewayAccountLimitWindowV2) { w.Unit = "usd" },
		func(w *GatewayAccountLimitWindowV2) { v := int64(2592000); w.Period.DurationSeconds = &v },
		func(w *GatewayAccountLimitWindowV2) { w.ObservedAt = nil },
		func(w *GatewayAccountLimitWindowV2) { w.Dimension = "rate_limit" },
		func(w *GatewayAccountLimitWindowV2) { raw := "raw-provider-label"; w.Label = &raw },
	} {
		invalid := base
		change(&invalid)
		require.False(t, ValidateGatewayAccountLimitWindowsV2([]GatewayAccountLimitWindowV2{invalid}))
	}
	require.False(t, ValidateGatewayAccountLimitWindowsV2([]GatewayAccountLimitWindowV2{base, base}))
	require.False(t, ValidateGatewayAccountLimitWindowsV2(make([]GatewayAccountLimitWindowV2, 9)))
}
func TestGatewayAccountLimitsV2PrincipalGenerationAndGrokContinuity(t *testing.T) {
	p := GatewayNativeOAuthPhysical{Scope: GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "account", Generation: limitsV2Route().Generation, Purpose: GatewayCredentialPurpose}, Route: limitsV2Route(), Subject: "subject", Issuer: GatewayGrokOAuthIssuer, ProviderAccount: "personal"}
	original := GatewayAccountLimitsPrincipalV2(p)
	rotated := p
	rotated.CredentialRevision = 2
	require.Equal(t, original, GatewayAccountLimitsPrincipalV2(rotated))
	replaced := p
	replaced.Subject = "foreign"
	require.NotEqual(t, original, GatewayAccountLimitsPrincipalV2(replaced))
	key := p
	key.Route.Profile = "kimi-code-global-responses-apikey-v1"
	changed := key
	changed.Subject = "unverified-ignored"
	require.Equal(t, GatewayAccountLimitsPrincipalV2(key), GatewayAccountLimitsPrincipalV2(changed))
	changed = key
	changed.Scope.Generation = "22222222-2222-4222-8222-222222222222"
	require.NotEqual(t, GatewayAccountLimitsPrincipalV2(key), GatewayAccountLimitsPrincipalV2(changed))
	changed = key
	changed.Route.CreatedAt = changed.Route.CreatedAt.Add(time.Microsecond)
	require.NotEqual(t, GatewayAccountLimitsPrincipalV2(key), GatewayAccountLimitsPrincipalV2(changed))
}
