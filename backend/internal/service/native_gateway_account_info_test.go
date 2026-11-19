package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayAccountInfoSourceWithdrawalFreshnessAndCredentialRevision(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	claims := GatewayAccountInfoEmptyFields(GatewayCodexOAuthResponsesProfile)
	claims.Email = gatewayKnownFact("synthetic@example.invalid", "verified_claim", at)
	claims.Subscription = gatewayKnownFact(GatewayAccountSubscription{Code: "pro", Label: "Pro 200", Scope: "personal"}, "verified_claim", at)
	api := GatewayAccountInfoEmptyFields(GatewayCodexOAuthResponsesProfile)
	api.AccountLabel = gatewayKnownFact("Review account", "provider_api", at)
	cred := GatewayAccountInfoEmptyFields(GatewayCodexOAuthResponsesProfile)
	cred.CredentialExpiresAt = gatewayKnownFact(at.Add(time.Hour).Format(time.RFC3339), "provider_api", at)
	stored := GatewayAccountInfoStored{Revision: 3, CredentialRevision: 2, Sources: map[string]GatewayAccountInfoObservation{
		"verified_claims": {Source: "verified_claims", Order: 1, CredentialRevision: 1, Fields: claims},
		"account_check":   {Source: "account_check", Order: 2, CredentialRevision: 1, Fields: api},
		"credential":      {Source: "credential", Order: 3, CredentialRevision: 1, Fields: cred},
	}}
	fields, valid := GatewayAccountInfoProject(GatewayCodexOAuthResponsesProfile, stored, at.Add(25*time.Hour))
	require.True(t, valid)
	require.Equal(t, "unknown", fields.Subscription.Status, "authoritative omission must not resurrect a claims tariff")
	require.Equal(t, "synthetic@example.invalid", *fields.Email.Value)
	require.Equal(t, "stale", fields.Email.Freshness)
	require.Equal(t, at.Format(time.RFC3339), fields.Email.ObservedAt, "read must not refresh observation time")
	require.Equal(t, "unknown", fields.CredentialExpiresAt.Status, "rotation invalidates only credential expiry")
	require.Equal(t, "Review account", *fields.AccountLabel.Value)
}

func TestGatewayAccountInfoExactDatesAndSafeFieldBounds(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	f := GatewayAccountInfoEmptyFields(GatewayCodexOAuthResponsesProfile)
	f.Email = gatewayKnownFact(strings.Repeat("界", 320), "verified_claim", at)
	f.Subscription = gatewayKnownFact(GatewayAccountSubscription{Code: "plus", Label: "Plus", Scope: "personal", EndsAt: &GatewayAccountInfoDate{Kind: "date", Value: "2026-12-06"}}, "provider_api", at)
	require.True(t, GatewayAccountInfoFieldsValid(f))
	raw, err := json.Marshal(f)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"kind":"date","value":"2026-12-06"`)
	f.Subscription.Value.EndsAt.Value = "2026-02-30"
	require.False(t, GatewayAccountInfoFieldsValid(f))
	f.Subscription.Value.EndsAt = nil
	f.Email.Value = new(string)
	*f.Email.Value = "unsafe\u0085label"
	require.False(t, GatewayAccountInfoFieldsValid(f))
	*f.Email.Value = strings.Repeat("界", 321)
	require.False(t, GatewayAccountInfoFieldsValid(f))
	f.Email = GatewayAccountFact[string]{Status: "unknown", Source: "verified_claim"}
	require.False(t, GatewayAccountInfoFieldsValid(f))
	key := GatewayAccountInfoEmptyFields(GatewayOpenRouterResponsesProfile)
	require.Equal(t, "unsupported", key.Email.Status)
	require.Equal(t, "unsupported", key.Subscription.Status)
}

type accountInfoTestCache struct {
	reads int
	read  func(int) (GatewayAccountInfoStored, error)
}

func (c *accountInfoTestCache) ReadGatewayAccountInfo(_ context.Context, _ GatewayAccountLimitsInput, _ GatewayNativeRoute) (GatewayAccountInfoStored, error) {
	c.reads++
	return c.read(c.reads)
}

func TestGatewayAccountInfoReaderUsesCurrentSnapshotAndFinalAuthority(t *testing.T) {
	ctx, err := WithGatewayNativeConsumer(context.Background(), "fixture-consumer")
	require.NoError(t, err)
	in := GatewayAccountLimitsInput{OwnerRef: "fixture-owner", AccountRef: "fixture-account", ProfileID: GatewayCodexOAuthResponsesProfile, ExpectedAuthorizationEpoch: 3}
	route := GatewayNativeRoute{AccountID: 1, Generation: "44444444-4444-4444-8444-444444444444", CreatedAt: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC), Profile: in.ProfileID, BaseURL: GatewayCodexOAuthBaseURL, Model: GatewayCodexOAuthModel}
	at := route.CreatedAt
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "withdrawal", true: "revoked"}[revoke], func(t *testing.T) {
			cache := &accountInfoTestCache{read: func(n int) (GatewayAccountInfoStored, error) {
				fields := GatewayAccountInfoEmptyFields(in.ProfileID)
				if n == 1 {
					fields.Subscription = gatewayKnownFact(GatewayAccountSubscription{Code: "plus", Label: "Plus", Scope: "personal"}, "provider_api", at)
				}
				return GatewayAccountInfoStored{PrincipalVersion: "synthetic-principal", Revision: int64(n), Sources: map[string]GatewayAccountInfoObservation{"account_check": {Source: "account_check", Order: int64(n), Fields: fields}}}, nil
			}}
			calls := 0
			reader, err := NewGatewayAccountInfoReader(cache, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				calls++
				if revoke && calls == 2 {
					return GatewayNativeRoute{}, ErrGatewayNativeIdentity
				}
				return route, nil
			})
			require.NoError(t, err)
			reader.now = func() time.Time { return at }
			out := reader.Read(ctx, in)
			require.Empty(t, reader.active, "owner slots are released on success and revoked authority")
			if revoke {
				require.Equal(t, GatewayAccountInfoResult{Info: GatewayAccountInfo{Status: "unavailable"}}, out)
				return
			}
			require.Equal(t, "available", out.Info.Status)
			require.Equal(t, "2", out.Info.InfoRevision)
			require.Equal(t, "unknown", out.Info.Fields.Subscription.Status)
			require.Equal(t, route.Generation, out.PhysicalGeneration)
		})
	}
}
