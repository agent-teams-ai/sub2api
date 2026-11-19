//go:build unit

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayCodexRetainedInfoRequiresWholeBundleProofAndOriginalTime(t *testing.T) {
	custody := nativeFixtureCustody(t)
	observed := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	expiry := observed.Add(time.Hour)
	claims := `{"iss":"https://auth.openai.com","sub":"retained-owner","email":"original@example.test","name":"Original account","https://api.openai.com/auth":{"chatgpt_plan_type":"plus"}}`
	bundle := GatewayNativeOAuthBundle{AccessToken: "retained-access", RefreshToken: "retained-refresh", IDToken: "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature", SensitiveMetadata: json.RawMessage(`{"expires_in":3600}`)}
	p := GatewayNativeOAuthPhysical{Issuer: GatewayOAuthIssuer, Subject: "retained-owner", CredentialRevision: 7}
	require.Empty(t, gatewayCodexRetainedInfo(p, bundle, custody), "plain historical JWT/metadata is not verified evidence")
	// This private proof can only be minted after the fixed verifier in the
	// production exchange. It cryptographically binds the complete old bundle.
	timed, err := gatewayOAuthTimedBundle(bundle, observed, GatewayNativeOAuthIdentity{issuer: p.Issuer, subject: p.Subject, expiresAt: expiry}, custody)
	require.NoError(t, err)
	info := gatewayCodexRetainedInfo(p, timed, custody)
	require.Len(t, info, 2)
	require.EqualValues(t, 0, info[0].Order)
	require.Equal(t, observed.Format(time.RFC3339Nano), info[0].Fields.Email.ObservedAt)
	require.Equal(t, observed.Format(time.RFC3339Nano), info[1].Fields.CredentialExpiresAt.ObservedAt)
	require.Equal(t, expiry.Format(time.RFC3339Nano), *info[1].Fields.CredentialExpiresAt.Value)
	fields, ok := GatewayAccountInfoProject(GatewayCodexOAuthResponsesProfile, GatewayAccountInfoStored{Revision: 2, CredentialRevision: 7, Sources: map[string]GatewayAccountInfoObservation{"verified_claims": info[0], "credential": info[1]}}, time.Now())
	require.True(t, ok)
	require.Equal(t, "original@example.test", *fields.Email.Value)
	require.Equal(t, "plus", fields.Subscription.Value.Code)
	require.Equal(t, "stale", fields.Email.Freshness)
	for _, mutate := range []func(*GatewayNativeOAuthBundle){
		func(b *GatewayNativeOAuthBundle) { b.IDToken = strings.ReplaceAll(b.IDToken, "header", "unverified") },
		func(b *GatewayNativeOAuthBundle) { b.AccessToken += "changed" },
		func(b *GatewayNativeOAuthBundle) {
			b.SensitiveMetadata = json.RawMessage(strings.ReplaceAll(string(b.SensitiveMetadata), "3600", "7200"))
		},
	} {
		changed := timed
		mutate(&changed)
		require.Empty(t, gatewayCodexRetainedInfo(p, changed, custody))
	}
	p.Subject = "different-owner"
	require.Empty(t, gatewayCodexRetainedInfo(p, timed, custody))
}

type codexInfoMaintenanceFixture struct {
	GatewayNativeOAuthRefreshRepository
	*oauthDispatchStore
	initialized bool
	stored      []GatewayAccountInfoObservation
}

func (r *codexInfoMaintenanceFixture) ResolveGatewayNativeOAuthRefresh(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthRefreshResolution, error) {
	return GatewayNativeOAuthRefreshResolution{AccountID: r.row.ID, CreatedAt: r.row.CreatedAt, Version: 1, Envelope: r.row.GetCredential("oauth_bundle"), Qualified: true, AccountInfoInitialized: r.initialized}, nil
}
func (r *codexInfoMaintenanceFixture) ReserveGatewayAccountInfoOrder(context.Context) (int64, error) {
	return 0, ErrGatewayNativeIdentity // cached hydration must not mint a live order
}
func (r *codexInfoMaintenanceFixture) StoreGatewayAccountInfo(ctx context.Context, p GatewayNativeOAuthPhysical, initialize bool, observations ...GatewayAccountInfoObservation) error {
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 2*time.Second || r.locks != r.releases || p.CredentialRevision != 1 || !initialize || len(observations) != 2 {
		return ErrGatewayNativeIdentity
	}
	for _, observation := range observations {
		if observation.Order != 0 {
			return ErrGatewayNativeIdentity
		}
	}
	r.stored = append(r.stored, observations...)
	r.initialized = true
	return nil
}

func TestGatewayCodexMaintenanceHydratesOnceWithoutProviderHTTP(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	f.qualify(t)
	identity, err := f.dispatch.verifier.Verify(f.ctx, f.bundle.IDToken)
	require.NoError(t, err)
	observed := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	bundle, err := gatewayOAuthTimedBundle(f.bundle, observed, identity, f.dispatch.custody)
	require.NoError(t, err)
	envelope, err := f.dispatch.custody.sealOAuthVersion(f.scope, 1, bundle)
	require.NoError(t, err)
	f.store.row.Credentials = map[string]any{"oauth_bundle": envelope, "credential_version": "1"}
	repository := &codexInfoMaintenanceFixture{oauthDispatchStore: f.store}
	refresh, err := NewGatewayNativeOAuthRefresh(repository, f.dispatch.custody, f.dispatch.verifier, f.dispatch.client.Transport)
	require.NoError(t, err)
	checks, jwks := f.checks.Load(), f.jwks.Load()
	first, err := refresh.Maintain(f.ctx, f.scope, f.store.physical.Operation)
	require.NoError(t, err)
	require.Equal(t, "idle", first.State)
	require.Len(t, repository.stored, 2)
	require.Equal(t, observed.Format(time.RFC3339Nano), repository.stored[1].Fields.CredentialExpiresAt.ObservedAt)
	locks := f.store.locks
	second, err := refresh.Maintain(f.ctx, f.scope, f.store.physical.Operation)
	require.NoError(t, err)
	require.Equal(t, "idle", second.State)
	require.Len(t, repository.stored, 2)
	require.Equal(t, locks, f.store.locks, "initialized idle does not acquire another metadata lock")
	require.Equal(t, checks, f.checks.Load())
	require.Equal(t, jwks, f.jwks.Load())
	require.Zero(t, f.entries.Load())
}
