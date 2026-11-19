//go:build unit

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type oauthInfoFixture struct {
	GatewayNativeClaudeRepository
	GatewayNativeGrokRepository
	physical GatewayNativeOAuthPhysical
	envelope string
	order    int64
	held     bool
	stored   []GatewayAccountInfoObservation
	storeErr error
}

func (r *oauthInfoFixture) ReserveGatewayAccountInfoOrder(context.Context) (int64, error) {
	r.order++
	return r.order, nil
}
func (r *oauthInfoFixture) StoreGatewayAccountInfo(ctx context.Context, p GatewayNativeOAuthPhysical, initialize bool, observations ...GatewayAccountInfoObservation) error {
	if len(observations) != 1 {
		return ErrGatewayNativeIdentity
	}
	o := observations[0]
	deadline, bounded := ctx.Deadline()
	if r.held || !bounded || time.Until(deadline) > 2*time.Second || p != r.physical || !initialize {
		return ErrGatewayNativeIdentity
	}
	if r.storeErr != nil {
		return r.storeErr
	}
	r.stored = append(r.stored, o)
	r.physical.AccountInfoInitialized = true
	return nil
}
func (r *oauthInfoFixture) lock(scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthPhysical, string, func(), error) {
	if scope != r.physical.Scope || operation != r.physical.Operation {
		return GatewayNativeOAuthPhysical{}, "", nil, ErrGatewayNativeIdentity
	}
	r.held = true
	return r.physical, r.envelope, func() { r.held = false }, nil
}
func (r *oauthInfoFixture) LockGatewayClaudePhysical(_ context.Context, scope GatewayNativeCredentialScope, operation string, _ *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error) {
	return r.lock(scope, operation)
}
func (r *oauthInfoFixture) LockGatewayGrokPhysical(_ context.Context, scope GatewayNativeCredentialScope, operation string, _ *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error) {
	return r.lock(scope, operation)
}
func (r *oauthInfoFixture) LockGatewayClaudeMaintenance(_ context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthPhysical, string, string, string, func(), error) {
	p, envelope, release, err := r.lock(scope, operation)
	return p, envelope, "completed", "", release, err
}
func (r *oauthInfoFixture) LockGatewayGrokMaintenance(_ context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthPhysical, string, string, string, func(), error) {
	p, envelope, release, err := r.lock(scope, operation)
	return p, envelope, "completed", "", release, err
}

func TestGatewayClaudeInfoOnlyUsesAuthenticatedAccountAndPreservesPartialRefresh(t *testing.T) {
	repo := &oauthInfoFixture{}
	account, organization := uuid.NewString(), uuid.NewString()
	response := map[string]any{"access_token": "private-access", "refresh_token": "private-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "user:inference", "account": map[string]any{"uuid": account, "email_address": "owner@example.test", "name": "unqualified-label", "plan": "unqualified-plan"}, "organization": map[string]string{"uuid": organization}}
	s, err := NewGatewayNativeClaudeOAuth(repo, nativeFixtureCustody(t), claudeOAuthFixtureTransport(func(r *http.Request) (*http.Response, error) {
		require.Positive(t, repo.order, "source order is reserved before HTTP")
		require.Equal(t, oauth.TokenURL, r.URL.String())
		raw, _ := json.Marshal(response)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	}))
	require.NoError(t, err)
	bundle, err := s.exchange(context.Background(), map[string]any{}, nil)
	require.NoError(t, err)
	require.Len(t, bundle.info, 2)
	accountInfo := bundle.info[0]
	require.True(t, GatewayAccountInfoObservationValid(GatewayClaudeOAuthMessagesProfile, accountInfo))
	require.Equal(t, "owner@example.test", *accountInfo.Fields.Email.Value)
	require.Equal(t, "provider_api", accountInfo.Fields.Email.Source)
	require.Equal(t, "unknown", accountInfo.Fields.AccountLabel.Status)
	require.Equal(t, "unknown", accountInfo.Fields.Subscription.Status)
	sealedJSON, err := json.Marshal(bundle)
	require.NoError(t, err)
	require.NotContains(t, string(sealedJSON), "owner@example.test", "UI facts have one native snapshot store")
	require.NotContains(t, string(sealedJSON), "unqualified")
	delete(response, "account")
	delete(response, "organization")
	refreshed, err := s.exchange(context.Background(), map[string]any{}, &bundle)
	require.NoError(t, err)
	require.Len(t, refreshed.info, 1, "partial token response cannot tombstone an absent account read")
	require.Equal(t, "credential", refreshed.info[0].Source)
	require.EqualValues(t, 2, refreshed.info[0].CredentialRevision)
	response["account"] = map[string]any{"uuid": account, "email_address": 123}
	refreshed, err = s.exchange(context.Background(), map[string]any{}, &refreshed)
	require.NoError(t, err, "an invalid optional display field cannot fail credential rotation")
	require.Equal(t, "unknown", refreshed.info[0].Fields.Email.Status)
}

func TestGatewayGrokInfoFollowsAuthenticatedRefreshUserinfo(t *testing.T) {
	repo := &oauthInfoFixture{}
	prior := gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: "old-access", RefreshToken: "old-refresh", Subject: "owner", Team: "team:team", Nonce: strings.Repeat("n", 43), ClientID: "qualified-client", ExpiresAt: time.Now()}
	user := map[string]any{"sub": "owner", "team_id": "team", "email": "grok@example.test", "name": "Review account", "plan": "unqualified-plan"}
	s, err := NewGatewayNativeGrokOAuth(repo, nativeFixtureCustody(t), grokFixtureHTTP(func(r *http.Request) (*http.Response, error) {
		require.Positive(t, repo.order)
		var body any
		switch r.URL.String() {
		case xai.DefaultTokenURL:
			body = map[string]any{"access_token": "next-access", "token_type": "Bearer", "expires_in": 3600}
		case xai.ProtectedUserinfoURL:
			require.Equal(t, "Bearer next-access", r.Header.Get("Authorization"))
			body = user
		default:
			t.Fatal("metadata added provider HTTP")
		}
		raw, _ := json.Marshal(body)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	}), GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
	require.NoError(t, err)
	bundle, err := s.exchange(context.Background(), url.Values{}, "", &prior)
	require.NoError(t, err)
	require.Len(t, bundle.info, 2)
	require.True(t, GatewayAccountInfoObservationValid(GatewayGrokOAuthResponsesProfile, bundle.info[0]))
	require.Equal(t, "grok@example.test", *bundle.info[0].Fields.Email.Value)
	require.Equal(t, "Review account", *bundle.info[0].Fields.AccountLabel.Value)
	require.Equal(t, "unknown", bundle.info[0].Fields.Subscription.Status)
	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "grok@example.test")
	user["email"], user["name"] = 123, "line\nbreak"
	bundle, err = s.exchange(context.Background(), url.Values{}, "", &prior)
	require.NoError(t, err)
	require.Equal(t, "unknown", bundle.info[0].Fields.Email.Status)
	require.Equal(t, "unknown", bundle.info[0].Fields.AccountLabel.Status)
	user["sub"] = "foreign"
	bundle, err = s.exchange(context.Background(), url.Values{}, "", &prior)
	require.Error(t, err)
	require.Empty(t, bundle.info, "a changed principal cannot publish its facts")
}

func TestGatewayOAuthInfoHydrationKeepsOriginalObservationAndNeverCallsHTTP(t *testing.T) {
	for _, provider := range []string{"claude", "grok"} {
		t.Run(provider, func(t *testing.T) {
			_, _, ctx, scope := connectPureFixture(t)
			repo := &oauthInfoFixture{physical: GatewayNativeOAuthPhysical{Scope: scope, Operation: "connect", CredentialRevision: 1}}
			repo.physical.Route = GatewayNativeRoute{AccountID: 42, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Generation: scope.Generation}
			transport := grokFixtureHTTP(func(*http.Request) (*http.Response, error) {
				t.Fatal("hydration performed provider HTTP")
				return nil, ErrGatewayNativeIdentity
			})
			expiry := time.Now().UTC().Add(time.Hour)
			var seal func(time.Time) (string, error)
			var hydrate func(context.Context, GatewayNativeCredentialScope, string) error
			var maintain func(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthMaintenanceOutcome, error)
			allow := func(context.Context, GatewayNativeCredentialScope, string) error { return nil }
			if provider == "claude" {
				repo.physical.Issuer, repo.physical.Subject, repo.physical.ProviderAccount = GatewayClaudeOAuthIssuer, uuid.NewString(), uuid.NewString()
				repo.physical.Route.Profile, repo.physical.Route.BaseURL, repo.physical.Route.Model = GatewayClaudeOAuthMessagesProfile, GatewayClaudeOAuthBaseURL, GatewayClaudeOAuthModel
				s, err := NewGatewayNativeClaudeOAuth(repo, nativeFixtureCustody(t), transport)
				require.NoError(t, err)
				hydrate = s.HydrateAccountInfo
				maintain = s.Maintain
				require.NoError(t, s.SetEntryAuthorizers(allow, allow))
				seal = func(at time.Time) (string, error) {
					return s.seal(scope, gatewayClaudeBundle{Kind: "claude-oauth/v1", Revision: 1, AccessToken: "private-access", RefreshToken: "private-refresh", Account: repo.physical.Subject, Organization: repo.physical.ProviderAccount, ExpiresAt: expiry, ObservedAt: at})
				}
			} else {
				repo.physical.Issuer, repo.physical.Subject, repo.physical.ProviderAccount = GatewayGrokOAuthIssuer, "owner", "personal:owner"
				repo.physical.Route.Profile, repo.physical.Route.BaseURL, repo.physical.Route.Model = GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthBaseURL, GatewayGrokOAuthModel
				s, err := NewGatewayNativeGrokOAuth(repo, nativeFixtureCustody(t), transport, GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
				require.NoError(t, err)
				hydrate = s.HydrateAccountInfo
				maintain = s.Maintain
				require.NoError(t, s.SetEntryAuthorizers(allow, allow))
				seal = func(at time.Time) (string, error) {
					return s.seal(scope, gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: "private-access", RefreshToken: "private-refresh", Subject: repo.physical.Subject, Team: repo.physical.ProviderAccount, ExpiresAt: expiry, ObservedAt: at, Nonce: strings.Repeat("n", 43), ClientID: "qualified-client"})
				}
			}
			var err error
			repo.envelope, err = seal(time.Time{})
			require.NoError(t, err)
			require.NoError(t, hydrate(ctx, scope, "connect"))
			require.Empty(t, repo.stored, "legacy missing observation time stays unknown")
			original := time.Now().UTC().Add(-48 * time.Hour)
			repo.envelope, err = seal(original)
			require.NoError(t, err)
			repo.storeErr = ErrGatewayNativeIdentity
			_, err = maintain(ctx, scope, "connect")
			require.ErrorIs(t, err, ErrGatewayNativeIdentity, "explicit maintenance must surface failed initialization")
			require.Empty(t, repo.stored)
			require.False(t, repo.physical.AccountInfoInitialized)
			repo.storeErr = nil
			maintained, err := maintain(ctx, scope, "connect")
			require.NoError(t, err)
			require.Equal(t, "idle", maintained.State)
			require.False(t, repo.held, "release custody before acquiring the snapshot write fence")
			require.Len(t, repo.stored, 1)
			o := repo.stored[0]
			require.Equal(t, original.Format(time.RFC3339Nano), o.Fields.CredentialExpiresAt.ObservedAt)
			fields, ok := GatewayAccountInfoProject(repo.physical.Route.Profile, GatewayAccountInfoStored{Revision: 1, CredentialRevision: 1, Sources: map[string]GatewayAccountInfoObservation{"credential": o}}, time.Now())
			require.True(t, ok)
			require.Equal(t, "stale", fields.CredentialExpiresAt.Freshness)
			require.Equal(t, "unknown", fields.Email.Status)
			_, err = maintain(ctx, scope, "connect")
			require.NoError(t, err)
			require.Len(t, repo.stored, 1, "an initialized idle account does not acquire a snapshot write transaction")
			foreign := scope
			foreign.Owner = "foreign"
			require.Error(t, hydrate(ctx, foreign, "connect"))
			repo.envelope, err = seal(expiry.Add(time.Minute))
			require.NoError(t, err)
			require.Error(t, hydrate(ctx, scope, "connect"))
			require.Len(t, repo.stored, 1)
		})
	}
}
