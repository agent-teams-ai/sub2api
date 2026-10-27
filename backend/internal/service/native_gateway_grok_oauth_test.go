//go:build unit

package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/stretchr/testify/require"
)

type grokFixtureRepository struct {
	GatewayNativeGrokRepository
	row    GatewayGrokConnectIntent
	claims int
}

func (r *grokFixtureRepository) PutGatewayGrokConnect(_ context.Context, in GatewayGrokConnectIntent) (GatewayGrokConnectIntent, error) {
	if r.row.Operation == "" {
		r.row = in
	}
	return r.row, nil
}
func (r *grokFixtureRepository) ReadGatewayGrokConnect(_ context.Context, s GatewayNativeCredentialScope, op string) (GatewayGrokConnectIntent, error) {
	if r.row.Scope != s || r.row.Operation != op {
		return GatewayGrokConnectIntent{}, ErrGatewayNativeIdentity
	}
	return r.row, nil
}
func (r *grokFixtureRepository) ClaimGatewayGrokConnect(_ context.Context, s GatewayNativeCredentialScope, op, hash string) (GatewayGrokConnectIntent, error) {
	if r.row.State != "prepared" || r.row.StateHash != hash {
		return GatewayGrokConnectIntent{}, ErrGatewayNativeIdentity
	}
	r.claims++
	r.row.State = "exchanging"
	return r.row, nil
}

type grokFixtureHTTP func(*http.Request) (*http.Response, error)

func (f grokFixtureHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayGrokSingleEffectPKCEAndQualification(t *testing.T) {
	_, _, ctx, scope := connectPureFixture(t)
	custody := nativeFixtureCustody(t)
	repo := &grokFixtureRepository{}
	qualified := GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true}
	disabled := qualified
	disabled.DeploymentQualified = false
	_, err := NewGatewayNativeGrokOAuth(repo, custody, nil, disabled)
	require.Error(t, err)
	for _, redirect := range []string{"http://attacker.example/callback", "http://127.0.0.1:1234/callback", "https://host.example/callback?", "https://host.example/callback#", "https://user@host.example/callback", "https://host.example"} {
		q := qualified
		q.RedirectURI = redirect
		require.False(t, GatewayNativeGrokQualificationValid(q), redirect)
	}
	hosted := qualified
	hosted.RedirectURI = "https://review.example/oauth/callback"
	require.True(t, GatewayNativeGrokQualificationValid(hosted))
	calls := 0
	s, err := NewGatewayNativeGrokOAuth(repo, custody, grokFixtureHTTP(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, xai.DefaultTokenURL, r.URL.String())
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		return nil, ErrGatewayNativeIdentity
	}), qualified)
	require.NoError(t, err)
	allow := func(context.Context, GatewayNativeCredentialScope, string) error { return nil }
	require.NoError(t, s.SetEntryAuthorizers(allow, allow))
	first, err := s.BeginConnectMethod(ctx, scope, "operation", "browser")
	require.NoError(t, err)
	repeat, err := s.BeginConnectMethod(ctx, scope, "operation", "browser")
	require.NoError(t, err)
	require.Equal(t, first, repeat)
	u, err := url.Parse(first.AuthorizeURL)
	require.NoError(t, err)
	require.Equal(t, xai.DefaultAuthorizeURL, u.Scheme+"://"+u.Host+u.Path)
	var secret gatewayGrokConnectSecret
	require.NoError(t, s.open(scope, repo.row.Envelope, &secret))
	hash := sha256.Sum256([]byte(secret.Verifier))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), u.Query().Get("code_challenge"))
	require.Equal(t, secret.Nonce, u.Query().Get("nonce"))
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	require.NotContains(t, repo.row.Envelope, secret.Verifier)
	_, err = s.CompleteOwnerCallback(ctx, scope, "operation", strings.Repeat("0", 64), "code")
	require.Error(t, err)
	require.Zero(t, repo.claims)
	require.Zero(t, calls)
	_, err = s.CompleteOwnerCallback(ctx, scope, "operation", secret.State, "code#foreign")
	require.Error(t, err)
	require.Zero(t, repo.claims)
	_, err = s.CompleteOwnerCallback(ctx, scope, "operation", secret.State, "code")
	require.Error(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, repo.claims)
	// A restart shares only sealed state+journal, so uncertain exchange cannot rearm.
	restarted, err := NewGatewayNativeGrokOAuth(repo, custody, s.client.Transport, qualified)
	require.NoError(t, err)
	require.NoError(t, restarted.SetEntryAuthorizers(allow, allow))
	_, err = restarted.CompleteOwnerCallback(ctx, scope, "operation", secret.State, "code")
	require.Error(t, err)
	require.Equal(t, 1, calls)
	view, err := restarted.ReadConnect(ctx, scope, "operation")
	require.NoError(t, err)
	require.Equal(t, "unknown", view.State)
}

// Rotation must preserve the previous verified personal/team binding, including
// providers that legitimately omit refresh_token or id_token on refresh.
func TestGatewayGrokRefreshRotationAndContinuity(t *testing.T) {
	prior := gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: "prior-access", RefreshToken: "prior-refresh", Subject: "owner", Team: "team:team", Nonce: strings.Repeat("n", 43), ClientID: "qualified-client", ExpiresAt: time.Now()}
	for _, mode := range []string{"nonrotation", "rotation", "subject-change", "team-change", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			s := &GatewayNativeGrokOAuth{qualification: GatewayNativeGrokOAuthQualification{ClientID: "qualified-client"}}
			s.client = &http.Client{Transport: grokFixtureHTTP(func(r *http.Request) (*http.Response, error) {
				var body any
				status := 200
				switch r.URL.String() {
				case xai.DefaultTokenURL:
					require.NoError(t, r.ParseForm())
					require.Equal(t, "prior-refresh", r.Form.Get("refresh_token"))
					require.Empty(t, r.Header.Get("Authorization"))
					token := map[string]any{"access_token": "next-access", "token_type": "Bearer", "expires_in": 3600}
					if mode == "rotation" {
						token["refresh_token"] = "rotated-refresh"
					}
					body = token
					if mode == "revoked" {
						status = 400
						body = map[string]string{"error": "invalid_grant"}
					}
				case xai.ProtectedUserinfoURL:
					require.Equal(t, "Bearer next-access", r.Header.Get("Authorization"))
					user := map[string]string{"sub": "owner", "team_id": "team"}
					if mode == "subject-change" {
						user["sub"] = "foreign"
					}
					if mode == "team-change" {
						user["team_id"] = "foreign"
					}
					body = user
				default:
					t.Fatalf("unexpected request %s", r.URL.String())
				}
				raw, _ := json.Marshal(body)
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
			})}
			out, err := s.exchange(context.Background(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {prior.RefreshToken}}, "", &prior)
			if mode == "rotation" || mode == "nonrotation" {
				require.NoError(t, err)
				require.EqualValues(t, 2, out.Revision)
				require.Equal(t, prior.Subject, out.Subject)
				require.Equal(t, prior.Team, out.Team)
				if mode == "rotation" {
					require.Equal(t, "rotated-refresh", out.RefreshToken)
				} else {
					require.Equal(t, prior.RefreshToken, out.RefreshToken)
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}

type grokQuotaLeaseFixture struct {
	GatewayNativeGrokRepository
	physical GatewayNativeOAuthPhysical
	envelope string
	releases int
}

func (r *grokQuotaLeaseFixture) ResolveGatewayGrokCanonical(_ context.Context, _ GatewayNativeRoute, _ string) (GatewayNativeCredentialScope, string, error) {
	return r.physical.Scope, r.physical.Operation, nil
}
func (r *grokQuotaLeaseFixture) LockGatewayGrokPhysical(_ context.Context, scope GatewayNativeCredentialScope, operation string, route *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error) {
	if scope != r.physical.Scope || operation != r.physical.Operation || route == nil || !SameGatewayNativeDescriptor(*route, r.physical.Route) {
		return GatewayNativeOAuthPhysical{}, "", nil, ErrGatewayNativeIdentity
	}
	return r.physical, r.envelope, func() { r.releases++ }, nil
}

// Background quota work gets only an expiring exact-physical credential lease;
// mismatched sealed principals cannot cause requests or leak plaintext material.
func TestGatewayGrokQuotaLeaseCustodyAndNoRefresh(t *testing.T) {
	_, _, ctx, scope := connectPureFixture(t)
	route := GatewayNativeRoute{AccountID: 42, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Generation: scope.Generation, Profile: GatewayGrokOAuthResponsesProfile, BaseURL: GatewayGrokOAuthBaseURL, Model: GatewayGrokOAuthModel}
	r := &grokQuotaLeaseFixture{physical: GatewayNativeOAuthPhysical{Scope: scope, Operation: "connect", Route: route, Issuer: GatewayGrokOAuthIssuer, Subject: "owner", ProviderAccount: "personal:owner", CredentialRevision: 1}}
	s, err := NewGatewayNativeGrokOAuth(r, nativeFixtureCustody(t), grokFixtureHTTP(func(*http.Request) (*http.Response, error) {
		t.Fatal("quota lease called OAuth or inference")
		return nil, ErrGatewayNativeIdentity
	}), GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
	require.NoError(t, err)
	b := gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: "private-access", RefreshToken: "private-refresh", Subject: "owner", Team: "personal:owner", Nonce: strings.Repeat("n", 43), ClientID: "qualified-client", ExpiresAt: time.Now().Add(time.Hour)}
	r.envelope, err = s.seal(scope, b)
	require.NoError(t, err)
	var retained []byte
	require.NoError(t, s.WithQuotaCredential(ctx, scope, route, func(token []byte, p GatewayNativeOAuthPhysical) error {
		require.Equal(t, "private-access", string(token))
		require.Equal(t, r.physical, p)
		retained = token
		return nil
	}))
	require.Equal(t, 1, r.releases)
	require.Equal(t, make([]byte, len(retained)), retained)
	r.physical.Subject = "foreign"
	err = s.WithQuotaCredential(ctx, scope, route, func([]byte, GatewayNativeOAuthPhysical) error {
		t.Fatal("foreign principal reached collector")
		return nil
	})
	require.Error(t, err)
	require.Equal(t, 2, r.releases)
}

// Pasted code recovers PKCE/state from the original sealed intent. It cannot
// borrow another owner/profile/operation or retry an uncertain exchange.
func TestGatewayGrokOwnerAuthorizationCode(t *testing.T) {
	_, _, ctx, scope := connectPureFixture(t)
	repo := &grokFixtureRepository{}
	calls := 0
	verifier := ""
	transport := grokFixtureHTTP(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, xai.DefaultTokenURL, r.URL.String())
		require.NoError(t, r.ParseForm())
		require.Equal(t, "fixture-plain-code", r.Form.Get("code"))
		require.Equal(t, verifier, r.Form.Get("code_verifier"))
		return nil, ErrGatewayNativeIdentity
	})
	qualification := GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true}
	custody := nativeFixtureCustody(t)
	s, err := NewGatewayNativeGrokOAuth(repo, custody, transport, qualification)
	require.NoError(t, err)
	allow := func(context.Context, GatewayNativeCredentialScope, string) error { return nil }
	require.NoError(t, s.SetEntryAuthorizers(allow, allow))
	_, err = s.BeginConnectMethod(ctx, scope, "operation", "browser")
	require.NoError(t, err)
	original := repo.row
	var secret gatewayGrokConnectSecret
	require.NoError(t, s.open(scope, original.Envelope, &secret))
	verifier = secret.Verifier
	for _, tc := range []struct {
		name      string
		scope     GatewayNativeCredentialScope
		operation string
	}{
		{"owner", func() GatewayNativeCredentialScope { x := scope; x.Owner = "foreign-owner"; return x }(), "operation"},
		{"generation", func() GatewayNativeCredentialScope {
			x := scope
			x.Generation = "22222222-2222-4222-8222-222222222222"
			return x
		}(), "operation"},
		{"purpose", func() GatewayNativeCredentialScope { x := scope; x.Purpose = GatewayCredentialPurpose; return x }(), "operation"},
		{"operation", scope, "foreign-operation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CompleteOwnerCode(ctx, tc.scope, tc.operation, "fixture-plain-code")
			require.Error(t, err)
			require.Zero(t, repo.claims)
			require.Zero(t, calls)
		})
	}
	_, err = s.CompleteOwnerCode(context.Background(), scope, "operation", "fixture-plain-code")
	require.Error(t, err)
	for _, code := range []string{"", " code", "code ", "code\n", "code#other", "code?other", "code&other", strings.Repeat("a", 4097), string([]byte{255})} {
		_, err = s.CompleteOwnerCode(ctx, scope, "operation", code)
		require.Error(t, err)
		require.Zero(t, repo.claims)
		require.Zero(t, calls)
	}
	repo.row.StateHash = strings.Repeat("0", 64)
	_, err = s.CompleteOwnerCode(ctx, scope, "operation", "fixture-plain-code")
	require.Error(t, err)
	require.Zero(t, repo.claims)
	repo.row = original
	foreign := secret
	foreign.Kind = "codex-connect/v1"
	repo.row.Envelope, err = s.seal(scope, foreign)
	require.NoError(t, err)
	_, err = s.CompleteOwnerCode(ctx, scope, "operation", "fixture-plain-code")
	require.Error(t, err)
	require.Zero(t, repo.claims)
	require.Zero(t, calls)
	repo.row = original
	_, err = s.CompleteOwnerCallback(ctx, scope, "operation", strings.Repeat("0", 64), "fixture-plain-code")
	require.Error(t, err)
	require.Zero(t, repo.claims)
	_, err = s.CompleteOwnerCode(ctx, scope, "operation", "fixture-plain-code")
	require.Error(t, err)
	require.Equal(t, 1, repo.claims)
	require.Equal(t, 1, calls)
	// The provider outcome is uncertain. Pasting again, including after restart,
	// is authorized readback only; no second claim or upstream exchange occurs.
	restarted, err := NewGatewayNativeGrokOAuth(repo, custody, transport, qualification)
	require.NoError(t, err)
	require.NoError(t, restarted.SetEntryAuthorizers(allow, allow))
	out, err := restarted.CompleteOwnerCode(ctx, scope, "operation", "fixture-plain-code")
	require.NoError(t, err)
	require.Equal(t, "unknown", out.State)
	require.Equal(t, 1, repo.claims)
	require.Equal(t, 1, calls)
	// A completed journal needs no retained PKCE material to return its existing
	// owner-scoped result; completing again cannot mint another credential.
	repo.row.State = "completed"
	repo.row.Envelope = ""
	out, err = s.CompleteOwnerCode(ctx, scope, "operation", "fixture-plain-code")
	require.NoError(t, err)
	require.Equal(t, "staged", out.Outcome)
	require.Equal(t, 1, repo.claims)
	require.Equal(t, 1, calls)
}
