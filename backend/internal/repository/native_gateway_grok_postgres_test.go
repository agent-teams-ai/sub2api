package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type grokPGTransport func(*http.Request) (*http.Response, error)

func (f grokPGTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Real migrated PostgreSQL owns all one-use entry, birth, principal, maintenance
// and cache fences. The only fake is the provider HTTP transport; no live login.
func TestGatewayNativeGrokPostgresProtectedOAuthLifecycle(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_GROK_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: disposable Grok PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	require.Contains(t, []string{"127.0.0.1", "::1"}, u.Hostname())
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_grok_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(6)
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	source, err := NewGatewayNativeGrokRepository(db)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("grok-test", map[string][]byte{"grok-test": key})
	require.NoError(t, err)
	account, team := uuid.NewString(), uuid.NewString()
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonce := ""
	var exchanges atomic.Int32
	var mode atomic.Int32
	challenge := ""
	transport := grokPGTransport(func(r *http.Request) (*http.Response, error) {

		if r.URL.String() == xai.ProtectedJWKSURL {
			body, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "fixture", "x": base64.RawURLEncoding.EncodeToString(signing.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(signing.Y.FillBytes(make([]byte, 32)))}}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
		}
		if r.URL.String() == xai.ProtectedUserinfoURL {
			require.Equal(t, "Bearer fixture-access-private", r.Header.Get("Authorization"))
			body, _ := json.Marshal(map[string]string{"sub": account, "team_id": team})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
		}
		exchanges.Add(1)
		require.Equal(t, xai.DefaultTokenURL, r.URL.String())
		require.Equal(t, http.MethodPost, r.Method)
		require.Empty(t, r.Header.Get("Cookie"))
		require.Empty(t, r.Header.Get("Authorization"))
		require.NoError(t, r.ParseForm())
		body := map[string]any{}
		for k, v := range r.Form {
			body[k] = v[0]
		}
		require.Equal(t, "qualified-client", body["client_id"])

		if body["grant_type"] == "authorization_code" {
			verifier, ok := body["code_verifier"].(string)
			require.True(t, ok)
			digest := sha256.Sum256([]byte(verifier))
			require.Equal(t, challenge, base64.RawURLEncoding.EncodeToString(digest[:]))
			require.Equal(t, xai.DefaultRedirectURI, body["redirect_uri"])
		} else {
			require.Equal(t, "refresh_token", body["grant_type"])
			require.Equal(t, "fixture-refresh-private", body["refresh_token"])
		}
		if mode.Load() == 2 {
			return nil, service.ErrGatewayNativeIdentity
		}
		principal := account
		if mode.Load() == 1 {
			principal = uuid.NewString()
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": xai.OAuthIssuer, "aud": "qualified-client", "sub": principal, "team_id": team, "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
		token.Header["kid"] = "fixture"
		idToken, e := token.SignedString(signing)
		require.NoError(t, e)
		payload, _ := json.Marshal(map[string]any{"access_token": "fixture-access-private", "refresh_token": "fixture-refresh-private", "id_token": idToken, "token_type": "Bearer", "expires_in": 60, "scope": "openid grok-cli:access"})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(payload))), Request: r}, nil
	})
	grok, err := service.NewGatewayNativeGrokOAuth(source, custody, transport, service.GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
	require.NoError(t, err)
	allow := func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }
	require.NoError(t, grok.SetEntryAuthorizers(allow, allow))
	ownerCtx, scope := oauthPGScope(t, uuid.NewString(), uuid.NewString(), uuid.NewString())
	ownerCtx, cancelOwner := context.WithTimeout(ownerCtx, 50*time.Second)
	defer cancelOwner()
	op := uuid.NewString()
	begin := func(s service.GatewayNativeCredentialScope, operation string) service.GatewayNativeOAuthConnectResult {
		out, e := grok.BeginConnectMethod(ownerCtx, s, operation, "browser")
		require.NoError(t, e)
		parsed, e := url.Parse(out.AuthorizeURL)
		require.NoError(t, e)
		challenge = parsed.Query().Get("code_challenge")
		nonce = parsed.Query().Get("nonce")
		require.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
		return out
	}
	first := begin(scope, op)
	repeat := begin(scope, op)
	require.Equal(t, first, repeat)
	_, err = grok.BeginConnectMethod(ownerCtx, scope, uuid.NewString(), "device_code")
	require.Error(t, err)
	require.Zero(t, exchanges.Load())
	parsed, err := url.Parse(first.AuthorizeURL)
	require.NoError(t, err)
	state := parsed.Query().Get("state")
	_, err = grok.CompleteOwnerCallback(ownerCtx, scope, op, strings.Repeat("0", 64), "fixture-code")
	require.Error(t, err)
	require.Zero(t, exchanges.Load())

	restarted, err := service.NewGatewayNativeGrokOAuth(source, custody, transport, service.GatewayNativeGrokOAuthQualification{ClientID: "qualified-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
	require.NoError(t, err)
	require.NoError(t, restarted.SetEntryAuthorizers(allow, allow))
	type completion struct {
		out service.GatewayNativeOAuthConnectResult
		err error
	}
	results := make(chan completion, 2)
	for _, instance := range []*service.GatewayNativeGrokOAuth{grok, restarted} {
		go func(instance *service.GatewayNativeGrokOAuth) {
			out, e := instance.CompleteOwnerCallback(ownerCtx, scope, op, state, "fixture-code")
			results <- completion{out, e}
		}(instance)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		done := <-results
		if done.err == nil {
			successes++
			require.Equal(t, "completed", done.out.State)
			require.Equal(t, "staged", done.out.Outcome)
		}
	}
	require.Positive(t, successes)

	_, err = grok.CompleteOwnerCallback(ownerCtx, scope, op, state, "fixture-code")
	require.NoError(t, err)
	require.EqualValues(t, 1, exchanges.Load())
	descriptor, err := grok.Descriptor(ownerCtx, scope, op)
	require.NoError(t, err)
	require.Equal(t, "controlled-source-v1", descriptor.Qualification)
	require.NotNil(t, descriptor.Native)
	route := *descriptor.Native
	gatewayAccountLimitsV2GrokPostgresFixture(t, ownerCtx, db, scope, op, route)
	var stored string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials::text||extra::text FROM accounts WHERE id=$1`, route.AccountID).Scan(&stored))
	require.NotContains(t, stored, "fixture-access-private")
	require.NotContains(t, stored, "fixture-refresh-private")
	require.NotContains(t, stored, "id_token")
	for _, sql := range []string{`UPDATE accounts SET schedulable=true WHERE id=$1`, `UPDATE accounts SET credentials='{}'::jsonb WHERE id=$1`, `UPDATE accounts SET extra='{}'::jsonb WHERE id=$1`, `DELETE FROM accounts WHERE id=$1`} {
		_, e := db.ExecContext(ctx, sql, route.AccountID)
		require.Error(t, e)
	}
	entry, err := grok.Enter(ownerCtx, scope, op, route)
	require.NoError(t, err)
	require.True(t, entry.Claim())
	require.False(t, entry.Claim())
	entry.Release()
	require.EqualValues(t, 1, exchanges.Load())
	// A fresh physical admission fences refresh until its own release. Passive
	// publication releases admission before rechecking source identity in SQL.
	entry, err = grok.Enter(ownerCtx, scope, op, route)
	require.NoError(t, err)
	// Refresh waits for the admitted request's physical fence.
	refreshDone := make(chan error, 1)
	refreshOp := uuid.NewString()
	go func() { _, e := grok.Refresh(ownerCtx, scope, op, refreshOp); refreshDone <- e }()
	select {
	case e := <-refreshDone:
		t.Fatalf("refresh crossed physical fence: %v", e)
	case <-time.After(75 * time.Millisecond):
	}
	require.EqualValues(t, 1, exchanges.Load())
	entry.Release()
	require.NoError(t, <-refreshDone)
	require.EqualValues(t, 2, exchanges.Load())
	again, err := grok.Refresh(ownerCtx, scope, op, refreshOp)
	require.NoError(t, err)
	require.Equal(t, "completed", again.State)
	require.EqualValues(t, 2, exchanges.Load())
	// The facade always sends the same original connect operation. Native
	// maintenance derives a new attempt from each due encrypted revision.
	maintenance1, err := grok.Maintain(ownerCtx, scope, op)
	require.NoError(t, err)
	require.Equal(t, "completed", maintenance1.State)
	require.Equal(t, op, maintenance1.Operation)
	require.NotEmpty(t, maintenance1.RefreshRef)
	maintenance2, err := grok.Maintain(ownerCtx, scope, op)
	require.NoError(t, err)
	require.Equal(t, "completed", maintenance2.State)
	require.NotEqual(t, maintenance1.RefreshRef, maintenance2.RefreshRef)
	require.EqualValues(t, 4, exchanges.Load())
	replayed, err := grok.Refresh(ownerCtx, scope, op, maintenance1.RefreshRef)
	require.NoError(t, err)
	require.Equal(t, "completed", replayed.State)
	require.EqualValues(t, 4, exchanges.Load())
	// A second intent that preflighted the old due credential may not claim
	// the already refreshed revision, even if it arrives after first completion.
	staleOp := uuid.NewString()
	_, _, _, err = source.ClaimGatewayGrokRefresh(ownerCtx, scope, op, staleOp, 1)
	require.Error(t, err)
	var staleAttempts int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_grok_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, staleOp).Scan(&staleAttempts))
	require.Zero(t, staleAttempts)
	require.EqualValues(t, 4, exchanges.Load())
	// A changed provider identity never replaces encrypted custody or rearms entry.
	mode.Store(1)
	badRefresh := uuid.NewString()
	unknown, err := grok.Refresh(ownerCtx, scope, op, badRefresh)
	require.Error(t, err)
	require.Equal(t, "unknown", unknown.State)
	require.EqualValues(t, 5, exchanges.Load())
	unknown, err = grok.Refresh(ownerCtx, scope, op, badRefresh)
	require.NoError(t, err)
	require.Equal(t, "unknown", unknown.State)
	require.EqualValues(t, 5, exchanges.Load())
	_, err = grok.Enter(ownerCtx, scope, op, route)
	require.Error(t, err)
	cleanup := service.GatewayNativeOAuthCleanupRequest{Scope: scope, Operation: op, Action: "erase", CleanupRef: uuid.NewString(), CleanupToken: uuid.NewString()}
	authority := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
		return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: time.Now().Add(time.Second), Native: &route}, nil
	}
	erased, err := grok.Cleanup(ownerCtx, cleanup, authority)
	require.NoError(t, err)
	require.True(t, erased.CredentialsErased)
	require.Equal(t, "unknown", erased.Closure)
	erased, err = grok.Cleanup(ownerCtx, cleanup, authority)
	require.NoError(t, err)
	require.Equal(t, "unknown", erased.Closure)
	// Reconnect creates a fresh birth for this permanently owned principal.
	mode.Store(0)
	next := scope
	next.Generation = uuid.NewString()
	nextOp := uuid.NewString()
	nextBegin := begin(next, nextOp)
	parsed, err = url.Parse(nextBegin.AuthorizeURL)
	require.NoError(t, err)
	_, err = grok.CompleteOwnerCallback(ownerCtx, next, nextOp, parsed.Query().Get("state"), "fixture-code")
	require.NoError(t, err)
	nextDescriptor, err := grok.Descriptor(ownerCtx, next, nextOp)
	require.NoError(t, err)
	require.NotEqual(t, route.AccountID, nextDescriptor.Native.AccountID)
	foreign := scope
	foreign.Account = uuid.NewString()
	foreign.Generation = uuid.NewString()
	foreignOp := uuid.NewString()
	foreignBegin := begin(foreign, foreignOp)
	parsed, err = url.Parse(foreignBegin.AuthorizeURL)
	require.NoError(t, err)
	_, err = grok.CompleteOwnerCallback(ownerCtx, foreign, foreignOp, parsed.Query().Get("state"), "fixture-code")
	require.Error(t, err)
	// Erasure before a physical birth retains a durable closure readback. An
	// uncertain token exchange stays unknown even after material is erased.
	for _, uncertain := range []bool{false, true} {
		pendingScope := scope
		pendingScope.Account = uuid.NewString()
		pendingScope.Generation = uuid.NewString()
		pendingOp := uuid.NewString()
		pendingBegin := begin(pendingScope, pendingOp)
		if uncertain {
			mode.Store(2)
			pendingURL, e := url.Parse(pendingBegin.AuthorizeURL)
			require.NoError(t, e)
			_, e = grok.CompleteOwnerCallback(ownerCtx, pendingScope, pendingOp, pendingURL.Query().Get("state"), "fixture-code")
			require.Error(t, e)
		}
		noBirthGrant := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: time.Now().Add(time.Second)}, nil
		}
		pendingCleanup := service.GatewayNativeOAuthCleanupRequest{Scope: pendingScope, Operation: pendingOp, Action: "erase", CleanupRef: uuid.NewString(), CleanupToken: uuid.NewString()}
		closed, e := grok.Cleanup(ownerCtx, pendingCleanup, noBirthGrant)
		require.NoError(t, e)
		require.True(t, closed.CredentialsErased)
		require.Nil(t, closed.Native)
		expected := "closed"
		if uncertain {
			expected = "unknown"
		}
		require.Equal(t, expected, closed.Closure)
		pendingCleanup.Action = "read"
		closed, e = grok.Cleanup(ownerCtx, pendingCleanup, noBirthGrant)
		require.NoError(t, e)
		require.True(t, closed.CredentialsErased)
		require.Equal(t, expected, closed.Closure)
	}

}
