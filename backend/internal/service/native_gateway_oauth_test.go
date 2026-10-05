package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func oauthFixtureKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}
func oauthFixtureSign(t *testing.T, key *rsa.PrivateKey, header, claims string) string {
	t.Helper()
	body := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	digest := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return body + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func oauthFixtureClaims(subject string, now time.Time) string {
	return fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":%q,"exp":%d,"iat":%d,"nbf":%d}`, GatewayOAuthIssuer, subject, gatewayOAuthAudience, now.Add(time.Hour).Unix(), now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix())
}
func oauthFixtureJWK(key *rsa.PrivateKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}
}
func oauthFixtureVerifier(t *testing.T, handler http.Handler, now time.Time) *GatewayNativeOAuthVerifier {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "auth.openai.com:443", address)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }
	client.Timeout = 2 * time.Second
	return &GatewayNativeOAuthVerifier{client: client, now: func() time.Time { return now }}
}

// Failure: decode-only JWT authority could reserve a fabricated subject, or a
// valid signature could authorize ambiguous/wrong critical claims.
func TestGatewayNativeOAuthSignedIdentityAndClaimRejections(t *testing.T) {
	key := oauthFixtureKey(t)
	other := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	var requests atomic.Int32
	verifier := oauthFixtureVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, "/.well-known/jwks.json", r.URL.Path)
		require.Equal(t, "auth.openai.com", r.Host)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
	}), now)
	header := `{"alg":"RS256","kid":"fixture","typ":"JWT"}`
	claims := oauthFixtureClaims("synthetic-subject", now)
	signed := oauthFixtureSign(t, key, header, claims)
	identity, err := verifier.Verify(context.Background(), signed)
	require.NoError(t, err)
	issuer, subject := identity.Principal()
	require.Equal(t, GatewayOAuthIssuer, issuer)
	require.Equal(t, "synthetic-subject", subject)
	require.True(t, identity.Verified())
	require.Positive(t, requests.Load())
	cases := map[string]string{
		"unsigned RS256":        strings.Join(strings.Split(signed, ".")[:2], ".") + ".",
		"wrong signature":       oauthFixtureSign(t, other, header, claims),
		"unknown key":           oauthFixtureSign(t, key, strings.ReplaceAll(header, "fixture", "missing"), claims),
		"unsigned none":         oauthFixtureSign(t, key, strings.ReplaceAll(header, "RS256", "none"), claims),
		"untrusted header jwks": oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture","jku":"https://evil.invalid/jwks"}`, claims),
	}
	mutations := map[string]string{
		"issuer":                     strings.ReplaceAll(claims, GatewayOAuthIssuer, "https://evil.invalid"),
		"audience":                   strings.ReplaceAll(claims, gatewayOAuthAudience, "wrong-client"),
		"empty subject":              strings.ReplaceAll(claims, "synthetic-subject", ""),
		"expired":                    strings.ReplaceAll(claims, fmt.Sprint(now.Add(time.Hour).Unix()), fmt.Sprint(now.Add(-time.Second).Unix())),
		"not yet valid":              strings.ReplaceAll(claims, fmt.Sprint(now.Add(-time.Minute).Unix()), fmt.Sprint(now.Add(time.Minute).Unix())),
		"duplicate escaped issuer":   strings.TrimSuffix(claims, "}") + `,"\u0069ss":"https://evil.invalid"}`,
		"issuer case alias":          strings.TrimSuffix(claims, "}") + `,"ISS":"https://evil.invalid"}`,
		"unicode critical name":      strings.TrimSuffix(claims, "}") + `,"ｅxp":9999999999}`,
		"fractional expiry":          strings.ReplaceAll(claims, fmt.Sprint(now.Add(time.Hour).Unix()), fmt.Sprint(now.Add(time.Hour).Unix())+".5"),
		"null expiry":                strings.ReplaceAll(claims, fmt.Sprint(now.Add(time.Hour).Unix()), "null"),
		"missing expiry":             fmt.Sprintf(`{"iss":%q,"sub":"synthetic","aud":%q}`, GatewayOAuthIssuer, gatewayOAuthAudience),
		"unpaired subject surrogate": strings.ReplaceAll(claims, `"synthetic-subject"`, `"\ud800"`),
		"subject wrong type":         strings.ReplaceAll(claims, `"synthetic-subject"`, `["synthetic-subject"]`),
		"multiple audiences":         strings.ReplaceAll(claims, fmt.Sprintf(`"aud":%q`, gatewayOAuthAudience), fmt.Sprintf(`"aud":[%q,"other"]`, gatewayOAuthAudience)),
	}
	for name, mutated := range mutations {
		cases[name] = oauthFixtureSign(t, key, header, mutated)
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			identity, err := verifier.Verify(context.Background(), encoded)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.False(t, identity.Verified())
			require.NotContains(t, err.Error(), "synthetic-subject")
		})
	}
	singleton := strings.ReplaceAll(claims, fmt.Sprintf(`"aud":%q`, gatewayOAuthAudience), fmt.Sprintf(`"aud":[%q]`, gatewayOAuthAudience))
	_, err = verifier.Verify(context.Background(), oauthFixtureSign(t, key, header, singleton))
	require.NoError(t, err)
}

// Failure: redirected, ambiguous or malformed JWKS could substitute an attacker's
// public key even though the JWT itself has a genuine cryptographic signature.
func TestGatewayNativeOAuthJWKSRejectsUntrustedMaterial(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	token := oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims("synthetic", now))
	for _, name := range []string{"redirect", "duplicate kid", "small modulus", "bad exponent", "encryption key", "private material", "bad key_ops", "duplicate field", "wrong alg", "oversized"} {
		t.Run(name, func(t *testing.T) {
			jwk := oauthFixtureJWK(key)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "redirect":
					http.Redirect(w, r, "https://untrusted.invalid/keys", http.StatusFound)
					return
				case "duplicate kid":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk, jwk}})
					return
				case "small modulus":
					jwk["n"] = "AQAB"
				case "bad exponent":
					jwk["e"] = "Aw"
				case "encryption key":
					jwk["use"] = "enc"
				case "private material":
					jwk["d"] = "private"
				case "bad key_ops":
					jwk["key_ops"] = []string{"sign", "verify"}
				case "wrong alg":
					jwk["alg"] = "HS256"
				case "duplicate field":
					_, _ = w.Write([]byte(`{"keys":[{"kid":"fixture","kid":"fixture"}]}`))
					return
				case "oversized":
					_, _ = w.Write([]byte(strings.Repeat(" ", 65537)))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
			})
			_, err := oauthFixtureVerifier(t, handler, now).Verify(context.Background(), token)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
}

// Failure: OAuth ciphertext could be opened with an API-key purpose, a foreign
// scope, a retired/same-ID wrong key, or tampered data; API-key Seal must stay gcn1.
func TestGatewayNativeOAuthCustodyDomainAndExactAAD(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	custody, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "logical", Generation: "11111111-1111-4111-8111-111111111111", Purpose: GatewayOAuthBundlePurpose}
	bundle := GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixture1, RefreshToken: gatewayOAuthGuardFixture2, IDToken: "synthetic-id", SensitiveMetadata: json.RawMessage(`{"sensitive":"synthetic-metadata"}`)}
	envelope, err := custody.SealOAuthBundle(scope, bundle)
	require.NoError(t, err)
	require.NoError(t, custody.ValidateOAuthEnvelope(envelope))
	require.NotContains(t, envelope, "synthetic")
	opened, err := custody.openOAuthBundle(envelope, scope)
	require.NoError(t, err)
	require.Equal(t, bundle, opened)
	_, err = custody.Seal(scope, "apikey")
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = custody.authorization(envelope, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	for _, field := range []string{"consumer", "owner", "account", "generation", "purpose"} {
		t.Run(field, func(t *testing.T) {
			foreign := scope
			switch field {
			case "consumer":
				foreign.Consumer = "foreign"
			case "owner":
				foreign.Owner = "foreign"
			case "account":
				foreign.Account = "foreign"
			case "generation":
				foreign.Generation = "22222222-2222-4222-8222-222222222222"
			case "purpose":
				foreign.Purpose = GatewayCredentialPurpose
			}
			_, err := custody.openOAuthBundle(envelope, foreign)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
	id, nonce, sealed, err := gatewayOAuthParseEnvelope(envelope)
	require.NoError(t, err)
	sealed[0] ^= 1
	tampered := "gco1." + id + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed)
	_, err = custody.openOAuthBundle(tampered, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	wrong, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": make([]byte, 32)})
	require.NoError(t, err)
	_, err = wrong.openOAuthBundle(envelope, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	retired, err := NewGatewayNativeCredentialCustody("new", map[string][]byte{"new": key})
	require.NoError(t, err)
	require.ErrorIs(t, retired.ValidateOAuthEnvelope(envelope), ErrGatewayNativeIdentity)
	_, err = retired.openOAuthBundle(envelope, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	malformed, err := custody.sealOAuthBytes(scope, []byte(`{"access_token":"synthetic"}`))
	require.NoError(t, err)
	_, err = custody.openOAuthBundle(malformed, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	apiScope := scope
	apiScope.Purpose = GatewayCredentialPurpose
	api, err := custody.Seal(apiScope, gatewayOAuthGuardFixture3)
	require.NoError(t, err)
	auth, err := custody.authorization(api, apiScope)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+gatewayOAuthGuardFixture3, auth)
	_, err = custody.openOAuthBundle(api, scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	row := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusDisabled, Schedulable: false, Extra: map[string]any{GatewayGenerationExtraKey: scope.Generation, GatewayProfileExtraKey: GatewayOAuthStagingProfile, GatewayCredentialScopeExtraKey: scope.Metadata()}, Credentials: map[string]any{"oauth_bundle": envelope}}
	require.True(t, HasGatewayNativeIdentity(row))
	_, err = GatewayNativeDescriptor(row)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
}

// Redis protocol endpoint records all token-cache operations. A seeded usable
// hit proves the guard runs before an ordinary access token can escape.
type oauthGuardCache struct {
	client *redis.Client
	calls  atomic.Int32
}

func (c *oauthGuardCache) GetAccessToken(ctx context.Context, key string) (string, error) {
	c.calls.Add(1)
	return c.client.Get(ctx, key).Result()
}
func (c *oauthGuardCache) SetAccessToken(ctx context.Context, key, value string, ttl time.Duration) error {
	c.calls.Add(1)
	return c.client.Set(ctx, key, value, ttl).Err()
}
func (c *oauthGuardCache) DeleteAccessToken(ctx context.Context, key string) error {
	c.calls.Add(1)
	return c.client.Del(ctx, key).Err()
}
func (c *oauthGuardCache) AcquireRefreshLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	c.calls.Add(1)
	return c.client.SetNX(ctx, key+":lock", "owned", ttl).Result()
}
func (c *oauthGuardCache) ReleaseRefreshLock(ctx context.Context, key string) error {
	c.calls.Add(1)
	return c.client.Del(ctx, key+":lock").Err()
}

// Failure: managed rows, even malformed markers, could use a Redis hit, publish
// plaintext tokens, acquire a refresh lock, or enter direct refresh.
func TestGatewayNativeOAuthOrdinaryGuardsBeforeTokenCacheAndRefresh(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer client.Close()
	cache := &oauthGuardCache{client: client}
	ctx := context.Background()
	for _, marker := range []string{GatewayGenerationExtraKey, GatewayProfileExtraKey, GatewayCredentialScopeExtraKey} {
		t.Run(marker, func(t *testing.T) {
			row := &Account{ID: 41, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Extra: map[string]any{marker: nil}, Credentials: map[string]any{"access_token": "synthetic-plaintext-access", "refresh_token": "synthetic-plaintext-refresh", "expires_at": "1"}}
			cacheKey := OpenAITokenCacheKey(row)
			require.NoError(t, client.Set(ctx, cacheKey, "synthetic-cache-hit", time.Hour).Err())
			before := redisServer.Dump()
			provider := NewOpenAITokenProvider(nil, cache, nil)
			token, err := provider.GetAccessToken(ctx, row)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Empty(t, token)
			// Nil provider/repository would panic if either path passed the guard.
			api := NewOAuthRefreshAPI(nil, cache)
			result, err := api.RefreshIfNeeded(ctx, row, &OpenAITokenRefresher{}, time.Hour)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Nil(t, result)
			refresher := NewOpenAITokenRefresher(nil, nil)
			require.False(t, refresher.CanRefresh(row))
			require.False(t, refresher.NeedsRefresh(row, time.Hour))
			credentials, err := refresher.Refresh(ctx, row)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Nil(t, credentials)
			require.Zero(t, cache.calls.Load())
			require.Equal(t, before, redisServer.Dump())
			require.NotContains(t, redisServer.Dump(), "synthetic-plaintext")
		})
	}
	ordinary := &Account{ID: 41, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	token, err := NewOpenAITokenProvider(nil, cache, nil).GetAccessToken(ctx, ordinary)
	require.NoError(t, err)
	require.Equal(t, "synthetic-cache-hit", token)
	require.Equal(t, int32(1), cache.calls.Load())
}

type oauthFreshManagedRepo struct {
	AccountRepository
	row   *Account
	reads atomic.Int32
}

func (r *oauthFreshManagedRepo) GetByID(context.Context, int64) (*Account, error) {
	r.reads.Add(1)
	return r.row, nil
}

// Failure: an initially ordinary snapshot could fall back to cached plaintext
// after the repository returns a managed identity, or refresh a managed reread.
func TestGatewayNativeOAuthFreshManagedRowsDenyOrdinaryPublication(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer client.Close()
	cache := &oauthGuardCache{client: client}
	managed := &Account{ID: 72, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Extra: map[string]any{GatewayCredentialScopeExtraKey: nil}}
	repo := &oauthFreshManagedRepo{row: managed}
	ordinary := &Account{ID: 72, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Credentials: map[string]any{"access_token": "synthetic-stale-access", "expires_at": time.Now().Add(time.Hour).Unix()}}
	token, err := NewOpenAITokenProvider(repo, cache, nil).GetAccessToken(context.Background(), ordinary)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.Empty(t, token)
	require.Positive(t, repo.reads.Load())
	require.Empty(t, redisServer.Keys())
	// This refresh path does acquire/release the ordinary snapshot's lock. The
	// fresh managed row must deny before a provider/executor or token write.
	result, err := NewOAuthRefreshAPI(repo, cache).RefreshIfNeeded(context.Background(), ordinary, &OpenAITokenRefresher{}, time.Hour)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.Nil(t, result)
	require.Empty(t, redisServer.Keys())
}

func gatewayOAuthGuardFixtureOpaque() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("synthetic fixture entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var gatewayOAuthGuardFixture1 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture2 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture3 = gatewayOAuthGuardFixtureOpaque()
