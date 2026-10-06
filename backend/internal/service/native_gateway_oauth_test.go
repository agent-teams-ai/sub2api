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
	baseTransport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "auth.openai.com:443", address)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	verifier := NewGatewayNativeOAuthVerifier(transport)
	verifier.now = func() time.Time { return now }
	return verifier
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

// Failure: a genuinely signed token can expire while JWKS is being fetched;
// using the pre-fetch clock can then grant first-enrollment identity authority.
func TestGatewayNativeOAuthTemporalClaimsAfterJWKS(t *testing.T) {
	key := oauthFixtureKey(t)
	start := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name      string
		retrieved time.Time
		exp       time.Time
		nbf       time.Time
		iat       time.Time
		valid     bool
	}{
		{"still valid after retrieval", start.Add(30 * time.Second), start.Add(time.Minute), start.Add(-time.Minute), start.Add(-time.Minute), true},
		{"expires at retrieval", start.Add(time.Minute), start.Add(time.Minute), start.Add(-time.Minute), start.Add(-time.Minute), false},
		{"expires during retrieval", start.Add(2 * time.Minute), start.Add(time.Minute), start.Add(-time.Minute), start.Add(-time.Minute), false},
		{"not yet valid after clock adjustment", start.Add(-2 * time.Minute), start.Add(time.Hour), start.Add(-time.Minute), start.Add(-3 * time.Minute), false},
		{"issued in future after clock adjustment", start.Add(-2 * time.Minute), start.Add(time.Hour), start.Add(-3 * time.Minute), start.Add(-time.Minute), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock atomic.Int64
			clock.Store(start.Unix())
			var requests atomic.Int32
			verifier := oauthFixtureVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				require.Equal(t, "auth.openai.com", r.Host)
				require.Equal(t, "/.well-known/jwks.json", r.URL.Path)
				// Model elapsed retrieval time without wall-clock sleeps. The key
				// is returned only after the trusted clock has changed.
				clock.Store(tc.retrieved.Unix())
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
			}), start)
			verifier.now = func() time.Time { return time.Unix(clock.Load(), 0) }
			claims := fmt.Sprintf(`{"iss":%q,"sub":"synthetic-subject","aud":%q,"exp":%d,"nbf":%d,"iat":%d}`, GatewayOAuthIssuer, gatewayOAuthAudience, tc.exp.Unix(), tc.nbf.Unix(), tc.iat.Unix())
			token := oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, claims)
			identity, err := verifier.Verify(context.Background(), token)
			if tc.valid {
				require.NoError(t, err)
				require.True(t, identity.Verified())
			} else {
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.Equal(t, GatewayNativeOAuthIdentity{}, identity)
			}
			require.Equal(t, int32(1), requests.Load())
		})
	}
}

// Failure: removing the production factory's redirect policy can contact an
// untrusted key destination even when the eventual JWKS origin check denies.
func TestGatewayNativeOAuthProductionVerifierRejectsRedirectWithoutDestinationRequest(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Unix(1800000000, 0)
	var sourceRequests, destinationRequests atomic.Int32
	var redirect atomic.Bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationRequests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceRequests.Add(1)
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/.well-known/jwks.json", r.URL.Path)
		if redirect.Load() {
			http.Redirect(w, r, destination.URL+"/keys", http.StatusFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
	}))
	defer source.Close()
	baseTransport, ok := source.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case "auth.openai.com:443":
			address = source.Listener.Addr().String()
		case destination.Listener.Addr().String():
		default:
			return nil, fmt.Errorf("unexpected fixture destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	verifier := NewGatewayNativeOAuthVerifier(transport)
	verifier.now = func() time.Time { return now }
	token := oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims("synthetic-subject", now))
	// Establish that the controlled source can satisfy the complete production
	// issuer/audience/JWKS/signature contract before testing redirect refusal.
	identity, err := verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	require.True(t, identity.Verified())
	redirect.Store(true)
	identity, err = verifier.Verify(context.Background(), token)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.Equal(t, GatewayNativeOAuthIdentity{}, identity)
	require.Equal(t, int32(2), sourceRequests.Load())
	require.Zero(t, destinationRequests.Load())
}

// Failure: ambiguous or malformed JWKS could substitute an attacker's
// public key even though the JWT itself has a genuine cryptographic signature.
func TestGatewayNativeOAuthJWKSRejectsUntrustedMaterial(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	token := oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims("synthetic", now))
	for _, name := range []string{"duplicate kid", "small modulus", "bad exponent", "encryption key", "private material", "bad key_ops", "duplicate field", "wrong alg", "oversized"} {
		t.Run(name, func(t *testing.T) {
			jwk := oauthFixtureJWK(key)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
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

// Fresh signed token authority cannot survive a bounded JWKS timeout. Signature
// authenticity alone never substitutes for successful fixed-origin verification.
func TestGatewayNativeOAuthSignedIdentityRetrievalDeadline(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	var calls atomic.Int32
	verifier := oauthFixtureVerifier(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }), now)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	identity, err := verifier.Verify(ctx, oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims("reserved-subject", now)))
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.False(t, identity.Verified())
	require.Equal(t, int32(1), calls.Load())
	require.Less(t, time.Since(start), time.Second)
}
