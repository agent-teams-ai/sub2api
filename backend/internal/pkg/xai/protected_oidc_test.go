package xai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type protectedFixtureTransport func(*http.Request) (*http.Response, error)

func (f protectedFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Decoding a JWT without signature, issuer, audience, expiry and nonce checks
// would make the forgery cases green and allow a foreign principal into custody.
func TestProtectedOIDCRejectsForgedPrincipal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, field           string
		value                 any
		signer                *ecdsa.PrivateKey
		userSubject, userTeam string
		valid                 bool
	}{
		{name: "personal", userSubject: "owner", valid: true},
		{name: "signed team", field: "team_id", value: "team", userSubject: "owner", userTeam: "team", valid: true},
		{name: "foreign signature", signer: foreign, userSubject: "owner"},
		{name: "wrong issuer", field: "iss", value: "https://attacker.example", userSubject: "owner"},
		{name: "wrong audience", field: "aud", value: "foreign", userSubject: "owner"},
		{name: "multiple audiences without azp", field: "aud", value: []string{"qualified-client", "foreign"}, userSubject: "owner"},
		{name: "expired", field: "exp", value: time.Now().Add(-time.Minute).Unix(), userSubject: "owner"},
		{name: "missing expiry", field: "exp", value: nil, userSubject: "owner"},
		{name: "nonce", field: "nonce", value: "foreign", userSubject: "owner"},
		{name: "userinfo subject", userSubject: "different"},
		{name: "unverified userinfo team", userSubject: "owner", userTeam: "team"},
		{name: "signed team mismatch", field: "team_id", value: "team", userSubject: "owner", userTeam: "different"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": OAuthIssuer, "aud": "qualified-client", "sub": "owner", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": "saved-nonce"}
			if tc.field != "" {
				if tc.value == nil {
					delete(claims, tc.field)
				} else {
					claims[tc.field] = tc.value
				}
			}
			signer := key
			if tc.signer != nil {
				signer = tc.signer
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = "fixture"
			raw, err := token.SignedString(signer)
			require.NoError(t, err)
			calls := 0
			client := &http.Client{Transport: protectedFixtureTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var body any
				switch r.URL.String() {
				case ProtectedJWKSURL:
					require.Empty(t, r.Header.Get("Authorization"))
					body = map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "fixture", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}}
				case ProtectedUserinfoURL:
					require.Equal(t, "Bearer private-access", r.Header.Get("Authorization"))
					body = map[string]string{"sub": tc.userSubject, "team_id": tc.userTeam}
				default:
					t.Fatalf("unexpected request: %s", r.URL.String())
				}
				encoded, _ := json.Marshal(body)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(encoded))), Request: r}, nil
			})}
			principal, err := VerifyProtectedPrincipal(context.Background(), client, raw, "private-access", "qualified-client", "saved-nonce", true)
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, "owner", principal.Subject)
				if tc.userTeam == "" {
					require.Equal(t, "personal:owner", principal.Account)
				} else {
					require.Equal(t, "team:team", principal.Account)
				}
				require.Equal(t, 2, calls)
			} else {
				require.ErrorIs(t, err, ErrProtectedIdentity)
				require.Empty(t, principal.Subject)
			}
		})
	}
}
