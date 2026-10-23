package xai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
)

const ProtectedUserAgent = "ReviewRouter/native-account-gateway"
const ProtectedClientIdentifier = "reviewrouter-native-account-gateway"

const ProtectedJWKSURL = OAuthIssuer + "/.well-known/jwks.json"
const ProtectedUserinfoURL = OAuthIssuer + "/oauth2/userinfo"

var ErrProtectedIdentity = errors.New("protected xai identity unavailable")

type ProtectedPrincipal struct{ Subject, Account string }
type protectedClaims struct {
	jwt.RegisteredClaims
	Nonce           string `json:"nonce"`
	TeamID          string `json:"team_id"`
	AuthorizedParty string `json:"azp"`
}

// FetchProtectedJSON uses fixed source-owned endpoints, bounded bodies, and the
// caller's nonredirecting HTTP client. Error bodies and credentials never escape.
func FetchProtectedJSON(ctx context.Context, client *http.Client, endpoint, access string, target any) error {
	if client == nil || endpoint != ProtectedJWKSURL && endpoint != ProtectedUserinfoURL {
		return ErrProtectedIdentity
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProtectedIdentity
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", ProtectedUserAgent)
	if access != "" {
		req.Header.Set("Authorization", "Bearer "+access)
	}
	res, err := client.Do(req)
	if err != nil || res == nil || res.Body == nil {
		return ErrProtectedIdentity
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 || res.StatusCode != http.StatusOK || res.Request == nil || res.Request.URL.String() != endpoint || json.Unmarshal(raw, target) != nil {
		return ErrProtectedIdentity
	}
	return nil
}

// VerifyProtectedPrincipal uses the pinned jwt library for ES256 verification
// and registered-claim validation. No endpoint, issuer, or algorithm comes from
// untrusted token claims. Authenticated userinfo must attest the same subject.
func VerifyProtectedPrincipal(ctx context.Context, client *http.Client, token, access, audience, nonce string, requireNonce bool) (ProtectedPrincipal, error) {
	var out ProtectedPrincipal
	if token == "" || len(token) > 32768 || audience == "" || requireNonce && nonce == "" {
		return out, ErrProtectedIdentity
	}
	var keys struct {
		Keys []struct{ Kty, Crv, Kid, Alg, Use, X, Y string } `json:"keys"`
	}
	if FetchProtectedJSON(ctx, client, ProtectedJWKSURL, "", &keys) != nil || len(keys.Keys) == 0 || len(keys.Keys) > 32 {
		return out, ErrProtectedIdentity
	}
	var claims protectedClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || t.Method != jwt.SigningMethodES256 {
			return nil, ErrProtectedIdentity
		}
		var found *ecdsa.PublicKey
		for _, k := range keys.Keys {
			if k.Kid != kid {
				continue
			}
			if found != nil || k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "" && k.Alg != "ES256" || k.Use != "" && k.Use != "sig" {
				return nil, ErrProtectedIdentity
			}
			x, e1 := base64.RawURLEncoding.DecodeString(k.X)
			y, e2 := base64.RawURLEncoding.DecodeString(k.Y)
			if e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
				return nil, ErrProtectedIdentity
			}
			key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !key.Curve.IsOnCurve(key.X, key.Y) {
				return nil, ErrProtectedIdentity
			}
			found = key
		}
		if found == nil {
			return nil, ErrProtectedIdentity
		}
		return found, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(OAuthIssuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || parsed == nil || !parsed.Valid || len(claims.Audience) > 1 && claims.AuthorizedParty != audience || claims.AuthorizedParty != "" && claims.AuthorizedParty != audience || !ProtectedPrincipalPart(claims.Subject) || requireNonce && claims.Nonce != nonce || !requireNonce && claims.Nonce != "" && claims.Nonce != nonce {
		return out, ErrProtectedIdentity
	}
	var user struct {
		Subject string `json:"sub"`
		Team    string `json:"team_id"`
	}
	if FetchProtectedJSON(ctx, client, ProtectedUserinfoURL, access, &user) != nil || user.Subject != claims.Subject || user.Team != claims.TeamID {
		return out, ErrProtectedIdentity
	}
	account := "personal:" + claims.Subject
	if claims.TeamID != "" {
		if !ProtectedPrincipalPart(claims.TeamID) {
			return out, ErrProtectedIdentity
		}
		account = "team:" + claims.TeamID
	}
	return ProtectedPrincipal{Subject: claims.Subject, Account: account}, nil
}
func ProtectedPrincipalPart(v string) bool {
	if v == "" || len(v) > 512 || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r > 127 {
			return false
		}
	}
	return true
}
