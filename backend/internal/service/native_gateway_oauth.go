package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const GatewayOAuthIssuer = "https://auth.openai.com"
const gatewayOAuthJWKS = GatewayOAuthIssuer + "/.well-known/jwks.json"
const gatewayOAuthAudience = "app_EMoamEEZ73f0CkXaXp7hrann"
const GatewayOAuthStagingProfile = "openai-oidc-oauth-staging-v1"
const GatewayOAuthBundlePurpose = "provider-oauth-bundle-v1"
const gatewayOAuthBundleLimit = 65536

var ErrGatewayOAuthConflict = errors.New("gateway oauth enrollment conflict")

// Only Verify produces a nonzero identity. This upstream principal is not RR
// owner authority, an account-check ID, a workspace, or dispatch qualification.
type GatewayNativeOAuthIdentity struct{ issuer, subject string }

func (i GatewayNativeOAuthIdentity) Principal() (string, string) { return i.issuer, i.subject }
func (i GatewayNativeOAuthIdentity) Verified() bool {
	return i.issuer == GatewayOAuthIssuer && GatewayNativeCredentialRefValid(i.subject)
}

type GatewayNativeOAuthVerifier struct {
	client *http.Client
	now    func() time.Time
}

// The transport, if supplied, is a trusted server composition dependency (e.g.
// a controlled TLS fixture). No ingress URL, issuer, audience or signing key is
// accepted. Redirect policy and the exact request origin remain fixed here.
func NewGatewayNativeOAuthVerifier(transport http.RoundTripper) *GatewayNativeOAuthVerifier {
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2}
	}
	return &GatewayNativeOAuthVerifier{client: &http.Client{
		Timeout: 5 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity },
	}, now: time.Now}
}

// Reject duplicate decoded names, case aliases and invalid UTF-8 before the
// maintained JWT parser sees claims. The same rule protects nested metadata.
func gatewayOAuthJSON(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) > gatewayOAuthBundleLimit || !utf8.Valid(raw) {
		return nil, ErrGatewayNativeIdentity
	}
	// encoding/json replaces unpaired UTF-16 surrogates. Reject them instead of
	// projecting a different signed subject/critical name into identity authority.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return nil, ErrGatewayNativeIdentity
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return nil, ErrGatewayNativeIdentity
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return nil, ErrGatewayNativeIdentity
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return nil, ErrGatewayNativeIdentity
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return nil, ErrGatewayNativeIdentity
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return nil, ErrGatewayNativeIdentity
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrGatewayNativeIdentity
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			names := map[string]bool{}
			for d.More() {
				tok, err = d.Token()
				if err != nil {
					return err
				}
				name, ok := tok.(string)
				if !ok {
					return ErrGatewayNativeIdentity
				}
				folded := strings.ToLower(name)
				if names[folded] {
					return ErrGatewayNativeIdentity
				}
				names[folded] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrGatewayNativeIdentity
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrGatewayNativeIdentity
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return result, nil
}
func gatewayOAuthString(m map[string]json.RawMessage, name string) (string, bool) {
	var value string
	err := json.Unmarshal(m[name], &value)
	return value, err == nil && value != ""
}
func gatewayOAuthCanonical(m map[string]json.RawMessage, names ...string) bool {
	for key := range m {
		for _, r := range key {
			if r > 127 {
				return false
			}
		}
		for _, name := range names {
			if strings.EqualFold(key, name) && key != name {
				return false
			}
		}
	}
	return true
}
func gatewayOAuthSeconds(raw json.RawMessage) (int64, bool) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil && n > 0 && string(raw) == strconv.FormatInt(n, 10)
}

func (v *GatewayNativeOAuthVerifier) Verify(ctx context.Context, encoded string) (GatewayNativeOAuthIdentity, error) {
	deny := func() (GatewayNativeOAuthIdentity, error) {
		return GatewayNativeOAuthIdentity{}, ErrGatewayNativeIdentity
	}
	if v == nil || v.client == nil || v.now == nil || len(encoded) > 32768 {
		return deny()
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		return deny()
	}
	decode := func(s string) ([]byte, error) {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
			return nil, ErrGatewayNativeIdentity
		}
		return b, nil
	}
	headerRaw, err := decode(parts[0])
	if err != nil {
		return deny()
	}
	claimRaw, err := decode(parts[1])
	if err != nil {
		return deny()
	}
	header, err := gatewayOAuthJSON(headerRaw)
	if err != nil {
		return deny()
	}
	for name := range header {
		if name != "alg" && name != "kid" && name != "typ" {
			return deny()
		}
	}
	alg, _ := gatewayOAuthString(header, "alg")
	kid, ok := gatewayOAuthString(header, "kid")
	if alg != "RS256" || !ok || !GatewayNativeCredentialRefValid(kid) {
		return deny()
	}
	if _, exists := header["typ"]; exists {
		typ, ok := gatewayOAuthString(header, "typ")
		if !ok || typ != "JWT" {
			return deny()
		}
	}
	claims, err := gatewayOAuthJSON(claimRaw)
	if err != nil || !gatewayOAuthCanonical(claims, "iss", "sub", "aud", "exp", "nbf", "iat", "azp") {
		return deny()
	}
	issuer, _ := gatewayOAuthString(claims, "iss")
	subject, _ := gatewayOAuthString(claims, "sub")
	if issuer != GatewayOAuthIssuer || !GatewayNativeCredentialRefValid(subject) {
		return deny()
	}
	var audiences []string
	if a, ok := gatewayOAuthString(claims, "aud"); ok {
		audiences = []string{a}
	} else if json.Unmarshal(claims["aud"], &audiences) != nil {
		return deny()
	}
	if len(audiences) != 1 || audiences[0] != gatewayOAuthAudience {
		return deny()
	}
	if _, exists := claims["azp"]; exists {
		azp, ok := gatewayOAuthString(claims, "azp")
		if !ok || azp != gatewayOAuthAudience {
			return deny()
		}
	}
	now := v.now()
	exp, ok := gatewayOAuthSeconds(claims["exp"])
	if !ok || !now.Before(time.Unix(exp, 0)) {
		return deny()
	}
	for _, field := range []string{"nbf", "iat"} {
		if raw, exists := claims[field]; exists {
			n, ok := gatewayOAuthSeconds(raw)
			if !ok || now.Before(time.Unix(n, 0)) {
				return deny()
			}
		}
	}
	key, err := v.key(ctx, kid)
	if err != nil {
		return deny()
	}
	token, err := jwt.Parse(encoded, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(GatewayOAuthIssuer),
		jwt.WithAudience(gatewayOAuthAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		return deny()
	}
	return GatewayNativeOAuthIdentity{issuer: issuer, subject: subject}, nil
}
func (v *GatewayNativeOAuthVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayOAuthJWKS, nil)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	response, err := v.client.Do(request)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != gatewayOAuthJWKS {
		return nil, ErrGatewayNativeIdentity
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, ErrGatewayNativeIdentity
	}
	root, err := gatewayOAuthJSON(raw)
	if err != nil || len(root) != 1 {
		return nil, ErrGatewayNativeIdentity
	}
	var keys []json.RawMessage
	if json.Unmarshal(root["keys"], &keys) != nil || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrGatewayNativeIdentity
	}
	var selected *rsa.PublicKey
	seen := map[string]bool{}
	for _, raw := range keys {
		k, err := gatewayOAuthJSON(raw)
		if err != nil || !gatewayOAuthCanonical(k, "kid", "kty", "alg", "use", "key_ops", "n", "e") {
			return nil, ErrGatewayNativeIdentity
		}
		id, ok := gatewayOAuthString(k, "kid")
		if !ok || seen[id] {
			return nil, ErrGatewayNativeIdentity
		}
		seen[id] = true
		if id != kid {
			continue
		}
		for name := range k {
			if name != "kid" && name != "kty" && name != "alg" && name != "use" && name != "key_ops" && name != "n" && name != "e" {
				return nil, ErrGatewayNativeIdentity
			}
		}
		kty, _ := gatewayOAuthString(k, "kty")
		alg, _ := gatewayOAuthString(k, "alg")
		if kty != "RSA" || alg != "RS256" {
			return nil, ErrGatewayNativeIdentity
		}
		if use, exists := k["use"]; exists && string(use) != `"sig"` {
			return nil, ErrGatewayNativeIdentity
		}
		if ops, exists := k["key_ops"]; exists {
			var allowed []string
			if json.Unmarshal(ops, &allowed) != nil || len(allowed) != 1 || allowed[0] != "verify" {
				return nil, ErrGatewayNativeIdentity
			}
		}
		n, _ := gatewayOAuthString(k, "n")
		e, _ := gatewayOAuthString(k, "e")
		nb, err := base64.RawURLEncoding.Strict().DecodeString(n)
		if err != nil || len(nb) < 256 || len(nb) > 512 || nb[0] == 0 || base64.RawURLEncoding.EncodeToString(nb) != n || e != "AQAB" {
			return nil, ErrGatewayNativeIdentity
		}
		modulus := new(big.Int).SetBytes(nb)
		if modulus.BitLen() < 2048 || modulus.BitLen() > 4096 || modulus.Bit(0) != 1 {
			return nil, ErrGatewayNativeIdentity
		}
		selected = &rsa.PublicKey{N: modulus, E: 65537}
	}
	if selected == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return selected, nil
}

// Write-only ingress; all metadata travels inside the encrypted bundle. No
// GetBundle API, plaintext Account credentials, cache publication, or probe.
type GatewayNativeOAuthBundle struct {
	AccessToken       string          `json:"access_token"`
	RefreshToken      string          `json:"refresh_token"`
	IDToken           string          `json:"id_token"`
	SensitiveMetadata json.RawMessage `json:"sensitive_metadata"`
}

func (b GatewayNativeOAuthBundle) bytes() ([]byte, error) {
	for _, token := range []string{b.AccessToken, b.RefreshToken, b.IDToken} {
		if len(token) == 0 || len(token) > 32768 || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n\x00") || !utf8.ValidString(token) {
			return nil, ErrGatewayNativeIdentity
		}
	}
	if _, err := gatewayOAuthJSON(b.SensitiveMetadata); err != nil {
		return nil, err
	}
	// Canonical object ordering prevents harmless metadata key order/spacing
	// changes from changing the accepted intent. Preserve json.Number precision.
	decoder := json.NewDecoder(bytes.NewReader(b.SensitiveMetadata))
	decoder.UseNumber()
	var metadata any
	if decoder.Decode(&metadata) != nil {
		return nil, ErrGatewayNativeIdentity
	}
	canonical, err := json.Marshal(metadata)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	b.SensitiveMetadata = canonical
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > gatewayOAuthBundleLimit {
		return nil, ErrGatewayNativeIdentity
	}
	return raw, nil
}
func GatewayNativeOAuthScopeValid(s GatewayNativeCredentialScope) bool {
	id, err := uuid.Parse(s.Generation)
	return GatewayNativeCredentialRefValid(s.Consumer) && GatewayNativeCredentialRefValid(s.Owner) && GatewayNativeCredentialRefValid(s.Account) && err == nil && id != uuid.Nil && id.String() == s.Generation && s.Purpose == GatewayOAuthBundlePurpose
}

type gatewayOAuthOwnerKey struct{}

// Authenticated server composition only, exactly as the trusted consumer context.
func WithGatewayNativeOAuthOwner(ctx context.Context, owner string) (context.Context, error) {
	if ctx == nil || !GatewayNativeCredentialRefValid(owner) {
		return nil, ErrGatewayNativeIdentity
	}
	return context.WithValue(ctx, gatewayOAuthOwnerKey{}, owner), nil
}
func GatewayNativeOAuthScopeAuthorized(ctx context.Context, s GatewayNativeCredentialScope) bool {
	if ctx == nil {
		return false
	}
	consumer, err := GatewayNativeConsumer(ctx)
	owner, _ := ctx.Value(gatewayOAuthOwnerKey{}).(string)
	return err == nil && consumer == s.Consumer && owner == s.Owner && GatewayNativeOAuthScopeValid(s)
}

// Safe readback deliberately excludes issuer/sub, intent commitment and envelope.
type GatewayNativeOAuthOutcome struct {
	Operation  string
	AccountID  int64
	Generation string
	State      string
}
type GatewayNativeOAuthReservation struct {
	Identity  GatewayNativeOAuthIdentity
	Scope     GatewayNativeCredentialScope
	Operation string
	IntentMAC string
	Envelope  string
}
type GatewayNativeOAuthRepository interface {
	StageGatewayNativeOAuth(context.Context, GatewayNativeOAuthReservation) (GatewayNativeOAuthOutcome, error)
	ReadGatewayNativeOAuth(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthOutcome, error)
	ReplayGatewayNativeOAuth(context.Context, GatewayNativeCredentialScope, string, string) (GatewayNativeOAuthOutcome, bool, error)
	EraseGatewayNativeOAuth(context.Context, GatewayNativeCredentialScope, string) error
}
type GatewayNativeOAuthEnrollment struct {
	verifier   *GatewayNativeOAuthVerifier
	custody    *GatewayNativeCredentialCustody
	repository GatewayNativeOAuthRepository
	intentKey  []byte
}

func NewGatewayNativeOAuthEnrollment(v *GatewayNativeOAuthVerifier, c *GatewayNativeCredentialCustody, r GatewayNativeOAuthRepository, intentKey []byte) (*GatewayNativeOAuthEnrollment, error) {
	if v == nil || c == nil || r == nil || len(intentKey) != 32 {
		return nil, ErrGatewayNativeIdentity
	}
	return &GatewayNativeOAuthEnrollment{verifier: v, custody: c, repository: r, intentKey: append([]byte(nil), intentKey...)}, nil
}
func (e *GatewayNativeOAuthEnrollment) Stage(ctx context.Context, s GatewayNativeCredentialScope, operation string, b GatewayNativeOAuthBundle) (GatewayNativeOAuthOutcome, error) {
	if e == nil || !GatewayNativeOAuthScopeAuthorized(ctx, s) || !GatewayNativeCredentialRefValid(operation) {
		return GatewayNativeOAuthOutcome{}, ErrGatewayNativeIdentity
	}
	// Snapshot the whole intent before the first network/repository call.
	raw, err := b.bytes()
	if err != nil {
		return GatewayNativeOAuthOutcome{}, err
	}
	var snapshot GatewayNativeOAuthBundle
	if json.Unmarshal(raw, &snapshot) != nil {
		return GatewayNativeOAuthOutcome{}, ErrGatewayNativeIdentity
	}
	scopeRaw, _ := json.Marshal(s)
	mac := hmac.New(sha256.New, e.intentKey)
	mac.Write([]byte("account-gateway/native/oauth-enrollment-intent/v1\x00"))
	mac.Write(scopeRaw)
	mac.Write([]byte{0})
	mac.Write([]byte(operation))
	mac.Write([]byte{0})
	mac.Write(raw)
	commitment := hex.EncodeToString(mac.Sum(nil))
	// A previously accepted exact intent reads its original durable outcome even
	// when the original ID token expires. This path creates no new authority.
	if outcome, found, err := e.repository.ReplayGatewayNativeOAuth(ctx, s, operation, commitment); err != nil || found {
		return outcome, err
	}
	identity, err := e.verifier.Verify(ctx, snapshot.IDToken)
	if err != nil {
		return GatewayNativeOAuthOutcome{}, err
	}
	envelope, err := e.custody.sealOAuthBytes(s, raw)
	if err != nil {
		return GatewayNativeOAuthOutcome{}, err
	}

	return e.repository.StageGatewayNativeOAuth(ctx, GatewayNativeOAuthReservation{Identity: identity, Scope: s, Operation: operation, IntentMAC: commitment, Envelope: envelope})
}
