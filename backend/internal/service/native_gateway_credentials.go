package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const GatewayCredentialScopeExtraKey = "gateway_credential_scope_v1"
const GatewayCredentialPurpose = "provider-authorization-v1"
const gatewayCredentialPrefix = "gcn1"
const gatewayCredentialKeyLimit = 4096

// Scope is supplied by authenticated control composition and the protected
// native row. The ciphertext contains no self-described authority or scope.
// AccountRef is the stable logical account, not the native numeric row ID.
type GatewayNativeCredentialScope struct {
	Consumer   string `json:"consumer"`
	Owner      string `json:"owner"`
	Account    string `json:"account"`
	Generation string `json:"generation"`
	Purpose    string `json:"purpose"`
}

func GatewayNativeCredentialRefValid(ref string) bool {
	if len(ref) == 0 || len(ref) > 200 || !utf8.ValidString(ref) || ref != strings.TrimSpace(ref) {
		return false
	}
	for _, r := range ref {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s GatewayNativeCredentialScope) valid() bool {
	id, err := uuid.Parse(s.Generation)
	return GatewayNativeCredentialRefValid(s.Consumer) && GatewayNativeCredentialRefValid(s.Owner) &&
		GatewayNativeCredentialRefValid(s.Account) && err == nil && id != uuid.Nil && id.String() == s.Generation &&
		s.Purpose == GatewayCredentialPurpose
}

func (s GatewayNativeCredentialScope) Metadata() map[string]any {
	return map[string]any{"consumer": s.Consumer, "owner": s.Owner, "account": s.Account,
		"generation": s.Generation, "purpose": s.Purpose}
}

// Only exact primitive strings are accepted, copied before blocking repository
// calls. Name and other mutable display metadata deliberately are not AAD.
func GatewayNativeCredentialScopeForAccount(a *Account) (GatewayNativeCredentialScope, error) {
	var s GatewayNativeCredentialScope
	if a == nil {
		return s, ErrGatewayNativeIdentity
	}
	m, ok := a.Extra[GatewayCredentialScopeExtraKey].(map[string]any)
	if !ok || len(m) != 5 {
		return s, ErrGatewayNativeIdentity
	}
	fields := []struct {
		key string
		dst *string
	}{{"consumer", &s.Consumer}, {"owner", &s.Owner}, {"account", &s.Account}, {"generation", &s.Generation}, {"purpose", &s.Purpose}}
	for _, f := range fields {
		value, ok := m[f.key].(string)
		if !ok {
			return GatewayNativeCredentialScope{}, ErrGatewayNativeIdentity
		}
		*f.dst = value
	}
	if !s.valid() || a.Extra[GatewayGenerationExtraKey] != s.Generation {
		return GatewayNativeCredentialScope{}, ErrGatewayNativeIdentity
	}
	return s, nil
}

type gatewayNativeConsumerKey struct{}
type gatewayNativeCustodyKey struct{}

// Trusted authentication/bootstrap only. Never derive this value from a body,
// query, caller header or stock admin identity. No stock-route fallback exists.
func WithGatewayNativeConsumer(ctx context.Context, consumer string) (context.Context, error) {
	if ctx == nil || !GatewayNativeCredentialRefValid(consumer) {
		return nil, ErrGatewayNativeIdentity
	}
	return context.WithValue(ctx, gatewayNativeConsumerKey{}, consumer), nil
}

func GatewayNativeConsumer(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", ErrGatewayNativeIdentity
	}
	consumer, _ := ctx.Value(gatewayNativeConsumerKey{}).(string)
	if !GatewayNativeCredentialRefValid(consumer) {
		return "", ErrGatewayNativeIdentity
	}
	return consumer, nil
}

// Immutable server-owned AES-256-GCM adapter. The constructor copies the keys;
// no mutable global, environment/file lookup, DB key or guessed fallback key.
// Explicit rotation constructs a new adapter with a new active ID and retained
// read keys. New physical candidates use the new key; existing envelopes never
// silently change. Retirement removes a read key and quarantines its candidates.
type GatewayNativeCredentialCustody struct {
	active string
	keys   map[string]cipher.AEAD
}

func gatewayCredentialKeyIDValid(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, c := range []byte(id) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func NewGatewayNativeCredentialCustody(active string, keys map[string][]byte) (*GatewayNativeCredentialCustody, error) {
	if !gatewayCredentialKeyIDValid(active) || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrGatewayNativeIdentity
	}
	c := &GatewayNativeCredentialCustody{active: active, keys: make(map[string]cipher.AEAD, len(keys))}
	for id, key := range keys {
		if !gatewayCredentialKeyIDValid(id) || len(key) != 32 {
			return nil, ErrGatewayNativeIdentity
		}
		block, err := aes.NewCipher(append([]byte(nil), key...))
		if err != nil {
			return nil, ErrGatewayNativeIdentity
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrGatewayNativeIdentity
		}
		c.keys[id] = aead
	}
	if c.keys[active] == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return c, nil
}

func WithGatewayNativeCustody(ctx context.Context, custody *GatewayNativeCredentialCustody) context.Context {
	return context.WithValue(ctx, gatewayNativeCustodyKey{}, custody)
}

func gatewayNativeCustody(ctx context.Context) *GatewayNativeCredentialCustody {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(gatewayNativeCustodyKey{}).(*GatewayNativeCredentialCustody)
	return c
}

func GatewayNativeIngressKeyValid(key string) bool {
	if len(key) == 0 || len(key) > gatewayCredentialKeyLimit {
		return false
	}
	for _, c := range []byte(key) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func gatewayCredentialAAD(scope GatewayNativeCredentialScope, id string) []byte {
	// Fixed struct ordering and domain/version/key-ID separation, not ambiguous
	// concatenation of user refs. JSON string escaping preserves exact Unicode.
	encoded, _ := json.Marshal(scope)
	return append([]byte("account-gateway/native/api-key/gcn1/"+id+"\x00"), encoded...)
}

func (c *GatewayNativeCredentialCustody) Seal(scope GatewayNativeCredentialScope, key string) (string, error) {
	if c == nil || !scope.valid() || !GatewayNativeIngressKeyValid(key) || c.keys[c.active] == nil {
		return "", ErrGatewayNativeIdentity
	}
	aead := c.keys[c.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	sealed := aead.Seal(nil, nonce, []byte(key), gatewayCredentialAAD(scope, c.active))
	return gatewayCredentialPrefix + "." + c.active + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func gatewayNativeParseEnvelope(envelope string) (string, []byte, []byte, error) {
	if len(envelope) > 5600 {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 4 || parts[0] != gatewayCredentialPrefix || !gatewayCredentialKeyIDValid(parts[1]) || len(parts[2]) != 16 || len(parts[3]) < 23 || len(parts[3]) > 5483 {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(nonce) != 12 || base64.RawURLEncoding.EncodeToString(nonce) != parts[2] {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(sealed) < 17 || len(sealed) > gatewayCredentialKeyLimit+16 || base64.RawURLEncoding.EncodeToString(sealed) != parts[3] {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	return parts[1], nonce, sealed, nil
}

// Readback checks bounds, shape and explicit key availability without decrypting.
// A same-ID wrong key or authentic-looking tamper is detected only at the
// provider Authorization boundary; readback is never credential qualification.
func (c *GatewayNativeCredentialCustody) ValidateEnvelope(envelope string) error {
	id, _, _, err := gatewayNativeParseEnvelope(envelope)
	if err != nil || c == nil || c.keys[id] == nil {
		return ErrGatewayNativeIdentity
	}
	return nil
}

// Deliberately private: plaintext is obtained only when constructing provider
// Authorization after locked encrypted-snapshot validation. No secret read API.
func (c *GatewayNativeCredentialCustody) authorization(envelope string, scope GatewayNativeCredentialScope) (string, error) {
	id, nonce, sealed, err := gatewayNativeParseEnvelope(envelope)
	if err != nil || c == nil || !scope.valid() || c.keys[id] == nil {
		return "", ErrGatewayNativeIdentity
	}
	plain, err := c.keys[id].Open(nil, nonce, sealed, gatewayCredentialAAD(scope, id))
	if err != nil || !GatewayNativeIngressKeyValid(string(plain)) {
		return "", ErrGatewayNativeIdentity
	}
	return "Bearer " + string(plain), nil
}

// Separate OAuth version/domain. API-key Seal and authorization remain gcn1
// only. There is deliberately no OAuth Authorization/dispatch entry point.
func gatewayOAuthAAD(scope GatewayNativeCredentialScope, id string) []byte {
	encoded, _ := json.Marshal(scope)
	return append([]byte("account-gateway/native/oauth-bundle/gco1/"+id+"\x00"), encoded...)
}
func (c *GatewayNativeCredentialCustody) SealOAuthBundle(scope GatewayNativeCredentialScope, bundle GatewayNativeOAuthBundle) (string, error) {
	raw, err := bundle.bytes()
	if err != nil {
		return "", err
	}
	return c.sealOAuthBytes(scope, raw)
}
func (c *GatewayNativeCredentialCustody) sealOAuthBytes(scope GatewayNativeCredentialScope, raw []byte) (string, error) {
	if c == nil || !GatewayNativeOAuthScopeValid(scope) || len(raw) == 0 || len(raw) > gatewayOAuthBundleLimit || c.keys[c.active] == nil {
		return "", ErrGatewayNativeIdentity
	}
	aead := c.keys[c.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	sealed := aead.Seal(nil, nonce, raw, gatewayOAuthAAD(scope, c.active))
	return "gco1." + c.active + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func gatewayOAuthParseEnvelope(envelope string) (string, []byte, []byte, error) {
	if len(envelope) > 87600 {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 4 || parts[0] != "gco1" || !gatewayCredentialKeyIDValid(parts[1]) {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	nonce, e1 := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	sealed, e2 := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if e1 != nil || e2 != nil || len(nonce) != 12 || len(sealed) < 17 || len(sealed) > gatewayOAuthBundleLimit+16 || base64.RawURLEncoding.EncodeToString(nonce) != parts[2] || base64.RawURLEncoding.EncodeToString(sealed) != parts[3] {
		return "", nil, nil, ErrGatewayNativeIdentity
	}
	return parts[1], nonce, sealed, nil
}
func (c *GatewayNativeCredentialCustody) ValidateOAuthEnvelope(envelope string) error {
	id, _, _, err := gatewayOAuthParseEnvelope(envelope)
	if err != nil || c == nil || c.keys[id] == nil {
		return ErrGatewayNativeIdentity
	}
	return nil
}

// Private credential boundary, used for authenticity validation. It grants no
// inference permit and must never be exposed as a readback/export API. Go
// strings are immutable; this code makes no string-zeroization promise.
func (c *GatewayNativeCredentialCustody) openOAuthBundle(envelope string, scope GatewayNativeCredentialScope) (GatewayNativeOAuthBundle, error) {
	id, nonce, sealed, err := gatewayOAuthParseEnvelope(envelope)
	if err != nil || c == nil || !GatewayNativeOAuthScopeValid(scope) || c.keys[id] == nil {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	raw, err := c.keys[id].Open(nil, nonce, sealed, gatewayOAuthAAD(scope, id))
	if err != nil {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	return gatewayOAuthDecodeBundle(raw)
}
func gatewayOAuthDecodeBundle(raw []byte) (GatewayNativeOAuthBundle, error) {
	var bundle GatewayNativeOAuthBundle
	fields, err := gatewayOAuthJSON(raw)
	if err != nil || len(fields) != 4 || json.Unmarshal(raw, &bundle) != nil {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	for _, name := range []string{"access_token", "refresh_token", "id_token", "sensitive_metadata"} {
		if _, ok := fields[name]; !ok {
			return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
		}
	}
	if _, err = bundle.bytes(); err != nil {
		return GatewayNativeOAuthBundle{}, err
	}
	return bundle, nil
}

// gco1 is accepted ONLY at initial engine version 1. Rotations use a distinct
// versioned AEAD domain; neither a format fallback nor a plaintext getter exists.
func gatewayOAuthVersionAAD(scope GatewayNativeCredentialScope, id string, version int64) []byte {
	encoded, _ := json.Marshal(scope)
	return append([]byte("account-gateway/native/oauth-bundle/gco2/"+id+"/"+strconv.FormatInt(version, 10)+"\x00"), encoded...)
}
func (c *GatewayNativeCredentialCustody) sealOAuthVersion(scope GatewayNativeCredentialScope, version int64, bundle GatewayNativeOAuthBundle) (string, error) {
	raw, err := bundle.bytes()
	if err != nil || c == nil || !GatewayNativeOAuthScopeValid(scope) || version < 2 || c.keys[c.active] == nil {
		return "", ErrGatewayNativeIdentity
	}
	aead := c.keys[c.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	sealed := aead.Seal(nil, nonce, raw, gatewayOAuthVersionAAD(scope, c.active, version))
	return "gco2." + c.active + "." + strconv.FormatInt(version, 10) + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (c *GatewayNativeCredentialCustody) openOAuthVersion(envelope string, scope GatewayNativeCredentialScope, version int64) (GatewayNativeOAuthBundle, error) {
	if version == 1 {
		return c.openOAuthBundle(envelope, scope)
	}
	parts := strings.Split(envelope, ".")
	if c == nil || !GatewayNativeOAuthScopeValid(scope) || version < 2 || len(envelope) > 87620 || len(parts) != 5 || parts[0] != "gco2" || parts[2] != strconv.FormatInt(version, 10) {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	// Reuse only the canonical nonce/ciphertext shape parser, never its gco1 AAD.
	id, nonce, sealed, err := gatewayOAuthParseEnvelope("gco1." + parts[1] + "." + parts[3] + "." + parts[4])
	if err != nil || c.keys[id] == nil {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	raw, err := c.keys[id].Open(nil, nonce, sealed, gatewayOAuthVersionAAD(scope, id, version))
	if err != nil {
		return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity
	}
	return gatewayOAuthDecodeBundle(raw)
}
