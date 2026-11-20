package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
)

// This adapter is deliberately separate from credential Seal/Open. A thought
// carrier cannot be interpreted as a provider authorization or OAuth bundle.
// The existing native keyring owns encryption and rotation; no extra key or
// conversation database is introduced.
type gatewayGeminiContinuationCodec struct {
	custody *GatewayNativeCredentialCustody
	binding []byte
}

func gatewayNativeGeminiContinuation(c *gin.Context) (apicompat.GeminiContinuationCodec, error) {
	if c == nil || c.Request == nil {
		return nil, nil
	}
	state, _ := c.Request.Context().Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	if state == nil || state.route.Profile != GatewayGeminiAPIKeyProfile {
		return nil, nil
	}
	if state.custody == nil || !state.scope.valid() || state.scope.Generation != state.route.Generation || state.route.AccountID <= 0 || state.route.CreatedAt.IsZero() || !GatewayNativeAPIKeyProfileValid(state.route.Profile, state.route.BaseURL, state.route.Model) || !GatewayAccountModelIDValid(state.requestedModel) {
		return nil, ErrGatewayNativeIdentity
	}
	// Stable struct field order, exact route birth/generation and requested model
	// bind every carrier even when another account uses the same custody key.
	route := state.route
	route.CreatedAt = route.CreatedAt.UTC()
	binding, err := json.Marshal(struct {
		Scope GatewayNativeCredentialScope `json:"scope"`
		Route GatewayNativeRoute           `json:"route"`
		Model string                       `json:"model"`
	}{state.scope, route, state.requestedModel})
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	return &gatewayGeminiContinuationCodec{custody: state.custody, binding: binding}, nil
}

func (c *gatewayGeminiContinuationCodec) aad(id string) []byte {
	return append([]byte("account-gateway/native/gemini-thoughts/v1/"+id+"\x00"), c.binding...)
}

func (c *gatewayGeminiContinuationCodec) Seal(raw []byte) (string, error) {
	if c == nil || c.custody == nil || len(raw) == 0 || len(raw) > apicompat.GeminiContinuationMaxBytes || len(c.binding) == 0 {
		return "", ErrGatewayNativeIdentity
	}
	id := c.custody.active
	aead := c.custody.keys[id]
	if !gatewayCredentialKeyIDValid(id) || aead == nil {
		return "", ErrGatewayNativeIdentity
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	sealed := aead.Seal(nil, nonce, raw, c.aad(id))
	return id + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *gatewayGeminiContinuationCodec) Open(value string) ([]byte, error) {
	if c == nil || c.custody == nil || len(c.binding) == 0 || len(value) > apicompat.GeminiContinuationMaxBytes*2 {
		return nil, ErrGatewayNativeIdentity
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || !gatewayCredentialKeyIDValid(parts[0]) || len(parts[1]) != 16 {
		return nil, ErrGatewayNativeIdentity
	}
	aead := c.custody.keys[parts[0]]
	if aead == nil {
		return nil, ErrGatewayNativeIdentity
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(nonce) != aead.NonceSize() || base64.RawURLEncoding.EncodeToString(nonce) != parts[1] {
		return nil, ErrGatewayNativeIdentity
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sealed) <= aead.Overhead() || len(sealed) > apicompat.GeminiContinuationMaxBytes+aead.Overhead() || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] {
		return nil, ErrGatewayNativeIdentity
	}
	plain, err := aead.Open(nil, nonce, sealed, c.aad(parts[0]))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	return plain, nil
}

var _ apicompat.GeminiContinuationCodec = (*gatewayGeminiContinuationCodec)(nil)
