//go:build unit

package service

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func geminiCarrierFixtureState(t *testing.T) gatewayNativeDispatch {
	t.Helper()
	scope := custodyTestScope()
	return gatewayNativeDispatch{
		scope: scope, custody: custodyTestKeyring(t, "fixture-k1"), requestedModel: GatewayGeminiAPIModel,
		route: GatewayNativeRoute{AccountID: 41, Generation: scope.Generation, CreatedAt: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), Profile: GatewayGeminiAPIKeyProfile, BaseURL: GatewayGeminiAPIBaseURL, Model: GatewayGeminiAPIModel},
	}
}

func geminiCarrierFixtureCodec(t *testing.T, state *gatewayNativeDispatch) apicompat.GeminiContinuationCodec {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil).WithContext(context.WithValue(context.Background(), gatewayNativeContextKey{}, state))
	codec, err := gatewayNativeGeminiContinuation(c)
	require.NoError(t, err)
	return codec
}

func TestGatewayGeminiContinuationBindsEveryAuthorityAndNativeIdentity(t *testing.T) {
	state := geminiCarrierFixtureState(t)
	codec := geminiCarrierFixtureCodec(t, &state)
	plain := []byte(`{"version":1,"position":"before","items":[{"signature":"fixture-only"}]}`)
	sealed, err := codec.Seal(plain)
	require.NoError(t, err)
	require.NotContains(t, sealed, "fixture-only")
	opened, err := codec.Open(sealed)
	require.NoError(t, err)
	require.Equal(t, plain, opened)
	for _, change := range []struct {
		name  string
		apply func(*gatewayNativeDispatch)
	}{
		{"consumer", func(s *gatewayNativeDispatch) { s.scope.Consumer = "another-consumer" }},
		{"owner", func(s *gatewayNativeDispatch) { s.scope.Owner = "another-owner" }},
		{"logical-account", func(s *gatewayNativeDispatch) { s.scope.Account = "another-account" }},
		{"generation", func(s *gatewayNativeDispatch) {
			s.scope.Generation = "b1111111-1111-4111-8111-111111111111"
			s.route.Generation = s.scope.Generation
		}},
		{"physical-account", func(s *gatewayNativeDispatch) { s.route.AccountID++ }},
		{"birth", func(s *gatewayNativeDispatch) { s.route.CreatedAt = s.route.CreatedAt.Add(time.Second) }},
		{"requested-model", func(s *gatewayNativeDispatch) { s.requestedModel = "another-valid-model" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			other := geminiCarrierFixtureState(t)
			other.custody = state.custody
			change.apply(&other)
			_, err := geminiCarrierFixtureCodec(t, &other).Open(sealed)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
	// Equivalent timestamp locations describe the same birth instant.
	state.route.CreatedAt = state.route.CreatedAt.In(time.FixedZone("fixture", 3600))
	_, err = geminiCarrierFixtureCodec(t, &state).Open(sealed)
	require.NoError(t, err)
	credential, err := state.custody.Seal(state.scope, "fixture-provider-key")
	require.NoError(t, err)
	_, err = codec.Open(credential)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = state.custody.authorization("gcn1."+sealed, state.scope)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
}

func TestGatewayGeminiContinuationRotationTamperAndBounds(t *testing.T) {
	keys := map[string][]byte{"old": bytes.Repeat([]byte{11}, 32), "new": bytes.Repeat([]byte{22}, 32)}
	old, err := NewGatewayNativeCredentialCustody("old", keys)
	require.NoError(t, err)
	state := geminiCarrierFixtureState(t)
	state.custody = old
	codec := geminiCarrierFixtureCodec(t, &state)
	sealed, err := codec.Seal([]byte("opaque-fixture"))
	require.NoError(t, err)
	rotated, err := NewGatewayNativeCredentialCustody("new", keys)
	require.NoError(t, err)
	state.custody = rotated
	current := geminiCarrierFixtureCodec(t, &state)
	_, err = current.Open(sealed)
	require.NoError(t, err)
	withoutOld, err := NewGatewayNativeCredentialCustody("new", map[string][]byte{"new": keys["new"]})
	require.NoError(t, err)
	state.custody = withoutOld
	_, err = geminiCarrierFixtureCodec(t, &state).Open(sealed)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	parts := strings.Split(sealed, ".")
	parts[2] = "A" + parts[2][1:]
	if strings.Join(parts, ".") == sealed {
		parts[2] = "B" + parts[2][1:]
	}
	for _, invalid := range []string{strings.Join(parts, "."), sealed + "=", strings.Repeat("x", apicompat.GeminiContinuationMaxBytes*2+1), "unknown." + strings.Join(parts[1:], ".")} {
		_, err = current.Open(invalid)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte{'x'}, apicompat.GeminiContinuationMaxBytes+1)} {
		_, err = current.Seal(invalid)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	state.route.Profile = "openai-responses-apikey-v1"
	require.Nil(t, geminiCarrierFixtureCodec(t, &state))
}
