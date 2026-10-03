//go:build unit

package service

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Synthetic server-side key shared only by existing native test fixtures.
// Transport assertions keep their independently expected plaintext Authorization.
func nativeFixtureCustody(t *testing.T) *GatewayNativeCredentialCustody {
	t.Helper()
	c, err := NewGatewayNativeCredentialCustody("native-fixture", map[string][]byte{
		"native-fixture": bytes.Repeat([]byte{0x42}, 32),
	})
	require.NoError(t, err)
	return c
}

func nativeFixtureScope(a *Account) GatewayNativeCredentialScope {
	scope := custodyTestScope()
	scope.Generation = a.Extra[GatewayGenerationExtraKey].(string)
	return scope
}

func nativeFixtureSealAccount(t *testing.T, a *Account) *Account {
	t.Helper()
	scope := nativeFixtureScope(a)
	envelope, err := nativeFixtureCustody(t).Seal(scope, a.GetCredential("api_key"))
	require.NoError(t, err)
	a.Credentials["api_key"] = envelope
	a.Extra[GatewayCredentialScopeExtraKey] = scope.Metadata()
	return a
}

func nativeFixtureContext(t *testing.T, base context.Context) context.Context {
	t.Helper()
	ctx, err := WithGatewayNativeConsumer(base, custodyTestScope().Consumer)
	require.NoError(t, err)
	return WithGatewayNativeCustody(ctx, nativeFixtureCustody(t))
}
