//go:build unit

package admin

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGatewayAccountModelsStrictSelector(t *testing.T) {
	valid := `{"ownerRef":"owner","accountRef":"account","profileId":"openai-codex-oauth-responses-v1","expectedAuthorizationEpoch":7}`
	in, ok := DecodeGatewayAccountModelsInput([]byte(valid))
	require.True(t, ok)
	require.False(t, in.ForceRefresh)
	withForce := strings.TrimSuffix(valid, "}") + `,"forceRefresh":true}`
	in, ok = DecodeGatewayAccountModelsInput([]byte(withForce))
	require.True(t, ok)
	require.True(t, in.ForceRefresh)
	for _, raw := range []string{
		strings.TrimSuffix(valid, "}") + `,"forceRefresh":null}`,
		strings.TrimSuffix(valid, "}") + `,"forceRefresh":"true"}`,
		strings.TrimSuffix(valid, "}") + `,"forceRefresh":true,"ForceRefresh":false}`,
		strings.TrimSuffix(valid, "}") + `,"generation":"forbidden"}`,
		strings.Replace(valid, `"expectedAuthorizationEpoch":7`, `"expectedAuthorizationEpoch":7.0`, 1),
		strings.Replace(valid, `"expectedAuthorizationEpoch":7`, `"expectedAuthorizationEpoch":9007199254740992`, 1),
		strings.Replace(valid, `"ownerRef":"owner"`, `"ownerRef":"owner","OwnerRef":"other"`, 1),
	} {
		_, ok := DecodeGatewayAccountModelsInput([]byte(raw))
		require.False(t, ok, raw)
	}
}
