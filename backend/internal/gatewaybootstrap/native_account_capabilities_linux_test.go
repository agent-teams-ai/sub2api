//go:build linux

package gatewaybootstrap

import (
	"encoding/json"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestNativeAccountCapabilitiesExposeImportsOnlyWithComposedCodex(t *testing.T) {
	profile := fixtureConfig().Profile
	transport := &gatewaytransport.Handler{}
	for _, partial := range []*privateOAuth{nil, {}, {connect: &service.GatewayNativeOAuthConnect{}}, {dispatch: &service.GatewayNativeOAuthDispatch{}}} {
		catalog := privateAccountCapabilities(profile, transport, partial)
		for _, capability := range catalog.Profiles {
			require.NotEqual(t, service.GatewayCodexOAuthResponsesProfile, capability.ProfileID)
		}
	}
	composed := &privateOAuth{connect: &service.GatewayNativeOAuthConnect{}, dispatch: &service.GatewayNativeOAuthDispatch{}}
	catalog := privateAccountCapabilities(profile, transport, composed)
	found := false
	for _, capability := range catalog.Profiles {
		if capability.ProfileID != service.GatewayCodexOAuthResponsesProfile {
			continue
		}
		found = true
		require.Len(t, capability.Methods, 4)
		methods := map[string]bool{}
		for _, method := range capability.Methods {
			require.True(t, method.Create)
			require.True(t, method.Reconnect)
			if method.Kind == "credential_import" {
				require.Equal(t, service.GatewayOAuthImportInputLimit, method.MaxBytes)
				methods[method.Method] = true
			}
		}
		require.Equal(t, map[string]bool{"refresh_token": true, "oauth_auth_json": true}, methods)
	}
	require.True(t, found)
}

func TestNativeOfficialAPIConfigUsesExistingClosedFD6Profiles(t *testing.T) {
	c := fixtureConfig()
	anthropic, gemini := c.Profile, c.Profile
	anthropic.BaseURL, anthropic.Model = service.GatewayAnthropicAPIBaseURL, service.GatewayAnthropicAPIModel
	gemini.BaseURL, gemini.Model = service.GatewayGeminiAPIBaseURL, service.GatewayGeminiAPIModel
	c.AnthropicAPI, c.GeminiAPI = &anthropic, &gemini
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	var decoded Config
	require.NoError(t, decodeStrict(raw, &decoded))
	_, err = decoded.validate()
	require.NoError(t, err)
	profiles := decoded.officialAPIProfiles()
	require.Len(t, profiles, 2)
	require.Equal(t, service.GatewayAnthropicAPIKeyProfile, profiles[0].Profile)
	require.Equal(t, service.GatewayGeminiAPIKeyProfile, profiles[1].Profile)
	decoded.GeminiAPI.BaseURL = "https://arbitrary.invalid/openai"
	_, err = decoded.validate()
	require.Error(t, err)
	decoded.GeminiAPI.BaseURL = gemini.BaseURL
	decoded.AnthropicAPI.Model = "unqualified-model"
	_, err = decoded.validate()
	require.Error(t, err)
}
