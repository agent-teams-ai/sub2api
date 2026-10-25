//go:build unit

package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const accountModelsFixture = `{"models":[{"slug":"unseen-future-preview","supported_in_api":false,"visibility":"list","supported_endpoints":["responses"],"input_modalities":["text"],"supported_reasoning_levels":[{"effort":"low"},{"effort":"ultra"}],"default_reasoning_level":"ultra","instructions":"PRIVATE-PROVIDER-PROMPT"}]}`

// An existing fixed descriptor must admit a previously unknown provider model,
// while catalogue removal and unsupported effort stop before Responses entry.
func TestGatewayAccountModelsDynamicDispatch(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	route := f.qualify(t)
	f.modelsBody = accountModelsFixture
	payload := []byte(strings.ReplaceAll(string(oauthDispatchPayload()), GatewayCodexOAuthModel, "unseen-future-preview"))
	payload = append(payload[:len(payload)-1], []byte(`,"reasoning":{"effort":"ultra"}}`)...)
	_, entered, err, _ := f.call(t, route, payload)
	require.NoError(t, err)
	require.True(t, entered)
	require.Equal(t, int32(1), f.entries.Load())
	require.Equal(t, int32(1), f.modelsReads.Load())
	require.Contains(t, f.lastPayload.Load().(string), `"model":"unseen-future-preview"`)
	require.Equal(t, GatewayCodexOAuthModel, route.Model)
	for _, body := range [][]byte{[]byte(strings.ReplaceAll(string(payload), "unseen-future-preview", "unknown-model")), []byte(strings.ReplaceAll(string(payload), `"ultra"`, `"high"`))} {
		_, entered, err, _ = f.call(t, route, body)
		require.Error(t, err)
		require.False(t, entered)
	}
	require.Equal(t, int32(1), f.entries.Load())
	f.modelsBody = `{"models":[]}`
	result := f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, true)
	require.Equal(t, "snapshot", result.Status)
	require.Empty(t, *result.Models)
	_, entered, err, _ = f.call(t, route, payload)
	require.Error(t, err)
	require.False(t, entered)
	// An authoritative empty catalogue also removes the legacy anchor.
	_, entered, err, _ = f.call(t, route, oauthDispatchPayload())
	require.Error(t, err)
	require.False(t, entered)
	require.Equal(t, int32(1), f.entries.Load())
}

func TestGatewayAccountModelsReadFencesAndRedaction(t *testing.T) {
	for _, change := range []string{"none", "owner", "epoch", "generation", "revision"} {
		t.Run(change, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			f.modelsBody = accountModelsFixture
			in := GatewayAccountModelsInput{GatewayAccountLimitsInput: GatewayAccountLimitsInput{f.scope.Owner, f.scope.Account, route.Profile, 7}}
			calls := 0
			reader, err := NewGatewayAccountModelsReader(f.dispatch, func(_ context.Context, input GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				calls++
				if input.OwnerRef != f.scope.Owner || input.ExpectedAuthorizationEpoch != 7 {
					return GatewayNativeRoute{}, ErrGatewayNativeIdentity
				}
				if calls == 2 && change == "generation" {
					changed := route
					changed.Generation = "different"
					return changed, nil
				}
				if calls == 2 && change == "revision" {
					f.store.row.Credentials["oauth_bundle"] = "invalid"
				}
				return route, nil
			})
			require.NoError(t, err)
			if change == "owner" {
				in.OwnerRef = "another-owner"
			}
			if change == "epoch" {
				in.ExpectedAuthorizationEpoch = 8
			}
			result := reader.Read(f.ctx, in)
			if change != "none" {
				require.Equal(t, GatewayAccountModelsResult{Status: "unavailable"}, result)
				return
			}
			require.Equal(t, "snapshot", result.Status)
			require.Equal(t, route.Generation, result.PhysicalGeneration)
			require.Len(t, *result.Models, 1)
			wire, err := json.Marshal(result)
			require.NoError(t, err)
			require.NotContains(t, string(wire), "PRIVATE-PROVIDER-PROMPT")
			require.NotContains(t, string(wire), f.bundle.AccessToken)
			require.NotContains(t, string(wire), "instructions")
			first, _ := time.Parse(time.RFC3339Nano, result.FetchedAt)
			last, _ := time.Parse(time.RFC3339Nano, result.ExpiresAt)
			require.Equal(t, time.Minute, last.Sub(first))
			require.Equal(t, int32(1), f.modelsReads.Load())
			require.Equal(t, int32(0), f.entries.Load())
		})
	}
}

func TestGatewayAccountModelsMalformedUnavailableAndExpiry(t *testing.T) {
	for _, raw := range []string{`{}`, `{"models":null}`, `{"models":[{"slug":"bad model"}]}`, `{"models":[{"slug":"same"},{"slug":"same"}]}`, `{"models":[{"slug":"x","supported_reasoning_levels":["low"],"default_reasoning_level":"ultra"}]}`, `{"models":[],"Models":[]}`} {
		_, err := parseGatewayCodexAccountModels([]byte(raw))
		require.Error(t, err)
	}
	models, err := parseGatewayCodexAccountModels([]byte(`{"models":[{"slug":"codex-auto-review","visibility":"hide"},{"slug":"image","input_modalities":["image"]},{"slug":"disabled","available":false},{"slug":"chat","supported_endpoints":["chat_completions"]}]}`))
	require.NoError(t, err)
	require.Empty(t, models)
	f := newOAuthDispatchFixture(t)
	f.qualify(t)
	f.modelsBody = accountModelsFixture
	require.Equal(t, "snapshot", f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, false).Status)
	f.dispatch.models.Lock()
	for key, entry := range f.dispatch.models.entries {
		entry.expires = time.Now().Add(-time.Second)
		f.dispatch.models.entries[key] = entry
	}
	f.dispatch.models.Unlock()
	f.modelsBody = `{"models":[]}`
	out := f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, false)
	require.Equal(t, "snapshot", out.Status)
	require.Empty(t, *out.Models)
	require.Equal(t, int32(2), f.modelsReads.Load())
	f.modelsStatus = 502
	f.modelsBody = "PRIVATE-PROVIDER-ERROR"
	out = f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, true)
	require.Equal(t, GatewayAccountModelsResult{Status: "unavailable"}, out)
	require.False(t, gatewayAccountModelsAllow(out, "unseen-future-preview", nil))
	require.True(t, gatewayAccountModelsAllow(out, GatewayCodexOAuthModel, nil))
}

func TestGatewayAccountModelsUnsupportedProfile(t *testing.T) {
	reader, err := NewGatewayAccountModelsReader(nil, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
		return GatewayNativeRoute{Profile: GatewayClaudeOAuthMessagesProfile}, nil
	})
	require.NoError(t, err)
	out := reader.Read(context.Background(), GatewayAccountModelsInput{GatewayAccountLimitsInput: GatewayAccountLimitsInput{"owner", "account", GatewayClaudeOAuthMessagesProfile, 1}})
	require.Equal(t, GatewayAccountModelsResult{Status: "unsupported"}, out)
}

func TestGatewayAccountModelsReasoningCapability(t *testing.T) {
	models := []GatewayAccountModel{{ModelID: "plain"}, {ModelID: "reasoning", Reasoning: &GatewayAccountModelChoices{Allowed: []string{"low", "ultra"}, Default: "low"}}}
	snapshot := GatewayAccountModelsResult{Status: "snapshot", Models: &models}
	for _, model := range []string{"plain", "reasoning"} {
		require.True(t, gatewayAccountModelsAllow(snapshot, model, nil))
		require.True(t, gatewayAccountModelsAllow(snapshot, model, json.RawMessage(`null`)))
	}
	require.False(t, gatewayAccountModelsAllow(snapshot, "plain", json.RawMessage(`{}`)))
	require.False(t, gatewayAccountModelsAllow(snapshot, "plain", json.RawMessage(`{"summary":"auto"}`)))
	require.True(t, gatewayAccountModelsAllow(snapshot, "reasoning", json.RawMessage(`{"summary":"auto"}`)))
	require.True(t, gatewayAccountModelsAllow(snapshot, "reasoning", json.RawMessage(`{"effort":"ultra"}`)))
	require.False(t, gatewayAccountModelsAllow(snapshot, "reasoning", json.RawMessage(`{"effort":"high"}`)))
	require.False(t, gatewayAccountModelsAllow(snapshot, "reasoning", json.RawMessage(`{"effort":null}`)))
	require.False(t, gatewayAccountModelsAllow(snapshot, "reasoning", json.RawMessage(`{"effort":"low","Effort":"ultra"}`)))
}
