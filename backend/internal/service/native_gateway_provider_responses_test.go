//go:build unit

package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// An omitted optional tier must reach the exact provider without forcing a
// caller override. Explicit non-default or malformed tiers remain pre-custody
// rejections, rather than being silently dropped/coerced to a different tier.
func TestGatewayProviderResponsesOptionalDefaultTier(t *testing.T) {
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
	} {
		t.Run(tuple.profile, func(t *testing.T) {
			payload := func(tier string) []byte {
				return []byte(fmt.Sprintf(`{"model":%q,"input":"text","stream":true,"store":false,"max_output_tokens":100%s}`, tuple.model, tier))
			}
			for _, tier := range []string{"", `,"service_tier":"default"`, `,"service_tier":"\u0064efault"`} {
				body := payload(tier)
				wire, _, err := gatewayNativePrepareProviderResponses(tuple.profile, body, 4096)
				require.NoError(t, err)
				fields, ok := GatewayNativePayloadFields(wire, "service_tier")
				require.True(t, ok)
				if tier == "" {
					require.Nil(t, fields["service_tier"])
				} else {
					require.NotNil(t, fields["service_tier"])
				}
			}
			for _, tier := range []string{`"auto"`, `"priority"`, `null`, `true`, `1`, `{}`, `[]`} {
				require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, payload(`,"service_tier":`+tier), 4096), ErrGatewayNativeIdentity)
			}
		})
	}
}

// Capability metadata advertises no reasoning setting. Exact null is only a
// transport representation of None; configured objects must never be dropped
// silently or reach custody/provider entry under a different configuration.
func TestGatewayProviderResponsesUnsupportedReasoning(t *testing.T) {
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
	} {
		t.Run(tuple.profile, func(t *testing.T) {
			payload := func(field string) []byte {
				return []byte(fmt.Sprintf(`{"model":%q,"input":"text","stream":true,"store":false,"max_output_tokens":100%s}`, tuple.model, field))
			}
			for _, field := range []string{"", `,"reasoning":null`, `,"reasoning":  null `} {
				body := payload(field)
				original := string(body)
				wire, _, err := gatewayNativePrepareProviderResponses(tuple.profile, body, 4096)
				require.NoError(t, err)
				fields, ok := GatewayNativePayloadFields(wire, "reasoning")
				require.True(t, ok)
				require.Nil(t, fields["reasoning"])
				require.Equal(t, original, string(body), "normalization must not mutate admitted input bytes")
			}
			for _, field := range []string{
				`,"reasoning":{"effort":"high"}`, `,"reasoning":{"effort":"xhigh"}`, `,"reasoning":{"effort":"none"}`,
				`,"reasoning":{}`, `,"reasoning":true`, `,"reasoning":[]`, `,"reasoning":"none"`,
				`,"Reasoning":null`, `,"reasoning":null,"reasoning":{"effort":"high"}`,
			} {
				require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, payload(field), 4096), ErrGatewayNativeIdentity)
			}
		})
	}
}

func TestGatewayProviderResponsesCodexMetadata(t *testing.T) {
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
	} {
		t.Run(tuple.profile, func(t *testing.T) {
			payload := func(fields string) []byte {
				return []byte(fmt.Sprintf(`{"model":%q,"input":"text","stream":true,"store":false,"max_output_tokens":100%s}`, tuple.model, fields))
			}
			metadata := `,"prompt_cache_key":"33333333-3333-4333-8333-333333333333","client_metadata":{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444"}`
			for _, text := range []string{"", `,"text":null`, `,"text":{"format":{"type":"text"},"verbosity":"low"}`} {
				body := payload(metadata + `,"reasoning":null` + text)
				original := string(body)
				wire, _, err := gatewayNativePrepareProviderResponses(tuple.profile, body, 4096)
				require.NoError(t, err)
				fields, ok := GatewayNativePayloadFields(wire, "reasoning", "text", "prompt_cache_key", "client_metadata")
				require.True(t, ok)
				require.Nil(t, fields["reasoning"])
				if text == "" || text == `,"text":null` {
					require.Nil(t, fields["text"])
				} else {
					require.JSONEq(t, `{"format":{"type":"text"},"verbosity":"low"}`, string(fields["text"]))
				}
				require.JSONEq(t, `"33333333-3333-4333-8333-333333333333"`, string(fields["prompt_cache_key"]))
				require.JSONEq(t, `{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444"}`, string(fields["client_metadata"]))
				require.Equal(t, original, string(body))
			}
			for _, fields := range []string{
				`,"prompt_cache_key":null`, `,"prompt_cache_key":123`, `,"prompt_cache_key":"not-a-uuid"`, `,"prompt_cache_key":"33333333333343338333333333333333"`,
				`,"prompt_cache_key":"33333333-3333-4333-8333-33333333333A"`,
				`,"prompt_cache_key":"` + strings.Repeat("a", 257) + `"`,
				`,"client_metadata":null`, `,"client_metadata":[]`, `,"client_metadata":{}`, `,"client_metadata":"value"`,
				`,"client_metadata":{"x-codex-installation-id":true}`, `,"client_metadata":{"x-codex-installation-id":"invalid"}`,
				`,"client_metadata":{"x-codex-installation-id":"` + strings.Repeat("a", 257) + `"}`,
				`,"client_metadata":{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444","authorization":"forbidden"}`,
				`,"client_metadata":{"X-Codex-Installation-Id":"44444444-4444-4444-8444-444444444444"}`,
				`,"client_metadata":{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444","x-codex-installation-id":"55555555-5555-4555-8555-555555555555"}`,
				`,"client_metadata":{` + strings.Repeat(" ", 513) + `"x-codex-installation-id":"44444444-4444-4444-8444-444444444444"}`,
				`,"Text":null`, `,"text":null,"text":{"format":{"type":"json_schema"}}`,
			} {
				require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, payload(fields), 4096), ErrGatewayNativeIdentity)
			}
		})
	}
}

// The installed review caller always supplies its output schema. Preserve the
// pinned Codex format envelope and opaque schema, including strict false; do
// not silently discard them or accept arbitrary format/name/extension fields.
func TestGatewayProviderResponsesCodexOutputSchema(t *testing.T) {
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
	} {
		t.Run(tuple.profile, func(t *testing.T) {
			schema := `{"type":"object","properties":{"findings":{"type":"array","items":{"type":"object"}},"revalidations":{"type":"array"}},"required":["findings","revalidations"],"additionalProperties":false}`
			payload := func(format string) []byte {
				return []byte(fmt.Sprintf(`{"model":%q,"input":"text","stream":true,"store":false,"max_output_tokens":100,"reasoning":null,"prompt_cache_key":"33333333-3333-4333-8333-333333333333","client_metadata":{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444"},"text":{"format":%s}}`, tuple.model, format))
			}
			for _, strict := range []string{"true", "false"} {
				format := fmt.Sprintf(`{"type":"json_schema","name":"codex_output_schema","strict":%s,"schema":%s}`, strict, schema)
				wire, _, err := gatewayNativePrepareProviderResponses(tuple.profile, payload(format), 4096)
				require.NoError(t, err)
				fields, ok := GatewayNativePayloadFields(wire, "text", "reasoning")
				require.True(t, ok)
				require.Nil(t, fields["reasoning"])
				require.JSONEq(t, `{"format":`+format+`}`, string(fields["text"]))
			}
			for _, format := range []string{
				`{"type":"json_schema","name":"response","strict":true,"schema":{}}`,
				`{"type":"json_schema","name":"codex_output_schema","schema":{}}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":null,"schema":{}}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":"true","schema":{}}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":1,"schema":{}}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":[]}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":"schema"}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":{},"url":"https://forbidden.invalid"}`,
				`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":{},"Strict":false}`,
				`{"type":"text","schema":{}}`, `{"type":"json_object"}`, `null`,
			} {
				require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, payload(format), 4096), ErrGatewayNativeIdentity)
			}
			require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(tuple.profile, payload(fmt.Sprintf(`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":%s}`, schema)), 100), ErrGatewayNativeIdentity)
		})
	}
}
