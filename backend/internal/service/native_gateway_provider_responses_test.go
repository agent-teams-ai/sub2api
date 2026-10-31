//go:build unit

package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
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

// The captured CLI groups five ordinary functions in one namespace. The source
// codec must flatten declarations/choice and restore the namespace on the real
// call lifecycle; the next caller turn must lower that history losslessly.
func TestGatewayProviderResponsesFunctionNamespaceRoundTrip(t *testing.T) {
	for _, tuple := range []struct{ profile, model string }{
		{GatewayKimiCodeResponsesProfile, GatewayKimiCodeResponsesModel},
		{GatewayGLMCodingResponsesProfile, GatewayGLMCodingResponsesModel},
		{GatewayMiniMaxMPlanResponsesProfile, GatewayMiniMaxMPlanResponsesModel},
		{GatewayGrokOAuthResponsesProfile, GatewayGrokOAuthModel},
	} {
		t.Run(tuple.profile, func(t *testing.T) {
			schema := map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string", "description": "preserve <>& schema"}}, "additionalProperties": false}
			children := []any{}
			for _, name := range []string{"list", "read", "lookup", "search", "inspect"} {
				children = append(children, map[string]any{"type": "function", "name": name, "description": "preserve " + name, "parameters": schema, "strict": true})
			}
			body := map[string]any{"model": tuple.model, "input": "text", "stream": true, "store": false, "max_output_tokens": 100, "tools": []any{map[string]any{"type": "namespace", "name": "functions", "description": "five client functions", "tools": children}, map[string]any{"type": "custom", "name": "apply_patch", "format": map[string]any{"type": "text"}}}, "tool_choice": map[string]any{"type": "function", "name": "read", "namespace": "functions"}}
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			wire, mapping, err := gatewayNativePrepareProviderResponses(tuple.profile, raw, 32768)
			require.NoError(t, err)
			require.Len(t, mapping.NamespaceTools, 5)
			require.True(t, mapping.CustomTools["apply_patch"])
			require.Equal(t, "functions__read", gjson.GetBytes(wire, "tool_choice.name").String())
			require.False(t, gjson.GetBytes(wire, "tool_choice.namespace").Exists())
			var prepared map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(wire, &prepared))
			var tools []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(prepared["tools"], &tools))
			require.Len(t, tools, 6)
			require.JSONEq(t, `"functions__read"`, string(tools[1]["name"]))
			schemaBytes, err := json.Marshal(schema)
			require.NoError(t, err)
			require.JSONEq(t, string(schemaBytes), string(tools[1]["parameters"]))
			require.Equal(t, "true", string(tools[1]["strict"]))
			restorer := apicompat.NewResponsesClientToolStreamRestorer(mapping)
			events, _, err := restorer.RestoreEvent([]byte(`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"item-read","call_id":"call-read","name":"functions__read","arguments":"{\"path\":\"source.txt\"}","status":"completed"}}`))
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Equal(t, "read", gjson.GetBytes(events[0], "item.name").String())
			require.Equal(t, "functions", gjson.GetBytes(events[0], "item.namespace").String())
			var event struct {
				Item map[string]any `json:"item"`
			}
			require.NoError(t, json.Unmarshal(events[0], &event))
			body["input"] = []any{event.Item, map[string]any{"type": "function_call_output", "call_id": "call-read", "output": "file contents"}}
			raw, err = json.Marshal(body)
			require.NoError(t, err)
			wire, _, err = gatewayNativePrepareProviderResponses(tuple.profile, raw, 32768)
			require.NoError(t, err)
			require.Equal(t, "functions__read", gjson.GetBytes(wire, "input.0.name").String())
			require.False(t, gjson.GetBytes(wire, "input.0.namespace").Exists())
			require.Equal(t, `{"path":"source.txt"}`, gjson.GetBytes(wire, "input.0.arguments").String())
			require.Equal(t, "file contents", gjson.GetBytes(wire, "input.1.output").String())
		})
	}
}

func TestGatewayProviderResponsesNamespaceGuards(t *testing.T) {
	leaf := func(name string) map[string]any {
		return map[string]any{"type": "function", "name": name, "parameters": map[string]any{"type": "object"}}
	}
	namespace := func(name string, children ...any) map[string]any {
		return map[string]any{"type": "namespace", "name": name, "description": "client functions", "tools": children}
	}
	payload := func(tools []any, input any, choice any) []byte {
		body := map[string]any{"model": GatewayKimiCodeResponsesModel, "input": input, "stream": true, "store": false, "max_output_tokens": 100, "tools": tools}
		if choice != nil {
			body["tool_choice"] = choice
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		return raw
	}
	many := []any{}
	for i := 0; i < 129; i++ {
		many = append(many, leaf(fmt.Sprintf("function%d", i)))
	}
	for _, tools := range [][]any{
		{namespace("functions")},
		{namespace("functions", many...)},
		{leaf("direct"), namespace("functions", many[:128]...)},
		{namespace("functions", map[string]any{"type": "custom", "name": "apply_patch", "format": map[string]any{"type": "text"}})},
		{namespace("functions", namespace("nested", leaf("read")))},
		{namespace("functions", map[string]any{"type": "web_search"})},
		{namespace("functions", leaf("read"), leaf("read"))},
		{namespace("functions", leaf("read")), namespace("functions", leaf("write"))},
		{leaf("functions__read"), namespace("functions", leaf("read"))},
		{namespace("a__b", leaf("c")), namespace("a", leaf("b__c"))},
		{namespace(" functions ", leaf("read"))},
		{namespace(strings.Repeat("n", 129), leaf("read"))},
		{namespace("functions", leaf(strings.Repeat("n", 129)))},
		{map[string]any{"type": "namespace", "name": "functions", "description": 123, "tools": []any{leaf("read")}}},
		{map[string]any{"type": "namespace", "name": "functions", "tools": "invalid"}},
		{map[string]any{"type": "namespace", "name": "functions", "tools": []any{leaf("read")}, "children": []any{leaf("hidden")}}},
		{namespace("functions", map[string]any{"type": "function", "name": "read", "parameters": []any{}})},
		{namespace("functions", map[string]any{"type": "function", "name": "read", "parameters": map[string]any{}, "strict": "true"})},
		{namespace("functions", leaf("read")), map[string]any{"type": "web_search"}},
	} {
		require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(GatewayKimiCodeResponsesProfile, payload(tools, "text", nil), 262144), ErrGatewayNativeIdentity)
	}
	tools := []any{namespace("functions", leaf("read"))}
	for _, input := range []any{
		[]any{map[string]any{"type": "function_call", "name": "missing", "namespace": "functions", "call_id": "c", "arguments": "{}"}},
		[]any{map[string]any{"type": "function_call", "name": "read", "namespace": "missing", "call_id": "c", "arguments": "{}"}},
		[]any{map[string]any{"type": "function_call", "name": "read", "namespace": 123, "call_id": "c", "arguments": "{}"}},
		[]any{map[string]any{"type": "custom_tool_call", "name": "read", "namespace": "functions", "call_id": "c", "input": "text"}},
	} {
		require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(GatewayKimiCodeResponsesProfile, payload(tools, input, nil), 32768), ErrGatewayNativeIdentity)
	}
	require.ErrorIs(t, ValidateGatewayNativeProviderResponsesBounded(GatewayKimiCodeResponsesProfile, payload(tools, "text", map[string]any{"type": "function", "name": "missing", "namespace": "functions"}), 32768), ErrGatewayNativeIdentity)
}

// Clients replay the previous output items unchanged on the next turn. Open
// reasoning models served through OpenRouter put their text in a reasoning
// item's content, which used to be refused at input admission (a 502 for the
// whole review).
func TestGatewayNativeOpenRouterAcceptsReplayedReasoningText(t *testing.T) {
	accepted := []string{
		`[{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"reasoning_text","text":"deep thought"}]}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"s"}],"content":[{"type":"reasoning_text","text":"t"}],"encrypted_content":"abc","status":"completed"}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[]}]`,
	}
	for _, raw := range accepted {
		require.True(t, gatewayNativeProviderTextInput(GatewayOpenRouterResponsesProfile, []byte(raw)), raw)
	}
	// Everything else stays strict: unknown keys, null values, other part types.
	rejected := []string{
		`[{"type":"reasoning","id":"rs_1","summary":[],"format":"unknown"}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[],"content":null}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"input_text","text":"x"}]}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"reasoning_text","text":"x","extra":1}]}]`,
		`[{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":null}]`,
	}
	for _, raw := range rejected {
		require.False(t, gatewayNativeProviderTextInput(GatewayOpenRouterResponsesProfile, []byte(raw)), raw)
	}
	// A profile that never returned reasoning content still refuses it.
	require.False(t, gatewayNativeProviderTextInput(GatewayKimiCodeResponsesProfile, []byte(accepted[0])))
}
