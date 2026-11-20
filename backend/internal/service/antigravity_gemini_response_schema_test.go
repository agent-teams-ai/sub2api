//go:build unit

package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func cleanGeminiRequestMap(t *testing.T, body string) map[string]any {
	t.Helper()
	out, err := cleanGeminiRequest([]byte(body))
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(out, &payload))
	return payload
}

func TestCleanGeminiRequest_ResponseJsonSchemaBecomesResponseSchema(t *testing.T) {
	payload := cleanGeminiRequestMap(t, `{
		"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
		"generationConfig": {
			"responseMimeType": "application/json",
			"responseJsonSchema": {
				"$schema": "https://json-schema.org/draft/2020-12/schema",
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"title": {"type": "string", "maxLength": 40},
					"mood": {"type": "string", "enum": ["vui", "buồn"]},
					"beats": {"type": "array", "minItems": 3, "items": {"type": "string"}}
				},
				"required": ["title", "mood", "beats"]
			}
		}
	}`)

	config := payload["generationConfig"].(map[string]any)
	require.NotContains(t, config, "responseJsonSchema")
	require.Equal(t, "application/json", config["responseMimeType"])

	schema := config["responseSchema"].(map[string]any)
	require.NotContains(t, schema, "$schema")
	require.NotContains(t, schema, "additionalProperties")
	require.Equal(t, "object", schema["type"])
	require.ElementsMatch(t, []any{"title", "mood", "beats"}, schema["required"])

	props := schema["properties"].(map[string]any)
	require.Equal(t, []any{"vui", "buồn"}, props["mood"].(map[string]any)["enum"])
	// Antigravity 不支持的约束迁移到 description，模型仍能看到。
	require.Contains(t, props["beats"].(map[string]any)["description"], "minItems: 3")
	require.NotContains(t, props["title"].(map[string]any), "maxLength")
}

func TestCleanGeminiRequest_SnakeCaseResponseJsonSchema(t *testing.T) {
	payload := cleanGeminiRequestMap(t, `{"generation_config": {"response_json_schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}`)
	config := payload["generation_config"].(map[string]any)
	require.NotContains(t, config, "response_json_schema")
	require.Equal(t, "object", config["responseSchema"].(map[string]any)["type"])
}

func TestCleanGeminiRequest_ExistingResponseSchemaWins(t *testing.T) {
	payload := cleanGeminiRequestMap(t, `{"generationConfig": {
		"responseSchema": {"type": "STRING"},
		"responseJsonSchema": {"type": "object", "properties": {"a": {"type": "string"}}}
	}}`)
	config := payload["generationConfig"].(map[string]any)
	require.NotContains(t, config, "responseJsonSchema")
	require.Equal(t, map[string]any{"type": "STRING"}, config["responseSchema"])
}

func TestCleanGeminiRequest_NoSchemaLeavesBodyUntouched(t *testing.T) {
	body := `{"generationConfig": {"temperature": 0.5}}`
	out, err := cleanGeminiRequest([]byte(body))
	require.NoError(t, err)
	require.Equal(t, body, string(out))
}

func TestCleanGeminiRequest_PreservesUnchangedSchemaOrderAndExactJSON(t *testing.T) {
	body := []byte(`{"generationConfig":{"responseJsonSchema":{"type":"object","properties":{"zeta":{"type":"string"},"alpha":{"type":"string"}},"required":["zeta","alpha"]}}}`)
	out, err := cleanGeminiRequest(body)
	require.NoError(t, err)
	require.NotContains(t, string(out), "responseJsonSchema")
	schema := gjson.GetBytes(out, "generationConfig.responseSchema")
	require.True(t, schema.Exists())
	require.Contains(t, schema.Raw, `"properties":{"zeta":`)
	require.Less(t, strings.Index(schema.Raw, `"zeta"`), strings.Index(schema.Raw, `"alpha"`))
	require.Equal(t, `{"type":"object","properties":{"zeta":{"type":"string"},"alpha":{"type":"string"}},"required":["zeta","alpha"]}`, schema.Raw)
}

func TestCleanGeminiRequest_DoesNotRoundLargeEnumIntegerDuringCleanup(t *testing.T) {
	body := []byte(`{"generationConfig":{"responseJsonSchema":{"type":"object","properties":{"value":{"type":"integer","enum":[9007199254740993]}}}}}`)
	out, err := cleanGeminiRequest(body)
	require.NoError(t, err)
	require.NotContains(t, string(out), "9007199254740992")
	require.Contains(t, string(out), "9007199254740993")
	require.Equal(t, "9007199254740993", gjson.GetBytes(out, "generationConfig.responseSchema.properties.value.enum.0").String())
}

