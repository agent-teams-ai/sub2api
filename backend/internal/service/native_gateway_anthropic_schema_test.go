//go:build unit

package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeAnthropicSchemaPreservesOriginalConstraints(t *testing.T) {
	original := json.RawMessage(`{"type":"object","properties":{"confidence":{"type":"number","minimum":0,"maximum":1},"minimum":{"type":["string","null"]}},"required":["confidence","minimum"],"additionalProperties":false}`)
	lowered, validate, err := gatewayAnthropicOutputSchema(original)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(lowered, &fields))
	var props map[string]map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fields["properties"], &props))
	require.Nil(t, props["confidence"]["minimum"])
	require.Nil(t, props["confidence"]["maximum"])
	require.Contains(t, string(props["confidence"]["description"]), "greater than or equal to 0")
	require.NotNil(t, props["minimum"], "property names are not schema keywords")
	require.Contains(t, string(original), `"maximum":1`, "the caller schema stays intact")
	for _, tc := range []struct {
		json string
		ok   bool
	}{
		{`{"confidence":0,"minimum":null}`, true},
		{`{"confidence":1,"minimum":"value"}`, true},
		{`{"confidence":1.01,"minimum":null}`, false},
		{`{"confidence":-0.01,"minimum":null}`, false},
		{`{"confidence":0.5}`, false},
		{`{"confidence":0.5,"minimum":null,"extra":1}`, false},
		{`{"confidence":1.01,"confidence":0.5,"minimum":null}`, false},
		{`{"confidence":0.5,"minimum":"\ud800"}`, false},
	} {
		t.Run(tc.json, func(t *testing.T) {
			output := []apicompat.ResponsesOutput{{Type: "message", Role: "assistant", Content: []apicompat.ResponsesContentPart{{Type: "output_text", Text: tc.json}}}}
			require.Equal(t, tc.ok, validate(output))
		})
	}
	for _, unsupported := range []string{
		`{"$ref":"https://example.invalid/schema"}`,
		`{"type":"object","properties":{"x":{"$ref":"#"}},"additionalProperties":false}`,
		`{"type":"object","properties":{"x":{"type":"string","minLength":2}},"additionalProperties":false}`,
		`{"type":"object","additionalProperties":true}`,
		`{"type":"object","properties":{"x":{"type":"number","minimum":0,"minimum":1}},"additionalProperties":false}`,
	} {
		_, _, err := gatewayAnthropicOutputSchema(json.RawMessage(unsupported))
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
}

func TestGatewayNativeOfficialAnthropicOriginalSchemaBeforeSuccess(t *testing.T) {
	const schema = `{"type":"object","properties":{"confidence":{"type":"number","minimum":0,"maximum":1}},"required":["confidence"],"additionalProperties":false}`
	for _, tc := range []struct {
		name, text string
		ok         bool
	}{{"within range", `{"confidence":0.8}`, true}, {"out of range", `{"confidence":1.1}`, false}} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			_, _, call := officialAPIWireFixture(t, GatewayAnthropicAPIKeyProfile, GatewayAnthropicAPIBaseURL, GatewayAnthropicAPIModel, func(w http.ResponseWriter, r *http.Request) {
				requests++
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Contains(t, string(body), `"format":{"type":"json_schema"`)
				require.NotContains(t, string(body), `"minimum":`)
				require.NotContains(t, string(body), `"maximum":`)
				require.Contains(t, string(body), "less than or equal to 1")
				w.Header().Set("Content-Type", "text/event-stream")
				for _, event := range []any{
					map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_schema", "type": "message", "role": "assistant", "model": GatewayAnthropicAPIModel, "content": []any{}, "usage": map[string]int{"input_tokens": 5, "output_tokens": 0}}},
					map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}},
					map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": tc.text}},
					map[string]any{"type": "content_block_stop", "index": 0},
					map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn"}, "usage": map[string]int{"output_tokens": 3}},
					map[string]any{"type": "message_stop"},
				} {
					raw, err := json.Marshal(event)
					require.NoError(t, err)
					fmt.Fprintf(w, "data: %s\n\n", raw)
				}
			})
			body := []byte(`{"model":"claude-sonnet-4-6","input":"Review","stream":true,"store":false,"max_output_tokens":512,"text":{"format":{"type":"json_schema","strict":true,"schema":` + schema + `}}}`)
			recorder, entered, err := call(body)
			require.True(t, entered)
			require.Equal(t, 1, requests)
			if tc.ok {
				require.NoError(t, err)
				require.NotEmpty(t, officialAPICompletedOutput(t, recorder.Body.String()))
			} else {
				require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
				require.False(t, strings.Contains(recorder.Body.String(), `"type":"response.completed"`))
			}
		})
	}
}
