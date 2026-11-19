package apicompat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResponsesToAnthropicPreservesStructuredOutputAndEffort(t *testing.T) {
	format := json.RawMessage(`{"type":"json_schema","name":"codex_output_schema","strict":true,"schema":{"type":"object","additionalProperties":false,"required":["confidence"],"properties":{"confidence":{"type":["number","null"],"minimum":0,"maximum":1}}}}`)
	for _, model := range []string{"claude-sonnet-4-6", "claude-sonnet-5-5", "claude-haiku-5-5"} {
		for _, effort := range []string{"", "low", "none"} {
			t.Run(model+"/"+effort, func(t *testing.T) {
				req := &ResponsesRequest{Model: model, Input: json.RawMessage(`"Review this change"`), Text: &ResponsesText{Format: format}}
				if effort != "" {
					req.Reasoning = &ResponsesReasoning{Effort: effort}
				}
				out, err := ResponsesToAnthropicRequest(req)
				require.NoError(t, err)
				require.NotNil(t, out.OutputConfig)
				require.NotNil(t, out.OutputConfig.Format)
				require.Equal(t, "json_schema", out.OutputConfig.Format.Type)
				require.JSONEq(t, `{"type":"object","additionalProperties":false,"required":["confidence"],"properties":{"confidence":{"type":["number","null"],"minimum":0,"maximum":1}}}`, string(out.OutputConfig.Format.Schema))
				wire, err := json.Marshal(out)
				require.NoError(t, err)
				require.NotContains(t, string(wire), "codex_output_schema")
				require.Contains(t, string(wire), `"maximum":1`)
			})
		}
	}
}

func TestResponsesToAnthropicStructuredOutputRejectsUnsupportedEnvelope(t *testing.T) {
	for _, raw := range []string{
		`{"type":"json_object"}`,
		`{"type":"json_schema","schema":[]}`,
		`{"type":"json_schema","schema":true}`,
		`{"type":"json_schema","schema":{},"strict":"yes"}`,
		`{"type":"json_schema","schema":{},"unknown":true}`,
		`{"type":"text","schema":{}}`,
		`{"type":"json_schema","schema":{},"description":"` + strings.Repeat("a", 64<<10) + `"}`,
	} {
		_, err := ResponsesToAnthropicRequest(&ResponsesRequest{Model: "claude-sonnet-4-6", Input: json.RawMessage(`"fixture"`), Text: &ResponsesText{Format: json.RawMessage(raw)}})
		require.Error(t, err)
		require.NotContains(t, err.Error(), raw)
	}
	for _, raw := range []string{"null", `{"type":"text"}`} {
		out, err := ResponsesToAnthropicRequest(&ResponsesRequest{Model: "claude-sonnet-4-6", Input: json.RawMessage(`"fixture"`), Text: &ResponsesText{Format: json.RawMessage(raw)}})
		require.NoError(t, err)
		require.Nil(t, out.OutputConfig)
	}
}
