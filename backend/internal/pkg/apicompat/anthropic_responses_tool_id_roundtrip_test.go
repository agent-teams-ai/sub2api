package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Anthropic's tool IDs allow letters, digits, underscores and hyphens; their
// identity must survive a Responses client returning the provider's tool call.
func TestAnthropicResponsesContinuationPreservesProviderToolIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
	}{
		{name: "bare", ids: []string{"joined-call-1"}},
		{name: "call prefix", ids: []string{"call_joined"}},
		{name: "toolu prefix", ids: []string{"toolu_joined"}},
		{name: "distinct bare and prefixed", ids: []string{"joined-call-1", "toolu_joined-call-1"}},
		{name: "fc toolu prefix", ids: []string{"fc_toolu_joined"}},
		{name: "fc call prefix", ids: []string{"fc_call_joined"}},
		{name: "distinct fc and toolu", ids: []string{"fc_toolu_joined", "toolu_joined"}},
		{name: "distinct fc and call", ids: []string{"fc_call_joined", "call_joined"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var blocks []AnthropicContentBlock
			for _, id := range tc.ids {
				blocks = append(blocks, AnthropicContentBlock{
					Type: "tool_use", ID: id, Name: "lookup", Input: json.RawMessage(`{}`),
				})
			}
			response := AnthropicToResponsesResponse(&AnthropicResponse{
				ID: "msg_provider_ids", Model: "claude-sonnet-4-6", Content: blocks,
			})
			require.Len(t, response.Output, len(tc.ids))
			for i, id := range tc.ids {
				require.Equal(t, "function_call", response.Output[i].Type)
				require.Equal(t, id, response.Output[i].CallID)
			}

			// Return the actual serialized response output, as an SDK client does.
			raw, err := json.Marshal(response.Output)
			require.NoError(t, err)
			var input []ResponsesInputItem
			require.NoError(t, json.Unmarshal(raw, &input))
			for _, item := range response.Output {
				input = append(input, ResponsesInputItem{
					Type: "function_call_output", CallID: item.CallID, Output: "result:" + item.CallID,
				})
			}
			raw, err = json.Marshal(input)
			require.NoError(t, err)
			continuation, err := ResponsesToAnthropicRequest(&ResponsesRequest{
				Model: response.Model, Input: raw,
			})
			require.NoError(t, err)
			assertAnthropicPairing(t, continuation.Messages)
			require.Len(t, continuation.Messages, 2)
			assert.Equal(t, "assistant", continuation.Messages[0].Role)
			assert.Equal(t, "user", continuation.Messages[1].Role)
			var calls, results []AnthropicContentBlock
			require.NoError(t, json.Unmarshal(continuation.Messages[0].Content, &calls))
			require.NoError(t, json.Unmarshal(continuation.Messages[1].Content, &results))
			require.Len(t, calls, len(tc.ids))
			require.Len(t, results, len(tc.ids))
			for i, id := range tc.ids {
				assert.Equal(t, id, calls[i].ID)
				assert.Equal(t, id, results[i].ToolUseID)
				assert.JSONEq(t, `"result:`+id+`"`, string(results[i].Content))
			}
		})
	}
}
