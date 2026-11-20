package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func marshalMessageWire(t *testing.T, value any) gjson.Result {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return gjson.ParseBytes(raw)
}

func TestMessageContentWireConsistent(t *testing.T) {
	for _, text := range []string{"", "search result"} {
		t.Run(text, func(t *testing.T) {
			part := ResponsesContentPart{Type: "output_text", Text: text}
			item := ResponsesOutput{Type: "message", ID: "msg_1", Role: "assistant", Status: "completed", Content: []ResponsesContentPart{part}}
			response := ResponsesResponse{ID: "resp_1", Object: "response", Status: "completed", Output: []ResponsesOutput{item}}
			parts := []gjson.Result{
				marshalMessageWire(t, ResponsesStreamEvent{Type: "response.content_part.done", Part: &part}).Get("part"),
				marshalMessageWire(t, ResponsesStreamEvent{Type: "response.output_item.done", Item: &item}).Get("item.content.0"),
				marshalMessageWire(t, ResponsesStreamEvent{Type: "response.completed", Response: &response}).Get("response.output.0.content.0"),
				marshalMessageWire(t, response).Get("output.0.content.0"),
			}
			for _, encoded := range parts {
				require.Equal(t, "output_text", encoded.Get("type").String())
				require.True(t, encoded.Get("text").Exists())
				require.Equal(t, text, encoded.Get("text").String())
				require.Equal(t, "[]", encoded.Get("annotations").Raw)
				require.Equal(t, "[]", encoded.Get("logprobs").Raw)
			}
		})
	}
}

func TestMessageRefusalPreserved(t *testing.T) {
	item := ResponsesOutput{Type: "message", ID: "msg_1", Role: "assistant", Content: []ResponsesContentPart{{Type: "refusal", Refusal: "Cannot provide this."}}}
	for _, encoded := range []gjson.Result{
		marshalMessageWire(t, item),
		marshalMessageWire(t, ResponsesStreamEvent{Type: "response.output_item.done", Item: &item}).Get("item"),
	} {
		require.Equal(t, "refusal", encoded.Get("content.0.type").String())
		require.Equal(t, "Cannot provide this.", encoded.Get("content.0.refusal").String())
		require.False(t, encoded.Get("content.0.text").Exists())
	}
}

func TestEmptyMessageContentArray(t *testing.T) {
	item := marshalMessageWire(t, ResponsesOutput{Type: "message", ID: "msg_1", Role: "assistant"})
	require.Equal(t, "[]", item.Get("content").Raw)
}

func TestMergedResponsesReasoningSummaryWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		summary []ResponsesSummary
	}{
		{name: "empty"},
		{name: "present", summary: []ResponsesSummary{{Type: "summary_text", Text: "plan"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := ResponsesOutput{Type: "reasoning", ID: "rs_1", Status: "completed", Summary: tc.summary}
			response := ResponsesResponse{ID: "resp_1", Object: "response", Status: "completed", Output: []ResponsesOutput{item}}
			encoded := []gjson.Result{
				marshalMessageWire(t, item),
				marshalMessageWire(t, response).Get("output.0"),
				marshalMessageWire(t, ResponsesStreamEvent{Type: "response.output_item.done", Item: &item}).Get("item"),
				marshalMessageWire(t, ResponsesStreamEvent{Type: "response.completed", Response: &response}).Get("response.output.0"),
			}
			for _, result := range encoded {
				require.True(t, result.Get("summary").Exists(), "required reasoning summary array must be present")
				require.True(t, result.Get("summary").IsArray(), "reasoning summary must be an array")
				require.Len(t, result.Get("summary").Array(), len(tc.summary))
				if len(tc.summary) != 0 {
					require.Equal(t, "summary_text", result.Get("summary.0.type").String())
					require.Equal(t, "plan", result.Get("summary.0.text").String())
				}
			}
		})
	}
}

func TestMergedResponsesClientToolSearchWire(t *testing.T) {
	item := ResponsesOutput{Type: "tool_search_call", ID: "tsc_1", CallID: "call_1", Arguments: "{\"query\":\"repo\"}"}
	response := ResponsesResponse{ID: "resp_1", Object: "response", Status: "completed", Output: []ResponsesOutput{item}}
	encoded := []gjson.Result{
		marshalMessageWire(t, item),
		marshalMessageWire(t, response).Get("output.0"),
		marshalMessageWire(t, ResponsesStreamEvent{Type: "response.output_item.done", Item: &item}).Get("item"),
	}
	for _, result := range encoded {
		require.Equal(t, "tool_search_call", result.Get("type").String())
		require.Equal(t, "tsc_1", result.Get("id").String())
		require.Equal(t, "call_1", result.Get("call_id").String())
		require.Equal(t, "client", result.Get("execution").String())
		require.True(t, result.Get("arguments").IsObject(), "tool_search arguments must be an object")
		require.Equal(t, "repo", result.Get("arguments.query").String())
	}
}
