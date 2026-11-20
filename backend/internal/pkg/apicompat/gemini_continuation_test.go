package apicompat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type geminiFixtureCodec struct {
	aead  cipher.AEAD
	scope string
}

func newGeminiFixtureCodec(t *testing.T, scope string) geminiFixtureCodec {
	t.Helper()
	block, err := aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return geminiFixtureCodec{aead, scope}
}
func (c geminiFixtureCodec) Seal(raw []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(c.aead.Seal(nonce, nonce, raw, []byte(c.scope))), nil
}
func (c geminiFixtureCodec) Open(raw string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(data) < c.aead.NonceSize() {
		return nil, ErrGeminiContinuation
	}
	return c.aead.Open(nil, data[:c.aead.NonceSize()], data[c.aead.NonceSize():], []byte(c.scope))
}

func geminiFixtureSource(t *testing.T, raw string) *ChatCompletionsResponse {
	t.Helper()
	var source ChatCompletionsResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &source))
	return &source
}

func geminiFixtureOutput(t *testing.T, source *ChatCompletionsResponse, codec GeminiContinuationCodec, custom map[string]bool) *ResponsesResponse {
	t.Helper()
	out := ChatCompletionsResponseToResponses(source, "gemini-fixture", custom, nil, false, nil)
	require.NoError(t, AttachGeminiContinuation(out, source.Choices[0].Message, codec))
	return out
}

func geminiFixtureInput(t *testing.T, outputs ...*ResponsesResponse) json.RawMessage {
	t.Helper()
	items := []any{map[string]any{"role": "user", "content": "Review the fixture"}}
	for _, out := range outputs {
		for _, item := range out.Output {
			items = append(items, item)
		}
		for _, item := range out.Output {
			if item.Type == "function_call" || item.Type == "custom_tool_call" {
				items = append(items, map[string]any{"type": item.Type + "_output", "call_id": item.CallID, "output": "fixture-tool-result"})
			}
		}
	}
	raw, err := json.Marshal(items)
	require.NoError(t, err)
	return raw
}

func geminiFixtureRestore(t *testing.T, input json.RawMessage, codec GeminiContinuationCodec) *ChatCompletionsRequest {
	t.Helper()
	chat, err := ResponsesToChatCompletionsRequest(&ResponsesRequest{Model: "gemini-fixture", Input: input})
	require.NoError(t, err)
	require.NoError(t, RestoreGeminiContinuation(input, chat, codec))
	return chat
}

// The pinned CLI commits history in output_item.done event order, regardless
// of output_index. This is intentionally separate from buffered output order.
func geminiStreamFixtureInput(t *testing.T, events []ResponsesStreamEvent) json.RawMessage {
	t.Helper()
	var output []ResponsesOutput
	for _, event := range events {
		if event.Type == "response.output_item.done" && event.Item != nil {
			output = append(output, *event.Item)
		}
	}
	return geminiFixtureInput(t, &ResponsesResponse{Output: output})
}

func TestGeminiContinuationPreservesParallelCallAssociationAndCustomInput(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "owner/account/generation/model")
	source := geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-function","type":"function","function":{"name":"lookup","arguments":"{\"path\":\"main.go\"}"},"extra_content":{"google":{"thought_signature":"fixture-first-signature"}}},{"id":"call-custom","type":"function","function":{"name":"exec","arguments":"{\"input\":\"rg TODO\"}"}}]},"finish_reason":"tool_calls"}]}`)
	out := geminiFixtureOutput(t, source, codec, map[string]bool{"exec": true})
	require.Len(t, out.Output, 3)
	require.Equal(t, "custom_tool_call", out.Output[1].Type)
	require.Equal(t, "rg TODO", out.Output[1].Input)
	public, _ := json.Marshal(out)
	require.NotContains(t, string(public), "fixture-first-signature")
	chat := geminiFixtureRestore(t, geminiFixtureInput(t, out), codec)
	require.Len(t, chat.Messages[1].ToolCalls, 2)
	require.Equal(t, "call-function", chat.Messages[1].ToolCalls[0].ID)
	require.Equal(t, "fixture-first-signature", chat.Messages[1].ToolCalls[0].ExtraContent.Google.ThoughtSignature)
	require.Nil(t, chat.Messages[1].ToolCalls[1].ExtraContent)
	require.JSONEq(t, `{"input":"rg TODO"}`, chat.Messages[1].ToolCalls[1].Function.Arguments)
}

func TestGeminiContinuationKeepsSequentialStepsDistinct(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	first := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-a","function":{"name":"read","arguments":"{}"},"extra_content":{"google":{"thought_signature":"sig-a"}}}]}}]}`), codec, nil)
	second := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-b","function":{"name":"read","arguments":"{}"},"extra_content":{"google":{"thought_signature":"sig-b"}}}]}}]}`), codec, nil)
	chat := geminiFixtureRestore(t, geminiFixtureInput(t, first, second), codec)
	got := map[string]string{}
	for _, message := range chat.Messages {
		for _, call := range message.ToolCalls {
			got[call.ID] = call.ExtraContent.Google.ThoughtSignature
		}
	}
	require.Equal(t, map[string]string{"call-a": "sig-a", "call-b": "sig-b"}, got)
}

func TestGeminiContinuationRejectsMissingChangedForeignAndDuplicateProof(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "owner-one")
	source := geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-a","function":{"name":"read","arguments":"{}"},"extra_content":{"google":{"thought_signature":"private-fixture-signature"}}}]}}]}`)
	out := geminiFixtureOutput(t, source, codec, nil)
	input := geminiFixtureInput(t, out)
	for _, test := range []struct {
		name  string
		raw   json.RawMessage
		codec GeminiContinuationCodec
	}{
		{"foreign scope", input, newGeminiFixtureCodec(t, "owner-two")},
		{"changed call", json.RawMessage(strings.Replace(string(input), `"name":"read"`, `"name":"write"`, 1)), codec},
		{"removed proof", geminiFixtureInput(t, &ResponsesResponse{Output: out.Output[:1]}), codec},
		{"duplicated proof", geminiFixtureInput(t, &ResponsesResponse{Output: append(append([]ResponsesOutput{}, out.Output...), out.Output[1])}), codec},
		{"unknown carrier", json.RawMessage(strings.Replace(string(input), GeminiContinuationPrefix, "other-v1.", 1)), codec},
	} {
		t.Run(test.name, func(t *testing.T) {
			chat, err := ResponsesToChatCompletionsRequest(&ResponsesRequest{Input: test.raw})
			require.NoError(t, err)
			err = RestoreGeminiContinuation(test.raw, chat, test.codec)
			require.ErrorIs(t, err, ErrGeminiContinuation)
			require.NotContains(t, err.Error(), "private-fixture-signature")
		})
	}
}

func TestGeminiContinuationAcceptsLateSignatureAndEmitsProofBeforeToolDone(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	state := NewChatCompletionsToResponsesStreamState("gemini-fixture")
	signatures := NewGeminiContinuationStream(state)
	for _, raw := range []string{
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-a","function":{"name":"read","arguments":"{"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}},{"index":1,"id":"call-b","function":{"name":"read","arguments":"{}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{},"extra_content":{"google":{"thought_signature":"late-signature"}}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}`,
	} {
		var chunk ChatCompletionsChunk
		require.NoError(t, json.Unmarshal([]byte(raw), &chunk))
		require.NoError(t, signatures.Observe(&chunk))
		ChatCompletionsChunkToResponsesEvents(&chunk, state)
	}
	events, err := signatures.Finalize(state, codec)
	require.NoError(t, err)
	require.Equal(t, "reasoning", events[1].Item.Type)
	require.Equal(t, "response.output_item.done", events[1].Type)
	require.Equal(t, "response.completed", events[len(events)-1].Type)
	for i := 1; i < len(events); i++ {
		require.Equal(t, events[i-1].SequenceNumber+1, events[i].SequenceNumber)
	}
	out := events[len(events)-1].Response
	require.Equal(t, 13, out.Usage.TotalTokens)
	chat := geminiFixtureRestore(t, geminiStreamFixtureInput(t, events), codec)
	buffered := geminiFixtureRestore(t, geminiFixtureInput(t, out), codec)
	require.Equal(t, chat, buffered, "stream-event and completed-array clients must recover identical history")
	for _, event := range events {
		if event.Type == "response.output_item.done" && event.Item != nil {
			require.Equal(t, event.Item.Type, out.Output[event.OutputIndex].Type)
			if event.Item.Type == "reasoning" {
				require.Equal(t, *event.Item, out.Output[event.OutputIndex])
			}
		}
	}
	require.Equal(t, "late-signature", chat.Messages[1].ToolCalls[0].ExtraContent.Google.ThoughtSignature)
	require.Nil(t, chat.Messages[1].ToolCalls[1].ExtraContent)
}

func TestGeminiContinuationWireMatchesCompletedHistory(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	state := NewChatCompletionsToResponsesStreamState("gemini-3.1-pro-preview")
	continuation := NewGeminiContinuationStream(state)
	var wire strings.Builder
	emit := func(events []ResponsesStreamEvent) {
		for _, event := range events {
			sse, err := ResponsesEventToSSE(event)
			require.NoError(t, err)
			wire.WriteString(sse)
		}
	}
	// The joined native fixture sends the signature after the function call.
	for _, raw := range []string{
		`{"id":"joined-official","object":"chat.completion.chunk","created":1,"model":"gemini-3.1-pro-preview","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"joined-call-1","type":"function","function":{"name":"joined_lookup","arguments":"{}"}}]},"finish_reason":null}]}`,
		`{"id":"joined-official","object":"chat.completion.chunk","created":1,"model":"gemini-3.1-pro-preview","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"extra_content":{"google":{"thought_signature":"joined-gemini-signature"}}}]},"finish_reason":null}]}`,
		`{"id":"joined-official","object":"chat.completion.chunk","created":1,"model":"gemini-3.1-pro-preview","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`,
	} {
		var chunk ChatCompletionsChunk
		require.NoError(t, json.Unmarshal([]byte(raw), &chunk))
		require.NoError(t, continuation.Observe(&chunk))
		emit(ChatCompletionsChunkToResponsesEvents(&chunk, state))
	}
	final, err := continuation.Finalize(state, codec)
	require.NoError(t, err)
	emit(final)

	var done, completed []json.RawMessage
	for _, line := range strings.Split(wire.String(), "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type     string          `json:"type"`
			Item     json.RawMessage `json:"item"`
			Response struct {
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		require.NoError(t, json.Unmarshal([]byte(data), &event))
		switch event.Type {
		case "response.output_item.done":
			done = append(done, event.Item)
		case "response.completed":
			completed = event.Response.Output
		}
	}
	require.Len(t, done, 2)
	require.Len(t, completed, len(done))
	for i := range done {
		assert.JSONEq(t, string(done[i]), string(completed[i]), "wire history item %d", i)
	}
	input := func(items []json.RawMessage) json.RawMessage {
		raw, err := json.Marshal(items)
		require.NoError(t, err)
		var output []ResponsesOutput
		require.NoError(t, json.Unmarshal(raw, &output))
		return geminiFixtureInput(t, &ResponsesResponse{Output: output})
	}
	streamed := geminiFixtureRestore(t, input(done), codec)
	buffered := geminiFixtureRestore(t, input(completed), codec)
	require.Equal(t, streamed, buffered)
	require.Equal(t, "joined-call-1", streamed.Messages[1].ToolCalls[0].ID)
	require.Equal(t, "joined-gemini-signature", streamed.Messages[1].ToolCalls[0].ExtraContent.Google.ThoughtSignature)
}

func TestGeminiContinuationRetainsMessageSignatureAndLeavesOrdinaryConverterUnchanged(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	source := geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","content":"Review done","extra_content":{"google":{"thought_signature":"text-signature"}}},"finish_reason":"stop"}]}`)
	ordinary := ChatCompletionsResponseToResponses(source, "ordinary", nil, nil, false, nil)
	require.Len(t, ordinary.Output, 1)
	out := geminiFixtureOutput(t, source, codec, nil)
	chat := geminiFixtureRestore(t, geminiFixtureInput(t, out), codec)
	require.Equal(t, "text-signature", chat.Messages[1].ExtraContent.Google.ThoughtSignature)
	state := NewChatCompletionsToResponsesStreamState("gemini-fixture")
	stream := NewGeminiContinuationStream(state)
	text := "Review done"
	for _, chunk := range []*ChatCompletionsChunk{
		{Choices: []ChatChunkChoice{{Delta: ChatDelta{Content: &text}}}},
		{Choices: []ChatChunkChoice{{Delta: ChatDelta{ExtraContent: geminiExtra("text-signature")}}}},
	} {
		require.NoError(t, stream.Observe(chunk))
		ChatCompletionsChunkToResponsesEvents(chunk, state)
	}
	events, err := stream.Finalize(state, codec)
	require.NoError(t, err)
	chat = geminiFixtureRestore(t, geminiStreamFixtureInput(t, events), codec)
	require.Equal(t, "text-signature", chat.Messages[1].ExtraContent.Google.ThoughtSignature)
	require.Equal(t, chat, geminiFixtureRestore(t, geminiFixtureInput(t, events[len(events)-1].Response), codec))
}

func TestGeminiContinuationClosesUnsignedReservedSlotWithoutPrivateContent(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	state := NewChatCompletionsToResponsesStreamState("gemini-fixture")
	stream := NewGeminiContinuationStream(state)
	text := "Review done"
	chunk := &ChatCompletionsChunk{Choices: []ChatChunkChoice{{Delta: ChatDelta{Content: &text}}}}
	require.NoError(t, stream.Observe(chunk))
	ChatCompletionsChunkToResponsesEvents(chunk, state)
	events, err := stream.Finalize(state, codec)
	require.NoError(t, err)
	output := events[len(events)-1].Response
	require.Len(t, output.Output, 2)
	require.Equal(t, "reasoning", output.Output[0].Type)
	require.Empty(t, output.Output[0].EncryptedContent)
	require.Equal(t, 0, events[1].OutputIndex)
	require.Equal(t, geminiFixtureRestore(t, geminiStreamFixtureInput(t, events), codec), geminiFixtureRestore(t, geminiFixtureInput(t, output), codec))
}

func TestGeminiContinuationRejectsSignatureWithoutStreamedOutput(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	state := NewChatCompletionsToResponsesStreamState("gemini-fixture")
	stream := NewGeminiContinuationStream(state)
	chunk := &ChatCompletionsChunk{Choices: []ChatChunkChoice{{Delta: ChatDelta{ExtraContent: geminiExtra("orphan-signature")}}}}
	require.NoError(t, stream.Observe(chunk))
	ChatCompletionsChunkToResponsesEvents(chunk, state)
	events, err := stream.Finalize(state, codec)
	require.ErrorIs(t, err, ErrGeminiContinuation)
	require.Empty(t, events)
	require.False(t, state.CompletedSent)
	state.Reasoning.WriteString(" \t\n")
	events, err = stream.Finalize(state, codec)
	require.ErrorIs(t, err, ErrGeminiContinuation)
	require.Empty(t, events)
	require.False(t, state.CompletedSent, "whitespace cannot manufacture a message for an orphan signature")
}

func TestGeminiContinuationStringUserItemsRemainConversationBoundaries(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	out := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","content":"Done","extra_content":{"google":{"thought_signature":"text-proof"}}}}]}`), codec, nil)
	var items []json.RawMessage
	require.NoError(t, json.Unmarshal(geminiFixtureInput(t, out), &items))
	items[0] = json.RawMessage(`"Review this source"`)
	raw, err := json.Marshal(items)
	require.NoError(t, err)
	chat := geminiFixtureRestore(t, raw, codec)
	require.Equal(t, "text-proof", chat.Messages[1].ExtraContent.Google.ThoughtSignature)
	items = append(items[:2], append([]json.RawMessage{json.RawMessage(`"Different user turn"`)}, items[2:]...)...)
	raw, err = json.Marshal(items)
	require.NoError(t, err)
	chat, err = ResponsesToChatCompletionsRequest(&ResponsesRequest{Input: raw})
	require.NoError(t, err)
	require.ErrorIs(t, RestoreGeminiContinuation(raw, chat, codec), ErrGeminiContinuation)
}

func TestGeminiContinuationEmptyTextDoesNotSignPriorToolOnlyMessage(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	first := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-one","function":{"name":"read","arguments":"{}"},"extra_content":{"google":{"thought_signature":"call-proof"}}}]}}]}`), codec, nil)
	second := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","content":"","extra_content":{"google":{"thought_signature":"empty-text-proof"}}}}]}`), codec, nil)
	chat := geminiFixtureRestore(t, geminiFixtureInput(t, first, second), codec)
	require.Nil(t, chat.Messages[1].ExtraContent)
	require.Equal(t, "call-proof", chat.Messages[1].ToolCalls[0].ExtraContent.Google.ThoughtSignature)
	require.Equal(t, "empty-text-proof", chat.Messages[3].ExtraContent.Google.ThoughtSignature)
}

func TestGeminiContinuationRepeatedTextKeepsExactStepAssociationWithoutIDs(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	first := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","content":"Done","extra_content":{"google":{"thought_signature":"sig-first"}}}}]}`), codec, nil)
	second := geminiFixtureOutput(t, geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","content":"Done","extra_content":{"google":{"thought_signature":"sig-second"}}}}]}`), codec, nil)
	var items []map[string]any
	require.NoError(t, json.Unmarshal(geminiFixtureInput(t, first, second), &items))
	items = append([]map[string]any{{"role": "assistant", "content": "Done"}}, items...)
	for _, item := range items {
		delete(item, "id")
	}
	raw, err := json.Marshal(items)
	require.NoError(t, err)
	chat := geminiFixtureRestore(t, raw, codec)
	require.Nil(t, chat.Messages[0].ExtraContent)
	require.Equal(t, "sig-first", chat.Messages[2].ExtraContent.Google.ThoughtSignature)
	require.Equal(t, "sig-second", chat.Messages[3].ExtraContent.Google.ThoughtSignature)
	// Moving proof across a user boundary cannot sign the same text elsewhere.
	items[2], items[3] = items[3], items[2]
	raw, err = json.Marshal(items)
	require.NoError(t, err)
	converted, err := ResponsesToChatCompletionsRequest(&ResponsesRequest{Input: raw})
	require.NoError(t, err)
	require.ErrorIs(t, RestoreGeminiContinuation(raw, converted, codec), ErrGeminiContinuation)
}

func TestGeminiContinuationStreamingUnsignedTextSharesSignedToolStep(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	state := NewChatCompletionsToResponsesStreamState("gemini-fixture")
	stream := NewGeminiContinuationStream(state)
	for _, raw := range []string{
		`{"choices":[{"index":0,"delta":{"content":"Checking"}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-text","function":{"name":"read","arguments":"{}"},"extra_content":{"google":{"thought_signature":"tool-proof"}}}]}}]}`,
	} {
		var chunk ChatCompletionsChunk
		require.NoError(t, json.Unmarshal([]byte(raw), &chunk))
		require.NoError(t, stream.Observe(&chunk))
		ChatCompletionsChunkToResponsesEvents(&chunk, state)
	}
	events, err := stream.Finalize(state, codec)
	require.NoError(t, err)
	chat := geminiFixtureRestore(t, geminiStreamFixtureInput(t, events), codec)
	require.Nil(t, chat.Messages[1].ExtraContent)
	require.Equal(t, "tool-proof", chat.Messages[1].ToolCalls[0].ExtraContent.Google.ThoughtSignature)
}

func TestGeminiContinuationBoundsAndConflictsFailClosed(t *testing.T) {
	codec := newGeminiFixtureCodec(t, "fixture")
	source := geminiFixtureSource(t, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-a","function":{"name":"read","arguments":"{}"}}]}}]}`)
	for _, signature := range []string{"", strings.Repeat("s", geminiSignatureMaxBytes+1), "bad\nsignature"} {
		source.Choices[0].Message.ToolCalls[0].ExtraContent = geminiExtra(signature)
		out := ChatCompletionsResponseToResponses(source, "fixture", nil, nil, false, nil)
		require.ErrorIs(t, AttachGeminiContinuation(out, source.Choices[0].Message, codec), ErrGeminiContinuation)
	}
	stream := NewGeminiContinuationStream(NewChatCompletionsToResponsesStreamState("gemini-fixture"))
	index := 0
	chunk := &ChatCompletionsChunk{Choices: []ChatChunkChoice{{Delta: ChatDelta{ToolCalls: []ChatToolCall{{Index: &index, ExtraContent: geminiExtra("first")}}}}}}
	require.NoError(t, stream.Observe(chunk))
	chunk.Choices[0].Delta.ToolCalls[0].ExtraContent = geminiExtra("changed")
	require.ErrorIs(t, stream.Observe(chunk), ErrGeminiContinuation)
	index = geminiContinuationMaxCalls
	require.ErrorIs(t, NewGeminiContinuationStream(NewChatCompletionsToResponsesStreamState("gemini-fixture")).Observe(chunk), ErrGeminiContinuation)
	unknown, err := codec.Seal([]byte(`{"version":2,"items":[]}`))
	require.NoError(t, err)
	input := geminiFixtureInput(t, &ResponsesResponse{Output: []ResponsesOutput{{Type: "reasoning", EncryptedContent: GeminiContinuationPrefix + unknown}}})
	chat, err := ResponsesToChatCompletionsRequest(&ResponsesRequest{Input: input})
	require.NoError(t, err)
	require.ErrorIs(t, RestoreGeminiContinuation(input, chat, codec), ErrGeminiContinuation)
}
