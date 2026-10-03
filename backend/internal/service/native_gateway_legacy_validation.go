package service

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
)

// Inspect only protocol objects, never arbitrary nested user/tool payloads.
// Decoded names use the same case folding as encoding/json struct fields.
func gatewayNativeCanonicalObject(raw []byte, critical ...string) (map[string]json.RawMessage, bool) {
	if !json.Valid(raw) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		for _, name := range critical {
			if strings.EqualFold(key, name) && (key != name || fields[name] != nil) {
				return nil, false
			}
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	return fields, true
}

func gatewayNativeLegacyChoice(raw []byte, stream bool) (map[string]json.RawMessage, bool) {
	root, ok := gatewayNativeCanonicalObject(raw, "choices", "error", "usage")
	if !ok || root["error"] != nil {
		return nil, false
	}
	var choices []json.RawMessage
	if len(root["choices"]) == 0 || bytes.TrimSpace(root["choices"])[0] != '[' || json.Unmarshal(root["choices"], &choices) != nil {
		return nil, false
	}
	if stream && len(choices) == 0 {
		_, ok = gatewayNativeCanonicalObject(root["usage"])
		return nil, ok
	}
	if len(choices) != 1 {
		return nil, false
	}
	choice, ok := gatewayNativeCanonicalObject(choices[0], "index", "finish_reason", "message", "delta")
	var index *int
	if !ok || json.Unmarshal(choice["index"], &index) != nil || index == nil || *index != 0 {
		return nil, false
	}
	var finish *string
	if v := choice["finish_reason"]; len(v) > 0 && json.Unmarshal(v, &finish) != nil {
		return nil, false
	}
	if finish == nil || *finish == "" {
		return choice, stream
	}
	return choice, *finish == "stop" || *finish == "tool_calls"
}

func gatewayNativeLegacyChunk(raw []byte, chunk *apicompat.ChatCompletionsChunk) bool {
	choice, ok := gatewayNativeLegacyChoice(raw, true)
	if !ok {
		return false
	}
	if choice == nil {
		return len(chunk.Choices) == 0 && chunk.Usage != nil
	}
	_, ok = gatewayNativeCanonicalObject(choice["delta"], "role", "content", "reasoning", "reasoning_content", "tool_calls")
	return ok && len(chunk.Choices) == 1 && chunk.Choices[0].Index == 0
}

// Preserve sparse argument/name fragments, but never let the converter invent
// an upstream tool identity or normalize an unsupported tool type to function.
func gatewayNativeLegacyToolDelta(chunk *apicompat.ChatCompletionsChunk, state *apicompat.ChatCompletionsToResponsesStreamState) bool {
	for _, choice := range chunk.Choices {
		for _, tool := range choice.Delta.ToolCalls {
			if tool.Index == nil || *tool.Index < 0 {
				return false
			}
			prior, exists := state.ToolCalls[*tool.Index]
			if !exists && (tool.ID == "" || tool.Type != "function") {
				return false
			}
			if exists && ((tool.ID != "" && tool.ID != prior.ID) || (tool.Type != "" && tool.Type != "function")) {
				return false
			}
		}
	}
	return true
}

func gatewayNativeLegacyTool(tool *apicompat.ChatToolCall) bool {
	return tool != nil && tool.ID != "" && tool.Type == "function" &&
		strings.TrimSpace(tool.Function.Name) != "" && json.Valid([]byte(tool.Function.Arguments))
}

func gatewayNativeLegacyBuffered(raw []byte, response *apicompat.ChatCompletionsResponse) bool {
	choice, ok := gatewayNativeLegacyChoice(raw, false)
	if !ok || len(response.Choices) != 1 {
		return false
	}
	message, ok := gatewayNativeCanonicalObject(choice["message"], "role", "content", "reasoning", "reasoning_content", "tool_calls", "function_call")
	m := response.Choices[0].Message
	if !ok || m.Role != "assistant" || message["function_call"] != nil {
		return false
	}
	// Accept the converter's supported string/text-part content, or null for tools.
	var text string
	content := bytes.TrimSpace(m.Content)
	if len(content) > 0 && !bytes.Equal(content, []byte("null")) && json.Unmarshal(content, &text) != nil {
		var parts []apicompat.ChatContentPart
		if json.Unmarshal(content, &parts) != nil {
			return false
		}
		for _, part := range parts {
			if part.Type != "text" {
				return false
			}
			text += part.Text
		}
	}
	if response.Choices[0].FinishReason == "stop" {
		return len(m.ToolCalls) == 0 && (text != "" || strings.TrimSpace(m.ReasoningContent) != "" || strings.TrimSpace(m.Reasoning) != "")
	}
	if len(m.ToolCalls) == 0 {
		return false
	}
	ids := make(map[string]bool)
	for i := range m.ToolCalls {
		tool := &m.ToolCalls[i]
		if !gatewayNativeLegacyTool(tool) || ids[tool.ID] {
			return false
		}
		ids[tool.ID] = true
	}
	return true
}

func gatewayNativeLegacyFinal(state *apicompat.ChatCompletionsToResponsesStreamState) bool {
	if state.FinishReason == "stop" {
		return len(state.ToolCalls) == 0 && (state.Text.Len() > 0 || strings.TrimSpace(state.Reasoning.String()) != "")
	}
	if state.FinishReason != "tool_calls" || len(state.ToolCalls) == 0 {
		return false
	}
	ids := make(map[string]bool)
	for _, tool := range state.ToolCalls {
		if !gatewayNativeLegacyTool(tool) || ids[tool.ID] {
			return false
		}
		ids[tool.ID] = true
	}
	return true
}
