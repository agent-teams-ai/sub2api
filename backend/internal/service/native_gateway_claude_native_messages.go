package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

type gatewayNativeClaudeMessagesKey struct{}

// WithGatewayNativeClaudeMessages is set by the trusted /v1/messages handler.
// A request body or private transport DTO never selects its wire protocol.
func WithGatewayNativeClaudeMessages(ctx context.Context) context.Context {
	return context.WithValue(ctx, gatewayNativeClaudeMessagesKey{}, true)
}

func gatewayNativeClaudeMessagesMode(ctx context.Context) bool {
	return ctx != nil && ctx.Value(gatewayNativeClaudeMessagesKey{}) == true
}

// ValidateGatewayNativeClaudeMessagesBounded qualifies the native Claude Code
// slice before admission/provider entry. The original JSON is sent unchanged:
// system priority, tool schemas/results and signed thinking never round-trip
// through a different protocol or a lossy Go DTO.
func ValidateGatewayNativeClaudeMessagesBounded(body []byte, requestBytes, tokens int64) error {
	deny := ErrGatewayNativeIdentity
	if requestBytes < 1 || requestBytes > 4<<20 || tokens < 1 || len(body) == 0 || int64(len(body)) > requestBytes || !gatewayClaudeNativeJSON(body) {
		return deny
	}
	f, ok := gatewayClaudeObject(body, "model", "max_tokens", "stream", "messages", "system", "tools", "tool_choice", "thinking", "metadata", "context_management", "output_config", "temperature", "top_p", "top_k", "stop_sequences", "cache_control", "service_tier")
	var model string
	var stream bool
	var maximum int64
	if !ok || json.Unmarshal(f["model"], &model) != nil || model != GatewayClaudeOAuthModel || json.Unmarshal(f["stream"], &stream) != nil || !stream || json.Unmarshal(f["max_tokens"], &maximum) != nil || maximum < 1 || maximum > tokens || maximum > 65536 {
		return deny
	}
	var messages []json.RawMessage
	if json.Unmarshal(f["messages"], &messages) != nil || len(messages) == 0 || len(messages) > 4096 {
		return deny
	}
	for _, raw := range messages {
		m, valid := gatewayClaudeObject(raw, "role", "content")
		var role string
		if !valid || json.Unmarshal(m["role"], &role) != nil || role != "user" && role != "assistant" || !gatewayClaudeNativeContent(m["content"], role, 0) {
			return deny
		}
	}
	if raw := f["system"]; raw != nil && !gatewayClaudeNativeContent(raw, "system", 0) {
		return deny
	}
	if raw := f["tools"]; raw != nil {
		var tools []json.RawMessage
		if json.Unmarshal(raw, &tools) != nil || tools == nil || len(tools) > 256 {
			return deny
		}
		names := map[string]bool{}
		for _, raw := range tools {
			tool, valid := gatewayClaudeObject(raw, "name", "description", "input_schema", "cache_control", "type", "strict", "defer_loading", "input_examples", "allowed_callers")
			name, validName := gatewayClaudeNativeString(tool["name"], 128)
			_, schema := gatewayNativeCanonicalObject(tool["input_schema"])
			if !valid || !validName || name == "" || names[name] || !schema || !gatewayClaudeNativeCache(tool["cache_control"]) {
				return deny
			}
			names[name] = true
			if raw := tool["type"]; raw != nil && !gatewayClaudeNativeEnum(raw, "custom") {
				return deny
			}
			if raw := tool["description"]; raw != nil {
				if _, valid := gatewayClaudeNativeString(raw, 1<<20); !valid {
					return deny
				}
			}
			for _, name := range []string{"strict", "defer_loading"} {
				if raw := tool[name]; raw != nil && !gatewayClaudeNativeBool(raw) {
					return deny
				}
			}
			for _, name := range []string{"input_examples", "allowed_callers"} {
				if raw := tool[name]; raw != nil && !gatewayClaudeNativeArray(raw) {
					return deny
				}
			}
		}
	}
	if raw := f["tool_choice"]; raw != nil {
		choice, valid := gatewayClaudeObject(raw, "type", "name", "disable_parallel_tool_use")
		if !valid || !gatewayClaudeNativeEnum(choice["type"], "auto", "any", "tool", "none") || choice["disable_parallel_tool_use"] != nil && !gatewayClaudeNativeBool(choice["disable_parallel_tool_use"]) {
			return deny
		}
		if gatewayClaudeNativeEnum(choice["type"], "tool") {
			if name, valid := gatewayClaudeNativeString(choice["name"], 128); !valid || name == "" {
				return deny
			}
		} else if choice["name"] != nil {
			return deny
		}
	}
	if raw := f["thinking"]; raw != nil {
		thinking, valid := gatewayClaudeObject(raw, "type", "budget_tokens")
		if !valid || !gatewayClaudeNativeEnum(thinking["type"], "enabled", "disabled", "adaptive") {
			return deny
		}
		if gatewayClaudeNativeEnum(thinking["type"], "enabled") {
			var budget int64
			if json.Unmarshal(thinking["budget_tokens"], &budget) != nil || budget < 1024 || budget >= maximum {
				return deny
			}
		} else if thinking["budget_tokens"] != nil {
			return deny
		}
	}
	if raw := f["metadata"]; raw != nil {
		metadata, valid := gatewayClaudeObject(raw, "user_id")
		if !valid {
			return deny
		}
		if value := metadata["user_id"]; value != nil {
			if _, valid := gatewayClaudeNativeString(value, 1024); !valid {
				return deny
			}
		}
	}
	if raw := f["output_config"]; raw != nil {
		output, valid := gatewayClaudeObject(raw, "effort", "format")
		if !valid || output["effort"] != nil && !gatewayClaudeNativeEnum(output["effort"], "low", "medium", "high", "max") {
			return deny
		}
		if raw := output["format"]; raw != nil {
			format, valid := gatewayClaudeObject(raw, "type", "schema")
			_, schema := gatewayNativeCanonicalObject(format["schema"])
			if !valid || !schema || !gatewayClaudeNativeEnum(format["type"], "json_schema") {
				return deny
			}
		}
	}
	if raw := f["context_management"]; raw != nil {
		management, valid := gatewayClaudeObject(raw, "edits")
		var edits []json.RawMessage
		if !valid || json.Unmarshal(management["edits"], &edits) != nil || edits == nil || len(edits) > 16 {
			return deny
		}
		for _, raw := range edits {
			edit, valid := gatewayClaudeObject(raw, "type", "keep", "trigger", "clear_at_least", "exclude_tools", "clear_tool_inputs")
			if !valid || !gatewayClaudeNativeEnum(edit["type"], "clear_thinking_20251015", "clear_tool_uses_20250919") {
				return deny
			}
			for _, name := range []string{"keep", "trigger", "clear_at_least"} {
				if raw := edit[name]; raw != nil && !gatewayClaudeNativeCountControl(raw, name == "keep") {
					return deny
				}
			}
			if raw := edit["exclude_tools"]; raw != nil && !gatewayClaudeNativeStrings(raw, 256, 128) {
				return deny
			}
			if raw := edit["clear_tool_inputs"]; raw != nil && !gatewayClaudeNativeBool(raw) && !gatewayClaudeNativeStrings(raw, 256, 128) {
				return deny
			}
		}
	}
	for _, field := range []string{"temperature", "top_p"} {
		if raw := f[field]; raw != nil {
			var value float64
			if json.Unmarshal(raw, &value) != nil || value < 0 || value > 1 {
				return deny
			}
		}
	}
	if raw := f["top_k"]; raw != nil {
		var value int64
		if json.Unmarshal(raw, &value) != nil || value < 0 || value > 10000000 {
			return deny
		}
	}
	if raw := f["stop_sequences"]; raw != nil && !gatewayClaudeNativeStrings(raw, 256, 8192) || !gatewayClaudeNativeCache(f["cache_control"]) || f["service_tier"] != nil && !gatewayClaudeNativeEnum(f["service_tier"], "auto", "standard_only") {
		return deny
	}
	return nil
}

func gatewayClaudePrepareNativeMessages(body []byte, requestBytes, tokens int64) ([]byte, map[string]string, error) {
	if err := ValidateGatewayNativeClaudeMessagesBounded(body, requestBytes, tokens); err != nil {
		return nil, nil, err
	}
	headers := claude.DefaultHeaders()
	if !claude.IsSupportedCLIVersion(ExtractCLIVersion(headers["User-Agent"])) {
		return nil, nil, ErrGatewayNativeIdentity
	}
	return body, headers, nil
}

func gatewayClaudeNativeContent(raw json.RawMessage, role string, depth int) bool {
	if depth > 8 {
		return false
	}
	if _, valid := gatewayClaudeNativeString(raw, 4<<20); valid {
		return true
	}
	var blocks []json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) == 0 || len(blocks) > 4096 {
		return false
	}
	for _, raw := range blocks {
		b, valid := gatewayNativeCanonicalObject(raw, "type")
		var kind string
		if !valid || json.Unmarshal(b["type"], &kind) != nil {
			return false
		}
		allowed := map[string][]string{
			"text":              {"type", "text", "cache_control", "citations"},
			"thinking":          {"type", "thinking", "signature", "cache_control"},
			"redacted_thinking": {"type", "data", "cache_control"},
			"tool_use":          {"type", "id", "name", "input", "cache_control"},
			"tool_result":       {"type", "tool_use_id", "content", "is_error", "cache_control"},
			"image":             {"type", "source", "cache_control"},
			"document":          {"type", "source", "title", "context", "citations", "cache_control"},
		}
		b, valid = gatewayClaudeObject(raw, allowed[kind]...)
		if !valid || !gatewayClaudeNativeCache(b["cache_control"]) {
			return false
		}
		switch kind {
		case "text":
			if _, valid := gatewayClaudeNativeString(b["text"], 4<<20); !valid {
				return false
			}
		case "thinking":
			_, thought := gatewayClaudeNativeString(b["thinking"], 4<<20)
			signature, signed := gatewayClaudeNativeString(b["signature"], 4<<20)
			if role != "assistant" || !thought || !signed || signature == "" {
				return false
			}
		case "redacted_thinking":
			data, valid := gatewayClaudeNativeString(b["data"], 4<<20)
			if role != "assistant" || !valid || data == "" {
				return false
			}
		case "tool_use":
			id, validID := gatewayClaudeNativeString(b["id"], 256)
			name, validName := gatewayClaudeNativeString(b["name"], 128)
			_, input := gatewayNativeCanonicalObject(b["input"])
			if role != "assistant" || !validID || id == "" || !validName || name == "" || !input {
				return false
			}
		case "tool_result":
			id, validID := gatewayClaudeNativeString(b["tool_use_id"], 256)
			if role != "user" || !validID || id == "" || b["content"] != nil && !gatewayClaudeNativeContent(b["content"], "tool_result", depth+1) || b["is_error"] != nil && !gatewayClaudeNativeBool(b["is_error"]) {
				return false
			}
		case "image", "document":
			source, valid := gatewayClaudeObject(b["source"], "type", "media_type", "data", "url")
			if role == "system" || !valid || !gatewayClaudeNativeEnum(source["type"], "base64", "url", "text") {
				return false
			}
			for _, field := range []string{"media_type", "data", "url"} {
				if raw := source[field]; raw != nil {
					if _, valid := gatewayClaudeNativeString(raw, 4<<20); !valid {
						return false
					}
				}
			}
		default:
			return false
		}
		if role == "system" && kind != "text" {
			return false
		}
	}
	return true
}

func gatewayClaudeNativeCountControl(raw json.RawMessage, allowAll bool) bool {
	if allowAll && gatewayClaudeNativeEnum(raw, "all") {
		return true
	}
	f, valid := gatewayClaudeObject(raw, "type", "value")
	var count int64
	return valid && gatewayClaudeNativeEnum(f["type"], "thinking_turns", "tool_uses", "input_tokens") && json.Unmarshal(f["value"], &count) == nil && count >= 0 && count <= 10000000
}

func gatewayClaudeNativeString(raw json.RawMessage, bound int) (string, bool) {
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && len(value) <= bound
}
func gatewayClaudeNativeEnum(raw json.RawMessage, allowed ...string) bool {
	value, valid := gatewayClaudeNativeString(raw, 128)
	if valid {
		for _, option := range allowed {
			if value == option {
				return true
			}
		}
	}
	return false
}
func gatewayClaudeNativeBool(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("true")) || bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}
func gatewayClaudeNativeArray(raw json.RawMessage) bool {
	var values []json.RawMessage
	return json.Unmarshal(raw, &values) == nil && values != nil && len(values) <= 4096
}
func gatewayClaudeNativeStrings(raw json.RawMessage, items, length int) bool {
	var values []string
	if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > items {
		return false
	}
	for _, value := range values {
		if len(value) > length {
			return false
		}
	}
	return true
}
func gatewayClaudeNativeCache(raw json.RawMessage) bool {
	if raw == nil {
		return true
	}
	f, valid := gatewayClaudeObject(raw, "type", "ttl")
	return valid && gatewayClaudeNativeEnum(f["type"], "ephemeral") && (f["ttl"] == nil || gatewayClaudeNativeEnum(f["ttl"], "5m", "1h"))
}

// Every JSON object rejects duplicate names, including nested tool input and
// schema values. Only protocol objects additionally reject case aliases. User
// schema property names stay case sensitive. Recursion and collection bounds
// make parsing work proportional to the independently bounded request body.
func gatewayClaudeNativeJSON(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, collection := token.(json.Delim)
		if !collection {
			return true
		}
		if delim != '{' && delim != '[' {
			return false
		}
		seen := map[string]bool{}
		count := 0
		for d.More() {
			count++
			if count > 4096 {
				return false
			}
			if delim == '{' {
				key, err := d.Token()
				name, valid := key.(string)
				if err != nil || !valid || seen[name] || strings.IndexByte(name, 0) >= 0 {
					return false
				}
				seen[name] = true
			}
			if !value(depth + 1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
