package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/gin-gonic/gin"
)

// The private Gateway continues to speak Responses. Only this fixed qualified
// OAuth profile crosses the pure Responses/Messages conversion boundary. No
// ordinary gateway retries, caller headers, account overrides or raw errors run.
const gatewayClaudeMessagesURL = claudeAPIURL

// ValidateGatewayNativeClaudeResponses runs BEFORE credential/provider entry.
// This first bounded slice supports text histories and ordinary function tools.
// Images, hosted/custom tools, stateful Responses IDs and format constraints are
// rejected explicitly; converters must not silently discard these modalities.
func ValidateGatewayNativeClaudeResponses(body []byte) error {
	_, _, err := gatewayClaudePrepareResponses(body)
	return err
}

// The admitted request bound covers the actual expanded provider wire as well
// as the canonical payload. Attribution never creates an unbudgeted allowance.
func ValidateGatewayNativeClaudeResponsesBounded(body []byte, requestBytes int64) error {
	wire, _, err := gatewayClaudePrepareResponses(body)
	if err != nil || requestBytes < 1 || int64(len(body)) > requestBytes || int64(len(wire)) > requestBytes {
		return ErrGatewayNativeIdentity
	}
	return nil
}

func gatewayClaudePrepareResponses(body []byte) ([]byte, map[string]string, error) {
	wire, err := gatewayClaudeMessagesBody(body)
	if err != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	// Snapshot the maintained runtime identity once. Billing and outbound UA
	// must agree even if the administrator's version resolver changes mid-call.
	headers := claude.DefaultHeaders()
	version := ExtractCLIVersion(headers["User-Agent"])
	if !claude.IsSupportedCLIVersion(version) {
		return nil, nil, ErrGatewayNativeIdentity
	}
	fields, valid := gatewayNativeCanonicalObject(wire)
	if !valid {
		return nil, nil, ErrGatewayNativeIdentity
	}
	billing, err := buildBillingAttributionText(wire, version)
	if err != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	blocks := make([]json.RawMessage, 0, 4)
	for i, text := range []string{billing, claudeCodeSystemPrompt, claudeCodeSystemPromptExpansion} {
		block, err := marshalAnthropicSystemTextBlock(text, i == 2)
		if err != nil {
			return nil, nil, ErrGatewayNativeIdentity
		}
		blocks = append(blocks, block)
	}
	// Preserve caller instructions as system instructions. The ordinary public
	// compatibility rewrite moves them into synthetic user/assistant messages;
	// that rewrite, tool renaming and fingerprint/metadata stores do not run here.
	if raw := fields["system"]; len(raw) > 0 {
		var system string
		if json.Unmarshal(raw, &system) != nil {
			return nil, nil, ErrGatewayNativeIdentity
		}
		if system != "" {
			block, err := marshalAnthropicSystemTextBlock(system, false)
			if err != nil {
				return nil, nil, ErrGatewayNativeIdentity
			}
			blocks = append(blocks, block)
		}
	}
	fields["system"], err = json.Marshal(blocks)
	if err != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	if len(fields["tools"]) == 0 {
		fields["tools"] = json.RawMessage(`[]`)
	}
	if len(fields["temperature"]) == 0 {
		fields["temperature"] = json.RawMessage(`1`)
	}
	if thinking := fields["thinking"]; len(thinking) > 0 {
		var value struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(thinking, &value) != nil {
			return nil, nil, ErrGatewayNativeIdentity
		}
		if value.Type == "enabled" || value.Type == "adaptive" {
			fields["context_management"] = json.RawMessage(`{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}`)
		}
	}
	wire, err = json.Marshal(fields)
	if err != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	return wire, headers, nil
}

func gatewayClaudeObject(raw []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	fields, ok := gatewayNativeCanonicalObject(raw, allowed...)
	if !ok {
		return nil, false
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return fields, true
}

func gatewayClaudeMessagesBody(body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > gatewayNativeResponseLimit {
		return nil, ErrGatewayNativeIdentity
	}
	fields, ok := gatewayClaudeObject(body, "model", "input", "instructions", "stream", "store", "service_tier", "max_output_tokens", "tools", "tool_choice", "reasoning", "parallel_tool_calls", "temperature", "top_p")
	if !ok {
		return nil, ErrGatewayNativeIdentity
	}
	var req apicompat.ResponsesRequest
	if json.Unmarshal(body, &req) != nil || req.Model != GatewayClaudeOAuthModel || !req.Stream || req.Store == nil || *req.Store || req.ServiceTier != "default" || req.MaxOutputTokens == nil || *req.MaxOutputTokens < 1 || *req.MaxOutputTokens > 65536 {
		return nil, ErrGatewayNativeIdentity
	}
	for name, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, ErrGatewayNativeIdentity
		}
		if name == "temperature" || name == "top_p" {
			var value float64
			if json.Unmarshal(raw, &value) != nil || value < 0 || value > 1 {
				return nil, ErrGatewayNativeIdentity
			}
		}
	}
	if !gatewayClaudeInput(fields["input"]) {
		return nil, ErrGatewayNativeIdentity
	}
	if raw := fields["reasoning"]; raw != nil {
		reasoning, valid := gatewayClaudeObject(raw, "effort")
		var effort string
		if !valid || json.Unmarshal(reasoning["effort"], &effort) != nil {
			return nil, ErrGatewayNativeIdentity
		}
		switch effort {
		case "none", "low", "medium", "high", "xhigh":
		default:
			return nil, ErrGatewayNativeIdentity
		}
		// The existing converter maps none to a provider output effort; explicitly
		// clear it instead, so none means no thinking and never an invalid effort.
		if effort == "none" {
			req.Reasoning = nil
		}
	}
	if raw := fields["tools"]; raw != nil {
		var tools []json.RawMessage
		if json.Unmarshal(raw, &tools) != nil || len(tools) > 128 {
			return nil, ErrGatewayNativeIdentity
		}
		for _, rawTool := range tools {
			tool, valid := gatewayClaudeObject(rawTool, "type", "name", "description", "parameters", "strict")
			var kind, name string
			if !valid || json.Unmarshal(tool["type"], &kind) != nil || kind != "function" || json.Unmarshal(tool["name"], &name) != nil || name == "" || len(name) > 128 {
				return nil, ErrGatewayNativeIdentity
			}
			// Current pure converter does not preserve strict schema enforcement.
			if strict := tool["strict"]; strict != nil && !bytes.Equal(bytes.TrimSpace(strict), []byte("false")) {
				return nil, ErrGatewayNativeIdentity
			}
			schema, valid := gatewayNativeCanonicalObject(tool["parameters"], "type")
			var schemaType string
			if !valid || json.Unmarshal(schema["type"], &schemaType) != nil || schemaType != "object" {
				return nil, ErrGatewayNativeIdentity
			}
		}
	}
	if raw := fields["tool_choice"]; raw != nil {
		var choice string
		if json.Unmarshal(raw, &choice) == nil {
			if choice != "auto" && choice != "none" && choice != "required" {
				return nil, ErrGatewayNativeIdentity
			}
		} else {
			choiceFields, valid := gatewayClaudeObject(raw, "type", "name")
			var kind, name string
			if !valid || json.Unmarshal(choiceFields["type"], &kind) != nil || kind != "function" || json.Unmarshal(choiceFields["name"], &name) != nil || name == "" {
				return nil, ErrGatewayNativeIdentity
			}
		}
	}
	converted, err := apicompat.ResponsesToAnthropicRequest(&req)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	if len(converted.Messages) == 0 || converted.Thinking != nil && converted.Thinking.BudgetTokens >= converted.MaxTokens {
		return nil, ErrGatewayNativeIdentity
	}
	if converted.Thinking != nil {
		if req.Temperature != nil && *req.Temperature != 1 || req.TopP != nil {
			return nil, ErrGatewayNativeIdentity
		}
		var choice struct {
			Type string `json:"type"`
		}
		if len(converted.ToolChoice) > 0 && (json.Unmarshal(converted.ToolChoice, &choice) != nil || choice.Type == "any" || choice.Type == "tool") {
			return nil, ErrGatewayNativeIdentity
		}
	}
	if req.ParallelToolCalls != nil && len(converted.Tools) > 0 {
		choice := map[string]any{"type": "auto"}
		if len(converted.ToolChoice) > 0 && json.Unmarshal(converted.ToolChoice, &choice) != nil {
			return nil, ErrGatewayNativeIdentity
		}
		choice["disable_parallel_tool_use"] = !*req.ParallelToolCalls
		converted.ToolChoice, err = json.Marshal(choice)
		if err != nil {
			return nil, ErrGatewayNativeIdentity
		}
	}
	return json.Marshal(converted)
}

func gatewayClaudeInput(raw json.RawMessage) bool {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text) != ""
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 || len(items) > 4096 {
		return false
	}
	calls, outputs := map[string]bool{}, map[string]bool{}
	for _, rawItem := range items {
		item, ok := gatewayClaudeObject(rawItem, "type", "role", "content", "call_id", "name", "arguments", "output")
		if !ok {
			return false
		}
		var kind string
		if item["type"] != nil && json.Unmarshal(item["type"], &kind) != nil {
			return false
		}
		switch kind {
		case "", "message":
			if _, valid := gatewayClaudeObject(rawItem, "type", "role", "content"); !valid {
				return false
			}
			var role string
			if json.Unmarshal(item["role"], &role) != nil || (role != "user" && role != "assistant" && role != "system" && role != "developer") {
				return false
			}
			if json.Unmarshal(item["content"], &text) == nil {
				if strings.TrimSpace(text) == "" {
					return false
				}
				continue
			}
			var parts []json.RawMessage
			if json.Unmarshal(item["content"], &parts) != nil || len(parts) == 0 {
				return false
			}
			for _, rawPart := range parts {
				part, valid := gatewayClaudeObject(rawPart, "type", "text")
				var typ string
				if !valid || json.Unmarshal(part["type"], &typ) != nil || (typ != "input_text" && typ != "output_text" && typ != "text") ||
					role == "user" && typ == "output_text" || role == "assistant" && typ == "input_text" ||
					json.Unmarshal(part["text"], &text) != nil || strings.TrimSpace(text) == "" {
					return false
				}
			}
		case "function_call", "function_call_output":
			var id string
			if json.Unmarshal(item["call_id"], &id) != nil || id == "" {
				return false
			}
			if kind == "function_call" {
				if _, valid := gatewayClaudeObject(rawItem, "type", "call_id", "name", "arguments"); !valid {
					return false
				}
				var name, arguments string
				if calls[id] || json.Unmarshal(item["name"], &name) != nil || name == "" || json.Unmarshal(item["arguments"], &arguments) != nil || !json.Valid([]byte(arguments)) {
					return false
				}
				if _, valid := gatewayNativeCanonicalObject([]byte(arguments)); !valid {
					return false
				}
				calls[id] = true
			} else {
				if _, valid := gatewayClaudeObject(rawItem, "type", "call_id", "output"); !valid {
					return false
				}
				if outputs[id] || !calls[id] || json.Unmarshal(item["output"], &text) != nil {
					return false
				}
				outputs[id] = true
			}
		default:
			return false
		}
	}
	for id := range calls {
		if !outputs[id] {
			return false
		}
	}
	return true
}

func gatewayNativeClaudeResponses(ctx context.Context, c *gin.Context, entry GatewayNativeClaudeDispatchEntry, wire []byte, headers map[string]string, transport http.RoundTripper) (*OpenAIForwardResult, error) {
	if entry.Release == nil || entry.Claim == nil {
		return nil, ErrGatewayNativeIdentity
	}
	defer entry.Release()
	if len(wire) == 0 || len(headers) == 0 || c == nil || c.Writer == nil || transport == nil || entry.AccessToken == "" || strings.ContainsAny(entry.AccessToken, "\r\n") {
		return nil, ErrGatewayNativeIdentity
	}
	observation := GatewayNativeUsage{Source: "native_provider_response", State: "unknown", CostState: "unknown"}
	defer func() {
		observation.Finalized = true
		if observe, ok := ctx.Value(gatewayNativeUsageObserverKey{}).(func(GatewayNativeUsage)); ok {
			observe(observation)
		}
	}()
	upstreamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(upstreamCtx, http.MethodPost, gatewayClaudeMessagesURL, bytes.NewReader(wire))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("Authorization", "Bearer "+entry.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("anthropic-version", "2023-06-01")
	request.Header.Set("anthropic-beta", strings.Join(claude.FullClaudeCodeMimicryBetas(), ","))
	request.GetBody = nil
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	response, err := client.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil {
		return nil, ErrGatewayNativeEffectUnknown
	}
	received := time.Now().UTC()
	if (response.StatusCode >= 200 && response.StatusCode < 300 || response.StatusCode == http.StatusTooManyRequests) && entry.CaptureLimits != nil {
		entry.CaptureLimits(ctx, response.Header, received)
	}
	if response.StatusCode != http.StatusOK || gatewayNativeUpstreamMediaCategory(response.Header.Get("Content-Type")) != "sse" || (response.Header.Get("Content-Encoding") != "" && !strings.EqualFold(response.Header.Get("Content-Encoding"), "identity")) {
		return nil, ErrGatewayNativeEffectUnknown
	}
	idle, _ := ctx.Value(gatewayNativeProviderReadIdleKey{}).(time.Duration)
	if idle <= 0 || idle > gatewayNativeUpstreamReadIdle {
		idle = gatewayNativeUpstreamReadIdle
	}
	reader := &gatewayNativeIdleReader{reader: response.Body, idle: idle, cancel: cancel}
	scanner := bufio.NewScanner(io.LimitReader(reader, gatewayNativeResponseLimit+1))
	scanner.Split(gatewayNativeRawSSELine)
	scanner.Buffer(make([]byte, 4096), gatewayNativeSSEFrameLimit+1)
	state := apicompat.NewAnthropicEventToResponsesState()
	state.Model = GatewayClaudeOAuthModel
	result := &OpenAIForwardResult{Stream: true, Model: GatewayClaudeOAuthModel, UpstreamEndpoint: "/v1/messages"}
	var frame bytes.Buffer
	var data []string
	eventName := ""
	total, sent := 0, 0
	outputLimit := gatewayNativeResponseLimit
	if life := gatewayNativeLifetime(ctx); life != nil {
		outputLimit = int(life.outputBytes)
	}
	started, deltaSeen, blockOpen := false, false, false
	blockIndex, nextIndex := 0, 0
	blockKind, toolArgs := "", ""
	toolDelta := false
	var inputTotal int64
	var measuredInput, measuredOutput *int64
	var cacheRead, cacheWrite *int64
	for scanner.Scan() {
		raw := scanner.Bytes()
		total += len(raw)
		if total > gatewayNativeResponseLimit || frame.Len()+len(raw) > gatewayNativeSSEFrameLimit {
			return nil, ErrGatewayNativeEffectUnknown
		}
		frame.Write(raw)
		line := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\r'})
		if len(line) > 0 {
			if line[0] == ':' {
				continue
			}
			key, value, _ := bytes.Cut(line, []byte{':'})
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			switch string(key) {
			case "event":
				if eventName != "" {
					return nil, ErrGatewayNativeEffectUnknown
				}
				eventName = string(value)
			case "data":
				data = append(data, string(value))
			default:
				return nil, ErrGatewayNativeEffectUnknown
			}
			continue
		}
		if !utf8.Valid(frame.Bytes()) {
			return nil, ErrGatewayNativeEffectUnknown
		}
		if len(data) == 0 {
			frame.Reset()
			eventName = ""
			continue
		}
		payload := []byte(strings.Join(data, "\n"))
		fields, valid := gatewayNativeCanonicalObject(payload, "type", "message", "usage", "delta", "index", "content_block")
		var event apicompat.AnthropicStreamEvent
		if !valid || json.Unmarshal(payload, &event) != nil || (eventName != "" && eventName != event.Type) {
			return nil, ErrGatewayNativeEffectUnknown
		}
		switch event.Type {
		case "ping":
			frame.Reset()
			data = nil
			eventName = ""
			continue
		case "message_start":
			if started || event.Message == nil || event.Message.Type != "message" || event.Message.Role != "assistant" || event.Message.ID == "" || event.Message.Model != GatewayClaudeOAuthModel || len(event.Message.Content) != 0 {
				return nil, ErrGatewayNativeEffectUnknown
			}
			message, valid := gatewayNativeCanonicalObject(fields["message"], "usage", "id", "type", "role", "model", "content", "stop_reason", "stop_sequence")
			usage, validUsage := gatewayNativeCanonicalObject(message["usage"], "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
			if !valid || !validUsage {
				return nil, ErrGatewayNativeEffectUnknown
			}
			measuredInput = gatewayNativeUsageCount(usage["input_tokens"])
			cacheRead = gatewayNativeUsageCount(usage["cache_read_input_tokens"])
			cacheWrite = gatewayNativeUsageCount(usage["cache_creation_input_tokens"])
			if measuredInput == nil || usage["cache_read_input_tokens"] != nil && cacheRead == nil || usage["cache_creation_input_tokens"] != nil && cacheWrite == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			started = true
		case "content_block_start":
			if !started || deltaSeen || blockOpen || event.Index == nil || *event.Index != nextIndex || event.ContentBlock == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			if _, valid := gatewayNativeCanonicalObject(fields["content_block"], "type", "text", "id", "name", "input", "thinking", "signature", "data"); !valid {
				return nil, ErrGatewayNativeEffectUnknown
			}
			blockKind, toolArgs, toolDelta = event.ContentBlock.Type, "", false
			switch blockKind {
			case "text":
				if event.ContentBlock.Text != "" {
					return nil, ErrGatewayNativeEffectUnknown
				}
			case "tool_use":
				if event.ContentBlock.ID == "" || event.ContentBlock.Name == "" {
					return nil, ErrGatewayNativeEffectUnknown
				}
				toolArgs = string(event.ContentBlock.Input)
			case "thinking", "redacted_thinking":
			default:
				return nil, ErrGatewayNativeEffectUnknown
			}
			blockOpen = true
			blockIndex = *event.Index
		case "content_block_delta":
			if !blockOpen || event.Index == nil || *event.Index != blockIndex || event.Delta == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			if _, valid := gatewayNativeCanonicalObject(fields["delta"], "type", "text", "partial_json", "thinking", "signature"); !valid {
				return nil, ErrGatewayNativeEffectUnknown
			}
			switch event.Delta.Type {
			case "text_delta":
				if blockKind != "text" {
					return nil, ErrGatewayNativeEffectUnknown
				}
			case "input_json_delta":
				if blockKind != "tool_use" {
					return nil, ErrGatewayNativeEffectUnknown
				}
				if !toolDelta {
					toolArgs, toolDelta = "", true
				}
				toolArgs += event.Delta.PartialJSON
			case "thinking_delta", "signature_delta":
				if blockKind != "thinking" {
					return nil, ErrGatewayNativeEffectUnknown
				}
			default:
				return nil, ErrGatewayNativeEffectUnknown
			}
		case "content_block_stop":
			if !blockOpen || event.Index == nil || *event.Index != blockIndex {
				return nil, ErrGatewayNativeEffectUnknown
			}
			if blockKind == "tool_use" {
				if _, valid := gatewayNativeCanonicalObject([]byte(toolArgs)); !valid {
					return nil, ErrGatewayNativeEffectUnknown
				}
			}
			blockOpen = false
			nextIndex++
		case "message_delta":
			if !started || blockOpen || deltaSeen || event.Delta == nil || event.Usage == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			if _, valid := gatewayNativeCanonicalObject(fields["delta"], "stop_reason", "stop_sequence"); !valid {
				return nil, ErrGatewayNativeEffectUnknown
			}
			switch event.Delta.StopReason {
			case "end_turn", "tool_use", "stop_sequence":
			default:
				return nil, ErrGatewayNativeEffectUnknown
			}
			usage, valid := gatewayNativeCanonicalObject(fields["usage"], "output_tokens", "input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
			if !valid {
				return nil, ErrGatewayNativeEffectUnknown
			}
			measuredOutput = gatewayNativeUsageCount(usage["output_tokens"])
			if measuredOutput == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			for name, prior := range map[string]*int64{"input_tokens": measuredInput, "cache_read_input_tokens": cacheRead, "cache_creation_input_tokens": cacheWrite} {
				if raw := usage[name]; raw != nil {
					value := gatewayNativeUsageCount(raw)
					if value == nil || prior == nil || *value != *prior {
						return nil, ErrGatewayNativeEffectUnknown
					}
				}
			}
			deltaSeen = true
		case "message_stop":
			if !started || blockOpen || !deltaSeen || measuredInput == nil || measuredOutput == nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
			inputTotal = *measuredInput
			if cacheRead != nil {
				inputTotal += *cacheRead
			}
			if cacheWrite != nil {
				inputTotal += *cacheWrite
			}
			if inputTotal > 9007199254740991 {
				return nil, ErrGatewayNativeEffectUnknown
			}
		default:
			return nil, ErrGatewayNativeEffectUnknown
		}
		events := apicompat.AnthropicEventToResponsesEvents(&event, state)
		for _, converted := range events {
			encoded, err := apicompat.ResponsesEventToSSE(converted)
			if err != nil || len(encoded) > outputLimit-sent {
				return nil, ErrGatewayNativeEffectUnknown
			}
			c.Header("Content-Type", "text/event-stream")
			c.Header("Cache-Control", "no-store")
			n, err := io.WriteString(c.Writer, encoded)
			sent += n
			if err != nil || n != len(encoded) || gatewayNativeFlush(c.Writer) != nil {
				return nil, ErrGatewayNativeEffectUnknown
			}
		}
		if event.Type == "message_stop" {
			if !state.CompletedSent {
				return nil, ErrGatewayNativeEffectUnknown
			}
			observation.InputTokens = &inputTotal
			observation.OutputTokens = measuredOutput
			observation.CachedInputTokens = cacheRead
			observation.State = "complete"
			result.Usage = OpenAIUsage{InputTokens: int(inputTotal), OutputTokens: int(*measuredOutput)}
			result.Duration = time.Since(start)
			return result, nil
		}
		frame.Reset()
		data = nil
		eventName = ""
	}
	// The pure converter can synthesize terminal events on EOF. This protected
	// boundary deliberately never calls that helper: only message_stop settles.
	return nil, ErrGatewayNativeEffectUnknown
}
