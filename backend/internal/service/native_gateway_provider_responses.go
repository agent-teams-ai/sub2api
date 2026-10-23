package service

import (
	"bytes"
	"encoding/json"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
)

const (
	GatewayKimiCodeResponsesProfile     = "kimi-code-global-responses-apikey-v1"
	GatewayKimiCodeResponsesBaseURL     = "https://api.kimi.ai/coding/v1"
	GatewayKimiCodeResponsesModel       = "k3-256k"
	GatewayGLMCodingResponsesProfile    = "glm-coding-global-responses-apikey-v1"
	GatewayGLMCodingResponsesBaseURL    = "https://api.z.ai/api/v1"
	GatewayGLMCodingResponsesModel      = "glm-5.3-flash"
	GatewayMiniMaxMPlanResponsesProfile = "minimax-mplan-global-responses-apikey-v1"
	GatewayMiniMaxMPlanResponsesBaseURL = "https://api.minimax.io/v1"
	GatewayMiniMaxMPlanResponsesModel   = "MiniMax-M3.1-Flash"
)

// New subscription tuples are immutable source definitions. A definition is
// fixture-capable; production enrollment remains a separate deployment gate.
func GatewayNativeCodingPlanProfileValid(profile, baseURL, model string) bool {
	switch profile {
	case GatewayKimiCodeResponsesProfile:
		return baseURL == GatewayKimiCodeResponsesBaseURL && model == GatewayKimiCodeResponsesModel
	case GatewayGLMCodingResponsesProfile:
		return baseURL == GatewayGLMCodingResponsesBaseURL && model == GatewayGLMCodingResponsesModel
	case GatewayMiniMaxMPlanResponsesProfile:
		return baseURL == GatewayMiniMaxMPlanResponsesBaseURL && model == GatewayMiniMaxMPlanResponsesModel
	}
	return false
}

func GatewayNativeCodingPlanProfileIDValid(profile string) bool {
	switch profile {
	case GatewayKimiCodeResponsesProfile, GatewayGLMCodingResponsesProfile, GatewayMiniMaxMPlanResponsesProfile:
		return true
	}
	return false
}

func gatewayNativeProviderProfile(profile string) bool {
	switch profile {
	case GatewayKimiCodeResponsesProfile, GatewayGLMCodingResponsesProfile, GatewayMiniMaxMPlanResponsesProfile, GatewayGrokOAuthResponsesProfile:
		return true
	}
	return false
}

// Reject lossy/unsupported input before admission and custody. Only text and
// client function/custom tools enter this slice. Schema and tool/user bytes are
// opaque and preserved; nested schema keys never select transport authority.
func ValidateGatewayNativeProviderResponsesBounded(profile string, body []byte, requestBytes int64) error {
	_, _, err := gatewayNativePrepareProviderResponses(profile, body, requestBytes)
	return err
}

func gatewayNativePrepareProviderResponses(profile string, body []byte, requestBytes int64) ([]byte, apicompat.ResponsesClientToolMapping, error) {
	empty := apicompat.ResponsesClientToolMapping{}
	deny := func() ([]byte, apicompat.ResponsesClientToolMapping, error) {
		return nil, empty, ErrGatewayNativeIdentity
	}
	if !gatewayNativeProviderProfile(profile) || requestBytes < 1 || requestBytes > 4<<20 || int64(len(body)) > requestBytes {
		return deny()
	}
	fields, ok := gatewayClaudeObject(body, "model", "input", "instructions", "stream", "store", "service_tier", "max_output_tokens", "tools", "tool_choice", "reasoning", "parallel_tool_calls", "temperature", "top_p", "text", "include")
	if !ok || string(fields["stream"]) != "true" || string(fields["store"]) != "false" || string(fields["service_tier"]) != `"default"` {
		return deny()
	}
	var model string
	if json.Unmarshal(fields["model"], &model) != nil {
		return deny()
	}
	switch profile {
	case GatewayKimiCodeResponsesProfile:
		if model != GatewayKimiCodeResponsesModel {
			return deny()
		}
	case GatewayGLMCodingResponsesProfile:
		if model != GatewayGLMCodingResponsesModel {
			return deny()
		}
	case GatewayMiniMaxMPlanResponsesProfile:
		if model != GatewayMiniMaxMPlanResponsesModel {
			return deny()
		}
	case GatewayGrokOAuthResponsesProfile:
		if model != GatewayGrokOAuthModel {
			return deny()
		}
	}
	if _, ok := gatewayOAuthSeconds(fields["max_output_tokens"]); !ok || !gatewayNativeProviderTextInput(fields["input"]) {
		return deny()
	}
	if raw := fields["instructions"]; raw != nil {
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return deny()
		}
	}
	if raw := fields["reasoning"]; raw != nil {
		reasoning, valid := gatewayClaudeObject(raw, "effort", "summary")
		var effort string
		if !valid || json.Unmarshal(reasoning["effort"], &effort) != nil {
			return deny()
		}
		switch effort {
		case "none", "low", "medium", "high":
		default:
			return deny()
		}
		if summary := reasoning["summary"]; summary != nil {
			var v string
			if json.Unmarshal(summary, &v) != nil || (v != "auto" && v != "concise" && v != "detailed") {
				return deny()
			}
		}
	}
	if raw := fields["include"]; raw != nil {
		var include []string
		if json.Unmarshal(raw, &include) != nil {
			return deny()
		}
		for _, value := range include {
			if value != "reasoning.encrypted_content" {
				return deny()
			}
		}
	}
	if raw := fields["text"]; raw != nil {
		text, valid := gatewayClaudeObject(raw, "format", "verbosity")
		if !valid {
			return deny()
		}
		if format := text["format"]; format != nil {
			v, valid := gatewayClaudeObject(format, "type")
			if !valid || string(v["type"]) != `"text"` {
				return deny()
			}
		}
		if verbosity := text["verbosity"]; verbosity != nil {
			var v string
			if json.Unmarshal(verbosity, &v) != nil || (v != "low" && v != "medium" && v != "high") {
				return deny()
			}
		}
	}
	if raw := fields["tools"]; raw != nil {
		var tools []json.RawMessage
		if json.Unmarshal(raw, &tools) != nil || len(tools) > 128 {
			return deny()
		}
		for _, raw := range tools {
			tool, valid := gatewayClaudeObject(raw, "type", "name", "description", "parameters", "strict", "format")
			var kind, name string
			if !valid || json.Unmarshal(tool["type"], &kind) != nil || (kind != "function" && kind != "custom") || json.Unmarshal(tool["name"], &name) != nil || name == "" || len(name) > 128 {
				return deny()
			}
			if kind == "function" {
				if _, valid := gatewayNativeCanonicalObject(tool["parameters"]); !valid || tool["format"] != nil {
					return deny()
				}
			} else if tool["parameters"] != nil || tool["strict"] != nil {
				return deny()
			}
		}
	}
	if raw := fields["tool_choice"]; raw != nil {
		var choice string
		if json.Unmarshal(raw, &choice) == nil {
			if choice != "auto" && choice != "none" && choice != "required" {
				return deny()
			}
		} else {
			choice, valid := gatewayClaudeObject(raw, "type", "name")
			var kind, name string
			if !valid || json.Unmarshal(choice["type"], &kind) != nil || (kind != "function" && kind != "custom") || json.Unmarshal(choice["name"], &name) != nil || name == "" {
				return deny()
			}
		}
	}
	// Use only the pure client-tool codec, never the ordinary Grok sanitizer
	// which drops unsupported tools/modalities and owns retry policy.
	wire, mapping, err := adaptResponsesClientToolsForFunctionUpstream(body, "qualified provider")
	if err != nil || int64(len(wire)) > requestBytes {
		return deny()
	}
	return wire, mapping, nil
}

func gatewayNativeProviderTextInput(raw []byte) bool {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return true
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) > 4096 {
		return false
	}
	for _, raw := range items {
		fields, ok := gatewayNativeCanonicalObject(raw, "type", "role", "content", "input", "output", "name", "call_id")
		if !ok {
			return false
		}
		var kind string
		if t := fields["type"]; t != nil && json.Unmarshal(t, &kind) != nil {
			return false
		}
		switch kind {
		case "", "message":
			fields, ok = gatewayClaudeObject(raw, "type", "id", "role", "content", "status")
			var role string
			if !ok || json.Unmarshal(fields["role"], &role) != nil || (role != "user" && role != "assistant" && role != "system" && role != "developer") {
				return false
			}
			if json.Unmarshal(fields["content"], &text) == nil {
				continue
			}
			var parts []json.RawMessage
			if json.Unmarshal(fields["content"], &parts) != nil {
				return false
			}
			for _, raw := range parts {
				part, ok := gatewayClaudeObject(raw, "type", "text", "annotations")
				if !ok || (string(part["type"]) != `"input_text"` && string(part["type"]) != `"output_text"`) || json.Unmarshal(part["text"], &text) != nil {
					return false
				}
			}
		case "function_call", "custom_tool_call":
			fields, ok = gatewayClaudeObject(raw, "type", "id", "status", "name", "call_id", "arguments", "input")
			if !ok || !gatewayNativeProviderString(fields["call_id"]) || !gatewayNativeProviderString(fields["name"]) {
				return false
			}
			if kind == "function_call" {
				if !gatewayNativeProviderString(fields["arguments"]) || fields["input"] != nil {
					return false
				}
			} else if !gatewayNativeProviderString(fields["input"]) || fields["arguments"] != nil {
				return false
			}
		case "function_call_output", "custom_tool_call_output":
			fields, ok = gatewayClaudeObject(raw, "type", "id", "call_id", "output")
			if !ok || !gatewayNativeProviderString(fields["call_id"]) || !gatewayNativeProviderString(fields["output"]) {
				return false
			}
		case "reasoning":
			fields, ok = gatewayClaudeObject(raw, "type", "id", "summary", "encrypted_content", "status")
			if !ok {
				return false
			}
			if value := fields["encrypted_content"]; value != nil && !gatewayNativeProviderString(value) {
				return false
			}
			if summary := fields["summary"]; summary != nil {
				var parts []json.RawMessage
				if json.Unmarshal(summary, &parts) != nil {
					return false
				}
				for _, raw := range parts {
					part, ok := gatewayClaudeObject(raw, "type", "text")
					if !ok || string(part["type"]) != `"summary_text"` || !gatewayNativeProviderString(part["text"]) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func gatewayNativeProviderString(raw []byte) bool {
	var v string
	return !bytes.Equal(raw, []byte("null")) && json.Unmarshal(raw, &v) == nil
}
