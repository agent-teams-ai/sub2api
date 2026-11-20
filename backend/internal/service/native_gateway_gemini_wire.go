package service

import (
	"encoding/json"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
)

func gatewayNativeGeminiSelected(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	state, _ := c.Request.Context().Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	return state != nil && state.route.Profile == GatewayGeminiAPIKeyProfile
}

// Supplement the existing strict Chat framing only for the selected Gemini
// profile. Typed JSON alone would discard unknown signature fields/aliases.
func gatewayNativeGeminiWireValid(raw []byte, stream bool) bool {
	choice, ok := gatewayNativeLegacyChoice(raw, stream)
	if !ok {
		return false
	}
	if choice == nil {
		return true
	}
	field := "message"
	if stream {
		field = "delta"
	}
	message, ok := gatewayNativeCanonicalObject(choice[field], "extra_content", "tool_calls")
	if !ok || !gatewayNativeGeminiExtraValid(message["extra_content"]) {
		return false
	}
	if message["tool_calls"] == nil {
		return true
	}
	var calls []json.RawMessage
	if json.Unmarshal(message["tool_calls"], &calls) != nil || len(calls) > 64 {
		return false
	}
	for _, rawCall := range calls {
		call, ok := gatewayNativeCanonicalObject(rawCall, "index", "id", "type", "function", "extra_content")
		if !ok || !gatewayNativeGeminiExtraValid(call["extra_content"]) {
			return false
		}
	}
	return true
}

func gatewayNativeGeminiExtraValid(raw []byte) bool {
	if raw == nil {
		return true
	}
	if len(raw) > 128<<10 {
		return false
	}
	extra, ok := gatewayClaudeObject(raw, "google")
	if !ok || len(extra) != 1 {
		return false
	}
	google, ok := gatewayClaudeObject(extra["google"], "thought_signature")
	var signature string
	if !ok || len(google) != 1 || json.Unmarshal(google["thought_signature"], &signature) != nil {
		return false
	}
	return apicompat.GeminiThoughtSignatureValid(signature)
}
