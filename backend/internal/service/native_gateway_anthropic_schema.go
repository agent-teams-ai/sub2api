package service

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/google/jsonschema-go/jsonschema"
)

// The selected review schema uses only this bounded, non-recursive subset.
// Anthropic does not implement numeric bounds in its output grammar. Preserve
// the original schema for the terminal check and lower only those two keywords
// to descriptions on the provider wire. Other unsupported keywords fail before
// provider entry; there is no generic lossy schema sanitizer or remote loader.
func gatewayAnthropicOutputSchema(raw json.RawMessage) (json.RawMessage, func([]apicompat.ResponsesOutput) bool, error) {
	deny := func() (json.RawMessage, func([]apicompat.ResponsesOutput) bool, error) {
		return nil, nil, ErrGatewayNativeIdentity
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return deny()
	}
	if _, err := gatewayOAuthJSON(raw); err != nil {
		return deny()
	}
	var schema jsonschema.Schema
	if json.Unmarshal(raw, &schema) != nil {
		return deny()
	}
	nodes := 0
	lowered, err := gatewayAnthropicSchemaNode(raw, 0, &nodes)
	if err != nil || len(lowered) > 64<<10 {
		return deny()
	}
	// The closed walk rejects all reference keywords before Resolve. Keeping a
	// nil loader additionally prevents any external schema I/O by construction.
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return deny()
	}
	validate := func(output []apicompat.ResponsesOutput) bool {
		var text strings.Builder
		for _, item := range output {
			if item.Type != "message" || item.Role != "assistant" {
				return false
			}
			for _, part := range item.Content {
				if part.Type != "output_text" || len(part.Text) > gatewayNativeResponseLimit-text.Len() {
					return false
				}
				text.WriteString(part.Text)
			}
		}
		// Validation is against the full original schema, including minimum and
		// maximum. Do not expose validator messages or partial data as success.
		var value any
		raw := []byte(text.String())
		return len(raw) > 0 && gatewayOAuthUnicodeValid(raw) && gatewayClaudeNativeJSON(raw) && json.Unmarshal(raw, &value) == nil && resolved.Validate(value) == nil
	}
	return lowered, validate, nil
}

func gatewayAnthropicSchemaNode(raw json.RawMessage, depth int, nodes *int) (json.RawMessage, error) {
	*nodes++
	if depth > 16 || *nodes > 2048 {
		return nil, ErrGatewayNativeIdentity
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrGatewayNativeIdentity
	}
	for name := range fields {
		switch name {
		case "type", "title", "description", "properties", "required", "additionalProperties", "items", "enum", "const", "anyOf", "minimum", "maximum":
		default:
			return nil, ErrGatewayNativeIdentity
		}
	}
	var types []string
	if t := fields["type"]; len(t) > 0 {
		var single string
		if json.Unmarshal(t, &single) == nil {
			types = []string{single}
		} else if json.Unmarshal(t, &types) != nil {
			return nil, ErrGatewayNativeIdentity
		}
	}
	object := fields["properties"] != nil
	for _, kind := range types {
		if kind == "object" {
			object = true
		}
	}
	if object && !bytes.Equal(bytes.TrimSpace(fields["additionalProperties"]), []byte("false")) {
		return nil, ErrGatewayNativeIdentity
	}
	if extra := fields["additionalProperties"]; extra != nil && !bytes.Equal(bytes.TrimSpace(extra), []byte("false")) {
		return nil, ErrGatewayNativeIdentity
	}
	if properties := fields["properties"]; properties != nil {
		var props map[string]json.RawMessage
		if json.Unmarshal(properties, &props) != nil || props == nil {
			return nil, ErrGatewayNativeIdentity
		}
		for name, child := range props {
			lowered, err := gatewayAnthropicSchemaNode(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			props[name] = lowered
		}
		fields["properties"], _ = json.Marshal(props)
	}
	if child := fields["items"]; child != nil {
		lowered, err := gatewayAnthropicSchemaNode(child, depth+1, nodes)
		if err != nil {
			return nil, err
		}
		fields["items"] = lowered
	}
	if union := fields["anyOf"]; union != nil {
		var children []json.RawMessage
		if json.Unmarshal(union, &children) != nil || len(children) == 0 || len(children) > 16 {
			return nil, ErrGatewayNativeIdentity
		}
		for i, child := range children {
			lowered, err := gatewayAnthropicSchemaNode(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			children[i] = lowered
		}
		fields["anyOf"], _ = json.Marshal(children)
	}
	var guidance []string
	for _, bound := range []struct{ name, words string }{{"minimum", "greater than or equal to "}, {"maximum", "less than or equal to "}} {
		if value := fields[bound.name]; value != nil {
			var number float64
			if json.Unmarshal(value, &number) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, ErrGatewayNativeIdentity
			}
			guidance = append(guidance, "Numeric values must be "+bound.words+string(bytes.TrimSpace(value))+".")
			delete(fields, bound.name)
		}
	}
	if len(guidance) > 0 {
		var description string
		if original := fields["description"]; original != nil && json.Unmarshal(original, &description) != nil {
			return nil, ErrGatewayNativeIdentity
		}
		if description != "" {
			guidance = append([]string{description}, guidance...)
		}
		fields["description"], _ = json.Marshal(strings.Join(guidance, " "))
	}
	return json.Marshal(fields)
}
