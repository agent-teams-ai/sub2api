package gatewaytransport

// Strict public JSON ingress and safe Responses defaults.
import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Standard Responses clients may omit the safe server defaults. Supplied values
// remain untouched and the common qualifier still rejects store=true or a paid
// tier. SDK ingress keeps its exact existing explicit-field contract.
func standardResponsesDefaults(raw []byte) ([]byte, error) {
	if uniquePayloadJSON(raw) != nil {
		return nil, errDenied
	}
	fields, valid := service.GatewayNativePayloadFields(raw, "model", "stream", "store", "service_tier", "previous_response_id", "max_output_tokens")
	if !valid {
		return nil, errDenied
	}
	suffix := ""
	if fields["store"] == nil {
		suffix += `,"store":false`
	}
	if fields["service_tier"] == nil {
		suffix += `,"service_tier":"default"`
	}
	if suffix == "" {
		return raw, nil
	}
	end := bytes.LastIndexByte(raw, '}')
	if end < 0 {
		return nil, errDenied
	}
	out := make([]byte, 0, len(raw)+len(suffix))
	out = append(out, raw[:end]...)
	out = append(out, suffix...)
	out = append(out, raw[end:]...)
	return out, nil
}

// Decode names before normalization. This bounded scanner rejects duplicate
// decoded keys at every depth while leaving opaque numbers and body bytes alone.
func uniquePayloadJSON(raw []byte) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errDenied
		}
		token, err := decoder.Token()
		if err != nil {
			return errDenied
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]bool)
			for decoder.More() {
				token, err = decoder.Token()
				if err != nil {
					return errDenied
				}
				key, ok := token.(string)
				if !ok || keys[key] {
					return errDenied
				}
				keys[key] = true
				if value(depth+1) != nil {
					return errDenied
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim('}') {
				return errDenied
			}
		case '[':
			for decoder.More() {
				if value(depth+1) != nil {
					return errDenied
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim(']') {
				return errDenied
			}
		default:
			return errDenied
		}
		return nil
	}
	if value(0) != nil {
		return errDenied
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errDenied
	}
	return nil
}
