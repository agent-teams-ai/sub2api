//go:build unit

package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGatewayNativeGeminiWireRejectsNoncanonicalSignatures(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		valid       bool
	}{
		{"valid", `{"google":{"thought_signature":"opaque+/="}}`, true},
		{"null", `null`, false},
		{"unknown key", `{"google":{"thought_signature":"opaque"},"other":1}`, false},
		{"google alias", `{"Google":{"thought_signature":"opaque"}}`, false},
		{"signature alias", `{"google":{"Thought_Signature":"opaque"}}`, false},
		{"duplicate google", `{"google":{"thought_signature":"a"},"google":{"thought_signature":"b"}}`, false},
		{"duplicate signature", `{"google":{"thought_signature":"a","thought_signature":"b"}}`, false},
		{"null google", `{"google":null}`, false},
		{"null signature", `{"google":{"thought_signature":null}}`, false},
		{"empty signature", `{"google":{"thought_signature":""}}`, false},
		{"control", `{"google":{"thought_signature":"bad\nvalue"}}`, false},
		{"oversized", `{"google":{"thought_signature":"` + strings.Repeat("x", (64<<10)+1) + `"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.valid, gatewayNativeGeminiExtraValid([]byte(tc.extra)))
			for _, stream := range []bool{false, true} {
				field := "message"
				if stream {
					field = "delta"
				}
				for _, message := range []string{
					`{"extra_content":` + tc.extra + `}`,
					`{"tool_calls":[{"index":0,"id":"call","type":"function","function":{"name":"read","arguments":"{}"},"extra_content":` + tc.extra + `}]}`,
				} {
					wire := fmt.Sprintf(`{"choices":[{"index":0,"finish_reason":"stop",%q:%s}]}`, field, message)
					require.Equal(t, tc.valid, gatewayNativeGeminiWireValid([]byte(wire), stream))
				}
			}
		})
	}
	require.True(t, gatewayNativeGeminiExtraValid(nil))
	for _, message := range []string{
		`{"Extra_Content":{"google":{"thought_signature":"opaque"}}}`,
		`{"extra_content":{"google":{"thought_signature":"opaque"}},"extra_content":{"google":{"thought_signature":"opaque"}}}`,
		`{"tool_calls":[{"Extra_Content":{"google":{"thought_signature":"opaque"}}}]}`,
	} {
		wire := `{"choices":[{"index":0,"delta":` + message + `}]}`
		require.False(t, gatewayNativeGeminiWireValid([]byte(wire), true))
	}
}
