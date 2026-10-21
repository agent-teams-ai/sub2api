package service

import "testing"

func TestGatewayNativeUsageProjection(t *testing.T) {
	for _, test := range []struct {
		name, body, state                string
		complete                         bool
		input, output, cached, reasoning int64
	}{
		{"complete", `{"usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":4},"output_tokens_details":{"reasoning_tokens":2}},"output":[{"secret":"ignored"}]}`, "complete", true, 10, 5, 4, 2},
		{"zero", `{"usage":{"input_tokens":0,"output_tokens":0}}`, "complete", true, 0, 0, -1, -1},
		{"failure", `{"usage":{"input_tokens":10,"output_tokens":5}}`, "partial", false, 10, 5, -1, -1},
		{"partial", `{"usage":{"input_tokens":10,"output_tokens":1.5}}`, "partial", true, 10, -1, -1, -1},
		{"bounds", `{"usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":11},"output_tokens_details":{"reasoning_tokens":6}}}`, "complete", true, 10, 5, -1, -1},
		{"unsafe", `{"usage":{"input_tokens":9007199254740992,"output_tokens":-1}}`, "unknown", true, -1, -1, -1, -1},
		{"duplicate", `{"usage":{"input_tokens":1,"input_tokens":2,"output_tokens":3}}`, "unknown", true, -1, -1, -1, -1},
		{"nested", `{"output":{"usage":{"input_tokens":1,"output_tokens":2}}}`, "unknown", true, -1, -1, -1, -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := GatewayNativeUsage{State: "unknown"}
			gatewayNativeObserveUsage([]byte(test.body), &observation, test.complete)
			if observation.State != test.state {
				t.Fatalf("state %s", observation.State)
			}
			for i, pair := range []struct {
				got  *int64
				want int64
			}{{observation.InputTokens, test.input}, {observation.OutputTokens, test.output}, {observation.CachedInputTokens, test.cached}, {observation.ReasoningOutputTokens, test.reasoning}} {
				if pair.want < 0 {
					if pair.got != nil {
						t.Fatalf("field %d unexpectedly present", i)
					}
				} else if pair.got == nil || *pair.got != pair.want {
					t.Fatalf("field %d wrong", i)
				}
			}
		})
	}
}
