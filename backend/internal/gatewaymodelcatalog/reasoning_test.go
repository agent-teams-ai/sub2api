package gatewaymodelcatalog

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestWireEffortValidityPreservesCodexBoundary(t *testing.T) {
	for _, effort := range []string{"minimal", "low", "medium", "high", "xhigh", "max"} {
		if !WireEffortValid(effort) {
			t.Errorf("existing qualified wire effort %q was lost", effort)
		}
	}
	for _, effort := range []string{"", "none", "ultra", "HIGH", "future", " high", "high "} {
		if WireEffortValid(effort) {
			t.Errorf("unqualified wire effort %q was accepted", effort)
		}
	}
}

func TestOpenRouterReasoningExplicitControls(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		parameters []string
		metadata   string
		want       *Choices
	}{
		{"advertised-wire-values", []string{"reasoning"}, `{"supported_efforts":["max","xhigh","high","medium","low"],"default_effort":"medium"}`, &Choices{[]string{"max", "xhigh", "high", "medium", "low"}, "medium"}},
		{"deduplicate-without-remapping", []string{"tools", "reasoning"}, `{"supported_efforts":["ultra","none","high","medium","high"],"default_effort":"medium"}`, &Choices{[]string{"high", "medium"}, "medium"}},
		{"minimal-is-explicit", []string{"reasoning"}, `{"supported_efforts":["minimal","low"],"default_effort":"minimal"}`, &Choices{[]string{"minimal", "low"}, "minimal"}},
		{"parameter-name-only", []string{"reasoning"}, `{}`, nil},
		{"missing-parameter", []string{"tools"}, `{"supported_efforts":["high"],"default_effort":"high"}`, nil},
		{"missing-default", []string{"reasoning"}, `{"supported_efforts":["high"]}`, nil},
		{"default-not-advertised", []string{"reasoning"}, `{"supported_efforts":["high","medium"],"default_effort":"low"}`, nil},
		{"null-default", []string{"reasoning"}, `{"supported_efforts":["high"],"default_effort":null}`, nil},
		{"none-is-not-minimal", []string{"reasoning"}, `{"supported_efforts":["none","minimal"],"default_effort":"none"}`, nil},
		{"ultra-is-not-max", []string{"reasoning"}, `{"supported_efforts":["ultra","max"],"default_effort":"ultra"}`, nil},
		{"unknown-default", []string{"reasoning"}, `{"supported_efforts":["future"],"default_effort":"future"}`, nil},
		{"case-is-not-coerced", []string{"reasoning"}, `{"supported_efforts":["HIGH"],"default_effort":"HIGH"}`, nil},
		{"empty-efforts", []string{"reasoning"}, `{"supported_efforts":[],"default_effort":"high"}`, nil},
		{"null-efforts", []string{"reasoning"}, `{"supported_efforts":null,"default_effort":"high"}`, nil},
		{"wrong-effort-type", []string{"reasoning"}, `{"supported_efforts":"high","default_effort":"high"}`, nil},
		{"mixed-effort-types", []string{"reasoning"}, `{"supported_efforts":["high",42],"default_effort":"high"}`, nil},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var metadata map[string]json.RawMessage
			if err := json.Unmarshal([]byte(fixture.metadata), &metadata); err != nil {
				t.Fatal(err)
			}
			if got := OpenRouterReasoning(fixture.parameters, metadata); !reflect.DeepEqual(got, fixture.want) {
				t.Fatalf("reasoning projection = %#v, want %#v", got, fixture.want)
			}
		})
	}
}
