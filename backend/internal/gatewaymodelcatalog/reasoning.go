// Package gatewaymodelcatalog projects provider-advertised model controls into
// the private account-model wire contract. It performs no I/O or credential work.
package gatewaymodelcatalog

import (
	"encoding/json"
	"slices"
)

type Choices struct {
	Allowed []string `json:"allowed"`
	Default string   `json:"default"`
}

// WireEffortValid names the already qualified native Responses wire values.
// Vendor aliases are not wire values and must never be guessed or remapped.
func WireEffortValid(effort string) bool {
	switch effort {
	case "minimal", "low", "medium", "high", "xhigh", "max":
		return true
	}
	return false
}

// OpenRouterReasoning receives a canonical metadata object from the source JSON
// boundary. A parameter name alone cannot advertise an effort or its default.
func OpenRouterReasoning(parameters []string, metadata map[string]json.RawMessage) *Choices {
	if !slices.Contains(parameters, "reasoning") {
		return nil
	}
	var advertised []string
	var def string
	if json.Unmarshal(metadata["supported_efforts"], &advertised) != nil ||
		json.Unmarshal(metadata["default_effort"], &def) != nil || !WireEffortValid(def) {
		return nil
	}
	allowed := []string{}
	for _, effort := range advertised {
		if WireEffortValid(effort) && !slices.Contains(allowed, effort) {
			allowed = append(allowed, effort)
		}
	}
	if !slices.Contains(allowed, def) {
		return nil
	}
	return &Choices{Allowed: allowed, Default: def}
}
