package gemini

import (
	"strconv"
	"strings"
)

// SupportsMultimodalFunctionResponses reports whether tool media can remain
// inside functionResponse.parts (Gemini 3 and later).
func SupportsMultimodalFunctionResponses(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if idx := strings.LastIndex(model, "/models/"); idx >= 0 {
		model = model[idx+len("/models/"):]
	} else {
		model = strings.TrimPrefix(model, "models/")
	}
	version, ok := strings.CutPrefix(model, "gemini-")
	if !ok {
		return false
	}
	major, _, _ := strings.Cut(version, "-")
	major, _, _ = strings.Cut(major, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n >= 3
}
