// Command generate-plan-catalog emits the native-owned labels used by admin UI.
package main

import (
	"encoding/json"
	"os"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
)

func main() {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if e.Encode(openai.PlanCatalog()) != nil {
		os.Exit(1)
	}
}
