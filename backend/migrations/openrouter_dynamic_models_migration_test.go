package migrations

import (
	"strings"
	"testing"
)

// Replacing a trigger function must not silently drop a previously qualified
// provider, OAuth refresh fence, immutable birth, or credential erasure guard.
func TestGatewayOpenRouterDynamicModelsMigrationPreservesGuard(t *testing.T) {
	previous, err := FS.ReadFile("257_gateway_coding_plan_profiles.sql")
	if err != nil {
		t.Fatal(err)
	}
	current, err := FS.ReadFile("258_gateway_openrouter_dynamic_models.sql")
	if err != nil {
		t.Fatal(err)
	}
	const oldClause = "AND NEW.extra ->> 'gateway_model_v1' IN ('openai/gpt-5.4-mini','openai/gpt-5.4-nano'))"
	const newClause = "AND (NEW.extra ->> 'gateway_model_v1') COLLATE \"C\" ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'\n     AND strpos(NEW.extra ->> 'gateway_model_v1', '/') > 0\n     AND strpos(NEW.extra ->> 'gateway_model_v1', '://') = 0)"
	before := strings.Split(string(previous), "$$")
	after := strings.Split(string(current), "$$")
	if len(before) != 3 || len(after) != 3 || strings.Count(before[1], oldClause) != 1 || strings.Count(after[1], newClause) != 1 {
		t.Fatal("expected one isolated OpenRouter model clause in the protected trigger function")
	}
	if strings.Replace(before[1], oldClause, newClause, 1) != after[1] || before[2] != after[2] {
		t.Fatal("the dynamic OpenRouter migration changed an unrelated protected guard or statement")
	}
}
