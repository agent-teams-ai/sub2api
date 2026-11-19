package openai

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlanCatalogNativeAndGeneratedAdminData(t *testing.T) {
	raw, err := os.ReadFile("../../../../frontend/src/constants/openaiPlanTypes.builtin.json")
	require.NoError(t, err)
	var generated PlanTypeCatalog
	require.NoError(t, json.Unmarshal(raw, &generated))
	require.Equal(t, PlanCatalog(), generated)
	for _, sample := range []struct{ code, status, analytics string }{{"ChatGPT Pro", "Pro 200", "Pro 200"}, {"business", "Enterprise", "Business"}, {"self_serve_business_prolite", "Business Premium", "Business"}, {"edu_plus", "Edu Plus", "Education"}, {"unknown", "Unknown", "Account"}, {"future-tier", "", ""}} {
		require.Equal(t, sample.status, PlanTypeLabel(sample.code, false))
		require.Equal(t, sample.analytics, PlanTypeLabel(sample.code, true))
	}
}
