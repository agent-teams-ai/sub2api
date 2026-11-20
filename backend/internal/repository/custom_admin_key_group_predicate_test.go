package repository

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/stretchr/testify/require"
)

func TestScopedAdminGroupRuleAlternativesHonorsEmptyAndAllGroups(t *testing.T) {
	require.Empty(t, scopedAdminGroupRuleAlternatives(nil))
	require.Empty(t, scopedAdminGroupRuleAlternatives([]adminaccess.Rule{{}}),
		"rules without group IDs and without AllGroups must not broaden access")
	require.Len(t, scopedAdminGroupRuleAlternatives([]adminaccess.Rule{
		{GroupIDs: []int64{11}, Platforms: []string{"anthropic"}},
		{AllGroups: true, Platforms: []string{"gemini"}},
		{GroupIDs: nil, AllGroups: false},
	}), 2)
}
