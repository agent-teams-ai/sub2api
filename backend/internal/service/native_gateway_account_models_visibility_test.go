//go:build unit

package service

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// Uses the original parser API so this regression also compiles on the parent
// source: the old picker-only projection wrongly returns just listed-runnable.
func TestGatewayAccountModelsHiddenRunnable(t *testing.T) {
	models, err := parseGatewayCodexAccountModels([]byte(`{"models":[{"slug":"listed-runnable","visibility":"list"},{"slug":"hidden-runnable-preview","visibility":"hide","supported_in_api":false,"supported_endpoints":["responses"],"input_modalities":["text"]},{"slug":"unlisted-runnable","visibility":"none"}]}`))
	require.NoError(t, err)
	require.Len(t, models, 3)
	require.Equal(t, "hidden-runnable-preview", models[1].ModelID)
	require.Equal(t, "unlisted-runnable", models[2].ModelID)
}
