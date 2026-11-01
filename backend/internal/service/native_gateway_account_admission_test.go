package service

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestGatewayAccountAdmissionUsesStockCodexPolicy(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, primaryMinutes, secondaryMinutes, primaryUsed, secondaryUsed, primaryReset, secondaryReset string
		want                                                                                             int
	}{
		{"both exhausted prefer 7d even with earlier reset", "300", "10080", "100", "100", "600", "120", 120},
		{"reversed windows use duration not identifier", "10080", "300", "100", "100", "120", "600", 120},
		{"only 5h exhausted", "300", "10080", "100", "16", "600", "120", 600},
		{"below threshold", "300", "10080", "99.9", "16", "600", "120", 0},
		{"legacy aliases preserve stock mapping", "", "", "100", "100", "120", "600", 120},
		{"elapsed reset cannot restart", "300", "10080", "100", "16", "0", "120", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range map[string]string{"primary-window-minutes": tc.primaryMinutes, "secondary-window-minutes": tc.secondaryMinutes, "primary-used-percent": tc.primaryUsed, "secondary-used-percent": tc.secondaryUsed, "primary-reset-after-seconds": tc.primaryReset, "secondary-reset-after-seconds": tc.secondaryReset} {
				if v != "" {
					h.Set("x-codex-"+k, v)
				}
			}
			snapshot := GatewayAccountLimitsResult{Status: "snapshot", PhysicalGeneration: "fixture-generation", Windows: NormalizeGatewayCodexLimits(CaptureGatewayCodexLimits(h, now))}
			result := gatewayAccountAdmission(snapshot, now)
			if tc.want == 0 {
				require.Equal(t, "available", result.Status)
				return
			}
			require.Equal(t, "limited", result.Status)
			require.Equal(t, "fixture-generation", result.PhysicalGeneration)
			expected := now.Add(time.Duration(tc.want) * time.Second)
			require.Equal(t, expected.Format(time.RFC3339Nano), result.RetryAt)
			require.Equal(t, calculateOpenAI429ResetTimeAt(h, now).UTC().Format(time.RFC3339Nano), result.RetryAt)
			require.Equal(t, "available", gatewayAccountAdmission(snapshot, now.Add(20*time.Minute)).Status)
		})
	}
	require.Equal(t, "unknown", gatewayAccountAdmission(GatewayAccountLimitsResult{Status: "unknown"}, now).Status)
	require.Equal(t, "unsupported", gatewayAccountAdmission(GatewayAccountLimitsResult{Status: "snapshot", Windows: []GatewayAccountLimitWindow{{Family: "claude"}}}, now).Status)
}
