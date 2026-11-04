package service

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayAccountAdmissionDoesNotTreatSubscriptionExhaustionAsCreditExhaustion(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, primaryMinutes, secondaryMinutes, primaryUsed, secondaryUsed, primaryReset, secondaryReset string
		want                                                                                             string
	}{
		{"both subscriptions exhausted credits unknown", "300", "10080", "100", "100", "600", "120", "unknown"},
		{"reversed exhausted subscription windows", "10080", "300", "100", "100", "120", "600", "unknown"},
		{"only 5h exhausted", "300", "10080", "100", "16", "600", "120", "unknown"},
		{"below threshold", "300", "10080", "99.9", "16", "600", "120", "available"},
		{"legacy aliases do not establish credit exhaustion", "", "", "100", "100", "120", "600", "unknown"},
		{"elapsed reset cannot restart", "300", "10080", "100", "16", "0", "120", "available"},
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
			if tc.want == "available" {
				require.Equal(t, "available", result.Status)
				return
			}
			// A zero subscription remainder with unknown credits must not block
			// dispatch or advertise a total-spend reset/generation.
			require.Equal(t, GatewayAccountAdmissionResult{Status: "unknown"}, result)
			require.Equal(t, "available", gatewayAccountAdmission(snapshot, now.Add(20*time.Minute)).Status)
		})
	}
	for _, status := range []string{"unknown", "unavailable", "unsupported"} {
		require.Equal(t, GatewayAccountAdmissionResult{Status: status}, gatewayAccountAdmission(GatewayAccountLimitsResult{Status: status}, now))
	}
	require.Equal(t, "unsupported", gatewayAccountAdmission(GatewayAccountLimitsResult{Status: "snapshot", Windows: []GatewayAccountLimitWindow{{Family: "claude"}}}, now).Status)
}
