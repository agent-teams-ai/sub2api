//go:build unit

package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type limitsFixtureRepository struct {
	*oauthDispatchStore
	stored        GatewayAccountLimitsStored
	reads, writes int
	reject        bool
}

func (r *limitsFixtureRepository) ReadGatewayAccountLimits(_ context.Context, in GatewayAccountLimitsInput, route GatewayNativeRoute) (GatewayAccountLimitsStored, error) {
	r.reads++
	if r.reject || in.OwnerRef != r.physical.Scope.Owner || in.AccountRef != r.physical.Scope.Account || !SameGatewayNativeDescriptor(route, r.physical.Route) {
		return GatewayAccountLimitsStored{}, ErrGatewayNativeIdentity
	}
	out := r.stored
	out.PrincipalVersion = GatewayAccountLimitsPrincipal(r.physical)
	return out, nil
}
func (r *limitsFixtureRepository) StoreGatewayAccountLimits(_ context.Context, p GatewayNativeOAuthPhysical, raw GatewayCodexRawLimits, _ time.Time) error {
	if !sameGatewayOAuthPhysical(p, r.physical) {
		return ErrGatewayNativeIdentity
	}
	r.writes++
	r.stored.Revision++
	r.stored.Raw = &raw
	return nil
}

// This fails if cached reading enters any real provider path, local stats become
// a quota, or the actual passive forward path ceases persisting proven headers.
func TestGatewayAccountLimitsPassiveCaptureAndCachedRead(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	route := f.qualify(t)
	source := &limitsFixtureRepository{oauthDispatchStore: f.store}
	f.dispatch.repository = source
	in := GatewayAccountLimitsInput{f.scope.Owner, f.scope.Account, GatewayCodexOAuthResponsesProfile, 7}
	authorityCalls := 0
	reader, err := NewGatewayAccountLimitsReader(source, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
		authorityCalls++
		return route, nil
	})
	require.NoError(t, err)
	counts := func() []int32 { return []int32{f.entries.Load(), f.checks.Load(), f.jwks.Load()} }
	before := counts()
	// These aggregate stats are not consulted by this contract.
	f.store.row.Extra["window_stats"] = map[string]any{"requests": 99}
	require.Equal(t, GatewayAccountLimitsResult{Status: "unknown"}, reader.Read(f.ctx, in))
	delete(f.store.row.Extra, "window_stats") // immutable physical fixture stays valid
	require.Equal(t, before, counts())
	require.Zero(t, source.writes)
	f.limitHeaders = http.Header{"X-Codex-Primary-Used-Percent": {"37.5"}, "X-Codex-Primary-Window-Minutes": {"300"}, "X-Codex-Primary-Reset-After-Seconds": {"0"}}
	_, entered, err, _ := f.call(t, route, oauthDispatchPayload())
	require.NoError(t, err)
	require.True(t, entered)
	require.Equal(t, 1, source.writes)
	before = counts()
	out := reader.Read(f.ctx, in)
	require.Equal(t, "snapshot", out.Status)
	require.Equal(t, int64(1), out.Revision)
	require.Len(t, out.Windows, 1)
	require.Equal(t, 37.5, *out.Windows[0].UsedPercent)
	require.Equal(t, int64(18000), *out.Windows[0].DurationSeconds)
	require.Equal(t, out.Windows[0].ObservedAt, out.Windows[0].ResetAt)
	require.Equal(t, before, counts())
	require.Equal(t, 1, source.writes)
	principal := out.PrincipalVersion
	f.store.row.Name = "renamed"
	// Engine version/credential metadata is not part of the cached identity key.
	f.store.row.Credentials["credential_version"] = "2"
	out = reader.Read(f.ctx, in)
	require.Equal(t, "snapshot", out.Status)
	require.Equal(t, principal, out.PrincipalVersion)
	require.Equal(t, int64(1), out.Revision)
	require.Equal(t, before, counts())
	require.Equal(t, 6, authorityCalls)
}
func TestGatewayAccountLimitsIdentityFences(t *testing.T) {
	for _, scenario := range []string{"owner_revoked", "reconnect", "source_deleted", "principal_replaced", "snapshot_removed", "revision_rollback", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			raw := CaptureGatewayCodexLimits(http.Header{"X-Codex-Primary-Used-Percent": {"0"}}, time.Date(2026, 10, 22, 1, 0, 0, 0, time.UTC))
			source := &limitsFixtureRepository{oauthDispatchStore: f.store, stored: GatewayAccountLimitsStored{Revision: 1, Raw: &raw}}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			calls := 0
			reader, err := NewGatewayAccountLimitsReader(source, func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				calls++
				if calls == 2 {
					switch scenario {
					case "owner_revoked":
						return GatewayNativeRoute{}, ErrGatewayNativeIdentity
					case "reconnect":
						changed := route
						changed.Generation = "00000000-0000-4000-8000-000000000001"
						return changed, nil
					case "source_deleted":
						source.reject = true
					case "principal_replaced":
						source.physical.Subject = "replacement"
					case "snapshot_removed":
						source.stored.Raw = nil
					case "revision_rollback":
						source.stored.Revision = 0
					case "cancelled":
						cancel()
					}
				}
				return route, nil
			})
			require.NoError(t, err)
			result := reader.Read(ctx, GatewayAccountLimitsInput{f.scope.Owner, f.scope.Account, GatewayCodexOAuthResponsesProfile, 0})
			require.Equal(t, GatewayAccountLimitsResult{Status: "unavailable"}, result)
			require.Zero(t, source.writes)
		})
	}
}
func stringPointer(s string) *string { return &s }

// Expected constants are independent of the production normalizer. Covers
// observation/reset clocks without refreshing, resetting, clamping or aliases.
func TestGatewayAccountLimitsNormalize(t *testing.T) {
	cases := []struct {
		name, observed                    string
		used, minutes, absolute, relative *string
		wantUsed                          *float64
		duration                          *int64
		reset, observation                *string
		reason                            string
	}{
		{name: "reset keeps observation", observed: "2026-01-01T01:00:00+01:00", used: stringPointer("37.5"), minutes: stringPointer("300"), relative: stringPointer("0"), wantUsed: floatPointer(37.5), duration: intPointer(18000), reset: stringPointer("2026-01-01T00:00:00Z"), observation: stringPointer("2026-01-01T00:00:00Z")},
		{name: "weekly primary", observed: "1767225600", used: stringPointer("105.25"), minutes: stringPointer("10080"), absolute: stringPointer("1767225660"), wantUsed: floatPointer(105.25), duration: intPointer(604800), reset: stringPointer("2026-01-01T00:01:00Z"), observation: stringPointer("2026-01-01T00:00:00Z")},
		{name: "legacy alias unknown duration", used: stringPointer("0"), wantUsed: floatPointer(0)},
		{name: "missing observation rejects relative", observed: "invalid", used: stringPointer("22"), relative: stringPointer("5"), wantUsed: floatPointer(22)},
		{name: "reset conflict preserves percent", observed: "2026-01-01T00:00:00Z", used: stringPointer("37.5"), absolute: stringPointer("2026-01-01T00:05:00Z"), relative: stringPointer("0"), wantUsed: floatPointer(37.5), observation: stringPointer("2026-01-01T00:00:00Z"), reason: "reset_conflict"},
		{name: "absolute wins within tolerance", observed: "2026-01-01T00:00:00Z", absolute: stringPointer("2026-01-01T00:01:00Z"), relative: stringPointer("0"), reset: stringPointer("2026-01-01T00:01:00Z"), observation: stringPointer("2026-01-01T00:00:00Z")},
		{name: "invalid numbers", used: stringPointer("NaN"), minutes: stringPointer("-5"), relative: stringPointer("-1")},
		{name: "infinity", used: stringPointer("+Inf"), minutes: stringPointer("9007199254740991")},
		{name: "negative percent", used: stringPointer("-1")},
		{name: "UTC year underflow", observed: "0001-01-01T00:00:00+01:00", absolute: stringPointer("9999-12-31T23:59:59-01:00")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := NormalizeGatewayCodexLimits(GatewayCodexRawLimits{Windows: []GatewayCodexRawWindow{{ID: "primary", Used: tc.used, WindowMinutes: tc.minutes, ObservedAt: tc.observed, ResetAt: tc.absolute, ResetAfterSeconds: tc.relative}}})
			require.Len(t, out, 1)
			require.Equal(t, tc.wantUsed, out[0].UsedPercent)
			require.Equal(t, tc.duration, out[0].DurationSeconds)
			require.Equal(t, tc.reset, out[0].ResetAt)
			require.Equal(t, tc.observation, out[0].ObservedAt)
			require.Equal(t, tc.reason, out[0].Reason)
		})
	}
	raw := CaptureGatewayCodexLimits(http.Header{"X-Codex-Primary-Used-Percent": {"37.5"}, "X-Codex-Primary-Window-Minutes": {"300"}, "X-Codex-Secondary-Used-Percent": {"88"}, "X-Codex-Secondary-Window-Minutes": {"10080"}, "X-Codex-Spark-Used-Percent": {"1"}}, time.Now())
	out := NormalizeGatewayCodexLimits(raw)
	require.Len(t, out, 2)
	require.Equal(t, int64(18000), *out[0].DurationSeconds)
	require.Equal(t, int64(604800), *out[1].DurationSeconds)
	raw.Windows[1].ID = "primary"
	require.Empty(t, NormalizeGatewayCodexLimits(raw))
	wire, err := json.Marshal(GatewayAccountLimitsResult{Status: "unknown"})
	require.NoError(t, err)
	require.Equal(t, `{"status":"unknown"}`, string(wire))
	require.False(t, strings.Contains(string(wire), "windows"))
}
func floatPointer(n float64) *float64 { return &n }
func intPointer(n int64) *int64       { return &n }
