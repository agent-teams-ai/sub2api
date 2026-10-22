package repository

import (
	"context"
	"database/sql"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Called inside the existing disposable PG17 OAuth qualification fixture. It
// exercises migration252 + real passive response -> fenced SQL -> cached reader;
// the enclosing fixture then rotates credentials and rechecks this same cache.
func gatewayAccountLimitsPostgresFixture(t *testing.T, ctx context.Context, db *sql.DB, repo service.AccountRepository, dispatch *service.GatewayNativeOAuthDispatch, scope service.GatewayNativeCredentialScope, operation string, route service.GatewayNativeRoute) service.GatewayAccountLimitsStored {
	t.Helper()
	source, ok := repo.(service.GatewayAccountLimitsRepository)
	require.True(t, ok)
	input := service.GatewayAccountLimitsInput{OwnerRef: scope.Owner, AccountRef: scope.Account, ProfileID: route.Profile, ExpectedAuthorizationEpoch: 3}
	missing, err := source.ReadGatewayAccountLimits(ctx, input, route)
	require.NoError(t, err)
	require.Nil(t, missing.Raw)
	require.NotEmpty(t, missing.PrincipalVersion)
	var entries atomic.Int32
	gateway := oauthDispatchPGGateway(t, repo, &entries, true)
	result := oauthDispatchPGForward(ctx, dispatch, gateway, scope, operation, route)
	require.NoError(t, result.err)
	require.True(t, result.entered)
	require.EqualValues(t, 1, entries.Load())
	snapshot, err := source.ReadGatewayAccountLimits(ctx, input, route)
	require.NoError(t, err)
	require.NotNil(t, snapshot.Raw)
	require.Equal(t, int64(1), snapshot.Revision)
	require.Equal(t, missing.PrincipalVersion, snapshot.PrincipalVersion)
	windows := service.NormalizeGatewayCodexLimits(*snapshot.Raw)
	require.Len(t, windows, 1)
	require.Equal(t, 37.5, *windows[0].UsedPercent)
	require.Equal(t, int64(18000), *windows[0].DurationSeconds)
	require.Equal(t, windows[0].ObservedAt, windows[0].ResetAt)
	physical := service.GatewayNativeOAuthPhysical{Scope: scope, Operation: operation, Route: route}
	require.NoError(t, db.QueryRowContext(ctx, `SELECT issuer,subject,provider_account_id FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, route.AccountID).Scan(&physical.Issuer, &physical.Subject, &physical.ProviderAccount))
	observed, err := time.Parse(time.RFC3339Nano, *windows[0].ObservedAt)
	require.NoError(t, err)
	headers := http.Header{"X-Codex-Primary-Used-Percent": {"88"}, "X-Codex-Primary-Window-Minutes": {"300"}}
	older := observed.Add(-time.Second)
	require.NoError(t, source.StoreGatewayAccountLimits(ctx, physical, service.CaptureGatewayCodexLimits(headers, older), older))
	same, err := source.ReadGatewayAccountLimits(ctx, input, route)
	require.NoError(t, err)
	require.Equal(t, snapshot, same)
	replaced := physical
	replaced.Subject = "wrong-principal"
	require.Error(t, source.StoreGatewayAccountLimits(ctx, replaced, service.CaptureGatewayCodexLimits(headers, observed), observed))
	wrongBirth := route
	wrongBirth.CreatedAt = wrongBirth.CreatedAt.Add(time.Microsecond)
	_, err = source.ReadGatewayAccountLimits(ctx, input, wrongBirth)
	require.Error(t, err)
	wrongGeneration := route
	wrongGeneration.Generation = uuid.NewString()
	_, err = source.ReadGatewayAccountLimits(ctx, input, wrongGeneration)
	require.Error(t, err)
	wrongOwner := input
	wrongOwner.OwnerRef = uuid.NewString()
	_, err = source.ReadGatewayAccountLimits(ctx, wrongOwner, route)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `UPDATE accounts SET name='renamed limits fixture' WHERE id=$1`, route.AccountID)
	require.NoError(t, err)
	renamed, err := source.ReadGatewayAccountLimits(ctx, input, route)
	require.NoError(t, err)
	require.Equal(t, snapshot, renamed)
	newer := observed.Add(time.Second)
	require.NoError(t, source.StoreGatewayAccountLimits(ctx, physical, service.CaptureGatewayCodexLimits(headers, newer), newer))
	next, err := source.ReadGatewayAccountLimits(ctx, input, route)
	require.NoError(t, err)
	require.Equal(t, int64(2), next.Revision)
	require.Equal(t, snapshot.PrincipalVersion, next.PrincipalVersion)
	reader, err := service.NewGatewayAccountLimitsReader(source, func(context.Context, service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		return route, nil
	})
	require.NoError(t, err)
	out := reader.Read(ctx, input)
	require.Equal(t, "snapshot", out.Status)
	require.Equal(t, 88.0, *out.Windows[0].UsedPercent)
	require.Equal(t, int64(2), out.Revision)
	require.EqualValues(t, 1, entries.Load(), "cached read must never enter provider transport")
	return next
}
