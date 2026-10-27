package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func limitsV2PGWindow(provider string, observed time.Time, id string) service.GatewayAccountLimitWindowV2 {
	used := 0.0
	at := observed.UTC().Format(time.RFC3339Nano)
	duration := int64(18000)
	label := "5h"
	if id == "weekly" {
		duration = 604800
		label = "Week"
	}
	return service.GatewayAccountLimitWindowV2{ID: id, Provider: provider, Dimension: "plan_quota", Unit: "credits", Period: service.GatewayAccountLimitPeriodV2{Kind: "duration", DurationSeconds: &duration}, Label: &label, UsedPercent: &used, ObservedAt: &at}
}

// This catches real SQL CAS failures, windows merged instead of replaced,
// wrong-owner/birth publication, and erased custody remaining readable.
func TestGatewayAccountLimitsV2KeyPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_LIMITS_V2_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: dedicated disposable v2 limits PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	require.Contains(t, []string{"127.0.0.1", "::1"}, u.Hostname())
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_limits_v2_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(6)
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	scope := service.GatewayNativeCredentialScope{Consumer: "consumer-v2", Owner: "owner-v2", Account: "account-v2", Generation: uuid.NewString(), Purpose: service.GatewayCredentialPurpose}
	ctx, err = service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	ctx, err = service.WithGatewayNativeOAuthOwner(ctx, scope.Owner)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("limits-v2", map[string][]byte{"limits-v2": key})
	require.NoError(t, err)
	envelope, err := custody.Seal(scope, "fixture-secret-key")
	require.NoError(t, err)
	creds, err := json.Marshal(map[string]any{"api_key": envelope, "base_url": service.GatewayKimiCodeResponsesBaseURL})
	require.NoError(t, err)
	extra, err := json.Marshal(map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: service.GatewayKimiCodeResponsesProfile, service.GatewayModelExtraKey: service.GatewayKimiCodeResponsesModel, service.GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true})
	require.NoError(t, err)
	route := service.GatewayNativeRoute{Generation: scope.Generation, Profile: service.GatewayKimiCodeResponsesProfile, BaseURL: service.GatewayKimiCodeResponsesBaseURL, Model: service.GatewayKimiCodeResponsesModel}
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra) VALUES ('v2-fixture','openai','apikey','disabled',false,$1::jsonb,$2::jsonb) RETURNING id,created_at`, string(creds), string(extra)).Scan(&route.AccountID, &route.CreatedAt))
	physical := service.GatewayNativeOAuthPhysical{Scope: scope, Route: route}
	source := NewGatewayAccountLimitsRepositoryV2(db)
	input := service.GatewayAccountLimitsInput{OwnerRef: scope.Owner, AccountRef: scope.Account, ProfileID: route.Profile}
	missing, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.Nil(t, missing.Snapshot)
	require.NotEmpty(t, missing.PrincipalVersion)
	observed := time.Now().UTC().Truncate(time.Microsecond)
	initial := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("kimi", observed, "five_hour"), limitsV2PGWindow("kimi", observed, "weekly")}}
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, initial, observed))
	first, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 1, first.Revision)
	require.Len(t, first.Snapshot.Windows, 2)
	newer := observed.Add(time.Second)
	replacement := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("kimi", newer, "five_hour")}}
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, replacement, newer))
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, initial, observed))
	current, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 2, current.Revision)
	require.Len(t, current.Snapshot.Windows, 1)
	require.Equal(t, missing.PrincipalVersion, current.PrincipalVersion)
	foreign := physical
	foreign.Scope.Owner = "foreign"
	require.Error(t, source.StoreGatewayAccountLimitsV2(ctx, foreign, replacement, newer))
	foreign = physical
	foreign.Route.CreatedAt = foreign.Route.CreatedAt.Add(time.Microsecond)
	require.Error(t, source.StoreGatewayAccountLimitsV2(ctx, foreign, replacement, newer))
	wrongInput := input
	wrongInput.OwnerRef = "foreign"
	_, err = source.ReadGatewayAccountLimitsV2(ctx, wrongInput, route)
	require.Error(t, err)
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, service.GatewayAccountLimitsSnapshotV2{Scope: "subscription"}, newer.Add(time.Second)))
	empty, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 3, empty.Revision)
	require.Empty(t, empty.Snapshot.Windows)
	var v1 int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_account_limits_snapshots WHERE account_id=$1`, route.AccountID).Scan(&v1))
	require.Zero(t, v1)
	_, err = db.ExecContext(ctx, `UPDATE accounts SET credentials=credentials-'api_key',deleted_at=clock_timestamp() WHERE id=$1`, route.AccountID)
	require.NoError(t, err)
	_, err = source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.Error(t, err)
	require.Error(t, source.StoreGatewayAccountLimitsV2(ctx, physical, replacement, newer.Add(3*time.Second)))
}

func gatewayAccountLimitsV2GrokPostgresFixture(t *testing.T, ctx context.Context, db *sql.DB, scope service.GatewayNativeCredentialScope, op string, route service.GatewayNativeRoute) {
	t.Helper()
	grok := &gatewayGrokRepository{db}
	tx, physical, _, err := grok.physicalTxMode(ctx, scope, op, &route, false, true, true)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	source := NewGatewayAccountLimitsRepositoryV2(db)
	input := service.GatewayAccountLimitsInput{OwnerRef: scope.Owner, AccountRef: scope.Account, ProfileID: route.Profile}
	missing, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.Nil(t, missing.Snapshot)
	observed := time.Now().UTC().Truncate(time.Microsecond)
	raw := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("grok", observed, "weekly")}}
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, raw, observed))
	current, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 1, current.Revision)
	require.Len(t, current.Snapshot.Windows, 1)
	wrong := physical
	wrong.Subject = "foreign-principal"
	require.Error(t, source.StoreGatewayAccountLimitsV2(ctx, wrong, raw, observed))
	// Passive headers and billing can complete in either order. Their own source
	// timestamps, rather than the maximum observation time, fence stale batches.
	rateAt := observed.Add(4 * time.Second)
	rate := limitsV2PGWindow("grok", rateAt, "request_rate")
	rate.Dimension = "rate_limit"
	rate.Unit = "requests"
	rate.Label = nil
	seconds := int64(60)
	rate.Period = service.GatewayAccountLimitPeriodV2{Kind: "duration", DurationSeconds: &seconds}
	rates := service.GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []service.GatewayAccountLimitWindowV2{rate}}
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, rates, rateAt))
	planAt := observed.Add(2 * time.Second)
	plan := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("grok", planAt, "five_hour")}}
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, plan, planAt))
	interleaved, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 3, interleaved.Revision)
	require.Len(t, interleaved.Snapshot.Windows, 2)
	require.Equal(t, rate, interleaved.Snapshot.Windows[0], "billing preserves original passive rate observation")
	require.Equal(t, plan.Windows[0], interleaved.Snapshot.Windows[1], "billing replaces its entire prior weekly window set")
	staleRateAt := observed.Add(3 * time.Second)
	staleRate := rate
	staleObserved := staleRateAt.UTC().Format(time.RFC3339Nano)
	staleRate.ObservedAt = &staleObserved
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, service.GatewayAccountLimitsSnapshotV2{Scope: "account", Windows: []service.GatewayAccountLimitWindowV2{staleRate}}, staleRateAt))
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, raw, observed))
	unchanged, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.Equal(t, interleaved, unchanged)
	// An empty successful billing response clears only plan quota. A late prior
	// billing response cannot revive the disappeared windows after that clear.
	emptyAt := observed.Add(3 * time.Second)
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, service.GatewayAccountLimitsSnapshotV2{Scope: "subscription"}, emptyAt))
	require.NoError(t, source.StoreGatewayAccountLimitsV2(ctx, physical, plan, planAt))
	remaining, err := source.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 4, remaining.Revision)
	require.Equal(t, []service.GatewayAccountLimitWindowV2{rate}, remaining.Snapshot.Windows)
	var latest time.Time
	var sources []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT observed_at,source_observations FROM gateway_account_limits_v2_snapshots WHERE account_id=$1`, route.AccountID).Scan(&latest, &sources))
	require.True(t, latest.Equal(rateAt), "global observation maximum cannot move backwards")
	var stamps map[string]string
	require.NoError(t, json.Unmarshal(sources, &stamps))
	require.Equal(t, emptyAt.UTC().Format(time.RFC3339Nano), stamps["plan_quota"])
	require.Equal(t, rateAt.UTC().Format(time.RFC3339Nano), stamps["rate_limit"])
	mixed := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: append([]service.GatewayAccountLimitWindowV2{rate}, plan.Windows...)}
	require.Error(t, source.StoreGatewayAccountLimitsV2(ctx, physical, mixed, rateAt))
	reader, err := service.NewGatewayAccountLimitsReaderV2(source, func(context.Context, service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		return route, nil
	})
	require.NoError(t, err)
	result := reader.Read(ctx, input)
	require.Equal(t, "snapshot", result.Status)
	require.Equal(t, []service.GatewayAccountLimitWindowV2{rate}, result.Windows)
}
