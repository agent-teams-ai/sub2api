//go:build integration || gatewaycustody

package repository

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGatewayAccountInfoPostgresOrderingAtomicityAndReplacement(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_INFO_TEST_DSN", "gateway_info_test_")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	scope := service.GatewayNativeCredentialScope{Consumer: "info-consumer", Owner: "info-owner", Account: "info-account", Generation: uuid.NewString(), Purpose: service.GatewayCredentialPurpose}
	ctx, err = service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	ctx, err = service.WithGatewayNativeOAuthOwner(ctx, scope.Owner)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("info-fixture", map[string][]byte{"info-fixture": key})
	require.NoError(t, err)
	accountData := func(s service.GatewayNativeCredentialScope) (string, string) {
		envelope, e := custody.Seal(s, "synthetic-info-key")
		require.NoError(t, e)
		credentials, e := json.Marshal(map[string]any{"api_key": envelope, "base_url": service.GatewayGLMCodingResponsesBaseURL})
		require.NoError(t, e)
		extra, e := json.Marshal(map[string]any{service.GatewayGenerationExtraKey: s.Generation, service.GatewayProfileExtraKey: service.GatewayGLMCodingResponsesProfile, service.GatewayModelExtraKey: service.GatewayGLMCodingResponsesModel, service.GatewayCredentialScopeExtraKey: s.Metadata(), "openai_responses_mode": "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true})
		require.NoError(t, e)
		return string(credentials), string(extra)
	}
	credentials, extra := accountData(scope)
	route := service.GatewayNativeRoute{Generation: scope.Generation, Profile: service.GatewayGLMCodingResponsesProfile, BaseURL: service.GatewayGLMCodingResponsesBaseURL, Model: service.GatewayGLMCodingResponsesModel}
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra) VALUES('info fixture','openai','apikey','disabled',false,$1::jsonb,$2::jsonb) RETURNING id,created_at`, credentials, extra).Scan(&route.AccountID, &route.CreatedAt))
	p := service.GatewayNativeOAuthPhysical{Scope: scope, Route: route}
	info := NewGatewayAccountInfoRepository(db)
	input := service.GatewayAccountLimitsInput{OwnerRef: scope.Owner, AccountRef: scope.Account, ProfileID: route.Profile}
	initial, e := info.ReadGatewayAccountInfo(ctx, input, route)
	require.NoError(t, e)
	require.Empty(t, initial.Sources)
	at := time.Now().UTC().Truncate(time.Microsecond)
	observation := func(order int64, code string) service.GatewayAccountInfoObservation {
		fields := service.GatewayAccountInfoEmptyFields(route.Profile)
		if code != "" {
			value := service.GatewayAccountSubscription{Code: code, Label: code, Scope: "unknown"}
			fields.Subscription = service.GatewayAccountFact[service.GatewayAccountSubscription]{Status: "known", Value: &value, Source: "provider_api", ObservedAt: at.Format(time.RFC3339Nano), Freshness: "current"}
		}
		return service.GatewayAccountInfoObservation{Source: "plan_quota", Order: order, Fields: fields}
	}
	first, e := info.ReserveGatewayAccountInfoOrder(ctx)
	require.NoError(t, e)
	second, e := info.ReserveGatewayAccountInfoOrder(ctx)
	require.NoError(t, e)
	require.Greater(t, second, first)
	known := observation(first, "GLM Pro")
	quota := NewGatewayAccountLimitsRepositoryV2(db).(service.GatewayAccountQuotaInfoRepository)
	limits := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("glm", at, "five_hour")}}
	require.NoError(t, quota.StoreGatewayQuotaAndInfo(ctx, p, limits, at, &known))
	stored, e := info.ReadGatewayAccountInfo(ctx, input, route)
	require.NoError(t, e)
	require.EqualValues(t, 1, stored.Revision)
	require.Equal(t, "GLM Pro", stored.Sources["plan_quota"].Fields.Subscription.Value.Label)
	removed := observation(second, "")
	require.NoError(t, info.StoreGatewayAccountInfo(ctx, p, false, removed))
	require.NoError(t, info.StoreGatewayAccountInfo(ctx, p, false, known), "late same-credential response is ignored")
	legacy := known
	legacy.Order = 0
	require.NoError(t, info.StoreGatewayAccountInfo(ctx, p, true, legacy), "old cached hydration cannot replace live omission")
	stored, e = info.ReadGatewayAccountInfo(ctx, input, route)
	require.NoError(t, e)
	require.EqualValues(t, 2, stored.Revision)
	require.Equal(t, "unknown", stored.Sources["plan_quota"].Fields.Subscription.Status)
	bad := known
	bad.CredentialRevision = 1
	newer := at.Add(time.Second)
	changed := service.GatewayAccountLimitsSnapshotV2{Scope: "subscription", Windows: []service.GatewayAccountLimitWindowV2{limitsV2PGWindow("glm", newer, "weekly")}}
	require.Error(t, quota.StoreGatewayQuotaAndInfo(ctx, p, changed, newer, &bad))
	unchanged, e := quota.ReadGatewayAccountLimitsV2(ctx, input, route)
	require.NoError(t, e)
	require.EqualValues(t, 1, unchanged.Revision)
	require.Equal(t, "five_hour", unchanged.Snapshot.Windows[0].ID, "facts failure rolls quota write back")
	foreign := input
	foreign.OwnerRef = "foreign-owner"
	_, e = info.ReadGatewayAccountInfo(ctx, foreign, route)
	require.Error(t, e)

	// Protected physical identity is immutable. Replacement creates a fresh
	// candidate; no test or implementation may bypass the database birth guard.
	scope.Generation = uuid.NewString()
	newRoute := route
	newRoute.Generation = scope.Generation
	credentials, extra = accountData(scope)
	_, e = db.ExecContext(ctx, `UPDATE accounts SET credentials=$2::jsonb,extra=$3::jsonb WHERE id=$1`, route.AccountID, credentials, extra)
	require.Error(t, e, "in-place generation replacement is prohibited")
	_, e = db.ExecContext(ctx, `UPDATE accounts SET deleted_at=clock_timestamp() WHERE id=$1`, route.AccountID)
	require.NoError(t, e)
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra) VALUES('replacement info fixture','openai','apikey','disabled',false,$1::jsonb,$2::jsonb) RETURNING id,created_at`, credentials, extra).Scan(&newRoute.AccountID, &newRoute.CreatedAt))
	require.NotEqual(t, route.AccountID, newRoute.AccountID)
	_, e = info.ReadGatewayAccountInfo(ctx, input, route)
	require.Error(t, e)
	newPhysical := service.GatewayNativeOAuthPhysical{Scope: scope, Route: newRoute}
	order, e := info.ReserveGatewayAccountInfoOrder(ctx)
	require.NoError(t, e)
	require.NoError(t, info.StoreGatewayAccountInfo(ctx, newPhysical, false, observation(order, "GLM New")))
	replaced, e := info.ReadGatewayAccountInfo(ctx, input, newRoute)
	require.NoError(t, e)
	require.NotEqual(t, stored.PrincipalVersion, replaced.PrincipalVersion)
	require.EqualValues(t, 1, replaced.Revision)
	require.Equal(t, "GLM New", replaced.Sources["plan_quota"].Fields.Subscription.Value.Label)
	_, e = db.ExecContext(ctx, `UPDATE accounts SET deleted_at=clock_timestamp() WHERE id=$1`, newRoute.AccountID)
	require.NoError(t, e)
	var rows int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_account_info_snapshots WHERE account_id=$1`, newRoute.AccountID).Scan(&rows))
	require.Zero(t, rows)
	require.Error(t, info.StoreGatewayAccountInfo(ctx, newPhysical, false, observation(order+1, "late")))
	t.Run("Official API closed database profiles", func(t *testing.T) {
		gatewayOfficialAPIProfilesPostgres(t, db)
	})
}
