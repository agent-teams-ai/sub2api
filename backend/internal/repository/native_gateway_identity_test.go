//go:build unit

package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
)

// Redis protocol and persisted projection behavior; not real Redis durability.
func TestGatewayNativeIdentity_NoSchedulerCredentialProjection(t *testing.T) {
	ctx := context.Background()
	cache := newSchedulerCacheUnit(t)
	ordinary := service.Account{ID: 17, Status: service.StatusActive, Schedulable: true,
		Credentials: map[string]any{"api_key": "fixture-key"}}
	require.NoError(t, cache.SetAccount(ctx, &ordinary))
	cached, err := cache.GetAccount(ctx, 17)
	require.NoError(t, err)
	require.NotNil(t, cached)
	managed := ordinary
	managed.Extra = map[string]any{service.GatewayGenerationExtraKey: "55555555-5555-4555-8555-555555555555"}
	ids, err := cache.writeAccountIDs(ctx, []service.Account{managed})
	require.NoError(t, err)
	require.Empty(t, ids)
	cached, err = cache.GetAccount(ctx, 17)
	require.NoError(t, err)
	require.Nil(t, cached)
	require.NoError(t, cache.SetAccount(ctx, &managed))
	cached, err = cache.GetAccount(ctx, 17)
	require.NoError(t, err)
	require.Nil(t, cached)
	ordinary.ID = 18
	require.NoError(t, cache.SetAccount(ctx, &ordinary))
	cached, err = cache.GetAccount(ctx, 18)
	require.NoError(t, err)
	require.NotNil(t, cached)
}
