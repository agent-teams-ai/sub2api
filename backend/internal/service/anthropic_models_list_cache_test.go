//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/require"
)

type anthropicLongContextCacheRepo struct {
	AccountRepository
	calls    int
	accounts []Account
}

func (r *anthropicLongContextCacheRepo) ListSchedulableByGroupID(_ context.Context, _ int64) ([]Account, error) {
	r.calls++
	return r.accounts, nil
}

func TestExpandAnthropicLongContextModelsCachesAndInvalidatesByGroup(t *testing.T) {
	account := Account{
		ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth,
		Credentials: map[string]any{"model_mapping": map[string]any{"public": "upstream"}},
	}
	account.SetUpstreamModelMetadataSnapshot(UpstreamModelMetadataSnapshot{
		Models: map[string]UpstreamModelMetadata{"upstream": {ContextWindow: 900_000}},
	})
	repo := &anthropicLongContextCacheRepo{accounts: []Account{account}}
	svc := &GatewayService{
		accountRepo: repo, modelsListCache: gocache.New(time.Minute, time.Minute),
		modelsListCacheTTL: time.Minute,
	}
	group := &Group{ID: 314, Platform: PlatformAnthropic}
	id := group.ID
	first := svc.ExpandAnthropicLongContextModels(context.Background(), group, []string{"public"})
	require.Equal(t, []string{"public", "public[1m]"}, first)
	first[1] = "mutated"
	require.Equal(t, []string{"public", "public[1m]"},
		svc.ExpandAnthropicLongContextModels(context.Background(), group, []string{"public"}),
		"cache results must be cloned")
	require.Equal(t, 1, repo.calls)

	group.ModelRoutingEnabled = true
	group.ModelRouting = map[string][]int64{"public": {2}}
	require.Equal(t, []string{"public"}, svc.ExpandAnthropicLongContextModels(context.Background(), group, []string{"public"}))
	require.Equal(t, 2, repo.calls, "routing change must change the expansion key")

	svc.InvalidateAvailableModelsCache(&id, PlatformAnthropic)
	group.ModelRouting = nil
	group.ModelRoutingEnabled = false
	require.Equal(t, []string{"public", "public[1m]"},
		svc.ExpandAnthropicLongContextModels(context.Background(), group, []string{"public"}))
	require.Equal(t, 3, repo.calls, "invalidating base models must also evict long-context variants")
}

func TestAnthropicLongContextCacheTTLIsBoundedAcrossReplicas(t *testing.T) {
	require.Equal(t, 5*time.Second, anthropicLongContextCacheTTL(0))
	require.Equal(t, 5*time.Second, anthropicLongContextCacheTTL(time.Minute))
	require.Equal(t, 2*time.Second, anthropicLongContextCacheTTL(2*time.Second))
}
