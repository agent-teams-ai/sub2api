//go:build unit

package repository

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// Main supplies a NEW disposable loopback Redis instance, never a shared cache.
// Refuse a nonempty DB and remote address; no credentials or FLUSHDB are used.
func TestGatewayNativeReviewReasoningRealRedis(t *testing.T) {
	addr := os.Getenv("GATEWAY_NATIVE_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOT_RUN: dedicated Redis address not supplied")
	}
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.True(t, host == "127.0.0.1" || host == "::1", "only a disposable loopback Redis is allowed")
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	count, err := client.DBSize(context.Background()).Result()
	require.NoError(t, err)
	require.Zero(t, count, "dedicated Redis must start empty")
	nativeReviewReasoningDomains(t, NewGatewayCache(client))
}
