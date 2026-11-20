//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// hydrate 失败时，已经占用的并发槽位必须在返回前释放，否则调用方拿不到
// ReleaseFunc，槽位会一直泄漏到 TTL 到期。
func TestGatewayServiceNewSelectionResultReleasesSlotOnHydrationError(t *testing.T) {
	svc := &GatewayService{
		schedulerSnapshot: &SchedulerSnapshotService{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	released := 0
	selection, err := svc.newSelectionResult(ctx, &Account{ID: 42}, true, func() { released++ }, nil)

	require.Error(t, err)
	require.Nil(t, selection)
	require.Equal(t, 1, released)
}

type sessionReleaseRecordingCache struct {
	SessionLimitCache
	calls     int
	accountID int64
	sessionID string
	ctxErr    error
}

func (c *sessionReleaseRecordingCache) UnregisterSession(ctx context.Context, accountID int64, sessionID string) error {
	c.calls++
	c.accountID = accountID
	c.sessionID = sessionID
	c.ctxErr = ctx.Err()
	return nil
}

func TestGatewayServiceNewSelectionResultReleasesSessionOnHydrationError(t *testing.T) {
	cache := &sessionReleaseRecordingCache{}
	svc := &GatewayService{
		schedulerSnapshot: &SchedulerSnapshotService{},
		sessionLimitCache: cache,
	}
	account := &Account{
		ID: 42, Platform: PlatformAnthropic, Type: AccountTypeOAuth,
		Extra: map[string]any{"max_sessions": 1},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	released := 0
	got, err := svc.newSelectionResult(ctx, account, true, func() { released++ }, nil, "session-42")
	require.Error(t, err)
	require.Nil(t, got)
	require.Equal(t, 1, released)
	require.Equal(t, 1, cache.calls)
	require.Equal(t, int64(42), cache.accountID)
	require.Equal(t, "session-42", cache.sessionID)
	require.NoError(t, cache.ctxErr, "session cleanup must survive canceled request context")
}

// hydrate 成功时不能提前释放槽位，ReleaseFunc 应原样交给调用方。
func TestGatewayServiceNewSelectionResultKeepsReleaseOnSuccess(t *testing.T) {
	account := &Account{ID: 42, Platform: PlatformAnthropic}
	cache := &snapshotHydrationCache{
		accounts: map[int64]*Account{account.ID: account},
	}
	svc := &GatewayService{
		schedulerSnapshot: NewSchedulerSnapshotService(cache, nil, nil, nil, nil),
	}

	released := 0
	selection, err := svc.newSelectionResult(context.Background(), account, true, func() { released++ }, nil)

	require.NoError(t, err)
	require.NotNil(t, selection)
	require.Zero(t, released)
	require.NotNil(t, selection.ReleaseFunc)

	selection.ReleaseFunc()
	require.Equal(t, 1, released)
}
