package service

import (
	"context"
	"strconv"
	"time"
)

// ProviderQuota describes only a confirmed exhausted OpenRouter request quota.
// It supplies user diagnostics while the admitted request retains its unknown effect.
type GatewayNativeProviderQuota struct {
	Limit   int64
	ResetAt string
}
type gatewayNativeProviderQuotaObserverKey struct{}

func WithGatewayNativeProviderQuotaObserver(ctx context.Context, observe func(GatewayNativeProviderQuota)) context.Context {
	return context.WithValue(ctx, gatewayNativeProviderQuotaObserverKey{}, observe)
}

func gatewayNativeConfirmedProviderQuota(d gatewayNativeRateLimitDiagnostic) *GatewayNativeProviderQuota {
	limit, e1 := strconv.ParseInt(d.Headers["X-RateLimit-Limit"], 10, 64)
	reset, e2 := strconv.ParseInt(d.Headers["X-RateLimit-Reset"], 10, 64)
	if e1 != nil || e2 != nil || limit <= 0 || limit > 9007199254740991 || d.Headers["X-RateLimit-Remaining"] != "0" || reset < 946684800000 || reset > 4102444800000 {
		return nil
	}
	return &GatewayNativeProviderQuota{Limit: limit, ResetAt: time.UnixMilli(reset).UTC().Format("2006-01-02T15:04:05.000Z")}
}
