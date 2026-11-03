package service

import "testing"

func TestGatewayNativeConfirmedProviderQuota(t *testing.T) {
	d := gatewayNativeRateLimitDiagnostic{Headers: map[string]string{"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793750400000"}}
	q := gatewayNativeConfirmedProviderQuota(d)
	if q == nil || q.Limit != 1000 || q.ResetAt != "2026-11-04T00:00:00.000Z" {
		t.Fatalf("unexpected quota %#v", q)
	}
	for _, pair := range [][2]string{{"X-RateLimit-Limit", "0"}, {"X-RateLimit-Limit", "9007199254740992"}, {"X-RateLimit-Remaining", "1"}, {"X-RateLimit-Reset", "garbage"}, {"X-RateLimit-Reset", "1793750400"}} {
		copy := gatewayNativeRateLimitDiagnostic{Headers: map[string]string{}}
		for k, v := range d.Headers {
			copy.Headers[k] = v
		}
		copy.Headers[pair[0]] = pair[1]
		if gatewayNativeConfirmedProviderQuota(copy) != nil {
			t.Fatal("unconfirmed quota accepted")
		}
	}
}
