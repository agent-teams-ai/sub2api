package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestGatewayNativeRateLimitEvidence(t *testing.T) {
	headers := http.Header{"Retry-After": {"60"}, "X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"secret-value"}, "Authorization": {"Bearer secret"}}
	d := gatewayNativeRateLimitEvidence(strings.NewReader(`{"error":{"message":"secret prompt","metadata":{"limit_source":"upstream_provider_shared_pool","raw":"secret"}}}`), headers)
	if d.Source != "upstream_provider_shared_pool" || d.Headers["Retry-After"] != "60" || len(d.Headers) != 2 {
		t.Fatalf("unexpected safe evidence: %#v", d)
	}
	raw, _ := json.Marshal(d)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "prompt") {
		t.Fatal("unsafe content exported")
	}
}

func TestGatewayNativeRateLimitEvidenceRejectsUntrustedValues(t *testing.T) {
	for _, body := range []string{`{"error":{"metadata":{"limit_source":"arbitrary-secret"}}}`, `{"error":`, strings.Repeat("x", 16385)} {
		d := gatewayNativeRateLimitEvidence(strings.NewReader(body), http.Header{"Retry-After": {"1", "2"}})
		if d.Source != "" || len(d.Headers) != 0 {
			t.Fatal("untrusted diagnostics accepted")
		}
	}
	d := gatewayNativeRateLimitEvidence(strings.NewReader(`{"error":{"metadata":{"limit_source":"upstream_provider_shared_pool"}}}`), http.Header{"Content-Encoding": {"gzip"}, "Retry-After": {"30"}})
	if d.Source != "" || d.Headers["Retry-After"] != "30" {
		t.Fatal("encoded body should retain only safe headers")
	}
}
