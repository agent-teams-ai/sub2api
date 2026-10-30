//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func captureGatewayAdmissionDiagnostic(t *testing.T, run func()) []byte {
	t.Helper()
	stderr, err := os.CreateTemp(t.TempDir(), "admission-diagnostic-*")
	require.NoError(t, err)
	original := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = original; _ = stderr.Close() }()
	run()
	require.NoError(t, stderr.Sync())
	_, err = stderr.Seek(0, 0)
	require.NoError(t, err)
	raw, err := io.ReadAll(stderr)
	require.NoError(t, err)
	return raw
}

func TestGatewayNativeAdmissionDiagnosticClosedVocabulary(t *testing.T) {
	phases := []string{"admission_payload", "admission_input", "admission_tools", "admission_mapping", "admission_descriptor", "admission_credential", "admission_lifetime", "admission_catalog_unavailable", "admission_catalog_expired", "admission_catalog_policy", "admission_dispatch_target", "admission_account_lock", "admission_account_changed", "admission_replay", "admission_runtime"}
	raw := captureGatewayAdmissionDiagnostic(t, func() {
		gatewayNativeAdmissionDiagnostic(0)
		for phase := gatewayAdmissionPayload; phase <= gatewayAdmissionRuntime; phase++ {
			gatewayNativeAdmissionDiagnostic(phase)
		}
		gatewayNativeAdmissionDiagnostic(255)
	})
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	require.Len(t, lines, len(phases))
	for i, line := range lines {
		var row map[string]any
		require.NoError(t, json.Unmarshal(line, &row))
		require.Equal(t, map[string]any{"event": "gateway_native_response_failure", "phase": phases[i]}, row)
	}
}

func TestGatewayNativeAdmissionCatalogDiagnosticPreservesRefusal(t *testing.T) {
	models := []GatewayAccountModel{}
	cases := []struct {
		name   string
		result GatewayAccountModelsResult
		phase  string
	}{
		{"unavailable", GatewayAccountModelsResult{Status: "unavailable"}, "admission_catalog_unavailable"},
		{"wrong source", GatewayAccountModelsResult{Status: "snapshot", Source: "PRIVATE-source", Models: &models}, "admission_catalog_unavailable"},
		{"expired", GatewayAccountModelsResult{Status: "snapshot", Source: "openrouter", Models: &models, ExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339Nano)}, "admission_catalog_expired"},
		{"malformed expiry", GatewayAccountModelsResult{Status: "snapshot", Source: "openrouter", Models: &models, ExpiresAt: "PRIVATE-secret"}, "admission_catalog_expired"},
		{"no membership", GatewayAccountModelsResult{Status: "snapshot", Source: "openrouter", Models: &models, ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}, "admission_catalog_policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := captureGatewayAdmissionDiagnostic(t, func() { gatewayNativeCatalogAdmissionDiagnostic(tc.result) })
			require.JSONEq(t, `{"event":"gateway_native_response_failure","phase":"`+tc.phase+`"}`, string(raw))
			require.NotContains(t, string(raw), "PRIVATE")
			require.False(t, gatewayOpenRouterModelsAllow(tc.result, GatewayOpenRouterNanoModel, "vendor/not-a-member", []byte(`{"model":"vendor/not-a-member","input":"PRIVATE-prompt"}`)))
		})
	}
}

func TestGatewayNativeAdmissionPayloadRefusalsRemainBeforeEntry(t *testing.T) {
	cases := []struct{ name, payload, phase string }{
		{"unknown field", `{"model":"openai/gpt-4.1","input":"PRIVATE-prompt","secret_extra":"PRIVATE-key"}`, "admission_payload"},
		{"image input", `{"model":"openai/gpt-4.1","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://PRIVATE.invalid"}]}]}`, "admission_input"},
		{"server tool", `{"model":"openai/gpt-4.1","input":"PRIVATE-prompt","tools":[{"type":"web_search","name":"PRIVATE-tool"}]}`, "admission_tools"},
		{"oversized", strings.Repeat("PRIVATE", (4<<20)/7+1), "admission_payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{}}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(tc.payload))
			route := GatewayNativeRoute{Profile: GatewayOpenRouterResponsesProfile, BaseURL: GatewayOpenRouterBaseURL, Model: GatewayOpenRouterNanoModel}
			raw := captureGatewayAdmissionDiagnostic(t, func() {
				_, entered, err := service.ForwardGatewayRoute(context.Background(), c, route, []byte(tc.payload))
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
			})
			require.JSONEq(t, `{"event":"gateway_native_response_failure","phase":"`+tc.phase+`"}`, string(raw))
			require.NotContains(t, string(raw), "PRIVATE")
			require.Empty(t, recorder.Body.String())
		})
	}
}
