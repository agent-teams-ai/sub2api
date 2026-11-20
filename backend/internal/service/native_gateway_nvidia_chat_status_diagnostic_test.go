//go:build unit

package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// A rejected NVIDIA request used to leave no trace: the bridge answers every
// non-2xx with the same bare 502 and logged nothing. The status now reaches
// the Gateway as the existing http_status phase. The answer to the caller and
// the effect stay exactly as before, and no provider bytes are reported.
func TestGatewayNVIDIABuildChatUpstreamStatusDiagnostic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &Account{
		ID:        18,
		CreatedAt: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
		Platform:  PlatformOpenAI,
		Type:      AccountTypeAPIKey,
		Status:    StatusActive,
		Credentials: map[string]any{
			"api_key":  "nvidia-synthetic-credential",
			"base_url": GatewayNVIDIABuildBaseURL,
		},
		Extra: map[string]any{
			GatewayGenerationExtraKey:              "12345678-1234-4234-8234-123456789abc",
			GatewayProfileExtraKey:                 GatewayNVIDIABuildChatProfile,
			GatewayModelExtraKey:                   GatewayNVIDIABuildAnchorModel,
			"openai_responses_mode":                "force_chat_completions",
			"openai_passthrough":                   false,
			"native_api_key_cancel_on_disconnect":  true,
			"openai_preserve_compatible_reasoning": true,
		},
	}
	nativeFixtureSealAccount(t, a)
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	payload := []byte(`{"model":"` + GatewayNVIDIABuildAnchorModel + `","input":"synthetic only","store":false,"stream":true,"max_output_tokens":128}`)
	type diagnosticCase struct {
		name     string
		upstream *nativeDiagnosticHTTP
		line     string
		// A transport failure returns the sentinel before any byte is written;
		// the native handler turns it into the same bare 502 as before.
		bridgeWrites502 bool
	}
	cases := []diagnosticCase{{
		// A transport failure has no status; only the closed phase is reported.
		name:     "transport",
		upstream: &nativeDiagnosticHTTP{err: errors.New("dial tcp: provider-secret-text")},
		line:     `{"event":"gateway_native_response_failure","phase":"transport"}`,
	}}
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		cases = append(cases, diagnosticCase{
			name: strconv.Itoa(status),
			upstream: &nativeDiagnosticHTTP{response: &http.Response{
				StatusCode: status,
				Header:     http.Header{"Content-Type": []string{"application/json"}, "Retry-After": []string{"7"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"provider-secret-text","type":"synthetic"}}`)),
			}},
			line:            `{"event":"gateway_native_response_failure","phase":"http_status","http_status":` + strconv.Itoa(status) + `}`,
			bridgeWrites502: true,
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := tc.upstream
			svc := &OpenAIGatewayService{
				accountRepo:  &gatewayIdentityRepoFixture{row: a},
				httpUpstream: upstream,
				cfg:          rawChatCompletionsTestConfig(),
			}
			rec := httptest.NewRecorder()
			var entered bool
			var forwardErr error
			raw := captureGatewayAdmissionDiagnostic(t, func() {
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
				_, entered, forwardErr = svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			})
			require.True(t, entered)
			require.ErrorIs(t, forwardErr, ErrGatewayNativeEffectUnknown)
			require.Equal(t, 1, upstream.requests)
			if tc.bridgeWrites502 {
				require.Equal(t, http.StatusBadGateway, rec.Code)
				// The caller's answer is exactly the bare 502 it was before.
				require.JSONEq(t, `{"error":{"type":"native_effect_unknown","message":"native upstream request failed"}}`, rec.Body.String())
			} else {
				require.Empty(t, rec.Body.String())
			}
			require.JSONEq(t, tc.line, string(bytes.TrimSpace(raw)))
			require.NotContains(t, string(raw), "provider-secret-text")
			require.NotContains(t, string(raw), "nvidia-synthetic-credential")
		})
	}
}
