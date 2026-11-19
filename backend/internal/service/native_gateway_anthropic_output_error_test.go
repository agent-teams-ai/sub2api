//go:build unit

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeAnthropicSchemaUnsupportedFormatStaysClientError(t *testing.T) {
	for _, model := range []string{"claude-sonnet-4-6", "claude-opus-5-5"} {
		t.Run(model, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			body := `{"model":"` + model + `","input":"review","text":{"format":{"type":"json_object"}}}`
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			upstream := &anthropicHTTPUpstreamRecorder{}
			svc := &GatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			account := &Account{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Credentials: map[string]any{"api_key": "fixture-key"}}
			_, err := svc.ForwardAsResponses(context.Background(), c, account, []byte(body), nil)
			require.ErrorIs(t, err, apicompat.ErrResponsesOutputFormat)
			require.Equal(t, http.StatusBadRequest, recorder.Code)
			require.Contains(t, recorder.Body.String(), "invalid_request_error")
			require.Nil(t, upstream.lastReq, "unsupported caller constraint never enters the provider")
		})
	}
}
