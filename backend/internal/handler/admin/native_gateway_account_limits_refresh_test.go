//go:build unit

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayAccountLimitsRefreshPrivateHTTPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// A non-provider profile exercises the real handler/service boundary without
	// granting a credential or introducing a test-only provider implementation.
	refresher, err := service.NewGatewayAccountLimitsRefresher(&service.GatewayNativeOAuthDispatch{}, &cachedLimitsHandlerStore{}, func(context.Context, service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		return service.GatewayNativeRoute{}, nil
	})
	require.NoError(t, err)
	router := gin.New()
	require.NoError(t, RegisterGatewayAccountLimitsRefreshRoutes(router.Group(""), refresher, func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer fixture-control" {
			c.AbortWithStatus(http.StatusForbidden)
		}
	}))
	request := func(method, path, body, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	caps := "/private/native/v1/account-limits/refresh-capabilities"
	refresh := "/private/native/v1/account-limits/refresh"
	require.Equal(t, http.StatusForbidden, request("GET", caps, "", "").Code)
	out := request("GET", caps, "", "Bearer fixture-control")
	require.Equal(t, http.StatusOK, out.Code)
	require.JSONEq(t, `{"contract":"account-limits-refresh/v1","quotaOnlyRefresh":true,"profileIds":["openai-codex-oauth-responses-v1"]}`, out.Body.String())
	require.Equal(t, "private, no-store", out.Header().Get("Cache-Control"))
	input, _ := json.Marshal(service.GatewayAccountLimitsInput{OwnerRef: "owner", AccountRef: "account", ProfileID: service.GatewayClaudeOAuthMessagesProfile, ExpectedAuthorizationEpoch: 1})
	require.Equal(t, http.StatusForbidden, request("POST", refresh, string(input), "").Code)
	for _, bad := range []string{`{}`, string(input[:len(input)-1]) + `,"nativeAccountId":1}`, strings.Repeat(" ", 4097)} {
		require.Equal(t, http.StatusBadRequest, request("POST", refresh, bad, "Bearer fixture-control").Code)
	}
	out = request("POST", refresh, string(input), "Bearer fixture-control")
	require.Equal(t, http.StatusOK, out.Code)
	require.JSONEq(t, `{"status":"unsupported"}`, out.Body.String())
	require.Equal(t, http.StatusNotFound, request("GET", refresh, "", "Bearer fixture-control").Code)
}
