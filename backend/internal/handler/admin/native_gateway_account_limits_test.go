package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type cachedLimitsHandlerStore struct{ reads, writes int }

func (s *cachedLimitsHandlerStore) ReadGatewayAccountLimits(context.Context, service.GatewayAccountLimitsInput, service.GatewayNativeRoute) (service.GatewayAccountLimitsStored, error) {
	s.reads++
	return service.GatewayAccountLimitsStored{PrincipalVersion: "fixture"}, nil
}
func (s *cachedLimitsHandlerStore) StoreGatewayAccountLimits(context.Context, service.GatewayNativeOAuthPhysical, service.GatewayCodexRawLimits, time.Time) error {
	s.writes++
	return nil
}

// Verifies the actual opt-in private HTTP boundary. It rejects raw numeric IDs,
// ambiguous members and bad epoch types before even invoking the reader.
func TestGatewayAccountLimitsPrivateHTTPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &cachedLimitsHandlerStore{}
	authorizations := 0
	route := service.GatewayNativeRoute{AccountID: 1, Generation: "00000000-0000-4000-8000-000000000001", CreatedAt: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}
	reader, err := service.NewGatewayAccountLimitsReader(store, func(context.Context, service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		authorizations++
		return route, nil
	})
	require.NoError(t, err)
	router := gin.New()
	require.NoError(t, RegisterGatewayAccountLimitsRoutes(router.Group(""), reader, func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer fixture-control" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), "fixture-consumer")
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}))
	request := func(method, path, body, authorization string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", authorization)
		router.ServeHTTP(rec, req)
		return rec
	}
	input := `{"ownerRef":"fixture-owner","accountRef":"fixture-account","profileId":"openai-codex-oauth-responses-v1","expectedAuthorizationEpoch":3}`
	require.Equal(t, http.StatusForbidden, request("POST", "/private/native/v1/account-limits/read", input, "").Code)
	require.Zero(t, authorizations)
	require.Zero(t, store.reads)
	for _, body := range []string{
		input[:len(input)-1] + `,"nativeAccountId":1}`,
		input[:len(input)-1] + `,"ownerRef":"replacement"}`,
		input[:len(input)-1] + `,"OwnerRef":"replacement"}`,
		`{"ownerRef":"fixture-owner","accountRef":"fixture-account","profileId":"openai-codex-oauth-responses-v1","expectedAuthorizationEpoch":null}`,
		`{"ownerRef":"fixture-owner","accountRef":"fixture-account","profileId":"openai-codex-oauth-responses-v1","expectedAuthorizationEpoch":9007199254740992}`,
		`{"ownerRef":"fixture-owner","accountRef":"fixture-account","profileId":"openai-codex-oauth-responses-v1","expectedAuthorizationEpoch":1.5}`,
		input + `{}`,
	} {
		require.Equal(t, http.StatusBadRequest, request("POST", "/private/native/v1/account-limits/read", body, "Bearer fixture-control").Code)
	}
	require.Zero(t, authorizations)
	require.Zero(t, store.reads)
	out := request("POST", "/private/native/v1/account-limits/read", input, "Bearer fixture-control")
	require.Equal(t, http.StatusOK, out.Code)
	require.JSONEq(t, `{"status":"unknown"}`, out.Body.String())
	require.Equal(t, "private, no-store", out.Header().Get("Cache-Control"))
	require.Equal(t, 2, store.reads)
	require.Zero(t, store.writes)
	cap := request("GET", "/private/native/v1/account-limits/capabilities", "", "Bearer fixture-control")
	var capabilities service.GatewayAccountLimitsCapabilities
	require.NoError(t, json.Unmarshal(cap.Body.Bytes(), &capabilities))
	require.Equal(t, service.GatewayAccountLimitsCapabilities{Contract: "account-limits/v1", CachedRead: true, QuotaOnlyRefresh: false}, capabilities)
	require.Equal(t, http.StatusNotFound, request("GET", "/admin/accounts/1/limits", "", "Bearer fixture-control").Code)
}
