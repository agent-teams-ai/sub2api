package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
)

func RegisterGatewayAccountLimitsRefreshRoutes(group *gin.RouterGroup, refresher *service.GatewayAccountLimitsRefresher, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || refresher == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.GET("/private/native/v1/account-limits/refresh-capabilities", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		c.JSON(http.StatusOK, service.GatewayAccountLimitsRefreshCapabilities{Contract: service.GatewayAccountLimitsRefreshContract, QuotaOnlyRefresh: true, ProfileIDs: []string{service.GatewayCodexOAuthResponsesProfile}})
	})
	group.POST("/private/native/v1/account-limits/refresh", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, ok := DecodeGatewayAccountLimitsInput(raw)
		if err != nil || !ok {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_limits_unavailable"})
			return
		}
		c.JSON(http.StatusOK, refresher.Refresh(c.Request.Context(), in))
	})
	return nil
}
