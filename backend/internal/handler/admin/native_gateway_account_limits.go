package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// This private logical read accepts no numeric native IDs, generation or raw
// snapshot selectors. It is opt-in and never mounted on ordinary admin routes.
func DecodeGatewayAccountLimitsInput(raw []byte) (service.GatewayAccountLimitsInput, bool) {
	var in service.GatewayAccountLimitsInput
	fields, ok := service.GatewayNativePayloadFields(raw, "ownerRef", "accountRef", "profileId", "expectedAuthorizationEpoch")
	if !ok || len(raw) > 4096 || len(fields) != 4 {
		return in, false
	}
	for _, key := range []string{"ownerRef", "accountRef", "profileId", "expectedAuthorizationEpoch"} {
		if len(fields[key]) == 0 || string(fields[key]) == "null" {
			return in, false
		}
	}
	if json.Unmarshal(raw, &in) != nil || !in.Valid() {
		return in, false
	}
	return in, true
}
func RegisterGatewayAccountLimitsRoutes(group *gin.RouterGroup, reader *service.GatewayAccountLimitsReader, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || reader == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.GET("/private/native/v1/account-limits/capabilities", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		c.JSON(http.StatusOK, service.GatewayAccountLimitsCapabilities{Contract: service.GatewayAccountLimitsContract, CachedRead: true, QuotaOnlyRefresh: false})
	})
	group.POST("/private/native/v1/account-limits/read", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, valid := DecodeGatewayAccountLimitsInput(data)
		if err != nil || !valid {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_limits_unavailable"})
			return
		}
		c.JSON(http.StatusOK, reader.Read(c.Request.Context(), in))
	})
	group.POST("/private/native/v1/account-admission/read", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, valid := DecodeGatewayAccountLimitsInput(data)
		if err != nil || !valid {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_admission_unavailable"})
			return
		}
		c.JSON(http.StatusOK, reader.ReadAdmission(c.Request.Context(), in))
	})
	return nil
}

// V2 selects the same fenced logical read without changing the strict v1 DTO.
func RegisterGatewayAccountLimitsRoutesV2(group *gin.RouterGroup, reader *service.GatewayAccountLimitsReaderV2, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || reader == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.GET("/private/native/v2/account-limits/capabilities", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		c.JSON(http.StatusOK, service.GatewayAccountLimitsCapabilities{Contract: service.GatewayAccountLimitsContractV2, CachedRead: true, QuotaOnlyRefresh: false})
	})
	group.POST("/private/native/v2/account-limits/read", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, valid := DecodeGatewayAccountLimitsInput(data)
		if err != nil || !valid {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_limits_unavailable"})
			return
		}
		c.JSON(http.StatusOK, reader.Read(c.Request.Context(), in))
	})
	return nil
}
