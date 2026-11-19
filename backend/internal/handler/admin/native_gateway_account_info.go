package admin

import (
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Metadata is read by logical identity only. No administrative account DTO,
// physical selector, credential or source-refresh option is accepted.
func RegisterGatewayAccountInfoRoutes(group *gin.RouterGroup, reader *service.GatewayAccountInfoReader, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || reader == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.POST("/private/native/v1/account-info/read", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, valid := DecodeGatewayAccountLimitsInput(raw)
		if err != nil || !valid {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_info_unavailable"})
			return
		}
		c.JSON(http.StatusOK, reader.Read(c.Request.Context(), in))
	})
	return nil
}
