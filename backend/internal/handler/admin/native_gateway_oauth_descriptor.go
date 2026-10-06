package admin

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Explicit private sanitized composition only. authorize binds the typed control
// consumer and owner from live server policy; stock admin never registers this.
// This does not create a listener or the local1455 callback bridge.
func RegisterGatewayNativeOAuthDescriptorRoute(group *gin.RouterGroup, dispatch *service.GatewayNativeOAuthDispatch, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || dispatch == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.POST("/private/native/v1/oauth/connect/descriptor", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		fail := func() { c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"code": "native_descriptor_unavailable"}) }
		var input gatewayConnectInput
		if !gatewayConnectDecode(c, &input) {
			fail()
			return
		}
		consumer, err := service.GatewayNativeConsumer(c.Request.Context())
		if err != nil {
			fail()
			return
		}
		scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: input.Owner, Account: input.Account, Generation: input.Generation, Purpose: service.GatewayOAuthBundlePurpose}
		out, err := dispatch.Descriptor(c.Request.Context(), scope, input.Operation)
		if err != nil {
			fail()
			return
		}
		c.JSON(http.StatusOK, out)
	})
	return nil
}
