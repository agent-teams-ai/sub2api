package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
)

// Claude's browser flow hands its bounded code/state to the already-authorized
// owner completion endpoint. There is no public callback, device grant or poll.
func RegisterGatewayNativeClaudeOAuthRoutes(group *gin.RouterGroup, claude *service.GatewayNativeClaudeOAuth, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || claude == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	control := group.Group("/private/native/v1/claude/oauth", authorize)
	for _, action := range []string{"connect", "connect/read", "connect/complete"} {
		action := action
		control.POST("/"+action, func(c *gin.Context) {
			c.Header("Cache-Control", "no-store")
			fail := func() { c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"code": "native_connect_unavailable"}) }
			consumer, err := service.GatewayNativeConsumer(c.Request.Context())
			if err != nil {
				fail()
				return
			}
			var out service.GatewayNativeOAuthConnectResult
			if action == "connect/complete" {
				raw, e := io.ReadAll(io.LimitReader(c.Request.Body, GatewayNativeOAuthConnectCompletionBodyLimit+1))
				in, valid := DecodeGatewayNativeOAuthConnectCompletion(raw)
				if e != nil || !valid || c.Request.URL.RawQuery != "" {
					fail()
					return
				}
				scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.Owner, Account: in.Account, Generation: in.Generation, Purpose: service.GatewayOAuthBundlePurpose}
				out, err = claude.CompleteOwnerCallback(c.Request.Context(), scope, in.Operation, in.State, in.Code)
			} else {
				var in gatewayConnectInput
				if !gatewayConnectDecode(c, &in, action == "connect") {
					fail()
					return
				}
				scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.Owner, Account: in.Account, Generation: in.Generation, Purpose: service.GatewayOAuthBundlePurpose}
				if action == "connect" {
					method := in.Method
					if method == "" {
						method = "browser"
					}
					out, err = claude.BeginConnectMethod(c.Request.Context(), scope, in.Operation, method)
				} else {
					out, err = claude.ReadConnect(c.Request.Context(), scope, in.Operation)
				}
			}
			if err != nil {
				fail()
				return
			}
			c.JSON(http.StatusOK, out)
		})
	}
	return nil
}
