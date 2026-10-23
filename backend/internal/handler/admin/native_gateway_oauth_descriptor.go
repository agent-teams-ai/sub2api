package admin

import (
	"context"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Explicit private sanitized composition only. authorize binds the typed control
// consumer and owner from live server policy; stock admin never registers this.
// This does not create a listener or the local1455 callback bridge.
func RegisterGatewayNativeOAuthDescriptorRoute(group *gin.RouterGroup, dispatch interface {
	Descriptor(context.Context, service.GatewayNativeCredentialScope, string) (service.GatewayNativeOAuthDescriptorResult, error)
}, authorize gin.HandlerFunc, prefix ...string) error {
	if group == nil || group.BasePath() != "/" || dispatch == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	path := "/private/native/v1/oauth"
	if len(prefix) == 1 && (prefix[0] == "/private/native/v1/claude/oauth" || prefix[0] == "/private/native/v1/grok/oauth") {
		path = prefix[0]
	} else if len(prefix) > 0 {
		return service.ErrGatewayNativeIdentity
	}
	group.POST(path+"/connect/descriptor", authorize, func(c *gin.Context) {
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

// Inert readback for the original connect scope. Unlike Descriptor, this route
// performs no JWKS/provider/account-check call and cannot qualify or mutate it.
func RegisterGatewayNativeOAuthRetainedCustodyRoute(group *gin.RouterGroup, dispatch interface {
	RetainedCustody(context.Context, service.GatewayNativeCredentialScope, string, service.GatewayNativeRoute) (service.GatewayNativeRetainedCustodyResult, error)
}, authorize gin.HandlerFunc, prefix ...string) error {
	if group == nil || group.BasePath() != "/" || dispatch == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	path := "/private/native/v1/oauth"
	if len(prefix) == 1 && (prefix[0] == "/private/native/v1/claude/oauth" || prefix[0] == "/private/native/v1/grok/oauth") {
		path = prefix[0]
	} else if len(prefix) > 0 {
		return service.ErrGatewayNativeIdentity
	}
	group.POST(path+"/connect/custody", authorize, func(c *gin.Context) {
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		input, valid := DecodeGatewayNativeOAuthRetainedCustody(raw)
		if err != nil || !valid {
			retainedCustodyWireFailure(c)
			return
		}
		consumer, err := service.GatewayNativeConsumer(c.Request.Context())
		if err != nil {
			retainedCustodyWireFailure(c)
			return
		}
		scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: input.Owner, Account: input.Account,
			Generation: input.Generation, Purpose: service.GatewayOAuthBundlePurpose}
		out, err := dispatch.RetainedCustody(c.Request.Context(), scope, input.Operation, input.Descriptor)
		if err != nil {
			retainedCustodyWireFailure(c)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, out)
	})
	return nil
}
