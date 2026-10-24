package admin

import (
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
)

// Grok's browser flow hands its bounded code/state to the already-authorized
// owner completion endpoint. There is no public callback, device grant or poll.
func RegisterGatewayNativeGrokOAuthRoutes(group *gin.RouterGroup, grok *service.GatewayNativeGrokOAuth, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || grok == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	control := group.Group("/private/native/v1/grok/oauth", authorize)
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
				in, valid := DecodeGatewayNativeGrokConnectCompletion(raw)
				if e != nil || !valid || c.Request.URL.RawQuery != "" {
					fail()
					return
				}
				scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.Owner, Account: in.Account, Generation: in.Generation, Purpose: service.GatewayOAuthBundlePurpose}
				if in.AuthorizationCode != "" {
					out, err = grok.CompleteOwnerCode(c.Request.Context(), scope, in.Operation, in.AuthorizationCode)
				} else {
					out, err = grok.CompleteOwnerCallback(c.Request.Context(), scope, in.Operation, in.State, in.Code)
				}
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
					out, err = grok.BeginConnectMethod(c.Request.Context(), scope, in.Operation, method)
				} else {
					out, err = grok.ReadConnect(c.Request.Context(), scope, in.Operation)
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

// The alternate exact shape is private to Grok. Other OAuth routes retain the
// original mandatory-state decoder and cannot select this code-only handoff.
type GatewayNativeGrokConnectCompletionInput struct {
	GatewayNativeOAuthConnectCompletionInput
	AuthorizationCode string
}

func DecodeGatewayNativeGrokConnectCompletion(raw []byte) (GatewayNativeGrokConnectCompletionInput, bool) {
	var out GatewayNativeGrokConnectCompletionInput
	if len(raw) > GatewayNativeOAuthConnectCompletionBodyLimit {
		return out, false
	}
	fields, valid := service.GatewayNativeGrokCompletionFields(raw)
	if !valid {
		return out, false
	}
	if len(fields) == 6 && fields["authorizationCode"] == nil {
		old, ok := DecodeGatewayNativeOAuthConnectCompletion(raw)
		out.GatewayNativeOAuthConnectCompletionInput = old
		return out, ok
	}
	if len(fields) != 5 {
		return out, false
	}
	for name, raw := range fields {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return GatewayNativeGrokConnectCompletionInput{}, false
		}
		switch name {
		case "operation":
			out.Operation = value
		case "owner_ref":
			out.Owner = value
		case "account_ref":
			out.Account = value
		case "generation":
			out.Generation = value
		case "authorizationCode":
			out.AuthorizationCode = value
		default:
			return GatewayNativeGrokConnectCompletionInput{}, false
		}
	}
	return out, service.GatewayNativeCredentialRefValid(out.Operation) && service.GatewayNativeCredentialRefValid(out.Owner) && service.GatewayNativeCredentialRefValid(out.Account) && service.GatewayNativeCredentialRefValid(out.Generation) && service.GatewayNativeGrokAuthorizationCodeValid(out.AuthorizationCode)
}
