package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func DecodeGatewayAccountModelsInput(raw []byte) (service.GatewayAccountModelsInput, bool) {
	var in service.GatewayAccountModelsInput
	fields, ok := service.GatewayNativePayloadFields(raw, "ownerRef", "accountRef", "profileId", "expectedAuthorizationEpoch", "forceRefresh")
	if !ok || len(raw) > 4096 || len(fields) < 4 || len(fields) > 5 {
		return in, false
	}
	for _, name := range []string{"ownerRef", "accountRef", "profileId", "expectedAuthorizationEpoch"} {
		if len(fields[name]) == 0 || string(fields[name]) == "null" {
			return in, false
		}
	}
	for name := range fields {
		switch name {
		case "ownerRef", "accountRef", "profileId", "expectedAuthorizationEpoch", "forceRefresh":
		default:
			return in, false
		}
	}
	if value := fields["forceRefresh"]; value != nil && string(value) != "true" && string(value) != "false" {
		return in, false
	}
	if json.Unmarshal(raw, &in) != nil || !in.Valid() {
		return in, false
	}
	return in, true
}
func RegisterGatewayAccountModelsRoutes(group *gin.RouterGroup, reader *service.GatewayAccountModelsReader, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || reader == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	group.POST("/private/native/v1/account-models/read", authorize, func(c *gin.Context) {
		c.Header("Cache-Control", "private, no-store")
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
		in, ok := DecodeGatewayAccountModelsInput(raw)
		if err != nil || !ok {
			c.JSON(http.StatusBadRequest, gin.H{"code": "account_models_unavailable"})
			return
		}
		c.JSON(http.StatusOK, reader.Read(c.Request.Context(), in))
	})
	return nil
}
