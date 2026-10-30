package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// OAuth retained custody needs the original operation selector in addition to
// the immutable owner/account/generation scope and exact qualified descriptor.
type GatewayNativeOAuthRetainedCustodyInput struct {
	Contract   string                     `json:"contract"`
	Operation  string                     `json:"operation"`
	Owner      string                     `json:"owner_ref"`
	Account    string                     `json:"account_ref"`
	Generation string                     `json:"generation"`
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
}

func decodeNativeRetainedCustody(c *gin.Context, target any) error {
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
	if err != nil || len(raw) > 4096 || !utf8.Valid(raw) || !nativeGatewayCanonicalIngress(raw) {
		return service.ErrGatewayNativeIdentity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return service.ErrGatewayNativeIdentity
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

// Strict canonical bounded decoder shared by the private authorization and
// handler. It never reflects submitted values and accepts exactly one object.
func DecodeGatewayNativeOAuthRetainedCustody(raw []byte) (GatewayNativeOAuthRetainedCustodyInput, bool) {
	var out GatewayNativeOAuthRetainedCustodyInput
	if len(raw) > 4096 || !utf8.Valid(raw) || !nativeGatewayCanonicalIngress(raw) {
		return out, false
	}
	if decodeNativeRetainedCustodyBytes(raw, &out) != nil || out.Contract != service.GatewayNativeRetainedCustodyContract ||
		!service.GatewayNativeCredentialRefValid(out.Operation) || !service.GatewayNativeCredentialRefValid(out.Owner) ||
		!service.GatewayNativeCredentialRefValid(out.Account) || !service.GatewayNativeCredentialRefValid(out.Generation) ||
		out.Descriptor.Generation != out.Generation {
		return out, false
	}
	return out, true
}

func decodeNativeRetainedCustodyBytes(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return service.ErrGatewayNativeIdentity
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

func retainedCustodyWireFailure(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"code": "native_retained_custody_unavailable"})
}
