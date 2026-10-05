package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type gatewayConnectInput struct {
	Operation  string `json:"operation"`
	Owner      string `json:"owner_ref"`
	Account    string `json:"account_ref"`
	Generation string `json:"generation"`
}

// Opt-in private root group ONLY, on a sanitized server with no body/query/error/
// access diagnostic middleware. authorize MUST bind both typed consumer AND
// WithGatewayNativeOAuthOwner from live server authorization, never stock admin.
// Callback bypasses authorize: its one-use state only acts on its persisted
// owner intent. Mount/loopback operator forwarding or code handoff is pending;
// this registration creates no listener, callback-port bridge, login or dispatch.
func RegisterGatewayNativeOAuthConnectRoutes(group *gin.RouterGroup, connect *service.GatewayNativeOAuthConnect, authorize gin.HandlerFunc) error {
	if group == nil || group.BasePath() != "/" || connect == nil || authorize == nil {
		return service.ErrGatewayNativeIdentity
	}
	fail := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"code": "native_connect_unavailable"})
	}
	control := group.Group("/private/native/v1/oauth", authorize)
	control.POST("/connect", func(c *gin.Context) {
		var req gatewayConnectInput
		if !gatewayConnectDecode(c, &req) {
			fail(c)
			return
		}
		consumer, err := service.GatewayNativeConsumer(c.Request.Context())
		if err != nil {
			fail(c)
			return
		}
		scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: req.Owner, Account: req.Account, Generation: req.Generation, Purpose: service.GatewayOAuthBundlePurpose}
		out, err := connect.BeginConnect(c.Request.Context(), scope, req.Operation)
		if err != nil {
			fail(c)
			return
		}
		c.JSON(http.StatusOK, out)
	})
	control.POST("/connect/read", func(c *gin.Context) {
		var req gatewayConnectInput
		if !gatewayConnectDecode(c, &req) {
			fail(c)
			return
		}
		consumer, err := service.GatewayNativeConsumer(c.Request.Context())
		if err != nil {
			fail(c)
			return
		}
		scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: req.Owner, Account: req.Account, Generation: req.Generation, Purpose: service.GatewayOAuthBundlePurpose}
		out, err := connect.ReadConnect(c.Request.Context(), scope, req.Operation)
		if err != nil {
			fail(c)
			return
		}
		c.JSON(http.StatusOK, out)
	})
	group.GET("/auth/callback", func(c *gin.Context) {
		// Scrub before handler diagnostics; outer server MUST already exclude
		// access logging (Gin Logger snapshots query before calling this handler).
		query := c.Request.URL.RawQuery
		c.Request.URL.RawQuery = ""
		c.Request.RequestURI = "/auth/callback"
		c.Header("Cache-Control", "no-store")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		values := url.Values{}
		var err error
		if len(query) <= 8192 {
			values, err = url.ParseQuery(query)
		}
		if len(query) <= 8192 && err == nil && len(values) == 2 && len(values["state"]) == 1 && len(values["code"]) == 1 &&
			c.Request.ContentLength == 0 && len(c.Request.TransferEncoding) == 0 {
			_, _ = connect.CompleteCallback(c.Request.Context(), values.Get("state"), values.Get("code"))
		}
		// Identical response for every callback: no claims, operation, vendor
		// errors, code, state or query reflection. Owner reads the protected op.
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<!doctype html><title>Connect received</title><p>Return to the account owner application to read the connect result.</p>"))
	})
	return nil
}

func gatewayConnectDecode(c *gin.Context, req *gatewayConnectInput) bool {
	c.Header("Cache-Control", "no-store")
	if c.Request.URL.RawQuery != "" {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
	if err != nil || len(raw) > 4096 || !utf8.Valid(raw) {
		return false
	}
	// Exact decoded canonical names, including escaped duplicate/case aliases.
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		name, ok := tok.(string)
		if err != nil || !ok || seen[name] || (name != "operation" && name != "owner_ref" && name != "account_ref" && name != "generation") {
			return false
		}
		seen[name] = true
		var value string
		if d.Decode(&value) != nil || !service.GatewayNativeCredentialRefValid(value) {
			return false
		}
		switch name {
		case "operation":
			req.Operation = value
		case "owner_ref":
			req.Owner = value
		case "account_ref":
			req.Account = value
		case "generation":
			req.Generation = value
		}
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != 4 {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}
