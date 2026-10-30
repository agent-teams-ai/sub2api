//go:build linux

package gatewaybootstrap

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Public inference uses one request per connection so SDK pools cannot race the
// server's bounded idle timeout. Private control keeps its independent reuse.
func newPublicHTTPServer(ctx context.Context, handler http.Handler) *http.Server {
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16384,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	server.SetKeepAlivesEnabled(false)
	return server
}

func privateHandler(profile ProfileConfig, adminSvc service.AdminService, gateway *service.OpenAIGatewayService, custody *service.GatewayNativeCredentialCustody,
	transport *gatewaytransport.Handler, auth func(*http.Request) (gatewaytransport.Peer, error), oauthMode ...*privateOAuth) http.Handler {
	var oauth *privateOAuth
	if len(oauthMode) == 1 {
		oauth = oauthMode[0]
	}
	router := gin.New()
	authorizeCandidate := func(c *gin.Context) {
		peer, err := auth(c.Request)
		if err != nil || peer.Role != "management" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), peer.ConsumerID)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Request = c.Request.WithContext(service.WithGatewayNativeCustody(ctx, custody))
		c.Next()
	}
	secondary, hasOpenRouter := transport.OpenRouterProfile()
	var second []admin.GatewayNativeProfile
	if hasOpenRouter {
		second = []admin.GatewayNativeProfile{{ID: secondary.Profile, BaseURL: secondary.BaseURL, Model: secondary.Model}}
	}
	for _, p := range transport.CodingPlanProfiles() {
		second = append(second, admin.GatewayNativeProfile{ID: p.Profile, BaseURL: p.BaseURL, Model: p.Model})
	}
	admin.RegisterGatewayNativeRoutes(router.Group(""), adminSvc, gateway,
		admin.GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: profile.BaseURL, Model: profile.Model}, authorizeCandidate,
		func(*gin.Context, service.GatewayNativeRoute) error { return ErrDenied }, func(*gin.Context, bool, error) {}, custody, second...)
	if oauth != nil && oauth.models != nil {
		if admin.RegisterGatewayAccountModelsRoutes(router.Group(""), oauth.models, authorizeCandidate) != nil {
			panic("invalid private account models composition")
		}
	}
	if oauth != nil && oauth.limits != nil {
		if admin.RegisterGatewayAccountLimitsRoutes(router.Group(""), oauth.limits, authorizeCandidate) != nil {
			panic("invalid private account limits composition")
		}
	}
	if oauth != nil && oauth.limitsV2 != nil {
		if admin.RegisterGatewayAccountLimitsRoutesV2(router.Group(""), oauth.limitsV2, authorizeCandidate) != nil {
			panic("invalid private limits v2 composition")
		}
	}
	if oauth != nil {
		authorizeOAuth := func(c *gin.Context) {
			peer, err := auth(c.Request)
			if err != nil || peer.Role != "management" || oauth.owners == nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			bounded, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()
			path := strings.Replace(c.Request.URL.Path, "/private/native/v1/claude/oauth", "/private/native/v1/oauth", 1)
			path = strings.Replace(path, "/private/native/v1/grok/oauth", "/private/native/v1/oauth", 1)
			completion := path == "/private/native/v1/oauth/connect/complete"
			bodyLimit := 4096
			if completion {
				bodyLimit = admin.GatewayNativeOAuthConnectCompletionBodyLimit
			}
			data, err := io.ReadAll(io.LimitReader(c.Request.Body, int64(bodyLimit+1)))
			var tuple nativeOAuthOwnerTuple
			valid := false
			if completion {
				if c.Request.URL.Path == "/private/native/v1/grok/oauth/connect/complete" {
					req, ok := admin.DecodeGatewayNativeGrokConnectCompletion(data)
					tuple = nativeOAuthOwnerTuple{req.Operation, req.Owner, req.Account, req.Generation}
					valid = ok
				} else {
					req, ok := admin.DecodeGatewayNativeOAuthConnectCompletion(data)
					tuple = nativeOAuthOwnerTuple{req.Operation, req.Owner, req.Account, req.Generation}
					valid = ok
				}
			} else if path == "/private/native/v1/oauth/connect" {
				var req struct {
					Operation  string `json:"operation"`
					OwnerRef   string `json:"owner_ref"`
					AccountRef string `json:"account_ref"`
					Generation string `json:"generation"`
					Method     string `json:"method,omitempty"`
				}
				valid = decodeStrict(data, &req) == nil && (req.Method == "" || req.Method == "browser" || req.Method == "device_code")
				tuple = nativeOAuthOwnerTuple{req.Operation, req.OwnerRef, req.AccountRef, req.Generation}
			} else if path == "/private/native/v1/oauth/connect/custody" {
				req, ok := admin.DecodeGatewayNativeOAuthRetainedCustody(data)
				tuple = nativeOAuthOwnerTuple{req.Operation, req.Owner, req.Account, req.Generation}
				valid = ok
			} else {
				valid = decodeStrict(data, &tuple) == nil
			}
			if err != nil || len(data) > bodyLimit || !valid || !tuple.valid() {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(data))
			var owner string
			switch path {
			case "/private/native/v1/oauth/refresh":
				owner, err = oauth.owners.AuthorizeNativeOAuthRefreshOwner(bounded, peer.ConsumerID, tuple.Operation, tuple.AccountRef, tuple.Generation)
			case "/private/native/v1/oauth/connect/custody":
				custodyOwners, ok := oauth.owners.(NativeOAuthCustodyAuthority)
				if !ok {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
				owner, err = custodyOwners.AuthorizeNativeOAuthCustodyOwner(bounded, peer.ConsumerID, tuple.Operation, tuple.AccountRef, tuple.Generation)
			default:
				owner, err = oauth.owners.AuthorizeNativeOAuthOwner(bounded, peer.ConsumerID, tuple.Operation, tuple.AccountRef, tuple.Generation)
			}
			if err != nil || bounded.Err() != nil || owner != tuple.OwnerRef {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), peer.ConsumerID)
			if err == nil {
				ctx, err = service.WithGatewayNativeOAuthOwner(ctx, owner)
			}
			if err != nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Request = c.Request.WithContext(ctx)
			c.Next()
		}
		authorizeCleanup := func(c *gin.Context) {
			peer, err := auth(c.Request)
			if err != nil || peer.Role != "cleanup" || oauth.cleanup == nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
			var tuple struct {
				Operation    string `json:"operation"`
				OwnerRef     string `json:"owner_ref"`
				AccountRef   string `json:"account_ref"`
				Generation   string `json:"generation"`
				Action       string `json:"action"`
				CleanupRef   string `json:"cleanup_ref"`
				CleanupToken string `json:"cleanup_token"`
			}
			if err != nil || len(data) > 4096 || decodeStrict(data, &tuple) != nil || !(nativeOAuthOwnerTuple{tuple.Operation, tuple.OwnerRef, tuple.AccountRef, tuple.Generation}).valid() {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			in := service.GatewayNativeOAuthCleanupRequest{Scope: service.GatewayNativeCredentialScope{Consumer: peer.ConsumerID, Owner: tuple.OwnerRef, Account: tuple.AccountRef, Generation: tuple.Generation, Purpose: service.GatewayOAuthBundlePurpose}, Operation: tuple.Operation, Action: tuple.Action, CleanupRef: tuple.CleanupRef, CleanupToken: tuple.CleanupToken}
			grant, err := oauth.cleanup(c.Request.Context(), in)
			if err != nil || grant.Owner != tuple.OwnerRef {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), peer.ConsumerID)
			if err == nil {
				ctx, err = service.WithGatewayNativeOAuthOwner(ctx, grant.Owner)
			}
			if err != nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Request = c.Request.WithContext(ctx)
			c.Request.Body = io.NopCloser(bytes.NewReader(data))
			c.Next()
		}
		if oauth.connect != nil && oauth.cleanup != nil && admin.RegisterGatewayNativeOAuthCleanupRoute(router.Group(""), oauth.connect, authorizeCleanup, oauth.cleanup) != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
			})
		}
		if oauth.connect != nil && (admin.RegisterGatewayNativeOAuthConnectRoutes(router.Group(""), oauth.connect, authorizeOAuth) != nil ||
			admin.RegisterGatewayNativeOAuthDescriptorRoute(router.Group(""), oauth.dispatch, authorizeOAuth) != nil ||
			admin.RegisterGatewayNativeOAuthRetainedCustodyRoute(router.Group(""), oauth.dispatch, authorizeOAuth) != nil ||
			(oauth.refresh != nil && admin.RegisterGatewayNativeOAuthRefreshRoute(router.Group(""), oauth.refresh, authorizeOAuth) != nil)) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
			})
		}
		if oauth.claude != nil {
			const prefix = "/private/native/v1/claude/oauth"
			if admin.RegisterGatewayNativeClaudeOAuthRoutes(router.Group(""), oauth.claude, authorizeOAuth) != nil ||
				admin.RegisterGatewayNativeOAuthDescriptorRoute(router.Group(""), oauth.claude, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthRetainedCustodyRoute(router.Group(""), oauth.claude, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthRefreshRoute(router.Group(""), oauth.claude, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthCleanupRoute(router.Group(""), oauth.claude, authorizeCleanup, oauth.cleanup, prefix) != nil {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				})
			}
		}

		if oauth.grok != nil {
			const prefix = "/private/native/v1/grok/oauth"
			if admin.RegisterGatewayNativeGrokOAuthRoutes(router.Group(""), oauth.grok, authorizeOAuth) != nil ||
				admin.RegisterGatewayNativeOAuthDescriptorRoute(router.Group(""), oauth.grok, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthRetainedCustodyRoute(router.Group(""), oauth.grok, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthRefreshRoute(router.Group(""), oauth.grok, authorizeOAuth, prefix) != nil ||
				admin.RegisterGatewayNativeOAuthCleanupRoute(router.Group(""), oauth.grok, authorizeCleanup, oauth.cleanup, prefix) != nil {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				})
			}
		}

	}
	// Telemetry uses the same management credential, typed consumer context and
	// shared control budget as candidates. No execution/cleanup authority enters.
	router.GET("/private/native/v1/runtime", authorizeCandidate, nativeRuntime)
	management := transport.ManagementHandler(router)
	cleanup := transport.CleanupHandler(router)
	callback := transport.NativeOAuthCallbackHandler(router)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The sole query-bearing exception is the exact canonical GET callback.
		// F3 parses/scrubs the capability; this outer boundary also denies aliases,
		// duplicates, noncanonical encodings and body smuggling before bypassing auth.
		if oauth != nil && oauth.connect != nil && r.URL.Path == "/auth/callback" {
			query := r.URL.RawQuery
			values, err := url.ParseQuery(query)
			scope, hasScope := values["scope"]
			callbackFields := len(values) == 2 || (len(values) == 3 && hasScope && len(scope) == 1 && len(scope[0]) <= 1024)
			valid := r.Method == http.MethodGet && r.URL.RawPath == "" && !r.URL.ForceQuery && len(query) <= 8192 && len(r.RequestURI) <= 8210 &&
				r.RequestURI == "/auth/callback?"+query && err == nil && values.Encode() == query && callbackFields && len(values["state"]) == 1 && len(values["code"]) == 1 &&
				r.ContentLength == 0 && len(r.TransferEncoding) == 0 && r.Header.Get("Content-Encoding") == ""
			if !valid {
				r.URL.RawQuery = ""
				r.RequestURI = "/auth/callback"
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			// OAuth response scope is bounded metadata, never identity or authority.
			// Keep the inner one-use capability parser's exact code/state contract.
			if hasScope {
				values.Del("scope")
				r.URL.RawQuery = values.Encode()
				r.RequestURI = "/auth/callback?" + r.URL.RawQuery
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				r.URL.RawQuery = ""
				r.RequestURI = "/auth/callback"
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			callback.ServeHTTP(w, r.WithContext(bounded))
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(r.RequestURI) > 2048 ||
			r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "private native bootstrap denied", 400)
			return
		}
		switch {
		case oauth != nil && (oauth.limits != nil && r.URL.Path == "/private/native/v1/account-limits/capabilities" || oauth.limitsV2 != nil && r.URL.Path == "/private/native/v2/account-limits/capabilities"):
			if r.Method != http.MethodGet {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			management.ServeHTTP(w, r)
		case oauth != nil && (oauth.models != nil && r.URL.Path == "/private/native/v1/account-models/read" || oauth.limits != nil && r.URL.Path == "/private/native/v1/account-limits/read" || oauth.limitsV2 != nil && r.URL.Path == "/private/native/v2/account-limits/read"):
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			management.ServeHTTP(w, r.WithContext(bounded))
		case r.URL.Path == "/private/native/v1/runtime":
			management.ServeHTTP(w, r)
		case oauth != nil && (r.URL.Path == "/private/native/v1/oauth/connect/cleanup" || oauth.claude != nil && r.URL.Path == "/private/native/v1/claude/oauth/connect/cleanup" || oauth.grok != nil && r.URL.Path == "/private/native/v1/grok/oauth/connect/cleanup"):
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			cleanup.ServeHTTP(w, r.WithContext(bounded))
		case oauth != nil && (oauth.claude != nil && claudeControlPath(r.URL.Path) || oauth.grok != nil && grokControlPath(r.URL.Path)):
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(15*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(15*time.Second)) != nil {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			management.ServeHTTP(w, r.WithContext(bounded))
		case oauth != nil && (r.URL.Path == "/private/native/v1/oauth/connect" || r.URL.Path == "/private/native/v1/oauth/connect/read" || r.URL.Path == "/private/native/v1/oauth/connect/poll" || r.URL.Path == "/private/native/v1/oauth/connect/complete" || r.URL.Path == "/private/native/v1/oauth/connect/descriptor" || r.URL.Path == "/private/native/v1/oauth/connect/custody" || (oauth.refresh != nil && r.URL.Path == "/private/native/v1/oauth/refresh")):
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			management.ServeHTTP(w, r.WithContext(bounded))
		case r.URL.Path == "/private/native/v1/candidates" || strings.HasPrefix(r.URL.Path, "/private/native/v1/candidates/"):
			management.ServeHTTP(w, r)
		case r.URL.Path == "/private/native/v1/transports" || strings.HasPrefix(r.URL.Path, "/private/native/v1/transports/"):
			transport.ServeHTTP(w, r)
		default:
			// The internally registered /responses direct-review path is unreachable.
			http.Error(w, "private native bootstrap denied", http.StatusNotFound)
		}
	})
}
