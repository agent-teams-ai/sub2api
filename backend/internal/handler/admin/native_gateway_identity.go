package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// Profile is supplied by trusted server composition after MiMo Token Plan
// endpoint/model qualification. Neither endpoint nor model is accepted at create.
type GatewayNativeProfile struct{ ID, BaseURL, Model string }
type GatewayNativeCandidate struct {
	Descriptor    service.GatewayNativeRoute `json:"descriptor"`
	Name          string                     `json:"name"`
	State         string                     `json:"state"`
	GroupFree     bool                       `json:"group_free"`
	Schedulable   bool                       `json:"schedulable"`
	ProbesEnabled bool                       `json:"probes_enabled"`
}
type gatewayNativeCreate struct {
	Generation string `json:"generation"`
	Profile    string `json:"profile"`
	Name       string `json:"name"`
	APIKey     string `json:"api_key"` // ingress only; never used as a response DTO
	OwnerRef   string `json:"owner_ref"`
	AccountRef string `json:"account_ref"`
}
type gatewayNativeMutation struct {
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
	Name       string                     `json:"name,omitempty"`
	State      string                     `json:"state,omitempty"`
}
type gatewayNativeDispatchRequest struct {
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
	Payload    json.RawMessage            `json:"payload"`
}

// "inactive" is a private wire alias for native StatusDisabled.
func gatewayNativeWireState(status string) string {
	if status == service.StatusDisabled {
		return "inactive"
	}
	return status
}

// Runs before every ordinary admin account-ID handler, including probe/export.
func (h *AccountHandler) RejectGatewayNativeAdmin(c *gin.Context) {
	if strings.Contains(c.FullPath(), "/accounts/:id") {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err == nil {
			a, err := h.adminService.GetAccount(c.Request.Context(), id)
			if err == service.ErrGatewayNativeIdentity || service.HasGatewayNativeIdentity(a) {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"code": "account_not_found"})
				return
			}
		}
	}
	c.Next()
}

// Opt-in ONLY. The group must be private, with no body/error/access diagnostic
// middleware. authorize must authenticate the gateway server, not native admins
// or product clients. admit must validate live mapping/epoch/fences and durably
// claim this request before returning nil. settle preserves possible effects.
// These callbacks are REQUIRED outer-boundary composition, not an engine tenant
// framework. No route is registered by stock server/Wire automatically.
func RegisterGatewayNativeRoutes(group *gin.RouterGroup, admin service.AdminService, gateway *service.OpenAIGatewayService,
	profile GatewayNativeProfile, authorize gin.HandlerFunc,
	admit func(*gin.Context, service.GatewayNativeRoute) error,
	settle func(*gin.Context, bool, error), custody *service.GatewayNativeCredentialCustody, openRouter ...GatewayNativeProfile) {
	if group == nil || admin == nil || gateway == nil || authorize == nil || admit == nil || settle == nil || custody == nil ||
		!gatewayNativeProfileValid(profile) || len(openRouter) > 1 || len(openRouter) == 1 &&
		(openRouter[0].ID != service.GatewayOpenRouterResponsesProfile || profile.ID == openRouter[0].ID || !gatewayNativeProfileValid(openRouter[0])) {
		panic("invalid private native gateway composition")
	}
	// Capture at most one optional preset. No request owns a URL/model or catalog.
	var second GatewayNativeProfile
	if len(openRouter) == 1 {
		second = openRouter[0]
	}
	selectProfile := func(id string) (GatewayNativeProfile, bool) {
		if id == profile.ID {
			return profile, true
		}
		if second.ID != "" && id == second.ID {
			return second, true
		}
		return GatewayNativeProfile{}, false
	}
	validDescriptor := func(d service.GatewayNativeRoute) bool {
		selected, ok := selectProfile(d.Profile)
		return ok && d.BaseURL == selected.BaseURL && d.Model == selected.Model
	}
	fail := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"code": "native_candidate_quarantined"})
	}
	// Authentication must bind the consumer through the typed server context.
	// Composition supplies custody separately; clients can supply neither.
	routes := group.Group("/private/native/v1", authorize, func(c *gin.Context) {
		if _, err := service.GatewayNativeConsumer(c.Request.Context()); err != nil {
			fail(c)
			return
		}
		c.Request = c.Request.WithContext(service.WithGatewayNativeCustody(c.Request.Context(), custody))
		c.Next()
	})
	read := func(c *gin.Context, generation string) (*service.Account, bool) {
		a, err := gateway.ResolveGatewayCandidateMetadata(c.Request.Context(), generation)
		if err != nil {
			fail(c)
			return nil, false
		}
		d, err := service.GatewayNativeDescriptor(a)
		if err != nil || !validDescriptor(d) {
			fail(c)
			return nil, false
		}
		return a, true
	}
	emit := func(c *gin.Context, a *service.Account) {
		d, err := service.GatewayNativeDescriptor(a)
		if err != nil || !validDescriptor(d) {
			fail(c)
			return
		}
		c.JSON(http.StatusOK, GatewayNativeCandidate{d, a.Name, gatewayNativeWireState(a.Status), true, false, false})
	}
	routes.GET("/candidates/:generation", func(c *gin.Context) {
		if a, ok := read(c, c.Param("generation")); ok {
			emit(c, a)
		}
	})
	routes.POST("/candidates", func(c *gin.Context) {
		var req gatewayNativeCreate
		decodeErr := nativeGatewayDecode(c, &req)
		selected, configured := selectProfile(req.Profile)
		if decodeErr != nil || !configured || req.Name == "" || len(req.Name) > 400 ||
			!service.GatewayNativeIngressKeyValid(req.APIKey) || !service.GatewayNativeCredentialRefValid(req.OwnerRef) || !service.GatewayNativeCredentialRefValid(req.AccountRef) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": "invalid_native_candidate"})
			return
		}
		consumer, err := service.GatewayNativeConsumer(c.Request.Context())
		scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: req.OwnerRef, Account: req.AccountRef,
			Generation: req.Generation, Purpose: service.GatewayCredentialPurpose}
		envelope, sealErr := custody.Seal(scope, req.APIKey)
		req.APIKey = ""
		if err != nil || sealErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": "invalid_native_candidate"})
			return
		}
		// The facade MUST journal operation+generation before its ONE create attempt.
		// No stock idempotency coordinator: it retains vendor responses and permits
		// expired/retryable reclaim. The DB unique generation is the final one-row guard.
		mode, passthrough := "force_responses", true
		if selected.ID == service.GatewayLegacyBridgeProfile {
			mode, passthrough = "force_chat_completions", false
		}
		disabled := false
		a, err := admin.CreateAccount(service.WithGatewayNativeControl(c.Request.Context()), &service.CreateAccountInput{
			Name: req.Name, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
			Credentials: map[string]any{"api_key": envelope, "base_url": selected.BaseURL},
			Extra: map[string]any{service.GatewayGenerationExtraKey: req.Generation, service.GatewayProfileExtraKey: selected.ID,
				service.GatewayCredentialScopeExtraKey: scope.Metadata(),
				service.GatewayModelExtraKey:           selected.Model, "openai_responses_mode": mode, "openai_passthrough": passthrough,
				"native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true},
			Concurrency: 1, SkipDefaultGroupBind: true, ProbeEnabled: &disabled,
		})
		if err != nil {
			fail(c)
			return
		}
		// Ent's create result can retain nanoseconds that PostgreSQL did not store.
		// Read the SAME generation after the single create; a failed/lost read never
		// authorizes another create. Client descriptors are never rounded to match.
		persisted, ok := read(c, req.Generation)
		if !ok {
			return
		}
		persistedScope, scopeErr := service.GatewayNativeCredentialScopeForAccount(persisted)
		persistedDescriptor, descriptorErr := service.GatewayNativeDescriptor(persisted)
		if a == nil || persisted.ID != a.ID || scopeErr != nil || persistedScope != scope || persisted.GetCredential("api_key") != envelope ||
			descriptorErr != nil || persistedDescriptor.Profile != selected.ID || persistedDescriptor.BaseURL != selected.BaseURL || persistedDescriptor.Model != selected.Model {
			fail(c)
			return
		}
		emit(c, persisted)
	})
	routes.PUT("/candidates/:generation", func(c *gin.Context) {
		var req gatewayNativeMutation
		if nativeGatewayDecode(c, &req) != nil || len(req.Name) > 400 || (req.State != "" && req.State != "active" && req.State != "inactive") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": "invalid_native_mutation"})
			return
		}
		a, ok := read(c, c.Param("generation"))
		if !ok {
			return
		}
		d, _ := service.GatewayNativeDescriptor(a)
		if !service.SameGatewayNativeDescriptor(req.Descriptor, d) {
			fail(c)
			return
		}
		if req.State == "active" {
			if _, err := gateway.ResolveGatewayCandidate(c.Request.Context(), c.Param("generation")); err != nil {
				fail(c)
				return
			}
		}
		nativeStatus := req.State
		if nativeStatus == "inactive" {
			nativeStatus = service.StatusDisabled
		}
		updated, err := admin.UpdateAccount(service.WithGatewayNativeControl(c.Request.Context()), a.ID, &service.UpdateAccountInput{Name: req.Name, Status: nativeStatus})
		if err != nil {
			fail(c)
			return
		}
		emit(c, updated)
	})
	routes.POST("/candidates/:generation/erase", func(c *gin.Context) {
		var req struct {
			Descriptor service.GatewayNativeRoute `json:"descriptor"`
		}
		if nativeGatewayDecode(c, &req) != nil || req.Descriptor.Generation != c.Param("generation") ||
			!validDescriptor(req.Descriptor) {
			fail(c)
			return
		}
		// Trusted durable cleanup owner has already fenced and disabled this descriptor.
		if gateway.EraseGatewayCandidate(c.Request.Context(), req.Descriptor) != nil {
			fail(c)
			return
		}
		c.JSON(http.StatusOK, gin.H{"state": "tombstoned", "credentials_erased": true})
	})
	routes.POST("/responses", func(c *gin.Context) {
		var req gatewayNativeDispatchRequest
		if nativeGatewayDecode(c, &req) != nil || !validDescriptor(req.Descriptor) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": "invalid_native_route"})
			return
		}
		if err := admit(c, req.Descriptor); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": "native_admission_denied"})
			return
		}
		_, entered, err := gateway.ForwardGatewayRoute(c.Request.Context(), c, req.Descriptor, req.Payload)
		settle(c, entered, err)
		if err != nil && !c.Writer.Written() {
			code := "native_not_dispatched"
			if err == service.ErrGatewayNativeIdentity {
				code = "native_candidate_quarantined"
			}
			if entered {
				code = "native_effect_unknown"
			}
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"code": code})
		}
	})
}

func gatewayNativeProfileValid(p GatewayNativeProfile) bool {
	u, err := url.Parse(p.BaseURL)
	return service.GatewayNativeAPIKeyProfileValid(p.ID, p.BaseURL, p.Model) && err == nil &&
		u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// Strict bounded private ingress, including exactly one JSON value. Never return
// decoder errors; a malformed body can contain a submitted secret or prompt.
func nativeGatewayDecode(c *gin.Context, target any) error {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 || !utf8.Valid(body) || !nativeGatewayCanonicalIngress(body) {
		return service.ErrGatewayNativeIdentity
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return service.ErrGatewayNativeIdentity
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

// JSON struct decoding otherwise accepts repeated and case-aliased fields.
// Inspect only control members and the native descriptor; payload/tool/user
// bytes remain the existing engine's responsibility and are not rewritten.
func nativeGatewayCanonicalIngress(body []byte) bool {
	check := func(raw []byte, names []string) (map[string]json.RawMessage, bool) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			return nil, false
		}
		fields := make(map[string]json.RawMessage)
		for decoder.More() {
			token, err := decoder.Token()
			name, ok := token.(string)
			if err != nil || !ok {
				return nil, false
			}
			for _, canonical := range names {
				if strings.EqualFold(name, canonical) {
					if name != canonical || fields[canonical] != nil {
						return nil, false
					}
				}
			}
			var value json.RawMessage
			if decoder.Decode(&value) != nil {
				return nil, false
			}
			fields[name] = value
		}
		token, err = decoder.Token()
		return fields, err == nil && token == json.Delim('}')
	}
	fields, ok := check(body, []string{"generation", "profile", "name", "api_key", "owner_ref", "account_ref", "descriptor", "state", "payload"})
	if !ok {
		return false
	}
	if descriptor, exists := fields["descriptor"]; exists {
		_, ok = check(descriptor, []string{"account_id", "generation", "created_at", "profile", "base_url", "model"})
	}
	return ok
}
