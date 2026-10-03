package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

const GatewayGenerationExtraKey = "gateway_generation_v1"
const GatewayProfileExtraKey = "gateway_profile_v1"
const GatewayModelExtraKey = "gateway_model_v1"
const GatewayMiMoResponsesProfile = "openai-responses-apikey-v1"
const GatewayLegacyBridgeProfile = "mimo-token-plan-responses-chat-bridge-v1"

var ErrGatewayNativeIdentity = errors.New("gateway native identity rejected")
var ErrGatewayNativeReplay = errors.New("gateway native dispatch already entered")
var ErrGatewayNativeEffectUnknown = errors.New("gateway native effect unknown")

// This is PRIVATE server routing. It carries no authorization. The host must
// persist its admission/effect claim before calling ForwardGatewayRoute.
type GatewayNativeRoute struct {
	AccountID  int64     `json:"account_id"`
	Generation string    `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	Profile    string    `json:"profile"`
	BaseURL    string    `json:"base_url"`
	Model      string    `json:"model"`
}

// Wire identity compares the birth instant, not time.Time's location/cache
// representation. Every other frozen descriptor field remains exact.
func SameGatewayNativeDescriptor(a, b GatewayNativeRoute) bool {
	return a.AccountID == b.AccountID && a.Generation == b.Generation &&
		a.CreatedAt.Equal(b.CreatedAt) && a.Profile == b.Profile &&
		a.BaseURL == b.BaseURL && a.Model == b.Model
}

// This API selects a backend key domain inaccessible to unrestricted ordinary
// item IDs. Do not encode a generation into the old Get/SetReasoningContent ID.
type GatewayNativeReasoningCache interface {
	GetGatewayNativeReasoningContent(context.Context, string, string) (string, error)
	SetGatewayNativeReasoningContent(context.Context, string, string, string, time.Duration) error
}

// Implemented by the real PostgreSQL repository. A mere GetByID cannot close
// the fresh-check/delete/reuse race. The release function MUST always be called.
type GatewayNativeAccountLocker interface {
	LockGatewayNativeAccount(context.Context, int64) (*Account, func(), error)
}

type gatewayNativeContextKey struct{}
type gatewayNativeControlContextKey struct{}

// Server composition only; public admin handlers never receive this context.
func WithGatewayNativeControl(ctx context.Context) context.Context {
	return context.WithValue(ctx, gatewayNativeControlContextKey{}, true)
}
func isGatewayNativeControl(ctx context.Context) bool {
	allowed, _ := ctx.Value(gatewayNativeControlContextKey{}).(bool)
	return allowed
}

type GatewayNativeAccountEraser interface {
	EraseGatewayNativeAccount(context.Context, GatewayNativeRoute) error
}

func (s *OpenAIGatewayService) EraseGatewayCandidate(ctx context.Context, route GatewayNativeRoute) error {
	eraser, ok := s.accountRepo.(GatewayNativeAccountEraser)
	id, err := uuid.Parse(route.Generation)
	if !ok || err != nil || id == uuid.Nil || id.String() != route.Generation ||
		route.AccountID <= 0 || route.CreatedAt.IsZero() || route.BaseURL == "" || route.Model == "" ||
		(route.Profile != GatewayMiMoResponsesProfile && route.Profile != GatewayLegacyBridgeProfile) {
		return ErrGatewayNativeIdentity
	}
	return eraser.EraseGatewayNativeAccount(ctx, route)
}

type gatewayNativeDispatch struct {
	route   GatewayNativeRoute
	account *Account
	entered atomic.Bool
}

func HasGatewayNativeIdentity(a *Account) bool {
	if a == nil {
		return false
	}
	_, generation := a.Extra[GatewayGenerationExtraKey]
	_, profile := a.Extra[GatewayProfileExtraKey]
	return generation || profile
}

func validateGatewayNativeShape(a *Account) error {
	if a == nil || a.Platform != PlatformOpenAI || a.Type != AccountTypeAPIKey ||
		a.ParentAccountID != nil || a.ProxyID != nil || a.Schedulable ||
		len(a.GroupIDs) != 0 || len(a.AccountGroups) != 0 {
		return ErrGatewayNativeIdentity
	}
	generation, ok := a.Extra[GatewayGenerationExtraKey].(string)
	id, err := uuid.Parse(generation)
	if !ok || err != nil || id == uuid.Nil || id.String() != generation {
		return ErrGatewayNativeIdentity
	}
	profile := a.Extra[GatewayProfileExtraKey]
	mode, passthrough := "force_responses", true
	if profile == GatewayLegacyBridgeProfile {
		mode, passthrough = "force_chat_completions", false
	}
	if (profile != GatewayMiMoResponsesProfile && profile != GatewayLegacyBridgeProfile) ||
		a.Extra["openai_responses_mode"] != mode ||
		a.Extra["openai_passthrough"] != passthrough ||
		a.Extra["native_api_key_cancel_on_disconnect"] != true ||
		a.Extra["openai_preserve_compatible_reasoning"] != true {
		return ErrGatewayNativeIdentity
	}
	if model, ok := a.Extra[GatewayModelExtraKey].(string); !ok || strings.TrimSpace(model) == "" {
		return ErrGatewayNativeIdentity
	}
	if len(a.Credentials) != 2 || strings.TrimSpace(a.GetCredential("api_key")) == "" ||
		a.GetCredential("api_key") != strings.TrimSpace(a.GetCredential("api_key")) || a.GetCredential("base_url") == "" {
		return ErrGatewayNativeIdentity
	}
	// Extra is an allowlist, so no WS, pool, header override, probe, quota reset,
	// provider endpoint/protocol or model remapping knob can alter this profile.
	for key := range a.Extra {
		switch key {
		case GatewayGenerationExtraKey, GatewayProfileExtraKey, GatewayModelExtraKey,
			"openai_responses_mode", "openai_passthrough", "native_api_key_cancel_on_disconnect", "openai_preserve_compatible_reasoning":
		default:
			return ErrGatewayNativeIdentity
		}
	}
	return nil
}

func validateGatewayNativeRoute(r GatewayNativeRoute, a *Account) error {
	if validateGatewayNativeShape(a) != nil || r.AccountID <= 0 || r.CreatedAt.IsZero() ||
		r.AccountID != a.ID || r.Generation != a.Extra[GatewayGenerationExtraKey] ||
		r.Profile != a.Extra[GatewayProfileExtraKey] || !r.CreatedAt.Equal(a.CreatedAt) ||
		r.BaseURL == "" || r.BaseURL != a.GetCredential("base_url") ||
		r.Model == "" || r.Model != a.Extra[GatewayModelExtraKey] || !a.IsActive() ||
		(a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now())) {
		return ErrGatewayNativeIdentity
	}
	return nil
}

func GatewayNativeDescriptor(a *Account) (GatewayNativeRoute, error) {
	if validateGatewayNativeShape(a) != nil || a.ID <= 0 || a.CreatedAt.IsZero() {
		return GatewayNativeRoute{}, ErrGatewayNativeIdentity
	}
	return GatewayNativeRoute{a.ID, a.Extra[GatewayGenerationExtraKey].(string), a.CreatedAt,
		a.Extra[GatewayProfileExtraKey].(string), a.GetCredential("base_url"), a.Extra[GatewayModelExtraKey].(string)}, nil
}

// This is an exact candidate query, never name/latest/ID-only recovery. Zero,
// multiple, malformed or deleted candidates are quarantined by the facade.
func (s *OpenAIGatewayService) ResolveGatewayCandidate(ctx context.Context, generation string) (*Account, error) {
	id, err := uuid.Parse(generation)
	if err != nil || id == uuid.Nil || id.String() != generation || s.accountRepo == nil {
		return nil, ErrGatewayNativeIdentity
	}
	accounts, err := s.accountRepo.FindByExtraField(ctx, GatewayGenerationExtraKey, generation)
	if err != nil || len(accounts) != 1 {
		return nil, ErrGatewayNativeIdentity
	}
	a := &accounts[0]
	if _, err := GatewayNativeDescriptor(a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *OpenAIGatewayService) ForwardGatewayRoute(ctx context.Context, c *gin.Context, route GatewayNativeRoute, body []byte) (*OpenAIForwardResult, bool, error) {
	if ctx == nil || c == nil || c.Request == nil || s.accountRepo == nil || len(body) > 4<<20 || !gjson.ValidBytes(body) || !gjson.ParseBytes(body).IsObject() || !gatewayNativeUnambiguousPolicyFields(body) ||
		gjson.GetBytes(body, "model").String() != route.Model || (route.Profile != GatewayMiMoResponsesProfile && route.Profile != GatewayLegacyBridgeProfile) ||
		gjson.GetBytes(body, "previous_response_id").String() != "" ||
		(gjson.GetBytes(body, "service_tier").Exists() && gjson.GetBytes(body, "service_tier").String() != "default") ||
		(gjson.GetBytes(body, "store").Exists() && gjson.GetBytes(body, "store").Bool()) {
		return nil, false, ErrGatewayNativeIdentity
	}
	if _, ok := s.accountRepo.(GatewayNativeAccountLocker); !ok {
		return nil, false, ErrGatewayNativeIdentity
	}
	a, err := s.accountRepo.GetByID(ctx, route.AccountID)
	if err != nil || validateGatewayNativeRoute(route, a) != nil {
		return nil, false, ErrGatewayNativeIdentity
	}
	state := &gatewayNativeDispatch{route: route, account: a}
	ctx = WithHTTPUpstreamRedirectsDisabled(context.WithValue(ctx, gatewayNativeContextKey{}, state))
	// Restrict this private seam to a Responses request; never pass public route
	// path suffixes or authentication and affinity headers into upstream routing.
	request := c.Request.Clone(ctx)
	request.Header = make(http.Header)
	c.Request = request
	// Native Responses is the first qualification path. The separately selected
	// historical bridge is never an automatic fallback after any dispatch.
	var result *OpenAIForwardResult
	if route.Profile == GatewayMiMoResponsesProfile {
		result, err = s.forwardGatewayNativeResponses(ctx, c, a, body)
	} else {
		result, err = s.forwardResponsesViaRawChatCompletions(ctx, c, a, body)
	}
	if err != nil && err != ErrGatewayNativeIdentity && err != ErrGatewayNativeReplay {
		if state.entered.Load() {
			err = ErrGatewayNativeEffectUnknown
		} else {
			err = ErrGatewayNativeIdentity
		}
	}
	return result, state.entered.Load(), err
}

// Last common HTTP seam. The pointer is the EXACT credential-bearing Account
// used to construct Authorization and URL. The fresh row is locked until Do
// returns headers/error; status changes after that boundary are accepted effects.
func (s *OpenAIGatewayService) checkGatewayNativeDispatch(request *http.Request, a *Account) (func(), error) {
	noop := func() {}
	state, _ := request.Context().Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	if state == nil {
		if HasGatewayNativeIdentity(a) {
			return noop, ErrGatewayNativeIdentity
		}
		return noop, nil
	}
	if state.account != a || validateGatewayNativeRoute(state.route, a) != nil || request.Method != http.MethodPost ||
		request.Header.Get("Authorization") != "Bearer "+a.GetCredential("api_key") {
		return noop, ErrGatewayNativeIdentity
	}
	target, err := s.gatewayNativeTargetURL(a)
	if err != nil || request.URL.String() != target {
		return noop, ErrGatewayNativeIdentity
	}
	locker, ok := s.accountRepo.(GatewayNativeAccountLocker)
	if !ok {
		return noop, ErrGatewayNativeIdentity
	}
	fresh, release, err := locker.LockGatewayNativeAccount(request.Context(), state.route.AccountID)
	if err != nil {
		return noop, ErrGatewayNativeIdentity
	}
	if release == nil {
		return noop, ErrGatewayNativeIdentity
	}
	if validateGatewayNativeRoute(state.route, fresh) != nil || !reflect.DeepEqual(a.Credentials, fresh.Credentials) || !reflect.DeepEqual(a.Extra, fresh.Extra) {
		release()
		return noop, ErrGatewayNativeIdentity
	}
	if !state.entered.CompareAndSwap(false, true) {
		release()
		return noop, ErrGatewayNativeReplay
	}
	request.GetBody = nil
	request.Header.Del("Idempotency-Key")
	request.Header.Del("X-Idempotency-Key")
	return release, nil
}

func gatewayNativeReasoningScope(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	state, _ := c.Request.Context().Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	if state == nil {
		return ""
	}
	return state.route.Generation
}

// Different JSON readers choose different occurrences of duplicate keys. Scan
// decoded top-level names (including escapes), rejecting duplicate policy fields
// before any transport entry. Nested and noncritical fields retain native bytes.
func gatewayNativeUnambiguousPolicyFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, 4)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok {
			return false
		}
		switch key {
		case "model", "store", "previous_response_id", "service_tier":
			if seen[key] {
				return false
			}
			seen[key] = true
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}')
}
