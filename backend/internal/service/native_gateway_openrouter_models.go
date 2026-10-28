package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
)

const gatewayOpenRouterModelsURL = GatewayOpenRouterBaseURL + "/models"
const gatewayOpenRouterModelsMaximum = 2048
const gatewayOpenRouterModelsBytes = 16 << 20

// The cache holds complete catalogues per encrypted physical principal, never
// a selected model. Ordinary reads cannot decrypt credentials or choose URLs.
type GatewayOpenRouterModels struct {
	client *http.Client
	cache  gatewayModelsCache
}

// A supplied transport is trusted fixture composition only. The URL, deadline,
// redirect policy and absence of provider authentication remain fixed here.
func NewGatewayOpenRouterModels(transport http.RoundTripper) *GatewayOpenRouterModels {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16384}
	}
	return &GatewayOpenRouterModels{client: &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Startup-only dependency wiring; it cannot replace an admitted runtime source.
func (s *OpenAIGatewayService) SetGatewayOpenRouterModels(models *GatewayOpenRouterModels) error {
	if s == nil || models == nil || models.client == nil || s.gatewayOpenRouterModels != nil {
		return ErrGatewayNativeIdentity
	}
	s.gatewayOpenRouterModels = models
	return nil
}

func gatewayOpenRouterModelsPrincipal(scope GatewayNativeCredentialScope, envelope string) string {
	encoded, _ := json.Marshal(scope)
	digest := sha256.Sum256(append(append(encoded, 0), envelope...))
	return "openrouter_models_" + hex.EncodeToString(digest[:])
}

func (s *GatewayOpenRouterModels) read(ctx context.Context, principal string, force bool) GatewayAccountModelsResult {
	unavailable := GatewayAccountModelsResult{Status: "unavailable"}
	if s == nil || s.client == nil || ctx == nil || ctx.Err() != nil || principal == "" {
		return unavailable
	}
	return s.cache.read(ctx, principal, "", force, func() GatewayAccountModelsResult { return s.fetch(ctx) })
}

func (s *GatewayOpenRouterModels) fetch(ctx context.Context) GatewayAccountModelsResult {
	unavailable := GatewayAccountModelsResult{Status: "unavailable"}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, gatewayOpenRouterModelsURL, nil)
	if err != nil {
		return unavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return unavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != gatewayOpenRouterModelsURL {
		return unavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, gatewayOpenRouterModelsBytes+1))
	if err != nil || len(raw) > gatewayOpenRouterModelsBytes || bounded.Err() != nil {
		return unavailable
	}
	models, err := parseGatewayOpenRouterModels(raw)
	if err != nil {
		return unavailable
	}
	now := time.Now().UTC()
	return GatewayAccountModelsResult{Status: "snapshot", Source: "openrouter", FetchedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Models: &models}
}

func parseGatewayOpenRouterModels(raw []byte) ([]GatewayAccountModel, error) {
	root, ok := GatewayNativePayloadFields(raw, "data")
	if !ok || string(root["data"]) == "null" {
		return nil, ErrGatewayNativeIdentity
	}
	var rows []json.RawMessage
	if json.Unmarshal(root["data"], &rows) != nil || rows == nil || len(rows) > gatewayOpenRouterModelsMaximum {
		return nil, ErrGatewayNativeIdentity
	}
	models := []GatewayAccountModel{}
	seen := map[string]bool{}
	for _, row := range rows {
		fields, ok := GatewayNativePayloadFields(row, "id", "architecture", "supported_parameters")
		var id string
		if !ok || json.Unmarshal(fields["id"], &id) != nil || !GatewayOpenRouterModelValid(id) || seen[id] {
			return nil, ErrGatewayNativeIdentity
		}
		seen[id] = true
		architecture, ok := GatewayNativePayloadFields(fields["architecture"], "input_modalities", "output_modalities")
		var input, output, parameters []string
		if !ok || json.Unmarshal(architecture["input_modalities"], &input) != nil || json.Unmarshal(architecture["output_modalities"], &output) != nil ||
			(fields["supported_parameters"] != nil && json.Unmarshal(fields["supported_parameters"], &parameters) != nil) {
			return nil, ErrGatewayNativeIdentity
		}
		if !slices.Contains(input, "text") || !slices.Contains(output, "text") {
			continue
		}
		tools := GatewayAccountModelChoices{Allowed: []string{"none"}, Default: "none"}
		if slices.Contains(parameters, "tools") {
			tools = GatewayAccountModelChoices{Allowed: []string{"none", "function"}, Default: "function"}
		}
		// supported_parameters names a control, not its accepted effort values.
		// Unknown reasoning/fast settings remain absent rather than invented.
		models = append(models, GatewayAccountModel{ModelID: id, Tools: tools})
	}
	wire, err := json.Marshal(models)
	if err != nil || len(wire) > 2<<20 {
		return nil, ErrGatewayNativeIdentity
	}
	return models, nil
}

// Enrollment never accepts model membership from caller text or a descriptor.
// Only the configured anchor is checked, before the credential candidate exists.
func (s *OpenAIGatewayService) QualifyGatewayOpenRouterModel(ctx context.Context, scope GatewayNativeCredentialScope, envelope, model string) error {
	if s == nil || !scope.valid() || !GatewayOpenRouterModelValid(model) {
		return ErrGatewayNativeIdentity
	}
	result := s.gatewayOpenRouterModels.read(ctx, gatewayOpenRouterModelsPrincipal(scope, envelope), true)
	if result.Status != "snapshot" || result.Models == nil {
		return ErrGatewayNativeIdentity
	}
	for _, candidate := range *result.Models {
		if candidate.ModelID == model {
			return nil
		}
	}
	return ErrGatewayNativeIdentity
}

func gatewayOpenRouterAccountMatches(route GatewayNativeRoute, account *Account, scope GatewayNativeCredentialScope) bool {
	actual, err := GatewayNativeDescriptor(account)
	actualScope, scopeErr := GatewayNativeCredentialScopeForAccount(account)
	return err == nil && scopeErr == nil && SameGatewayNativeDescriptor(route, actual) && actualScope == scope &&
		route.Profile == GatewayOpenRouterResponsesProfile && route.BaseURL == GatewayOpenRouterBaseURL
}

func (s *OpenAIGatewayService) readGatewayOpenRouterAccountModels(ctx context.Context, in GatewayAccountModelsInput, before GatewayNativeRoute, authorize GatewayAccountLimitsAuthorizer) GatewayAccountModelsResult {
	unavailable := GatewayAccountModelsResult{Status: "unavailable"}
	if s == nil || s.accountRepo == nil || s.gatewayOpenRouterModels == nil || before.Profile != in.ProfileID {
		return unavailable
	}
	consumer, err := GatewayNativeConsumer(ctx)
	custody := gatewayNativeCustody(ctx)
	account, readErr := s.accountRepo.GetByID(ctx, before.AccountID)
	if err != nil || readErr != nil || custody == nil {
		return unavailable
	}
	scope := GatewayNativeCredentialScope{Consumer: consumer, Owner: in.OwnerRef, Account: in.AccountRef, Generation: before.Generation, Purpose: GatewayCredentialPurpose}
	if !gatewayOpenRouterAccountMatches(before, account, scope) || custody.ValidateEnvelope(account.GetCredential("api_key")) != nil {
		return unavailable
	}
	account = snapshotGatewayNativeAccount(account)
	principal := gatewayOpenRouterModelsPrincipal(scope, account.GetCredential("api_key"))
	out := s.gatewayOpenRouterModels.read(ctx, principal, in.ForceRefresh)
	after, err := authorize(ctx, in.GatewayAccountLimitsInput)
	locker, ok := s.accountRepo.(GatewayNativeAccountLocker)
	if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, after) || !ok {
		return unavailable
	}
	fresh, release, err := locker.LockGatewayNativeAccount(ctx, before.AccountID)
	if err != nil || release == nil {
		return unavailable
	}
	defer release()
	if !gatewayOpenRouterAccountMatches(after, fresh, scope) || !reflect.DeepEqual(account.Credentials, fresh.Credentials) || !reflect.DeepEqual(account.Extra, fresh.Extra) || custody.ValidateEnvelope(fresh.GetCredential("api_key")) != nil || ctx.Err() != nil {
		return unavailable
	}
	if out.Status == "snapshot" {
		out.PhysicalGeneration = before.Generation
		out.PrincipalVersion = principal
	}
	return out
}

func gatewayOpenRouterModelsAllow(result GatewayAccountModelsResult, anchor, model string, body []byte) bool {
	fields, ok := gatewayOpenRouterResponsesFields(body)
	if !ok || !GatewayOpenRouterModelValid(model) {
		return false
	}
	if result.Status == "unavailable" {
		// This retains only a birth model already admitted during enrollment.
		if model != anchor {
			return false
		}
		var tools []json.RawMessage
		if raw := fields["tools"]; len(raw) > 0 && string(raw) != "null" && (json.Unmarshal(raw, &tools) != nil || len(tools) != 0) {
			return false
		}
		if choice := fields["tool_choice"]; len(choice) > 0 && string(choice) != "null" && strings.TrimSpace(string(choice)) != `"none"` {
			return false
		}
		if raw := fields["reasoning"]; len(raw) > 0 && string(raw) != "null" {
			object, valid := GatewayNativePayloadFields(raw)
			return valid && len(object) == 0
		}
		return true
	}
	if result.Status != "snapshot" || result.Models == nil || result.Source != "openrouter" {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return false
	}
	for _, candidate := range *result.Models {
		if candidate.ModelID != model {
			continue
		}
		if reasoning := fields["reasoning"]; len(reasoning) > 0 && string(reasoning) != "null" {
			object, valid := GatewayNativePayloadFields(reasoning)
			if !valid || len(object) != 0 {
				return false
			}
		}
		var tools []json.RawMessage
		if raw := fields["tools"]; len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &tools) != nil {
			return false
		}
		if len(tools) > 0 && !slices.Contains(candidate.Tools.Allowed, "function") {
			return false
		}
		for _, tool := range tools {
			var toolType struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(tool, &toolType) != nil || toolType.Type != "function" {
				return false
			}
		}
		if choice := fields["tool_choice"]; len(choice) > 0 && string(choice) != "null" && !slices.Contains(candidate.Tools.Allowed, "function") && strings.TrimSpace(string(choice)) != `"none"` {
			return false
		}
		return true
	}
	return false
}

// OpenRouter exposes alternate-model routing and server-side tools outside the
// selected review model. Only the qualified client Responses subset may enter;
// tool schemas and user content remain opaque nested values.
func gatewayOpenRouterResponsesFields(body []byte) (map[string]json.RawMessage, bool) {
	return gatewayClaudeObject(body, "model", "input", "instructions", "stream", "store", "service_tier", "max_output_tokens", "tools", "tool_choice", "reasoning", "parallel_tool_calls", "temperature", "top_p", "text", "include", "prompt_cache_key", "client_metadata")
}
