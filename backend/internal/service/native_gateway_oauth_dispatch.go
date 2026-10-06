package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const GatewayCodexOAuthResponsesProfile = "openai-codex-oauth-responses-v1"
const GatewayCodexOAuthBaseURL = "https://chatgpt.com/backend-api/codex"
const GatewayCodexOAuthModel = "gpt-6.1-sol"
const gatewayCodexAccountCheckURL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"

// This receipt qualifies controlled source fixtures only. It does not attest a
// live account capability, canary, custody restore, product mount or publication.
const GatewayCodexOAuthQualification = "controlled-source-v1"

// Private immutable physical identity. Credential version belongs to the
// engine refresh writer and is deliberately absent from this record.
// GatewayNativeOAuthRefreshFence is the retained physical SQL lock boundary.
// Check must read the journal with a fresh statement immediately before entry.
type GatewayNativeOAuthRefreshFence interface {
	Check(context.Context) error
}

type GatewayNativeOAuthPhysical struct {
	Scope           GatewayNativeCredentialScope
	Operation       string
	Route           GatewayNativeRoute
	Issuer          string
	Subject         string
	ProviderAccount string
	QualifiedAt     time.Time
	proof           *gatewayOAuthQualificationProof
	RefreshFence    GatewayNativeOAuthRefreshFence
}

type GatewayNativeOAuthDispatchRepository interface {
	// Resolve the original connect operation only after its exact enrollment
	// commitment completed. F1 custody readback alone cannot qualify dispatch.
	ReadGatewayNativeOAuthDispatch(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthOutcome, error)
	LockGatewayNativeOAuthDispatch(context.Context, GatewayNativeCredentialScope, string, int64) (*Account, GatewayNativeOAuthPhysical, func(), error)
	QualifyGatewayNativeOAuthDispatch(context.Context, GatewayNativeOAuthPhysical, int64) error
}

// The transport owns this narrow post-admit lookup. Only authenticated consumer
// and the exact kernel-approved physical descriptor/logical account are inputs.
type GatewayNativeOAuthCanonicalRepository interface {
	ResolveGatewayNativeOAuthCanonical(context.Context, GatewayNativeRoute, string) (GatewayNativeCredentialScope, string, error)
}

func (s *GatewayNativeOAuthDispatch) BindApproved(ctx context.Context, route GatewayNativeRoute, account string, authorizationEpoch, requestBytes, tokens int64) (context.Context, error) {
	if s == nil || authorizationEpoch < 0 || route.Profile != GatewayCodexOAuthResponsesProfile || route.BaseURL != GatewayCodexOAuthBaseURL || route.Model != GatewayCodexOAuthModel || !GatewayNativeCredentialRefValid(account) {
		return nil, ErrGatewayNativeIdentity
	}
	repository, ok := s.repository.(GatewayNativeOAuthCanonicalRepository)
	if !ok {
		return nil, ErrGatewayNativeIdentity
	}
	scope, operation, err := repository.ResolveGatewayNativeOAuthCanonical(ctx, route, account)
	consumer, consumerErr := GatewayNativeConsumer(ctx)
	if err != nil || consumerErr != nil || scope.Consumer != consumer || scope.Account != account || scope.Generation != route.Generation || !GatewayNativeOAuthScopeValid(scope) {
		return nil, ErrGatewayNativeIdentity
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, scope.Owner)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	return WithGatewayNativeOAuthDispatch(ctx, s, scope, operation, requestBytes, tokens)
}

// Qualification evidence is minted only by the controlled checker. Repositories
// must call QualificationValid; arbitrary physical DTOs cannot promote a row.
type gatewayOAuthQualificationProof struct {
	physical GatewayNativeOAuthPhysical
	version  int64
}

// Kept outside JSON and outside Account.Extra so existing immutable birth and
// refresh guards remain authoritative. A copied DTO does not mint a proof.
func (p GatewayNativeOAuthPhysical) QualificationValid(version int64) bool {
	return p.proof != nil && version == p.proof.version && sameGatewayOAuthPhysical(p, p.proof.physical)
}

func sameGatewayOAuthPhysical(a, b GatewayNativeOAuthPhysical) bool {
	return a.Scope == b.Scope && a.Operation == b.Operation && SameGatewayNativeDescriptor(a.Route, b.Route) &&
		a.Issuer == b.Issuer && a.Subject == b.Subject && a.ProviderAccount == b.ProviderAccount && a.QualifiedAt.Equal(b.QualifiedAt)
}

type GatewayNativeOAuthDescriptorResult struct {
	Operation     string              `json:"operation"`
	Account       string              `json:"account_ref"`
	State         string              `json:"state"`
	Qualification string              `json:"qualification"`
	Native        *GatewayNativeRoute `json:"native,omitempty"`
}

type GatewayNativeOAuthDispatch struct {
	repository GatewayNativeOAuthDispatchRepository
	custody    *GatewayNativeCredentialCustody
	verifier   *GatewayNativeOAuthVerifier
	client     *http.Client
}

// Transport injection is trusted composition for loopback TLS fixtures only.
// Production mounting and live profile qualification are separate gates.
func NewGatewayNativeOAuthDispatch(r GatewayNativeOAuthDispatchRepository, c *GatewayNativeCredentialCustody, v *GatewayNativeOAuthVerifier, transport http.RoundTripper) (*GatewayNativeOAuthDispatch, error) {
	if r == nil || !GatewayNativeCredentialCustodyReady(c) || v == nil {
		return nil, ErrGatewayNativeIdentity
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, DisableKeepAlives: true}
	}
	return &GatewayNativeOAuthDispatch{repository: r, custody: c, verifier: v, client: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}}, nil
}

// F1 readback selects the exact scoped inert row; no latest/name/public DTO or
// F3 recovery path can introduce a physical candidate here.
func (s *GatewayNativeOAuthDispatch) Descriptor(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthDescriptorResult, error) {
	out := GatewayNativeOAuthDescriptorResult{Operation: operation, Account: scope.Account, State: "staged", Qualification: "pending"}
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return out, ErrGatewayNativeIdentity
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	row, err := s.repository.ReadGatewayNativeOAuthDispatch(bounded, scope, operation)
	if err != nil || row.Operation != operation || row.Generation != scope.Generation {
		return out, ErrGatewayNativeIdentity
	}
	if row.State != "completed" {
		if row.State == "prepared" || row.State == "entered" || row.State == "unknown" || row.State == "expired" {
			return out, nil
		}
		return out, ErrGatewayNativeIdentity
	}
	if row.AccountID <= 0 {
		return out, ErrGatewayNativeIdentity
	}
	a, physical, release, err := s.repository.LockGatewayNativeOAuthDispatch(bounded, scope, operation, row.AccountID)
	if err != nil || release == nil {
		return out, ErrGatewayNativeIdentity
	}
	if physical.Scope != scope || physical.Operation != operation || gatewayOAuthPhysicalValid(a, physical) != nil {
		release()
		return out, ErrGatewayNativeIdentity
	}
	if !physical.QualifiedAt.IsZero() {
		release()
		out.Qualification = GatewayCodexOAuthQualification
		route := physical.Route
		out.Native = &route
		return out, nil
	}
	version, err := gatewayOAuthCredentialVersion(a)
	var bundle GatewayNativeOAuthBundle
	if err == nil {
		bundle, err = s.custody.openOAuthVersion(a.GetCredential("oauth_bundle"), scope, version)
	}
	release()
	if err != nil {
		return out, ErrGatewayNativeIdentity
	}
	identity, err := s.verifier.Verify(bounded, bundle.IDToken)
	issuer, subject := identity.Principal()
	if err != nil || issuer != physical.Issuer || subject != physical.Subject {
		return out, ErrGatewayNativeIdentity
	}
	provider, err := s.accountCheck(bounded, bundle.AccessToken)
	bundle = GatewayNativeOAuthBundle{}
	if err != nil {
		return out, nil
	} // bounded ambiguity/failure remains staging
	physical.ProviderAccount = provider
	physical.QualifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	physical.proof = &gatewayOAuthQualificationProof{physical: physical, version: version}
	if err = s.repository.QualifyGatewayNativeOAuthDispatch(bounded, physical, version); err != nil {
		return out, ErrGatewayNativeIdentity
	}
	out.Qualification = GatewayCodexOAuthQualification
	route := physical.Route
	out.Native = &route
	return out, nil
}

func (s *GatewayNativeOAuthDispatch) accountCheck(ctx context.Context, access string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayCodexAccountCheckURL, nil)
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	if response.Body == nil {
		return "", ErrGatewayNativeIdentity
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) > 65536 || response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != gatewayCodexAccountCheckURL {
		return "", ErrGatewayNativeIdentity
	}
	return gatewayOAuthSelectAccount(raw, time.Now())
}

// Returned account records are authenticated by the fixed bearer endpoint.
// Map keys, defaults, tiers and JWT workspace hints never choose an account.
func gatewayOAuthSelectAccount(raw []byte, now time.Time) (string, error) {
	deny := func() (string, error) { return "", ErrGatewayNativeIdentity }
	root, err := gatewayOAuthJSON(raw)
	if err != nil || !gatewayOAuthCanonical(root, "accounts") {
		return deny()
	}
	accounts, err := gatewayOAuthJSON(root["accounts"])
	if err != nil || len(accounts) == 0 || len(accounts) > 32 {
		return deny()
	}
	seen := map[string]bool{}
	selected := ""
	for _, record := range accounts {
		entry, err := gatewayOAuthJSON(record)
		if err != nil || !gatewayOAuthCanonical(entry, "account", "entitlement") {
			return deny()
		}
		account, err := gatewayOAuthJSON(entry["account"])
		if err != nil || !gatewayOAuthCanonical(account, "account_id", "is_default") {
			return deny()
		}
		id, ok := gatewayOAuthString(account, "account_id")
		parsed, err := uuid.Parse(id)
		if !ok || err != nil || parsed == uuid.Nil || parsed.String() != id || seen[id] {
			return deny()
		}
		seen[id] = true
		usable := true
		for _, fields := range []map[string]json.RawMessage{entry, account} {
			if !gatewayOAuthCanonical(fields, "deactivated", "is_deactivated", "disabled", "is_disabled", "deactivated_at", "disabled_at", "deleted_at", "status", "state") {
				return deny()
			}
			for _, key := range []string{"deactivated", "is_deactivated", "disabled", "is_disabled"} {
				if value, exists := fields[key]; exists {
					var b bool
					if string(value) == "null" || json.Unmarshal(value, &b) != nil {
						return deny()
					}
					if b {
						usable = false
					}
				}
			}
			for _, key := range []string{"deactivated_at", "disabled_at", "deleted_at"} {
				if value, exists := fields[key]; exists && string(value) != "null" {
					var str string
					if json.Unmarshal(value, &str) != nil {
						return deny()
					}
					if str != "" {
						if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
							return deny()
						}
						usable = false
					}
				}
			}
			for _, key := range []string{"status", "state"} {
				if value, exists := fields[key]; exists {
					var str string
					if json.Unmarshal(value, &str) != nil || str != "active" {
						usable = false
					}
				}
			}
		}
		if value, exists := entry["entitlement"]; exists {
			entitlement, err := gatewayOAuthJSON(value)
			if err != nil || !gatewayOAuthCanonical(entitlement, "expires_at") {
				return deny()
			}
			if expiry, exists := entitlement["expires_at"]; exists && string(expiry) != "null" {
				var str string
				if json.Unmarshal(expiry, &str) != nil {
					return deny()
				}
				instant, err := time.Parse(time.RFC3339Nano, str)
				if err != nil {
					return deny()
				}
				if !instant.After(now) {
					usable = false
				}
			}
		}
		if usable {
			if selected != "" {
				return deny()
			}
			selected = id
		}
	}
	if selected == "" {
		return deny()
	}
	return selected, nil
}

func gatewayOAuthScopeForAccount(a *Account) (GatewayNativeCredentialScope, error) {
	var scope GatewayNativeCredentialScope
	if a == nil {
		return scope, ErrGatewayNativeIdentity
	}
	fields, ok := a.Extra[GatewayCredentialScopeExtraKey].(map[string]any)
	if !ok || len(fields) != 5 {
		return scope, ErrGatewayNativeIdentity
	}
	for name, dst := range map[string]*string{"consumer": &scope.Consumer, "owner": &scope.Owner, "account": &scope.Account, "generation": &scope.Generation, "purpose": &scope.Purpose} {
		value, ok := fields[name].(string)
		if !ok {
			return scope, ErrGatewayNativeIdentity
		}
		*dst = value
	}
	if !GatewayNativeOAuthScopeValid(scope) || a.Extra[GatewayGenerationExtraKey] != scope.Generation {
		return scope, ErrGatewayNativeIdentity
	}
	return scope, nil
}

func gatewayOAuthCredentialVersion(a *Account) (int64, error) {
	if a == nil {
		return 0, ErrGatewayNativeIdentity
	}
	envelope, ok := a.Credentials["oauth_bundle"].(string)
	if !ok {
		return 0, ErrGatewayNativeIdentity
	}
	if len(a.Credentials) == 1 {
		_, _, _, err := gatewayOAuthParseEnvelope(envelope)
		return 1, err
	}
	value, ok := a.Credentials["credential_version"].(string)
	version, err := strconv.ParseInt(value, 10, 64)
	parts := strings.Split(envelope, ".")
	if !ok || err != nil || version < 2 || value != strconv.FormatInt(version, 10) || len(a.Credentials) != 2 || len(parts) != 5 || parts[0] != "gco2" || parts[2] != value {
		return 0, ErrGatewayNativeIdentity
	}
	_, _, _, err = gatewayOAuthParseEnvelope("gco1." + parts[1] + "." + parts[3] + "." + parts[4])
	return version, err
}

func gatewayOAuthPhysicalValid(a *Account, p GatewayNativeOAuthPhysical) error {
	scope, err := gatewayOAuthScopeForAccount(a)
	if err != nil || scope != p.Scope || !GatewayNativeCredentialRefValid(p.Operation) || p.Issuer != GatewayOAuthIssuer || !GatewayNativeCredentialRefValid(p.Subject) ||
		a.ID <= 0 || a.ID != p.Route.AccountID || a.CreatedAt.IsZero() || a.CreatedAt.Nanosecond()%1000 != 0 || !a.CreatedAt.Equal(p.Route.CreatedAt) ||
		p.Route.Generation != scope.Generation || p.Route.Profile != GatewayCodexOAuthResponsesProfile || p.Route.BaseURL != GatewayCodexOAuthBaseURL || p.Route.Model != GatewayCodexOAuthModel ||
		a.Platform != PlatformOpenAI || a.Type != AccountTypeOAuth || a.Status != StatusDisabled || a.Schedulable || a.ProxyID != nil || a.ParentAccountID != nil || len(a.GroupIDs) != 0 || len(a.AccountGroups) != 0 || len(a.Extra) != 3 || a.Extra[GatewayProfileExtraKey] != GatewayOAuthStagingProfile ||
		(a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now())) {
		return ErrGatewayNativeIdentity
	}
	if _, err := gatewayOAuthCredentialVersion(a); err != nil {
		return err
	}
	if !p.QualifiedAt.IsZero() {
		id, err := uuid.Parse(p.ProviderAccount)
		if err != nil || id == uuid.Nil || id.String() != p.ProviderAccount || p.QualifiedAt.After(time.Now()) {
			return ErrGatewayNativeIdentity
		}
	}
	return nil
}

type gatewayOAuthDispatchBinding struct {
	dispatch     *GatewayNativeOAuthDispatch
	scope        GatewayNativeCredentialScope
	operation    string
	requestBytes int64
	tokens       int64
}
type gatewayOAuthDispatchBindingKey struct{}

// Explicit server-owned composition of an already approved operation/mapping
// and payload limits. It confers no SQL admit or replay permission; B owns those.
func WithGatewayNativeOAuthDispatch(ctx context.Context, dispatch *GatewayNativeOAuthDispatch, scope GatewayNativeCredentialScope, operation string, requestBytes, tokens int64) (context.Context, error) {
	if dispatch == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) || requestBytes < 1 || requestBytes > 4<<20 || tokens < 1 {
		return nil, ErrGatewayNativeIdentity
	}
	return context.WithValue(ctx, gatewayOAuthDispatchBindingKey{}, gatewayOAuthDispatchBinding{dispatch, scope, operation, requestBytes, tokens}), nil
}

func (s *OpenAIGatewayService) forwardGatewayOAuthRoute(ctx context.Context, c *gin.Context, route GatewayNativeRoute, body []byte) (*OpenAIForwardResult, bool, error) {
	binding, ok := ctx.Value(gatewayOAuthDispatchBindingKey{}).(gatewayOAuthDispatchBinding)
	life := gatewayNativeLifetime(ctx)
	if s == nil {
		return nil, false, ErrGatewayNativeIdentity
	}
	_, ownedTransport := s.httpUpstream.(*gatewayNativeLifetimeUpstream)
	if !ok || !ownedTransport || c == nil || c.Request == nil || life == nil || !life.matchesScope(binding.scope) || !GatewayNativeOAuthScopeAuthorized(ctx, binding.scope) || int64(len(body)) > binding.requestBytes {
		return nil, false, ErrGatewayNativeIdentity
	}
	fields, ok := GatewayNativePayloadFields(body, "model", "store", "stream", "service_tier", "previous_response_id", "max_output_tokens")
	var model, tier string
	var stream, store bool
	if !ok || json.Unmarshal(fields["model"], &model) != nil || model != GatewayCodexOAuthModel || model != route.Model ||
		string(fields["stream"]) != "true" || json.Unmarshal(fields["stream"], &stream) != nil || !stream ||
		string(fields["store"]) != "false" || json.Unmarshal(fields["store"], &store) != nil || store ||
		json.Unmarshal(fields["service_tier"], &tier) != nil || tier != "default" || fields["previous_response_id"] != nil {
		return nil, false, ErrGatewayNativeIdentity
	}
	cap, ok := gatewayOAuthSeconds(fields["max_output_tokens"])
	if !ok || cap > binding.tokens {
		return nil, false, ErrGatewayNativeIdentity
	}
	a, p, release, err := binding.dispatch.repository.LockGatewayNativeOAuthDispatch(ctx, binding.scope, binding.operation, route.AccountID)
	if err != nil || release == nil {
		return nil, false, ErrGatewayNativeIdentity
	}
	if p.Scope != binding.scope || p.Operation != binding.operation || gatewayOAuthPhysicalValid(a, p) != nil || p.QualifiedAt.IsZero() || !SameGatewayNativeDescriptor(route, p.Route) {
		release()
		return nil, false, ErrGatewayNativeIdentity
	}
	a = snapshotGatewayNativeAccount(a)
	release()
	state := &gatewayNativeDispatch{route: route, account: a, scope: binding.scope, custody: binding.dispatch.custody, oauth: &p}
	ctx = WithHTTPUpstreamRedirectsDisabled(context.WithValue(ctx, gatewayNativeContextKey{}, state))
	request := c.Request.Clone(ctx)
	request.Header = make(http.Header)
	c.Request = request
	result, err := s.forwardGatewayNativeResponses(ctx, c, a, body)
	if err != nil && err != ErrGatewayNativeIdentity && err != ErrGatewayNativeReplay {
		if state.entered.Load() {
			err = ErrGatewayNativeEffectUnknown
		} else {
			err = ErrGatewayNativeIdentity
		}
	}
	if err == nil {
		life.success()
	}
	return result, state.entered.Load(), err
}

func (s *OpenAIGatewayService) checkGatewayOAuthDispatch(request *http.Request, a *Account, state *gatewayNativeDispatch) (func(), error) {
	noop := func() {}
	binding, ok := request.Context().Value(gatewayOAuthDispatchBindingKey{}).(gatewayOAuthDispatchBinding)
	if !ok || state.account != a || state.oauth == nil || request.Method != http.MethodPost || request.URL.String() != GatewayCodexOAuthBaseURL+"/responses" || request.Header.Get("Authorization") != "" || request.Header.Get("ChatGPT-Account-Id") != "" {
		return noop, ErrGatewayNativeIdentity
	}
	fresh, p, release, err := binding.dispatch.repository.LockGatewayNativeOAuthDispatch(request.Context(), binding.scope, binding.operation, state.route.AccountID)
	if err != nil || release == nil {
		return noop, ErrGatewayNativeIdentity
	}
	deny := func() (func(), error) { release(); return noop, ErrGatewayNativeIdentity }
	if gatewayOAuthPhysicalValid(fresh, p) != nil || p.QualifiedAt.IsZero() || !sameGatewayOAuthPhysical(p, *state.oauth) || !GatewayNativeOAuthScopeAuthorized(request.Context(), p.Scope) {
		return deny()
	}
	version, err := gatewayOAuthCredentialVersion(fresh)
	if err != nil {
		return deny()
	}
	// Refresh may advance the encrypted version between admission and entry.
	// Read/decrypt only this fresh locked version, never snapshot-token DeepEqual.
	bounded, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	bundle, err := binding.dispatch.custody.openOAuthVersion(fresh.GetCredential("oauth_bundle"), p.Scope, version)
	if err != nil {
		return deny()
	}
	identity, err := binding.dispatch.verifier.Verify(bounded, bundle.IDToken)
	issuer, subject := identity.Principal()
	if err != nil || issuer != p.Issuer || subject != p.Subject {
		return deny()
	}
	if p.RefreshFence == nil || p.RefreshFence.Check(request.Context()) != nil {
		return deny()
	}
	if fresh.ExpiresAt != nil && !fresh.ExpiresAt.After(time.Now()) {
		return deny()
	}
	if !gatewayNativeEntered(request.Context(), &state.entered) {
		release()
		return noop, ErrGatewayNativeReplay
	}
	request.Header = make(http.Header)
	request.Header.Set("Authorization", "Bearer "+bundle.AccessToken)
	request.Header.Set("ChatGPT-Account-Id", p.ProviderAccount)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.GetBody = nil
	return release, nil
}
