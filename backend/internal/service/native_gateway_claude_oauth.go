package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/google/uuid"
)

const GatewayClaudeOAuthMessagesProfile = "anthropic-claude-oauth-messages-v1"
const GatewayClaudeOAuthBaseURL = "https://api.anthropic.com"
const GatewayClaudeOAuthModel = "claude-sonnet-4-6"
const GatewayClaudeOAuthIssuer = "https://claude.com"

// Private source-owned intent and qualification. Plaintext provider credentials
// never enter repository input, browser DTOs, or the Gateway wire.
type GatewayClaudeConnectIntent struct {
	Scope                                 GatewayNativeCredentialScope
	Operation, StateHash, Envelope, State string
	Deadline                              time.Time
}

type GatewayClaudeIdentity struct{ account, organization string }

func (i GatewayClaudeIdentity) Principal() (string, string) { return i.account, i.organization }
func (i GatewayClaudeIdentity) Verified() bool              { return i.account != "" && i.organization != "" }

type GatewayClaudeEnrollment struct {
	Intent   GatewayClaudeConnectIntent
	Identity GatewayClaudeIdentity
	Envelope string
}

// All reads authenticate the exact owner/consumer/generation and durable birth.
// Intent claim and refresh claim must commit before a provider effect, and may
// never grant a second entry after an uncertain exchange. LockPhysical retains
// its SQL lock until Release, fencing refresh/erase through dispatch. Passive
// publication then reacquires and checks the exact birth/principal/revision.
type GatewayNativeClaudeRepository interface {
	PutGatewayClaudeConnect(context.Context, GatewayClaudeConnectIntent) (GatewayClaudeConnectIntent, error)
	ReadGatewayClaudeConnect(context.Context, GatewayNativeCredentialScope, string) (GatewayClaudeConnectIntent, error)
	ClaimGatewayClaudeConnect(context.Context, GatewayNativeCredentialScope, string, string) (GatewayClaudeConnectIntent, error)
	CompleteGatewayClaudeConnect(context.Context, GatewayClaudeEnrollment) (GatewayNativeOAuthOutcome, error)
	LockGatewayClaudePhysical(context.Context, GatewayNativeCredentialScope, string, *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error)
	LockGatewayClaudeMaintenance(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthPhysical, string, string, string, func(), error)
	ReadGatewayClaudeRefresh(context.Context, GatewayNativeCredentialScope, string, string) (GatewayNativeOAuthRefreshOutcome, bool, error)
	ClaimGatewayClaudeRefresh(context.Context, GatewayNativeCredentialScope, string, string, int64) (GatewayNativeOAuthPhysical, string, bool, error)
	CompleteGatewayClaudeRefresh(context.Context, GatewayNativeOAuthPhysical, string, string) error
	CleanupGatewayClaude(context.Context, GatewayNativeOAuthCleanupRequest, GatewayNativeOAuthCleanupAuthorizer) (GatewayNativeOAuthCleanupResult, error)
	StoreGatewayClaudeLimits(context.Context, GatewayNativeOAuthPhysical, GatewayClaudeRawLimits, time.Time) error
	ReadGatewayClaudeLimits(context.Context, GatewayNativeCredentialScope, GatewayNativeRoute) (GatewayAccountLimitsStored, error)
	ResolveGatewayClaudeCanonical(context.Context, GatewayNativeRoute, string) (GatewayNativeCredentialScope, string, error)
}

type GatewayNativeClaudeDispatchEntry struct {
	AccessToken string
	Physical    GatewayNativeOAuthPhysical
	Release     func()
	Claim       func() bool
	// Captured only for this admitted response. Transport passes the real
	// response receipt instant; reading the cache cannot call this writer.
	CaptureLimits func(context.Context, map[string][]string, time.Time)
}

type gatewayClaudeBundle struct {
	Kind         string    `json:"kind"`
	Revision     int64     `json:"revision"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Account      string    `json:"account"`
	Organization string    `json:"organization"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type gatewayClaudeConnectSecret struct {
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Verifier string `json:"verifier"`
}

type GatewayNativeClaudeOAuth struct {
	repository                 GatewayNativeClaudeRepository
	custody                    *GatewayNativeCredentialCustody
	client                     *http.Client
	connectEntry, refreshEntry GatewayNativeOAuthEntryAuthorizer
}

func NewGatewayNativeClaudeOAuth(repo GatewayNativeClaudeRepository, custody *GatewayNativeCredentialCustody, transport http.RoundTripper) (*GatewayNativeClaudeOAuth, error) {
	if repo == nil || !GatewayNativeCredentialCustodyReady(custody) {
		return nil, ErrGatewayNativeIdentity
	}
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192}
	}
	return &GatewayNativeClaudeOAuth{repository: repo, custody: custody, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}}, nil
}

func (s *GatewayNativeClaudeOAuth) SetEntryAuthorizers(connect, refresh GatewayNativeOAuthEntryAuthorizer) error {
	if s == nil || connect == nil || refresh == nil || s.connectEntry != nil || s.refreshEntry != nil {
		return ErrGatewayNativeIdentity
	}
	s.connectEntry, s.refreshEntry = connect, refresh
	return nil
}

func claudeScope(ctx context.Context, scope GatewayNativeCredentialScope, operation string) bool {
	return GatewayNativeOAuthScopeAuthorized(ctx, scope) && GatewayNativeCredentialRefValid(operation)
}

func (s *GatewayNativeClaudeOAuth) open(scope GatewayNativeCredentialScope, envelope string, target any) error {
	id, nonce, sealed, err := gatewayOAuthParseEnvelope(envelope)
	if err != nil || s == nil || s.custody.keys[id] == nil || !GatewayNativeOAuthScopeValid(scope) {
		return ErrGatewayNativeIdentity
	}
	raw, err := s.custody.keys[id].Open(nil, nonce, sealed, gatewayOAuthAAD(scope, id))
	if err != nil {
		return ErrGatewayNativeIdentity
	}
	defer clear(raw)
	if _, err := gatewayOAuthJSON(raw); err != nil {
		return ErrGatewayNativeIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrGatewayNativeIdentity
	}
	return nil
}

func (s *GatewayNativeClaudeOAuth) seal(scope GatewayNativeCredentialScope, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	defer clear(raw)
	return s.custody.sealOAuthBytes(scope, raw)
}

func (s *GatewayNativeClaudeOAuth) BeginConnectMethod(ctx context.Context, scope GatewayNativeCredentialScope, operation, method string) (GatewayNativeOAuthConnectResult, error) {
	var empty GatewayNativeOAuthConnectResult
	if s == nil || !claudeScope(ctx, scope, operation) || method != "browser" {
		return empty, ErrGatewayNativeIdentity
	}
	state, verifier := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	if _, err := rand.Read(verifier); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	secret := gatewayClaudeConnectSecret{Kind: "claude-connect/v1", State: hex.EncodeToString(state), Verifier: base64.RawURLEncoding.EncodeToString(verifier)}
	envelope, err := s.seal(scope, secret)
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256([]byte(secret.State))
	in, err := s.repository.PutGatewayClaudeConnect(ctx, GatewayClaudeConnectIntent{Scope: scope, Operation: operation, StateHash: hex.EncodeToString(digest[:]), Envelope: envelope, State: "prepared", Deadline: time.Now().UTC().Add(10 * time.Minute)})
	if err != nil {
		return empty, err
	}
	out := claudeConnectView(in)
	if in.State != "prepared" || !time.Now().Before(in.Deadline) {
		return out, nil
	}
	if s.open(scope, in.Envelope, &secret) != nil || secret.Kind != "claude-connect/v1" {
		return empty, ErrGatewayNativeIdentity
	}
	challenge := sha256.Sum256([]byte(secret.Verifier))
	q := url.Values{"code": {"true"}, "client_id": {oauth.ClientID}, "response_type": {"code"}, "redirect_uri": {oauth.RedirectURI}, "scope": {oauth.ScopeAPI}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}, "state": {secret.State}}
	out.AuthorizeURL = oauth.AuthorizeURL + "?" + q.Encode()
	out.Method = "browser"
	return out, nil
}
func claudeConnectView(in GatewayClaudeConnectIntent) GatewayNativeOAuthConnectResult {
	state := in.State
	if state == "prepared" {
		state = "prepared"
		if !time.Now().Before(in.Deadline) {
			state = "expired"
		}
	}
	if state == "exchanging" || state == "erased" {
		state = "unknown"
	}
	out := GatewayNativeOAuthConnectResult{Operation: in.Operation, Account: in.Scope.Account, State: state, Method: "browser"}
	if in.State == "completed" {
		out.Outcome = "staged"
	}
	return out
}
func (s *GatewayNativeClaudeOAuth) ReadConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !claudeScope(ctx, scope, operation) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadGatewayClaudeConnect(ctx, scope, operation)
	return claudeConnectView(in), err
}

func (s *GatewayNativeClaudeOAuth) CompleteOwnerCallback(ctx context.Context, scope GatewayNativeCredentialScope, operation, state, code string) (GatewayNativeOAuthConnectResult, error) {
	var empty GatewayNativeOAuthConnectResult
	if s == nil || !claudeScope(ctx, scope, operation) || len(state) != 64 || !connectCodeValid(code) {
		return empty, ErrGatewayNativeIdentity
	}
	if i := strings.IndexByte(code, '#'); i >= 0 {
		if code[i+1:] != state {
			return empty, ErrGatewayNativeIdentity
		}
		code = code[:i]
	}
	if !connectCodeValid(code) {
		return empty, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadGatewayClaudeConnect(ctx, scope, operation)
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256([]byte(state))
	if hex.EncodeToString(digest[:]) != in.StateHash {
		return empty, ErrGatewayNativeIdentity
	}
	if in.State == "completed" {
		return claudeConnectView(in), nil
	}
	if s.connectEntry == nil || s.connectEntry(ctx, scope, operation) != nil {
		return empty, ErrGatewayNativeIdentity
	}
	in, err = s.repository.ClaimGatewayClaudeConnect(ctx, scope, operation, in.StateHash)
	if err != nil {
		return empty, err
	}
	var secret gatewayClaudeConnectSecret
	if s.open(scope, in.Envelope, &secret) != nil || secret.Kind != "claude-connect/v1" || secret.State != state {
		return empty, ErrGatewayNativeIdentity
	}
	bundle, err := s.exchange(ctx, map[string]any{"code": code, "state": state, "grant_type": "authorization_code", "client_id": oauth.ClientID, "redirect_uri": oauth.RedirectURI, "code_verifier": secret.Verifier}, nil)
	if err != nil {
		return empty, err
	}
	if s.connectEntry(ctx, scope, operation) != nil {
		return empty, ErrGatewayNativeIdentity
	}
	envelope, err := s.seal(scope, bundle)
	if err != nil {
		return empty, err
	}
	_, err = s.repository.CompleteGatewayClaudeConnect(ctx, GatewayClaudeEnrollment{Intent: in, Identity: GatewayClaudeIdentity{bundle.Account, bundle.Organization}, Envelope: envelope})
	if err != nil {
		return empty, err
	}
	return s.ReadConnect(ctx, scope, operation)
}

func claudeUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
func claudeToken(value string) bool {
	if len(value) == 0 || len(value) > 32768 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *GatewayNativeClaudeOAuth) exchange(ctx context.Context, body map[string]any, previous *gatewayClaudeBundle) (gatewayClaudeBundle, error) {
	var empty gatewayClaudeBundle
	raw, _ := json.Marshal(body)
	defer clear(raw)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauth.TokenURL, bytes.NewReader(raw))
	if err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	started := time.Now().UTC()
	res, err := s.client.Do(req)
	if err != nil || res == nil || res.Body == nil {
		return empty, ErrGatewayNativeIdentity
	}
	defer func() { _ = res.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer clear(response)
	if err != nil || len(response) > 65536 || res.StatusCode != http.StatusOK || res.Request == nil || res.Request.URL.String() != oauth.TokenURL {
		return empty, ErrGatewayNativeIdentity
	}
	claims, err := gatewayOAuthJSON(response)
	if err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	for _, key := range []string{"account", "organization"} {
		if raw, exists := claims[key]; exists {
			if _, err := gatewayOAuthJSON(raw); err != nil {
				return empty, ErrGatewayNativeIdentity
			}
		}
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Account      *struct {
			UUID string `json:"uuid"`
		} `json:"account"`
		Organization *struct {
			UUID string `json:"uuid"`
		} `json:"organization"`
	}
	if json.Unmarshal(response, &token) != nil || !claudeToken(token.AccessToken) || !claudeToken(token.RefreshToken) || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 90*24*60*60 {
		return empty, ErrGatewayNativeIdentity
	}
	hasInference := false
	for _, scope := range strings.Fields(token.Scope) {
		if scope == "user:inference" {
			hasInference = true
		}
	}
	if !hasInference {
		return empty, ErrGatewayNativeIdentity
	}
	b := gatewayClaudeBundle{Kind: "claude-oauth/v1", Revision: 1, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: started.Add(time.Duration(token.ExpiresIn) * time.Second)}
	if previous != nil {
		b.Account, b.Organization = previous.Account, previous.Organization
		b.Revision = previous.Revision + 1
	}
	if token.Account != nil {
		if previous != nil && token.Account.UUID != previous.Account {
			return empty, ErrGatewayNativeIdentity
		}
		b.Account = token.Account.UUID
	}
	if token.Organization != nil {
		if previous != nil && token.Organization.UUID != previous.Organization {
			return empty, ErrGatewayNativeIdentity
		}
		b.Organization = token.Organization.UUID
	}
	if !claudeUUID(b.Account) || !claudeUUID(b.Organization) {
		return empty, ErrGatewayNativeIdentity
	}
	return b, nil
}

func (s *GatewayNativeClaudeOAuth) bundle(scope GatewayNativeCredentialScope, envelope string, p GatewayNativeOAuthPhysical) (gatewayClaudeBundle, error) {
	var b gatewayClaudeBundle
	if s.open(scope, envelope, &b) != nil || b.Kind != "claude-oauth/v1" || b.Revision < 1 || b.Revision != p.CredentialRevision || !claudeToken(b.AccessToken) || !claudeToken(b.RefreshToken) || !claudeUUID(b.Account) || !claudeUUID(b.Organization) || b.Account != p.Subject || b.Organization != p.ProviderAccount || p.Issuer != GatewayClaudeOAuthIssuer || b.ExpiresAt.IsZero() {
		return b, ErrGatewayNativeIdentity
	}
	return b, nil
}

func (s *GatewayNativeClaudeOAuth) Descriptor(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthDescriptorResult, error) {
	var out GatewayNativeOAuthDescriptorResult
	if s == nil || !claudeScope(ctx, scope, operation) {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayClaudePhysical(ctx, scope, operation, nil)
	if err != nil {
		return out, err
	}
	defer release()
	if _, err = s.bundle(scope, envelope, p); err != nil {
		return out, err
	}
	return GatewayNativeOAuthDescriptorResult{Operation: operation, Account: scope.Account, State: "staged", Qualification: "controlled-source-v1", Native: &p.Route}, nil
}

func (s *GatewayNativeClaudeOAuth) Enter(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route GatewayNativeRoute) (GatewayNativeClaudeDispatchEntry, error) {
	var out GatewayNativeClaudeDispatchEntry
	if s == nil || !claudeScope(ctx, scope, operation) || route.Profile != GatewayClaudeOAuthMessagesProfile || route.BaseURL != GatewayClaudeOAuthBaseURL || route.Model != GatewayClaudeOAuthModel {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayClaudePhysical(ctx, scope, operation, &route)
	if err != nil {
		return out, err
	}
	b, err := s.bundle(scope, envelope, p)
	if err != nil || !time.Now().Before(b.ExpiresAt) {
		release()
		return out, ErrGatewayNativeIdentity
	}
	var claimed atomic.Bool
	var once sync.Once
	var mu sync.Mutex
	var pending GatewayClaudeRawLimits
	var receipt time.Time
	released := false
	out = GatewayNativeClaudeDispatchEntry{AccessToken: b.AccessToken, Physical: p, Claim: func() bool { return claimed.CompareAndSwap(false, true) }}
	out.Release = func() {
		once.Do(func() {
			mu.Lock()
			released = true
			raw, observed := pending, receipt
			mu.Unlock()
			release()
			if len(raw.Windows) > 0 {
				bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				defer cancel()
				_ = s.repository.StoreGatewayClaudeLimits(bounded, p, raw, observed)
			}
		})
	}
	out.CaptureLimits = func(_ context.Context, headers map[string][]string, observed time.Time) {
		if !claimed.Load() {
			return
		}
		raw := CaptureGatewayClaudeLimits(http.Header(headers), observed)
		if len(raw.Windows) == 0 {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !released && len(pending.Windows) == 0 {
			pending, receipt = raw, observed
		}
	}

	return out, nil
}

func (s *GatewayNativeClaudeOAuth) Refresh(ctx context.Context, scope GatewayNativeCredentialScope, connectOperation, refreshOperation string) (GatewayNativeOAuthRefreshOutcome, error) {
	var out GatewayNativeOAuthRefreshOutcome
	if s == nil || !claudeScope(ctx, scope, connectOperation) || !GatewayNativeCredentialRefValid(refreshOperation) || s.refreshEntry == nil || s.refreshEntry(ctx, scope, connectOperation) != nil {
		return out, ErrGatewayNativeIdentity
	}
	saved, found, err := s.repository.ReadGatewayClaudeRefresh(ctx, scope, connectOperation, refreshOperation)
	if err != nil {
		return out, err
	}
	if found {
		return saved, nil
	}
	p0, env0, release, err := s.repository.LockGatewayClaudePhysical(ctx, scope, connectOperation, nil)
	if err != nil {
		return out, err
	}
	prior, err := s.bundle(scope, env0, p0)
	release()
	if err != nil {
		return out, err
	}
	if time.Now().Add(5 * time.Minute).Before(prior.ExpiresAt) {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "idle", Version: p0.CredentialRevision}, nil
	}
	p, envelope, claimed, err := s.repository.ClaimGatewayClaudeRefresh(ctx, scope, connectOperation, refreshOperation, p0.CredentialRevision)
	if err != nil {
		return out, err
	}
	if !claimed {
		saved, found, readErr := s.repository.ReadGatewayClaudeRefresh(ctx, scope, connectOperation, refreshOperation)
		if readErr != nil || !found {
			return out, ErrGatewayNativeIdentity
		}
		return saved, nil
	}
	previous, err := s.bundle(scope, envelope, p)
	if err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	if s.refreshEntry(ctx, scope, connectOperation) != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, ErrGatewayNativeIdentity
	}
	b, err := s.exchange(ctx, map[string]any{"grant_type": "refresh_token", "refresh_token": previous.RefreshToken, "client_id": oauth.ClientID}, &previous)
	if err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	next, err := s.seal(scope, b)
	if err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	if s.refreshEntry(ctx, scope, connectOperation) != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, ErrGatewayNativeIdentity
	}
	if err = s.repository.CompleteGatewayClaudeRefresh(ctx, p, refreshOperation, next); err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "completed", Version: p.CredentialRevision + 1}, nil
}

func (s *GatewayNativeClaudeOAuth) RetainedCustody(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route GatewayNativeRoute) (GatewayNativeRetainedCustodyResult, error) {
	var out GatewayNativeRetainedCustodyResult
	if s == nil || !claudeScope(ctx, scope, operation) {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayClaudePhysical(ctx, scope, operation, &route)
	if err != nil {
		return out, err
	}
	defer release()
	b, err := s.bundle(scope, envelope, p)
	if err != nil {
		return out, err
	}
	out = retainedCustodyResult(route, GatewayNativeRetainedCustodyOAuthKind, "inactive")
	eligibility := "not-due-by-existing-policy"
	if !time.Now().Add(5 * time.Minute).Before(b.ExpiresAt) {
		eligibility = "eligible-by-existing-policy"
	}
	out.OAuthPolicy = &GatewayNativeOAuthRetentionPolicy{ProviderValidity: "unasserted", ExpiredButRefreshable: eligibility}
	return out, nil
}

func (s *GatewayNativeClaudeOAuth) Cleanup(ctx context.Context, in GatewayNativeOAuthCleanupRequest, authorize GatewayNativeOAuthCleanupAuthorizer) (GatewayNativeOAuthCleanupResult, error) {
	if s == nil || !claudeScope(ctx, in.Scope, in.Operation) || !GatewayNativeOAuthCleanupRequestValid(in) || authorize == nil {
		return GatewayNativeOAuthCleanupResult{}, ErrGatewayNativeIdentity
	}
	return s.repository.CleanupGatewayClaude(ctx, in, authorize)
}

// Maintain resolves the original exact generation; operation is a one-use durable
// refresh intent owned by the facade, not a selector for a latest account.
func (s *GatewayNativeClaudeOAuth) Maintain(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthMaintenanceOutcome, error) {
	out := GatewayNativeOAuthMaintenanceOutcome{Operation: operation, AccountRef: scope.Account, State: "idle"}
	if s == nil || !claudeScope(ctx, scope, operation) || s.refreshEntry == nil || s.refreshEntry(ctx, scope, operation) != nil {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, state, attempt, release, err := s.repository.LockGatewayClaudeMaintenance(ctx, scope, operation)
	if err != nil {
		return out, err
	}
	if state == "exchanging" {
		release()
		out.State = "unknown"
		out.RefreshRef = attempt
		return out, nil
	}
	previous, err := s.bundle(scope, envelope, p)
	release()
	if err != nil {
		return out, err
	}
	if time.Now().Add(5 * time.Minute).Before(previous.ExpiresAt) {
		if attempt != "" {
			out.State = "completed"
			out.RefreshRef = attempt
		}
		return out, nil
	}
	rotation := gatewayOAuthRotation(scope, p.Route.AccountID, p.Route.CreatedAt, p.CredentialRevision)
	attempt = "claude-" + rotation.Operation
	result, err := s.Refresh(ctx, scope, operation, attempt)
	out.State = result.State
	out.RefreshRef = attempt
	return out, err
}
