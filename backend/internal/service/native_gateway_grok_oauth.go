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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
)

const GatewayGrokOAuthResponsesProfile = "grok-subscription-responses-oauth-v1"
const GatewayGrokOAuthBaseURL = "https://cli-chat-proxy.grok.com"
const GatewayGrokOAuthModel = "grok-4.7"
const GatewayGrokOAuthIssuer = "https://auth.x.ai"

// Private source-owned intent and qualification. Plaintext provider credentials
// never enter repository input, browser DTOs, or the Gateway wire.
type GatewayGrokConnectIntent struct {
	Scope                                 GatewayNativeCredentialScope
	Operation, StateHash, Envelope, State string
	Deadline                              time.Time
}

type GatewayGrokIdentity struct{ subject, team string }

func (i GatewayGrokIdentity) Principal() (string, string) { return i.subject, i.team }
func (i GatewayGrokIdentity) Verified() bool {
	return grokPrincipal(i.subject) && grokPrincipal(i.team)
}

type GatewayGrokEnrollment struct {
	Intent   GatewayGrokConnectIntent
	Identity GatewayGrokIdentity
	Envelope string
}

// All reads authenticate the exact owner/consumer/generation and durable birth.
// Intent claim and refresh claim must commit before a provider effect, and may
// never grant a second entry after an uncertain exchange. LockPhysical retains
// its SQL lock until Release, fencing refresh/erase through dispatch. Passive
// publication then reacquires and checks the exact birth/principal/revision.
type GatewayNativeGrokRepository interface {
	PutGatewayGrokConnect(context.Context, GatewayGrokConnectIntent) (GatewayGrokConnectIntent, error)
	ReadGatewayGrokConnect(context.Context, GatewayNativeCredentialScope, string) (GatewayGrokConnectIntent, error)
	ClaimGatewayGrokConnect(context.Context, GatewayNativeCredentialScope, string, string) (GatewayGrokConnectIntent, error)
	CompleteGatewayGrokConnect(context.Context, GatewayGrokEnrollment) (GatewayNativeOAuthOutcome, error)
	LockGatewayGrokPhysical(context.Context, GatewayNativeCredentialScope, string, *GatewayNativeRoute) (GatewayNativeOAuthPhysical, string, func(), error)
	LockGatewayGrokMaintenance(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthPhysical, string, string, string, func(), error)
	ReadGatewayGrokRefresh(context.Context, GatewayNativeCredentialScope, string, string) (GatewayNativeOAuthRefreshOutcome, bool, error)
	ClaimGatewayGrokRefresh(context.Context, GatewayNativeCredentialScope, string, string, int64) (GatewayNativeOAuthPhysical, string, bool, error)
	CompleteGatewayGrokRefresh(context.Context, GatewayNativeOAuthPhysical, string, string) error
	CleanupGatewayGrok(context.Context, GatewayNativeOAuthCleanupRequest, GatewayNativeOAuthCleanupAuthorizer) (GatewayNativeOAuthCleanupResult, error)
	ResolveGatewayGrokCanonical(context.Context, GatewayNativeRoute, string) (GatewayNativeCredentialScope, string, error)
	ListGatewayGrokQuotaAccounts(context.Context) ([]GatewayNativeOAuthPhysical, error)
}

type GatewayNativeGrokDispatchEntry struct {
	AccessToken string
	Physical    GatewayNativeOAuthPhysical
	Release     func()
	Claim       func() bool
}

type gatewayGrokBundle struct {
	Kind         string    `json:"kind"`
	Revision     int64     `json:"revision"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Subject      string    `json:"subject"`
	Team         string    `json:"team"`
	ExpiresAt    time.Time `json:"expires_at"`
	Nonce        string    `json:"nonce"`
	ClientID     string    `json:"client_id"`
}
type gatewayGrokConnectSecret struct {
	Kind        string `json:"kind"`
	State       string `json:"state"`
	Verifier    string `json:"verifier"`
	Nonce       string `json:"nonce"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

type GatewayNativeGrokOAuth struct {
	repository                 GatewayNativeGrokRepository
	custody                    *GatewayNativeCredentialCustody
	client                     *http.Client
	qualification              GatewayNativeGrokOAuthQualification
	connectEntry, refreshEntry GatewayNativeOAuthEntryAuthorizer
}

func NewGatewayNativeGrokOAuth(repo GatewayNativeGrokRepository, custody *GatewayNativeCredentialCustody, transport http.RoundTripper, qualification GatewayNativeGrokOAuthQualification) (*GatewayNativeGrokOAuth, error) {
	if repo == nil || !GatewayNativeCredentialCustodyReady(custody) || !qualification.valid() {
		return nil, ErrGatewayNativeIdentity
	}
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192}
	}
	return &GatewayNativeGrokOAuth{repository: repo, custody: custody, qualification: qualification, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}}, nil
}

func (s *GatewayNativeGrokOAuth) SetEntryAuthorizers(connect, refresh GatewayNativeOAuthEntryAuthorizer) error {
	if s == nil || connect == nil || refresh == nil || s.connectEntry != nil || s.refreshEntry != nil {
		return ErrGatewayNativeIdentity
	}
	s.connectEntry, s.refreshEntry = connect, refresh
	return nil
}

func grokScope(ctx context.Context, scope GatewayNativeCredentialScope, operation string) bool {
	return GatewayNativeOAuthScopeAuthorized(ctx, scope) && GatewayNativeCredentialRefValid(operation)
}

func (s *GatewayNativeGrokOAuth) open(scope GatewayNativeCredentialScope, envelope string, target any) error {
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

func (s *GatewayNativeGrokOAuth) seal(scope GatewayNativeCredentialScope, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	defer clear(raw)
	return s.custody.sealOAuthBytes(scope, raw)
}

func (s *GatewayNativeGrokOAuth) BeginConnectMethod(ctx context.Context, scope GatewayNativeCredentialScope, operation, method string) (GatewayNativeOAuthConnectResult, error) {
	var empty GatewayNativeOAuthConnectResult
	if s == nil || !grokScope(ctx, scope, operation) || method != "browser" {
		return empty, ErrGatewayNativeIdentity
	}
	state, verifier := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	if _, err := rand.Read(verifier); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	secret := gatewayGrokConnectSecret{Kind: "grok-connect/v1", State: hex.EncodeToString(state), Verifier: base64.RawURLEncoding.EncodeToString(verifier), Nonce: base64.RawURLEncoding.EncodeToString(nonce), ClientID: s.qualification.ClientID, RedirectURI: s.qualification.RedirectURI}
	envelope, err := s.seal(scope, secret)
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256([]byte(secret.State))
	in, err := s.repository.PutGatewayGrokConnect(ctx, GatewayGrokConnectIntent{Scope: scope, Operation: operation, StateHash: hex.EncodeToString(digest[:]), Envelope: envelope, State: "prepared", Deadline: time.Now().UTC().Add(10 * time.Minute)})
	if err != nil {
		return empty, err
	}
	out := grokConnectView(in)
	if in.State != "prepared" || !time.Now().Before(in.Deadline) {
		return out, nil
	}
	if s.open(scope, in.Envelope, &secret) != nil || !s.connectSecretValid(secret) {
		return empty, ErrGatewayNativeIdentity
	}
	challenge := sha256.Sum256([]byte(secret.Verifier))
	q := url.Values{"client_id": {secret.ClientID}, "response_type": {"code"}, "redirect_uri": {secret.RedirectURI}, "scope": {xai.DefaultScope}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}, "state": {secret.State}, "nonce": {secret.Nonce}}
	out.AuthorizeURL = xai.DefaultAuthorizeURL + "?" + q.Encode()
	out.Method = "browser"
	return out, nil
}
func grokConnectView(in GatewayGrokConnectIntent) GatewayNativeOAuthConnectResult {
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
func (s *GatewayNativeGrokOAuth) ReadConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !grokScope(ctx, scope, operation) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadGatewayGrokConnect(ctx, scope, operation)
	return grokConnectView(in), err
}

// GatewayNativeGrokCompletionFields reuses the existing lossless OAuth JSON
// codec for transient Grok-only ingress (including duplicate/surrogate denial).
func GatewayNativeGrokCompletionFields(raw []byte) (map[string]json.RawMessage, bool) {
	fields, err := gatewayOAuthJSON(raw)
	return fields, err == nil
}

func GatewayNativeGrokAuthorizationCodeValid(code string) bool {
	return connectCodeValid(code) && !strings.ContainsAny(code, "#?&")
}

// CompleteOwnerCode retrieves original state only from the scoped sealed intent.
// Uncertain or completed operations are readback only, never a fresh exchange.
func (s *GatewayNativeGrokOAuth) CompleteOwnerCode(ctx context.Context, scope GatewayNativeCredentialScope, operation, code string) (GatewayNativeOAuthConnectResult, error) {
	var empty GatewayNativeOAuthConnectResult
	if s == nil || !grokScope(ctx, scope, operation) || !GatewayNativeGrokAuthorizationCodeValid(code) {
		return empty, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadGatewayGrokConnect(ctx, scope, operation)
	if err != nil || in.Scope != scope || in.Operation != operation {
		return empty, ErrGatewayNativeIdentity
	}
	switch in.State {
	case "completed", "exchanging", "erased":
		return grokConnectView(in), nil
	case "prepared":
		if !time.Now().Before(in.Deadline) {
			return grokConnectView(in), nil
		}
	default:
		return empty, ErrGatewayNativeIdentity
	}
	var secret gatewayGrokConnectSecret
	if s.open(scope, in.Envelope, &secret) != nil || !s.connectSecretValid(secret) || !GatewayNativeOAuthConnectCallbackValid(secret.State, code) {
		return empty, ErrGatewayNativeIdentity
	}
	digest := sha256.Sum256([]byte(secret.State))
	if hex.EncodeToString(digest[:]) != in.StateHash {
		return empty, ErrGatewayNativeIdentity
	}
	return s.CompleteOwnerCallback(ctx, scope, operation, secret.State, code)
}

func (s *GatewayNativeGrokOAuth) CompleteOwnerCallback(ctx context.Context, scope GatewayNativeCredentialScope, operation, state, code string) (GatewayNativeOAuthConnectResult, error) {
	var empty GatewayNativeOAuthConnectResult
	if s == nil || !grokScope(ctx, scope, operation) || len(state) != 64 || !connectCodeValid(code) || strings.ContainsAny(code, "#?&") {
		return empty, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadGatewayGrokConnect(ctx, scope, operation)
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256([]byte(state))
	if hex.EncodeToString(digest[:]) != in.StateHash {
		return empty, ErrGatewayNativeIdentity
	}
	if in.State == "completed" {
		return grokConnectView(in), nil
	}
	if s.connectEntry == nil || s.connectEntry(ctx, scope, operation) != nil {
		return empty, ErrGatewayNativeIdentity
	}
	in, err = s.repository.ClaimGatewayGrokConnect(ctx, scope, operation, in.StateHash)
	if err != nil {
		return empty, err
	}
	var secret gatewayGrokConnectSecret
	if s.open(scope, in.Envelope, &secret) != nil || !s.connectSecretValid(secret) || secret.State != state {
		return empty, ErrGatewayNativeIdentity
	}
	bundle, err := s.exchange(ctx, url.Values{"code": {code}, "grant_type": {"authorization_code"}, "client_id": {secret.ClientID}, "redirect_uri": {secret.RedirectURI}, "code_verifier": {secret.Verifier}}, secret.Nonce, nil)
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
	_, err = s.repository.CompleteGatewayGrokConnect(ctx, GatewayGrokEnrollment{Intent: in, Identity: GatewayGrokIdentity{bundle.Subject, bundle.Team}, Envelope: envelope})
	if err != nil {
		return empty, err
	}
	return s.ReadConnect(ctx, scope, operation)
}

func grokToken(value string) bool {
	if len(value) == 0 || len(value) > 32768 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r > 127 {
			return false
		}
	}
	return true
}

func (s *GatewayNativeGrokOAuth) bundle(scope GatewayNativeCredentialScope, envelope string, p GatewayNativeOAuthPhysical) (gatewayGrokBundle, error) {
	var b gatewayGrokBundle
	if !grokPhysicalValid(p, scope, p.Operation, nil) || s.open(scope, envelope, &b) != nil || b.Kind != "grok-oauth/v1" || b.Revision < 1 || b.Revision != p.CredentialRevision || !grokToken(b.AccessToken) || !grokToken(b.RefreshToken) || !grokPrincipal(b.Subject) || !grokPrincipal(b.Team) || b.Subject != p.Subject || b.Team != p.ProviderAccount || p.Issuer != GatewayGrokOAuthIssuer || b.ExpiresAt.IsZero() || len(b.Nonce) != 43 || b.ClientID != s.qualification.ClientID {
		return b, ErrGatewayNativeIdentity
	}
	return b, nil
}

func (s *GatewayNativeGrokOAuth) Descriptor(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthDescriptorResult, error) {
	var out GatewayNativeOAuthDescriptorResult
	if s == nil || !grokScope(ctx, scope, operation) {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayGrokPhysical(ctx, scope, operation, nil)
	if err != nil {
		return out, err
	}
	if release == nil || !grokPhysicalValid(p, scope, operation, nil) {
		if release != nil {
			release()
		}
		return out, ErrGatewayNativeIdentity
	}
	defer release()
	if _, err = s.bundle(scope, envelope, p); err != nil {
		return out, err
	}
	return GatewayNativeOAuthDescriptorResult{Operation: operation, Account: scope.Account, State: "staged", Qualification: "controlled-source-v1", Native: &p.Route}, nil
}

func (s *GatewayNativeGrokOAuth) Enter(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route GatewayNativeRoute) (GatewayNativeGrokDispatchEntry, error) {
	var out GatewayNativeGrokDispatchEntry
	if s == nil || !grokScope(ctx, scope, operation) || route.Profile != GatewayGrokOAuthResponsesProfile || route.BaseURL != GatewayGrokOAuthBaseURL || route.Model != GatewayGrokOAuthModel {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayGrokPhysical(ctx, scope, operation, &route)
	if err != nil {
		return out, err
	}
	if release == nil || !grokPhysicalValid(p, scope, operation, &route) {
		if release != nil {
			release()
		}
		return out, ErrGatewayNativeIdentity
	}
	b, err := s.bundle(scope, envelope, p)
	if err != nil || !time.Now().Before(b.ExpiresAt) {
		release()
		return out, ErrGatewayNativeIdentity
	}

	var claimed atomic.Bool
	var lifecycle sync.Mutex
	released := false
	out = GatewayNativeGrokDispatchEntry{AccessToken: b.AccessToken, Physical: p}
	out.Release = func() {
		lifecycle.Lock()
		defer lifecycle.Unlock()
		if !released {
			released = true
			release()
		}
	}
	out.Claim = func() bool {
		lifecycle.Lock()
		defer lifecycle.Unlock()
		return !released && time.Now().Before(b.ExpiresAt) && claimed.CompareAndSwap(false, true)
	}

	return out, nil
}

func (s *GatewayNativeGrokOAuth) Refresh(ctx context.Context, scope GatewayNativeCredentialScope, connectOperation, refreshOperation string) (GatewayNativeOAuthRefreshOutcome, error) {
	var out GatewayNativeOAuthRefreshOutcome
	if s == nil || !grokScope(ctx, scope, connectOperation) || !GatewayNativeCredentialRefValid(refreshOperation) || s.refreshEntry == nil || s.refreshEntry(ctx, scope, connectOperation) != nil {
		return out, ErrGatewayNativeIdentity
	}
	saved, found, err := s.repository.ReadGatewayGrokRefresh(ctx, scope, connectOperation, refreshOperation)
	if err != nil {
		return out, err
	}
	if found {
		return saved, nil
	}
	p0, env0, release, err := s.repository.LockGatewayGrokPhysical(ctx, scope, connectOperation, nil)
	if err != nil {
		return out, err
	}
	if release == nil || !grokPhysicalValid(p0, scope, connectOperation, nil) {
		if release != nil {
			release()
		}
		return out, ErrGatewayNativeIdentity
	}
	prior, err := s.bundle(scope, env0, p0)
	release()
	if err != nil {
		return out, err
	}
	if time.Now().Add(5 * time.Minute).Before(prior.ExpiresAt) {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "idle", Version: p0.CredentialRevision}, nil
	}
	p, envelope, claimed, err := s.repository.ClaimGatewayGrokRefresh(ctx, scope, connectOperation, refreshOperation, p0.CredentialRevision)
	if err != nil {
		return out, err
	}
	if !claimed {
		saved, found, readErr := s.repository.ReadGatewayGrokRefresh(ctx, scope, connectOperation, refreshOperation)
		if readErr != nil || !found {
			return out, ErrGatewayNativeIdentity
		}
		return saved, nil
	}
	if !grokPhysicalValid(p, scope, connectOperation, nil) {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, ErrGatewayNativeIdentity
	}
	previous, err := s.bundle(scope, envelope, p)
	if err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	if s.refreshEntry(ctx, scope, connectOperation) != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, ErrGatewayNativeIdentity
	}
	b, err := s.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {previous.RefreshToken}, "client_id": {s.qualification.ClientID}}, "", &previous)
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
	if err = s.repository.CompleteGatewayGrokRefresh(ctx, p, refreshOperation, next); err != nil {
		return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "unknown"}, err
	}
	return GatewayNativeOAuthRefreshOutcome{Operation: refreshOperation, State: "completed", Version: p.CredentialRevision + 1}, nil
}

func (s *GatewayNativeGrokOAuth) RetainedCustody(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route GatewayNativeRoute) (GatewayNativeRetainedCustodyResult, error) {
	var out GatewayNativeRetainedCustodyResult
	if s == nil || !grokScope(ctx, scope, operation) {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, release, err := s.repository.LockGatewayGrokPhysical(ctx, scope, operation, &route)
	if err != nil {
		return out, err
	}
	if release == nil || !grokPhysicalValid(p, scope, operation, &route) {
		if release != nil {
			release()
		}
		return out, ErrGatewayNativeIdentity
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

func (s *GatewayNativeGrokOAuth) Cleanup(ctx context.Context, in GatewayNativeOAuthCleanupRequest, authorize GatewayNativeOAuthCleanupAuthorizer) (GatewayNativeOAuthCleanupResult, error) {
	if s == nil || !grokScope(ctx, in.Scope, in.Operation) || !GatewayNativeOAuthCleanupRequestValid(in) || authorize == nil {
		return GatewayNativeOAuthCleanupResult{}, ErrGatewayNativeIdentity
	}
	return s.repository.CleanupGatewayGrok(ctx, in, authorize)
}

// Maintain resolves the original exact generation; operation is a one-use durable
// refresh intent owned by the facade, not a selector for a latest account.
func (s *GatewayNativeGrokOAuth) Maintain(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthMaintenanceOutcome, error) {
	out := GatewayNativeOAuthMaintenanceOutcome{Operation: operation, AccountRef: scope.Account, State: "idle"}
	if s == nil || !grokScope(ctx, scope, operation) || s.refreshEntry == nil || s.refreshEntry(ctx, scope, operation) != nil {
		return out, ErrGatewayNativeIdentity
	}
	p, envelope, state, attempt, release, err := s.repository.LockGatewayGrokMaintenance(ctx, scope, operation)
	if err != nil {
		return out, err
	}
	if release == nil || !grokPhysicalValid(p, scope, operation, nil) {
		if release != nil {
			release()
		}
		return out, ErrGatewayNativeIdentity
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
	attempt = "grok-" + rotation.Operation
	result, err := s.Refresh(ctx, scope, operation, attempt)
	out.State = result.State
	out.RefreshRef = attempt
	return out, err
}

func grokPhysicalValid(p GatewayNativeOAuthPhysical, scope GatewayNativeCredentialScope, operation string, route *GatewayNativeRoute) bool {
	return p.Scope == scope && p.Operation == operation && GatewayNativeCredentialRefValid(operation) && p.Issuer == GatewayGrokOAuthIssuer && p.Route.AccountID > 0 && !p.Route.CreatedAt.IsZero() && p.Route.Generation == scope.Generation && p.Route.Profile == GatewayGrokOAuthResponsesProfile && p.Route.BaseURL == GatewayGrokOAuthBaseURL && p.Route.Model == GatewayGrokOAuthModel && (route == nil || SameGatewayNativeDescriptor(p.Route, *route))
}
