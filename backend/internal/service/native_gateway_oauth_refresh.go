package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
)

// Engine credential version is independent of immutable birth generation and
// owner authorizationEpoch. This component has no inference/activation route.
type GatewayNativeOAuthRefreshIntent struct {
	Scope            GatewayNativeCredentialScope
	AccountID        int64
	CreatedAt        time.Time
	ExpectedVersion  int64
	Operation        string
	Intent           string
	ConnectOperation string
}

func (in GatewayNativeOAuthRefreshIntent) Authorized(ctx context.Context) bool {
	return GatewayNativeOAuthScopeAuthorized(ctx, in.Scope) && in.AccountID > 0 &&
		!in.CreatedAt.IsZero() && in.CreatedAt.Nanosecond()%1000 == 0 &&
		in.ExpectedVersion >= 1 && in.ExpectedVersion < math.MaxInt64 &&
		GatewayNativeCredentialRefValid(in.Operation) && GatewayNativeCredentialRefValid(in.Intent)
}

// Only safe operation metadata leaves Refresh. Fence/envelope/principal are
// private repository-to-custody inputs, never a product readback/secret API.
type GatewayNativeOAuthRefreshOutcome struct {
	Operation string
	State     string
	Version   int64
}
type GatewayNativeOAuthRefreshPrepared struct {
	Outcome  GatewayNativeOAuthRefreshOutcome
	Fence    int64
	Deadline time.Time
	Claimed  bool
	Envelope string
	Issuer   string
	Subject  string
}
type GatewayNativeOAuthRefreshRepository interface {
	PrepareGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent) (GatewayNativeOAuthRefreshPrepared, error)
	EnterGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) (bool, error)
	CompleteGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64, string) (GatewayNativeOAuthRefreshOutcome, error)
	UnknownGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) error
}
type GatewayNativeOAuthRefresh struct {
	repository     GatewayNativeOAuthRefreshRepository
	custody        *GatewayNativeCredentialCustody
	verifier       *GatewayNativeOAuthVerifier
	client         *http.Client
	authorizeEntry GatewayNativeOAuthEntryAuthorizer
}

func NewGatewayNativeOAuthRefresh(r GatewayNativeOAuthRefreshRepository, c *GatewayNativeCredentialCustody, v *GatewayNativeOAuthVerifier, transport http.RoundTripper) (*GatewayNativeOAuthRefresh, error) {
	if r == nil || c == nil || v == nil {
		return nil, ErrGatewayNativeIdentity
	}
	if transport == nil {
		transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192}
	}
	return &GatewayNativeOAuthRefresh{repository: r, custody: c, verifier: v, client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}}, nil
}
func (s *GatewayNativeOAuthRefresh) Refresh(ctx context.Context, in GatewayNativeOAuthRefreshIntent) (GatewayNativeOAuthRefreshOutcome, error) {
	if s == nil || !in.Authorized(ctx) {
		return GatewayNativeOAuthRefreshOutcome{}, ErrGatewayNativeIdentity
	}
	// Intent contains copied primitives only; no mutable ingress maps survive await.
	prepared, err := s.repository.PrepareGatewayNativeOAuthRefresh(ctx, in)
	if err != nil || !prepared.Claimed {
		return prepared.Outcome, err
	}
	unknown := func() (GatewayNativeOAuthRefreshOutcome, error) {
		// Caller cancellation cannot suppress durable ambiguity recording. Failure
		// here leaves ENTERED, which SQL quarantines on expiry rather than rearming.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = s.repository.UnknownGatewayNativeOAuthRefresh(cleanup, in, prepared.Fence)
		return GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "unknown"}, ErrGatewayNativeIdentity
	}
	previous, err := s.custody.openOAuthVersion(prepared.Envelope, in.Scope, in.ExpectedVersion)
	if err != nil {
		return unknown()
	} // invalid AEAD makes zero token/JWKS calls
	if ctx.Err() != nil || (s.authorizeEntry != nil && s.authorizeEntry(ctx, in.Scope, in.ConnectOperation) != nil) {
		return unknown()
	}
	entered, err := s.repository.EnterGatewayNativeOAuthRefresh(ctx, in, prepared.Fence)
	if err != nil {
		return unknown()
	} // lost entered ACK must never call upstream
	if !entered {
		return GatewayNativeOAuthRefreshOutcome{}, ErrGatewayOAuthConflict
	}
	callCtx, cancel := context.WithDeadline(ctx, prepared.Deadline)
	defer cancel()
	if callCtx.Err() != nil {
		return unknown()
	}
	next, err := s.exchange(callCtx, previous.RefreshToken, prepared.Issuer, prepared.Subject)
	if err != nil {
		return unknown()
	}
	envelope, err := s.custody.sealOAuthVersion(in.Scope, in.ExpectedVersion+1, next)
	if err != nil {
		return unknown()
	}
	// SQL publishes whole ciphertext and version atomically; a lost ACK is read
	// back by the same operation without decrypting or entering a second time.
	outcome, err := s.repository.CompleteGatewayNativeOAuthRefresh(callCtx, in, prepared.Fence, envelope)
	if err != nil {
		readCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		readback, readErr := s.repository.PrepareGatewayNativeOAuthRefresh(readCtx, in)
		stop()
		if readErr == nil && readback.Outcome.State == "completed" {
			return readback.Outcome, nil
		}
		return unknown()
	}
	return outcome, nil
}
func (s *GatewayNativeOAuthRefresh) exchange(ctx context.Context, refresh, issuer, subject string) (GatewayNativeOAuthBundle, error) {
	deny := func() (GatewayNativeOAuthBundle, error) { return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity }
	// No proxy/origin/header input, ordinary OAuth service, inference, or retry.
	body := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {openai.ClientID}, "scope": {openai.RefreshScopes}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openai.TokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return deny()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	started := time.Now()
	response, err := s.client.Do(req)
	if err != nil {
		return deny()
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) > 65536 || response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != openai.TokenURL {
		return deny()
	}
	fields, err := gatewayOAuthJSON(raw)
	if err != nil || !gatewayOAuthCanonical(fields, "access_token", "refresh_token", "id_token", "token_type", "expires_in", "scope") {
		return deny()
	}
	for name := range fields {
		if strings.EqualFold(name, gatewayOAuthTimingMember) {
			return deny()
		}
	}
	access, aok := gatewayOAuthString(fields, "access_token")
	nextRefresh, rok := gatewayOAuthString(fields, "refresh_token")
	id, iok := gatewayOAuthString(fields, "id_token")
	kind, kok := gatewayOAuthString(fields, "token_type")
	seconds, expiresOK := gatewayOAuthSeconds(fields["expires_in"])
	if !aok || !rok || !iok || !kok || !expiresOK || seconds <= 0 || seconds > math.MaxInt64/int64(time.Second) || !strings.EqualFold(kind, "Bearer") {
		return deny()
	}
	// This staging contract requires a returned refresh token. Omission is unknown
	// until the real provider's omission contract is independently qualified.
	identity, err := s.verifier.Verify(ctx, id)
	gotIssuer, gotSubject := identity.Principal()
	if err != nil || gotIssuer != issuer || gotSubject != subject {
		return deny()
	}
	// All response metadata, including unknown provider fields, remains encrypted.
	for _, name := range []string{"access_token", "refresh_token", "id_token"} {
		delete(fields, name)
	}
	metadata, err := json.Marshal(fields)
	if err != nil {
		return deny()
	}
	bundle := GatewayNativeOAuthBundle{AccessToken: access, RefreshToken: nextRefresh, IDToken: id, SensitiveMetadata: metadata}
	if _, err = bundle.bytes(); err != nil {
		return deny()
	}
	return gatewayOAuthTimedBundle(bundle, started, identity, s.custody)
}

// This projection is private to the engine; HTTP uses the separate finite reply.
type GatewayNativeOAuthRefreshResolution struct {
	AccountID int64
	CreatedAt time.Time
	Version   int64
	Envelope  string
	Attempt   *GatewayNativeOAuthRefreshIntent
	State     string
}
type GatewayNativeOAuthRefreshResolver interface {
	ResolveGatewayNativeOAuthRefresh(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthRefreshResolution, error)
}
type GatewayNativeOAuthMaintenanceOutcome struct {
	Operation  string `json:"operation"`
	AccountRef string `json:"account_ref"`
	State      string `json:"state"`
	RefreshRef string `json:"refresh_ref,omitempty"`
}

// Engine-only references use canonical immutable physical birth/scope/version.
// JSON array framing prevents ambiguous concatenation; no credential bytes enter.
func gatewayOAuthRotation(scope GatewayNativeCredentialScope, id int64, birth time.Time, version int64) GatewayNativeOAuthRefreshIntent {
	raw, _ := json.Marshal([]any{scope.Consumer, scope.Owner, scope.Account, scope.Generation, scope.Purpose, id, birth.UTC().Format(time.RFC3339Nano), version})
	reference := func(domain string) string {
		digest := sha256.Sum256(append([]byte(domain+"\x00"), raw...))
		return hex.EncodeToString(digest[:])
	}
	return GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: id, CreatedAt: birth, ExpectedVersion: version,
		Operation: reference("account-gateway/native/oauth-rotation-operation/v1"), Intent: reference("account-gateway/native/oauth-rotation-intent/v1")}
}

// Maintain takes only the original connect selectors. It never qualifies a row,
// exports custody, or accepts a caller-selected version/rotation operation.
func (s *GatewayNativeOAuthRefresh) Maintain(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthMaintenanceOutcome, error) {
	out := GatewayNativeOAuthMaintenanceOutcome{Operation: operation, AccountRef: scope.Account, State: "idle"}
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return out, ErrGatewayNativeIdentity
	}
	resolver, ok := s.repository.(GatewayNativeOAuthRefreshResolver)
	if !ok {
		return out, ErrGatewayNativeIdentity
	}
	current, err := resolver.ResolveGatewayNativeOAuthRefresh(ctx, scope, operation)
	if err != nil {
		return out, err
	}
	// Every unresolved attempt is reconstructed before considering current expiry
	// or version. ENTERED/UNKNOWN cannot re-enter, even while their deadline is live.
	if current.Attempt != nil && current.State != "completed" && current.State != "prepared" {
		attempt := *current.Attempt
		attempt.ConnectOperation = operation
		result, err := s.Refresh(ctx, attempt)
		out.State = result.State
		out.RefreshRef = current.Attempt.Operation
		return out, err
	}
	previous, err := s.custody.openOAuthVersion(current.Envelope, scope, current.Version)
	if err != nil {
		return out, ErrGatewayNativeIdentity
	}
	due, qualified := gatewayOAuthBundleDue(previous, time.Now(), s.custody)
	if !qualified || !due {
		if current.Attempt != nil {
			out.State = current.State
			out.RefreshRef = current.Attempt.Operation
		}
		return out, nil
	}
	in := gatewayOAuthRotation(scope, current.AccountID, current.CreatedAt, current.Version)
	// A completed ACK can be lost while a new caller knows no F2 reference.
	// Current-version attempts, including legacy references, remain authoritative.
	if current.Attempt != nil && current.Attempt.ExpectedVersion == current.Version {
		in = *current.Attempt
	}
	in.ConnectOperation = operation
	result, err := s.Refresh(ctx, in)
	out.State = result.State
	out.RefreshRef = in.Operation
	return out, err
}

func (s *GatewayNativeOAuthRefresh) SetEntryAuthorizer(authorize GatewayNativeOAuthEntryAuthorizer) error {
	if s == nil || authorize == nil {
		return ErrGatewayNativeIdentity
	}
	s.authorizeEntry = authorize
	return nil
}
