package service

import (
	"context"
	"crypto/tls"
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
	Scope           GatewayNativeCredentialScope
	AccountID       int64
	CreatedAt       time.Time
	ExpectedVersion int64
	Operation       string
	Intent          string
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
	repository GatewayNativeOAuthRefreshRepository
	custody    *GatewayNativeCredentialCustody
	verifier   *GatewayNativeOAuthVerifier
	client     *http.Client
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
	entered, err := s.repository.EnterGatewayNativeOAuthRefresh(ctx, in, prepared.Fence)
	if err != nil {
		return unknown()
	} // lost entered ACK must never call upstream
	if !entered {
		return GatewayNativeOAuthRefreshOutcome{}, ErrGatewayOAuthConflict
	}
	callCtx, cancel := context.WithDeadline(ctx, prepared.Deadline)
	defer cancel()
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
	access, aok := gatewayOAuthString(fields, "access_token")
	nextRefresh, rok := gatewayOAuthString(fields, "refresh_token")
	id, iok := gatewayOAuthString(fields, "id_token")
	kind, kok := gatewayOAuthString(fields, "token_type")
	_, expiresOK := gatewayOAuthSeconds(fields["expires_in"])
	if !aok || !rok || !iok || !kok || !expiresOK || !strings.EqualFold(kind, "Bearer") {
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
	return bundle, nil
}
