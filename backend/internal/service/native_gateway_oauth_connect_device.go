package service

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const GatewayOAuthDeviceRedirect = "https://auth.openai.com/deviceauth/callback"
const gatewayOAuthDeviceVerification = "https://auth.openai.com/codex/device"
const gatewayOAuthDeviceUserCode = "https://auth.openai.com/api/accounts/deviceauth/usercode"
const gatewayOAuthDeviceToken = "https://auth.openai.com/api/accounts/deviceauth/token"

// The only device capability safe to return to the initiating authenticated owner.
// It is never replayed from Begin/read/poll after its original response is lost.
type GatewayNativeDeviceAuthorization struct {
	UserCode        string    `json:"user_code"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	IntervalSeconds int       `json:"interval_seconds"`
}

// Device effects use the same durable connect row and custody enrollment. The
// claim must be committed before HTTP; a lost ACK never authorizes replay.
type GatewayNativeOAuthDeviceRepository interface {
	ClaimConnectDevice(context.Context, GatewayNativeOAuthConnectIntent, string) (bool, error)
	SaveConnectDevice(context.Context, GatewayNativeOAuthConnectIntent, string, time.Time) (bool, error)
}

func connectMethod(in GatewayNativeOAuthConnectIntent) string {
	if in.Method == "" {
		return "browser"
	}
	return in.Method
}

func deviceUserCodeValid(value string) bool {
	if len(value) < 4 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
		if !valid {
			return false
		}
	}
	return true
}

func deviceStringValid(value string, min, max int) bool {
	if len(value) < min || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// Provider values are bounded before decoding, never logged or used as URLs.
func (s *GatewayNativeOAuthConnect) deviceJSON(ctx context.Context, endpoint string, body any) (int, map[string]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, ErrGatewayNativeIdentity
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return 0, nil, ErrGatewayNativeIdentity
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, ErrGatewayNativeIdentity
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 8193))
	closeErr := resp.Body.Close()
	if err != nil || closeErr != nil || len(raw) > 8192 || resp.Request == nil || resp.Request.URL.String() != endpoint {
		return 0, nil, ErrGatewayNativeIdentity
	}
	// Official Codex identifies pending by status alone; empty pending bodies work.
	if endpoint == gatewayOAuthDeviceToken && (resp.StatusCode == 403 || resp.StatusCode == 404) {
		m, _ := gatewayOAuthJSON(raw)
		return resp.StatusCode, m, nil
	}
	m, err := gatewayOAuthJSON(raw)
	if err != nil {
		return 0, nil, ErrGatewayNativeIdentity
	}
	return resp.StatusCode, m, nil
}

func (s *GatewayNativeOAuthConnect) beginDevice(ctx context.Context, in GatewayNativeOAuthConnectIntent) (GatewayNativeOAuthConnectResult, error) {
	repo, ok := s.repository.(GatewayNativeOAuthDeviceRepository)
	if !ok {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if in.DevicePhase != "" {
		return connectResult(in), nil
	}
	if ctx.Err() != nil || (s.authorizeEntry != nil && s.authorizeEntry(ctx, in.Scope, in.Operation) != nil) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	won, err := repo.ClaimConnectDevice(ctx, in, "starting")
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !won {
		return s.ReadConnect(ctx, in.Scope, in.Operation)
	}
	in.DevicePhase, in.DeviceRevision = "starting", in.DeviceRevision+1
	status, m, err := s.deviceJSON(ctx, gatewayOAuthDeviceUserCode, map[string]string{"client_id": in.ClientID})
	if err != nil || status != 200 || !gatewayOAuthCanonical(m, "device_auth_id", "user_code", "usercode", "interval", "expires_in") {
		return s.failDevice(ctx, in)
	}
	deviceID, _ := gatewayOAuthString(m, "device_auth_id")
	userCode, _ := gatewayOAuthString(m, "user_code")
	alias, _ := gatewayOAuthString(m, "usercode")
	_, hasCode := m["user_code"]
	_, hasAlias := m["usercode"]
	if hasCode && hasAlias {
		return s.failDevice(ctx, in)
	}
	if !hasCode {
		userCode = alias
	}
	if !deviceStringValid(deviceID, 8, 256) || !deviceUserCodeValid(userCode) {
		return s.failDevice(ctx, in)
	}
	interval := int64(3)
	if value, exists := m["interval"]; exists {
		var text string
		if json.Unmarshal(value, &text) == nil {
			value = json.RawMessage(strings.TrimSpace(text))
		}
		seconds, valid := gatewayOAuthSeconds(value)
		if !valid || seconds < 1 || seconds > 300 {
			return s.failDevice(ctx, in)
		}
		interval = seconds
	}
	// Native ten minute intent expiry is the upper bound, also honoring any
	// shorter provider lifetime. The public expiry never extends local authority.
	expires := in.Deadline
	if value, exists := m["expires_in"]; exists {
		seconds, valid := gatewayOAuthSeconds(value)
		if !valid || seconds < 1 || seconds > 86400 {
			return s.failDevice(ctx, in)
		}
		if providerExpiry := s.now().Add(time.Duration(seconds) * time.Second); providerExpiry.Before(expires) {
			expires = providerExpiry
		}
	}
	material, err := s.open(in)
	if err != nil {
		return s.failDevice(ctx, in)
	}
	material.DeviceID, material.UserCode, material.Interval = deviceID, userCode, int(interval)
	// The prepared result may narrow the immutable native expiry. Subsequent
	// polls and reads cannot change it, including after a lost save ACK.
	in.DeviceDeadline = expires.UTC().Truncate(time.Microsecond)
	envelope, err := s.seal(in, material)
	if err != nil || len(envelope) > 1024 {
		return s.failDevice(ctx, in)
	}
	saved, err := repo.SaveConnectDevice(ctx, in, envelope, s.now().UTC().Truncate(time.Microsecond).Add(time.Duration(interval)*time.Second))
	if err != nil || !saved {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	result := connectResult(in)
	result.DeviceAuthorization = &GatewayNativeDeviceAuthorization{UserCode: userCode, VerificationURL: gatewayOAuthDeviceVerification, ExpiresAt: in.DeviceDeadline, IntervalSeconds: int(interval)}
	return result, nil
}

// Ambiguous device requests spend the same token-entry fence before quarantine.
// Neither begin nor polling can be retried against that accepted operation.
func (s *GatewayNativeOAuthConnect) failDevice(ctx context.Context, in GatewayNativeOAuthConnectIntent) (GatewayNativeOAuthConnectResult, error) {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	won, err := s.repository.EnterConnect(recovery, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !won {
		return s.ReadConnect(recovery, in.Scope, in.Operation)
	}
	in.State = "entered"
	saved, err := s.repository.FinishConnect(recovery, in, "quarantined", GatewayNativeOAuthOutcome{})
	return connectResult(saved), err
}

func (s *GatewayNativeOAuthConnect) PollDeviceConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadConnectIntent(ctx, scope, operation)
	if err != nil || !GatewayNativeOAuthConnectIntentValid(in) || in.Scope != scope || in.Operation != operation || connectMethod(in) != "device_code" {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err = s.reconcile(ctx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if in.State != "prepared" || in.DevicePhase != "pending" || s.now().Before(in.DevicePollAfter) {
		return connectResult(in), nil
	}
	repo, ok := s.repository.(GatewayNativeOAuthDeviceRepository)
	if !ok {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	material, err := s.open(in)
	if err != nil || !deviceStringValid(material.DeviceID, 8, 256) || !deviceUserCodeValid(material.UserCode) || material.Interval < 1 || material.Interval > 300 {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !s.now().Before(in.DeviceDeadline) {
		return s.failDevice(ctx, in)
	}
	if ctx.Err() != nil || (s.authorizeEntry != nil && s.authorizeEntry(ctx, scope, operation) != nil) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	won, err := repo.ClaimConnectDevice(ctx, in, "polling")
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !won {
		return s.ReadConnect(ctx, scope, operation)
	}
	in.DevicePhase, in.DeviceRevision = "polling", in.DeviceRevision+1
	status, m, err := s.deviceJSON(ctx, gatewayOAuthDeviceToken, map[string]string{"device_auth_id": material.DeviceID, "user_code": material.UserCode})
	if err != nil {
		return s.failDevice(ctx, in)
	}
	providerError := deviceProviderError(m)
	if providerError == "access_denied" || providerError == "deviceauth_access_denied" || providerError == "expired_token" || providerError == "deviceauth_expired" || providerError == "deviceauth_expired_token" {
		return s.failDevice(ctx, in)
	}
	if status == 403 || status == 404 || providerError == "authorization_pending" || providerError == "deviceauth_authorization_pending" {
		interval := material.Interval
		saved, err := repo.SaveConnectDevice(ctx, in, in.Envelope, s.now().UTC().Truncate(time.Microsecond).Add(time.Duration(interval)*time.Second))
		if err != nil || !saved {
			return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
		}
		return connectResult(in), nil
	}
	if status != 200 || !gatewayOAuthCanonical(m, "authorization_code", "code_verifier", "code_challenge") {
		return s.failDevice(ctx, in)
	}
	code, _ := gatewayOAuthString(m, "authorization_code")
	verifier, _ := gatewayOAuthString(m, "code_verifier")
	challenge, challengeOK := gatewayOAuthString(m, "code_challenge")
	_, hasChallenge := m["code_challenge"]
	if !connectCodeValid(code) || !deviceVerifierValid(verifier) || (hasChallenge && (!challengeOK || challenge != openai.GenerateCodeChallenge(verifier))) {
		return s.failDevice(ctx, in)
	}
	// Polling may have taken a full provider timeout. Revalidate the live
	// owner immediately before credential entry; an issued code after revocation
	// is quarantined rather than retried against another authorization grant.
	if ctx.Err() != nil || (s.authorizeEntry != nil && s.authorizeEntry(ctx, scope, operation) != nil) {
		return s.failDevice(ctx, in)
	}
	// The same durable entry claim used by the browser flow owns the one exchange.
	won, err = s.repository.EnterConnect(ctx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !won {
		return s.ReadConnect(ctx, scope, operation)
	}
	in.State = "entered"
	return s.completeEntered(ctx, in, code, verifier)
}

func deviceVerifierValid(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		valid := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)
		if !valid {
			return false
		}
	}
	return true
}

func deviceProviderError(m map[string]json.RawMessage) string {
	for _, name := range []string{"error", "error_code", "code"} {
		if value, ok := gatewayOAuthString(m, name); ok {
			return value
		}
	}
	return ""
}
