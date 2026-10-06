package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/google/uuid"
)

const GatewayOAuthConnectRedirect = "http://localhost:1455/auth/callback"
const GatewayOAuthConnectTTL = 10 * time.Minute

// Server-private persisted intent. Never marshal this as a response or log it.
// No authorization code or token response is persisted here.
type GatewayNativeOAuthConnectIntent struct {
	Scope               GatewayNativeCredentialScope `json:"-"`
	Operation           string                       `json:"-"`
	ClientID            string                       `json:"-"`
	Redirect            string                       `json:"-"`
	Deadline            time.Time                    `json:"-"`
	StateHash           string                       `json:"-"`
	Envelope            string                       `json:"-"`
	State               string                       `json:"-"`
	Outcome             GatewayNativeOAuthOutcome    `json:"-"`
	EnrollmentOperation string                       `json:"-"`
	EnrollmentMAC       string                       `json:"-"`
	RecoveryDenied      bool                         `json:"-"`
}

// One durable CAS owns token entry; no in-memory lock is replay authority.
// FindState is server-only capability lookup, not owner/admin authentication.
type GatewayNativeOAuthConnectRepository interface {
	PrepareConnect(context.Context, GatewayNativeOAuthConnectIntent) (GatewayNativeOAuthConnectIntent, error)
	ReadConnectIntent(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthConnectIntent, error)
	FindConnectState(context.Context, string) (GatewayNativeOAuthConnectIntent, error)
	EnterConnect(context.Context, GatewayNativeOAuthConnectIntent) (bool, error)
	BindConnectEnrollment(context.Context, GatewayNativeOAuthConnectIntent, string) (GatewayNativeOAuthConnectIntent, error)
	FinishConnect(context.Context, GatewayNativeOAuthConnectIntent, string, GatewayNativeOAuthOutcome) (GatewayNativeOAuthConnectIntent, error)
}

type GatewayNativeOAuthConnectReadback interface {
	ReplayGatewayNativeOAuth(context.Context, GatewayNativeCredentialScope, string, string) (GatewayNativeOAuthOutcome, bool, error)
}

// Safe public operation view: deliberately omits native row IDs and claims.
// Only BeginConnect may return the authorize URL to the authenticated owner.
type GatewayNativeOAuthConnectResult struct {
	Operation    string `json:"operation"`
	Account      string `json:"account_ref"`
	State        string `json:"state"`
	Outcome      string `json:"outcome,omitempty"`
	AuthorizeURL string `json:"authorize_url,omitempty"`
}

type GatewayNativeOAuthConnect struct {
	aead       cipher.AEAD
	client     *http.Client
	repository GatewayNativeOAuthConnectRepository
	enrollment *GatewayNativeOAuthEnrollment
	readback   GatewayNativeOAuthConnectReadback
	now        func() time.Time
}

// The key stays outside DB/backup. transport is trusted composition ONLY (TLS
// fixtures); no ingress endpoint, proxy, headers, deadline or redirect override.
func NewGatewayNativeOAuthConnect(key []byte, transport http.RoundTripper, repository GatewayNativeOAuthConnectRepository, enrollment *GatewayNativeOAuthEnrollment, readback GatewayNativeOAuthConnectReadback) (*GatewayNativeOAuthConnect, error) {
	if len(key) != 32 || repository == nil || enrollment == nil || readback == nil {
		return nil, ErrGatewayNativeIdentity
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 2, DisableKeepAlives: true}
	}
	return &GatewayNativeOAuthConnect{aead: aead, client: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }},
		repository: repository, enrollment: enrollment, readback: readback, now: time.Now}, nil
}

func GatewayNativeOAuthConnectIntentValid(in GatewayNativeOAuthConnectIntent) bool {
	hash, err := hex.DecodeString(in.StateHash)
	enrollmentID, idErr := uuid.Parse(strings.TrimPrefix(in.EnrollmentOperation, "connect-"))
	mac, macErr := hex.DecodeString(in.EnrollmentMAC)
	return GatewayNativeOAuthScopeValid(in.Scope) && GatewayNativeCredentialRefValid(in.Operation) &&
		idErr == nil && enrollmentID != uuid.Nil && in.EnrollmentOperation == "connect-"+enrollmentID.String() && in.EnrollmentOperation != in.Operation &&
		(in.EnrollmentMAC == "" || (macErr == nil && len(mac) == 32 && hex.EncodeToString(mac) == in.EnrollmentMAC)) &&
		in.ClientID == openai.ClientID && in.Redirect == GatewayOAuthConnectRedirect &&
		!in.Deadline.IsZero() && in.Deadline.Equal(in.Deadline.Truncate(time.Microsecond)) &&
		err == nil && len(hash) == 32 && hex.EncodeToString(hash) == in.StateHash
}

func SameGatewayNativeOAuthConnectIntent(a, b GatewayNativeOAuthConnectIntent) bool {
	return a.Scope == b.Scope && a.Operation == b.Operation && a.ClientID == b.ClientID && a.Redirect == b.Redirect
}

func connectAAD(in GatewayNativeOAuthConnectIntent) []byte {
	raw, _ := json.Marshal(struct {
		Scope                                                                 GatewayNativeCredentialScope
		Operation, EnrollmentOperation, Client, Redirect, Deadline, StateHash string
	}{
		in.Scope, in.Operation, in.EnrollmentOperation, in.ClientID, in.Redirect, in.Deadline.UTC().Format(time.RFC3339Nano), in.StateHash})
	return append([]byte("account-gateway/native/oauth-connect-material/v1\x00"), raw...)
}

type connectMaterial struct{ State, Verifier string }

func (s *GatewayNativeOAuthConnect) seal(in GatewayNativeOAuthConnectIntent, material connectMaterial) (string, error) {
	raw, _ := json.Marshal(material)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	sealed := s.aead.Seal(nonce, nonce, raw, connectAAD(in))
	return "gcc1." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *GatewayNativeOAuthConnect) open(in GatewayNativeOAuthConnectIntent) (connectMaterial, error) {
	var material connectMaterial
	if !GatewayNativeOAuthConnectIntentValid(in) || !strings.HasPrefix(in.Envelope, "gcc1.") || len(in.Envelope) > 1024 {
		return material, ErrGatewayNativeIdentity
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(in.Envelope, "gcc1."))
	if err != nil || len(sealed) < s.aead.NonceSize()+s.aead.Overhead() {
		return material, ErrGatewayNativeIdentity
	}
	n := s.aead.NonceSize()
	raw, err := s.aead.Open(nil, sealed[:n], sealed[n:], connectAAD(in))
	if err != nil || json.Unmarshal(raw, &material) != nil {
		return connectMaterial{}, ErrGatewayNativeIdentity
	}
	state, err := hex.DecodeString(material.State)
	verifier, vErr := hex.DecodeString(material.Verifier)
	if err != nil || vErr != nil || len(state) != 32 || len(verifier) != 64 || connectStateHash(material.State) != in.StateHash {
		return connectMaterial{}, ErrGatewayNativeIdentity
	}
	return material, nil
}

func connectStateHash(state string) string {
	h := sha256.Sum256([]byte(state))
	return hex.EncodeToString(h[:])
}

func connectResult(in GatewayNativeOAuthConnectIntent) GatewayNativeOAuthConnectResult {
	return GatewayNativeOAuthConnectResult{Operation: in.Operation, Account: in.Scope.Account, State: in.State, Outcome: in.Outcome.State}
}

func (s *GatewayNativeOAuthConnect) BeginConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	state, err := openai.GenerateState()
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	verifier, err := openai.GenerateCodeVerifier()
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in := GatewayNativeOAuthConnectIntent{Scope: scope, Operation: operation, ClientID: openai.ClientID, Redirect: GatewayOAuthConnectRedirect,
		EnrollmentOperation: "connect-" + uuid.NewString(),
		Deadline:            s.now().UTC().Truncate(time.Microsecond).Add(GatewayOAuthConnectTTL), StateHash: connectStateHash(state), State: "prepared"}
	in.Envelope, err = s.seal(in, connectMaterial{state, verifier})
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	// Persist before exposing capability. A lost prepare ACK is read by the SAME
	// operation; a new random candidate never replaces its accepted material/TTL.
	saved, err := s.repository.PrepareConnect(ctx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayOAuthConflict
	}
	if !SameGatewayNativeOAuthConnectIntent(in, saved) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayOAuthConflict
	}
	saved, err = s.reconcile(ctx, saved)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	result := connectResult(saved)
	if saved.State == "prepared" {
		material, err := s.open(saved)
		if err != nil {
			return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
		}
		result.AuthorizeURL = openai.BuildAuthorizationURL(material.State, openai.GenerateCodeChallenge(material.Verifier), GatewayOAuthConnectRedirect)
	}
	return result, nil
}

func (s *GatewayNativeOAuthConnect) ReadConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err := s.repository.ReadConnectIntent(ctx, scope, operation)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err = s.reconcile(ctx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	return connectResult(in), nil
}

// Callback authority is only the random persisted intent capability. Rebuild
// trusted consumer/owner from that row; upstream claims never supply RR authority.
func connectContext(ctx context.Context, in GatewayNativeOAuthConnectIntent) (context.Context, error) {
	ctx, err := WithGatewayNativeConsumer(ctx, in.Scope.Consumer)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	return WithGatewayNativeOAuthOwner(ctx, in.Scope.Owner)
}

// Enrollment and final intent commit are separate transactions. Readback bridges
// a lost Stage/final ACK; it NEVER exchanges again or speculatively stages.
// A concurrent active writer can finish unknown -> completed with its exact result.
func (s *GatewayNativeOAuthConnect) reconcile(ctx context.Context, in GatewayNativeOAuthConnectIntent) (GatewayNativeOAuthConnectIntent, error) {
	if !GatewayNativeOAuthConnectIntentValid(in) {
		return in, ErrGatewayNativeIdentity
	}
	if in.State == "prepared" && !s.now().Before(in.Deadline) {
		return s.repository.FinishConnect(ctx, in, "expired", GatewayNativeOAuthOutcome{})
	}
	if (in.State != "entered" && in.State != "unknown") || in.RecoveryDenied {
		return in, nil
	}
	ownerCtx, err := connectContext(ctx, in)
	if err != nil {
		return in, err
	}
	if in.EnrollmentMAC == "" {
		return s.repository.FinishConnect(ctx, in, "unknown", GatewayNativeOAuthOutcome{})
	}
	out, found, err := s.readback.ReplayGatewayNativeOAuth(ownerCtx, in.Scope, in.EnrollmentOperation, in.EnrollmentMAC)
	if err == nil && found && out.Operation == in.EnrollmentOperation && out.Generation == in.Scope.Generation && out.AccountID > 0 && (out.State == "staged" || out.State == "erased") {
		// F1 initial Stage always returns staged. Erase changes current readback,
		// not the original enrollment outcome retained by the connect operation.
		out.State = "staged"
		return s.repository.FinishConnect(ctx, in, "completed", out)
	}
	return s.repository.FinishConnect(ctx, in, "unknown", GatewayNativeOAuthOutcome{})
}

// Intercept the already verified/sealed F1 reservation to durably link its exact
// commitment before custody entry. F1 Stage and its commitment algorithm remain
// unchanged; neither tokens nor the bundle are persisted by F3.
type connectEnrollmentRepository struct {
	GatewayNativeOAuthRepository
	connect GatewayNativeOAuthConnectRepository
	intent  *GatewayNativeOAuthConnectIntent
}

func (r connectEnrollmentRepository) StageGatewayNativeOAuth(ctx context.Context, reservation GatewayNativeOAuthReservation) (GatewayNativeOAuthOutcome, error) {
	if reservation.Scope != r.intent.Scope || reservation.Operation != r.intent.EnrollmentOperation {
		return GatewayNativeOAuthOutcome{}, ErrGatewayOAuthConflict
	}
	saved, err := r.connect.BindConnectEnrollment(ctx, *r.intent, reservation.IntentMAC)
	if err != nil {
		return GatewayNativeOAuthOutcome{}, err
	}
	*r.intent = saved
	return r.GatewayNativeOAuthRepository.StageGatewayNativeOAuth(ctx, reservation)
}

func connectCodeValid(code string) bool {
	if code == "" || len(code) > 4096 || !utf8.ValidString(code) || strings.TrimSpace(code) != code {
		return false
	}
	for _, r := range code {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *GatewayNativeOAuthConnect) CompleteCallback(ctx context.Context, state, code string) (GatewayNativeOAuthConnectResult, error) {
	decoded, err := hex.DecodeString(state)
	if s == nil || err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != state || !connectCodeValid(code) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in, err := s.repository.FindConnectState(ctx, connectStateHash(state))
	if err != nil || !GatewayNativeOAuthConnectIntentValid(in) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	ownerCtx, err := connectContext(ctx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if in.State != "prepared" || !s.now().Before(in.Deadline) {
		in, err = s.reconcile(ownerCtx, in)
		return connectResult(in), err
	}
	material, err := s.open(in)
	if err != nil || material.State != state {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	won, err := s.repository.EnterConnect(ownerCtx, in)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	if !won {
		return s.ReadConnect(ownerCtx, in.Scope, in.Operation)
	}
	in.State = "entered"
	// Even a cancellation, transport error, crash or unknown token consumption
	// leaves the durable entry spent. No retry path, fallback, rearm or delete.
	bounded, cancel := context.WithTimeout(ownerCtx, 20*time.Second)
	defer cancel()
	bundle, err := s.exchange(bounded, code, material.Verifier)
	material = connectMaterial{}
	quarantine := err != nil
	if err == nil {
		enrollment := *s.enrollment
		enrollment.repository = connectEnrollmentRepository{enrollment.repository, s.repository, &in}
		out, stageErr := enrollment.Stage(bounded, in.Scope, in.EnrollmentOperation, bundle)
		quarantine = errors.Is(stageErr, ErrGatewayOAuthConflict) || in.EnrollmentMAC == ""
		if stageErr == nil {
			saved, finishErr := s.repository.FinishConnect(bounded, in, "completed", out)
			if finishErr == nil {
				return connectResult(saved), nil
			}
		}
	}
	// Bounded independent readback still works after the caller loses its ACK.
	recovery, stop := context.WithTimeout(context.WithoutCancel(ownerCtx), 5*time.Second)
	defer stop()
	if quarantine {
		saved, finishErr := s.repository.FinishConnect(recovery, in, "quarantined", GatewayNativeOAuthOutcome{})
		return connectResult(saved), finishErr
	}
	saved, recoveryErr := s.reconcile(recovery, in)
	if recoveryErr != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	return connectResult(saved), nil
}

func (s *GatewayNativeOAuthConnect) exchange(ctx context.Context, code, verifier string) (GatewayNativeOAuthBundle, error) {
	// One deadline covers dialing, TLS, headers AND reading/closing the body.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	deny := func() (GatewayNativeOAuthBundle, error) { return GatewayNativeOAuthBundle{}, ErrGatewayNativeIdentity }
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {openai.ClientID}, "redirect_uri": {GatewayOAuthConnectRedirect}, "code": {code}, "code_verifier": {verifier}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, openai.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return deny()
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return deny()
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) > 65536 || response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != openai.TokenURL {
		return deny()
	}
	m, err := gatewayOAuthJSON(raw)
	if err != nil || !gatewayOAuthCanonical(m, "access_token", "refresh_token", "id_token", "token_type", "expires_in", "scope") {
		return deny()
	}
	if _, exists := m["error"]; exists {
		return deny()
	}
	access, aOK := gatewayOAuthString(m, "access_token")
	refresh, rOK := gatewayOAuthString(m, "refresh_token")
	id, iOK := gatewayOAuthString(m, "id_token")
	kind, _ := gatewayOAuthString(m, "token_type")
	if !aOK || !rOK || !iOK || !strings.EqualFold(kind, "Bearer") {
		return deny()
	}
	if expiry, exists := m["expires_in"]; exists {
		if _, ok := gatewayOAuthSeconds(expiry); !ok {
			return deny()
		}
	}
	if rawScope, exists := m["scope"]; exists {
		var scope string
		if json.Unmarshal(rawScope, &scope) != nil {
			return deny()
		}
		got := strings.Fields(scope)
		want := strings.Fields(openai.DefaultScopes)
		seen := map[string]bool{}
		for _, name := range got {
			if seen[name] {
				return deny()
			}
			seen[name] = true
		}
		if len(got) != len(want) {
			return deny()
		}
		for _, name := range want {
			if !seen[name] {
				return deny()
			}
		}
	}
	delete(m, "access_token")
	delete(m, "refresh_token")
	delete(m, "id_token")
	metadata, err := json.Marshal(m)
	if err != nil {
		return deny()
	}
	bundle := GatewayNativeOAuthBundle{AccessToken: access, RefreshToken: refresh, IDToken: id, SensitiveMetadata: metadata}
	if _, err := bundle.bytes(); err != nil {
		return deny()
	}
	return bundle, nil
}
