package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/google/uuid"
)

const GatewayOAuthImportInputLimit = 64 * 1024
const GatewayOAuthImportBodyLimit = 400 * 1024
const GatewayOAuthImportEnvelopeLimit = 48 * 1024

// Transient sensitive ingress. Never an operation DTO or diagnostic record.
type GatewayNativeOAuthImportInput struct {
	Operation, Owner, Account, Generation, Method, Input string `json:"-"`
}

// The management authorizer and final handler use exactly the same decoder.
// Only this import route admits the escaped 400 KiB wire representation.
func DecodeGatewayNativeOAuthImport(raw []byte) (GatewayNativeOAuthImportInput, bool) {
	var in GatewayNativeOAuthImportInput
	deny := func() (GatewayNativeOAuthImportInput, bool) { return GatewayNativeOAuthImportInput{}, false }
	if len(raw) > GatewayOAuthImportBodyLimit || !gatewayOAuthUnicodeValid(raw) {
		return deny()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return deny()
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		name, ok := tok.(string)
		if err != nil || !ok || seen[name] || len(seen) >= 6 {
			return deny()
		}
		seen[name] = true
		var value string
		if d.Decode(&value) != nil {
			return deny()
		}
		switch name {
		case "operation", "owner_ref", "account_ref", "generation":
			if !GatewayNativeCredentialRefValid(value) {
				return deny()
			}
			switch name {
			case "operation":
				in.Operation = value
			case "owner_ref":
				in.Owner = value
			case "account_ref":
				in.Account = value
			case "generation":
				in.Generation = value
			}
		case "method":
			in.Method = value
		case "input":
			in.Input = value
		default:
			return deny()
		}
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != 6 || !GatewayNativeOAuthImportMethodValid(in.Method) || in.Input == "" || len(in.Input) > GatewayOAuthImportInputLimit {
		return deny()
	}
	if _, err = d.Token(); err != io.EOF {
		return deny()
	}
	return in, true
}

// GatewayNativeOAuthImportMethodValid is the closed import method vocabulary
// shared by parsing, envelopes and repository entry/claim guards.
func GatewayNativeOAuthImportMethodValid(method string) bool {
	return method == "refresh_token" || method == "auth_json"
}

func gatewayConnectMethodShapeValid(in GatewayNativeOAuthConnectIntent) bool {
	method := connectMethod(in)
	if GatewayNativeOAuthImportMethodValid(method) {
		return in.Redirect == "" && gatewayImportMACValid(in.ImportInputMAC) && gatewayImportMACValid(in.ImportClaimMAC) && gatewayImportMACValid(in.ImportKeyCommitment) && in.DevicePhase == "" && in.DeviceRevision == 0 && in.DevicePollAfter.IsZero() && in.DeviceDeadline.IsZero()
	}
	return in.ImportInputMAC == "" && in.ImportClaimMAC == "" && in.ImportKeyCommitment == "" && ((method == "browser" && in.Redirect == GatewayOAuthConnectRedirect) || (method == "device_code" && in.Redirect == GatewayOAuthDeviceRedirect))
}

func gatewayImportMACValid(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func gatewayImportTokenValid(value string) bool {
	if value == "" || len(value) > 32768 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// A selected ordinary Codex OAuth export is only a container for its RT. Supplied
// AT/ID/identity/plan data never enters Stage, timing, authorization or metadata.
// Schema reference: openai/codex@e1b7558 login/auth/storage.rs + token_data.rs.
func gatewayParseCodexImport(method, input string) (string, error) {
	deny := func() (string, error) { return "", ErrGatewayNativeIdentity }
	if len(input) == 0 || len(input) > GatewayOAuthImportInputLimit || !utf8.ValidString(input) {
		return deny()
	}
	if method == "refresh_token" {
		if !gatewayImportTokenValid(input) {
			return deny()
		}
		return input, nil
	}
	if method != "auth_json" {
		return deny()
	}
	root, err := gatewayOAuthJSON([]byte(input))
	if err != nil {
		return deny()
	}
	for name, raw := range root {
		switch name {
		case "tokens", "last_refresh":
		case "auth_mode":
			if string(raw) != "null" {
				var mode string
				if json.Unmarshal(raw, &mode) != nil || mode != "chatgpt" {
					return deny()
				}
			}
		case "OPENAI_API_KEY", "agent_identity", "personal_access_token", "bedrock_api_key", "bedrock_access_keys":
			if string(raw) != "null" {
				return deny()
			}
		default:
			return deny()
		}
	}
	fields, err := gatewayOAuthJSON(root["tokens"])
	if err != nil {
		return deny()
	}
	for name, raw := range fields {
		switch name {
		case "refresh_token", "access_token", "id_token":
			var token string
			if json.Unmarshal(raw, &token) != nil || (token != "" && !gatewayImportTokenValid(token)) {
				return deny()
			}
		case "account_id", "login_owner_id":
			if string(raw) != "null" {
				var label string
				if json.Unmarshal(raw, &label) != nil || len(label) > 1024 {
					return deny()
				}
			}
		case "oauth_provenance":
			if string(raw) == "null" {
				continue
			}
			provenance, err := gatewayOAuthJSON(raw)
			if err != nil || len(provenance) != 2 {
				return deny()
			}
			issuer, iOK := gatewayOAuthString(provenance, "issuer")
			client, cOK := gatewayOAuthString(provenance, "client_id")
			if !iOK || !cOK || issuer != GatewayOAuthIssuer || client != openai.ClientID {
				return deny()
			}
		default:
			return deny()
		}
	}
	refresh, ok := gatewayOAuthString(fields, "refresh_token")
	if !ok || !gatewayImportTokenValid(refresh) {
		return deny()
	}
	return refresh, nil
}

func (s *GatewayNativeOAuthConnect) importCommitments(scope GatewayNativeCredentialScope, operation, method, input, refresh string) (string, string) {
	mac := func(domain string, fields ...string) string {
		framed, _ := json.Marshal(fields)
		h := hmac.New(sha256.New, s.importKey)
		_, _ = h.Write([]byte(domain + "\x00"))
		_, _ = h.Write(framed)
		return hex.EncodeToString(h.Sum(nil))
	}
	inputMAC := mac("account-gateway/native/oauth-import-input/v1", scope.Consumer, scope.Owner, scope.Account, scope.Generation, scope.Purpose, operation, method, input)
	// Intentionally independent of owner, account, operation AND import method.
	claimMAC := mac("account-gateway/native/oauth-import-claim/v1", GatewayOAuthIssuer, openai.ClientID, refresh)
	return inputMAC, claimMAC
}

func gatewayImportAAD(in GatewayNativeOAuthConnectIntent) []byte {
	raw, _ := json.Marshal([]any{in.Scope, in.Operation, in.EnrollmentOperation, in.Method, in.ClientID, in.Deadline.UTC().Format(time.RFC3339Nano), in.StateHash, in.ImportInputMAC, in.ImportClaimMAC, in.ImportKeyCommitment})
	return append([]byte("account-gateway/native/oauth-import-material/v1\x00"), raw...)
}

func (s *GatewayNativeOAuthConnect) importKeyCommitment() string {
	mac := hmac.New(sha256.New, s.importKey)
	_, _ = mac.Write([]byte("account-gateway/native/oauth-import-key/v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *GatewayNativeOAuthConnect) sealImport(in GatewayNativeOAuthConnectIntent, refresh string) (string, error) {
	if !GatewayNativeOAuthConnectIntentValid(in) || !GatewayNativeOAuthImportMethodValid(in.Method) || !gatewayImportTokenValid(refresh) {
		return "", ErrGatewayNativeIdentity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrGatewayNativeIdentity
	}
	// Raw bytes, not JSON: even maximum tokens fit the import-only 48 KiB bound.
	sealed := s.aead.Seal(nonce, nonce, []byte(refresh), gatewayImportAAD(in))
	envelope := "gci1." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(envelope) > GatewayOAuthImportEnvelopeLimit {
		return "", ErrGatewayNativeIdentity
	}
	return envelope, nil
}

func (s *GatewayNativeOAuthConnect) openImport(in GatewayNativeOAuthConnectIntent) (string, error) {
	if !GatewayNativeOAuthConnectIntentValid(in) || !GatewayNativeOAuthImportMethodValid(in.Method) || !strings.HasPrefix(in.Envelope, "gci1.") || len(in.Envelope) > GatewayOAuthImportEnvelopeLimit {
		return "", ErrGatewayNativeIdentity
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(in.Envelope, "gci1."))
	n := s.aead.NonceSize()
	if err != nil || len(sealed) < n+s.aead.Overhead() {
		return "", ErrGatewayNativeIdentity
	}
	raw, err := s.aead.Open(nil, sealed[:n], sealed[n:], gatewayImportAAD(in))
	if err != nil {
		return "", ErrGatewayNativeIdentity
	}
	defer clear(raw)
	refresh := string(raw)
	if !gatewayImportTokenValid(refresh) {
		return "", ErrGatewayNativeIdentity
	}
	return refresh, nil
}

func (s *GatewayNativeOAuthConnect) ImportConnect(ctx context.Context, scope GatewayNativeCredentialScope, operation, method, input string) (GatewayNativeOAuthConnectResult, error) {
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) || s.authorizeEntry == nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	refresh, err := gatewayParseCodexImport(method, input)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, err
	}
	inputMAC, claimMAC := s.importCommitments(scope, operation, method, input, refresh)
	state, err := openai.GenerateState()
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	in := GatewayNativeOAuthConnectIntent{Scope: scope, Operation: operation, ClientID: openai.ClientID, Method: method, State: "prepared", EnrollmentOperation: "connect-" + uuid.NewString(), Deadline: s.now().UTC().Truncate(time.Microsecond).Add(GatewayOAuthConnectTTL - time.Second), StateHash: connectStateHash(state), ImportInputMAC: inputMAC, ImportClaimMAC: claimMAC, ImportKeyCommitment: s.importKeyCommitment()}
	in.Envelope, err = s.sealImport(in, refresh)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, err
	}
	saved, err := s.repository.PrepareConnect(ctx, in)
	if err != nil || !SameGatewayNativeOAuthConnectIntent(in, saved) {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayOAuthConflict
	}
	saved, err = s.reconcile(ctx, saved)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, err
	}
	if saved.State != "prepared" {
		return connectResult(saved), nil
	}
	refresh, err = s.openImport(saved)
	if err != nil || s.authorizeEntry(ctx, scope, operation) != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayNativeIdentity
	}
	won, err := s.repository.EnterConnect(ctx, saved)
	if err != nil {
		return GatewayNativeOAuthConnectResult{}, ErrGatewayOAuthConflict
	}
	if !won {
		return s.ReadConnect(ctx, scope, operation)
	}
	saved.State = "entered"
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {openai.ClientID}, "scope": {openai.RefreshScopes}}
	bundle, exchangeErr := s.exchangeConnectToken(bounded, form, refresh)
	return s.finishEntered(bounded, ctx, saved, bundle, exchangeErr)
}
