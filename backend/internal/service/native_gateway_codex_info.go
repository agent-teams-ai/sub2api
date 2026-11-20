package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Transient evidence travels through the existing refresh commit. It is bound
// to the exact private intent and cannot be minted by an exported DTO field.
type gatewayOAuthRefreshInfo struct {
	intent       GatewayNativeOAuthRefreshIntent
	observations []GatewayAccountInfoObservation
}

func (in GatewayNativeOAuthRefreshIntent) AccountInfoObservations() []GatewayAccountInfoObservation {
	if in.info == nil {
		return nil
	}
	identity := in
	identity.info = nil
	if identity != in.info.intent {
		return nil
	}
	raw, _ := json.Marshal(in.info.observations)
	var out []GatewayAccountInfoObservation
	_ = json.Unmarshal(raw, &out)
	return out
}

// The original fixed-issuer verification minted the timing proof over the
// entire encrypted bundle, including these exact ID-token bytes. This explicit
// legacy hydration does not reverify expired claims as current, call JWKS, or
// rotate credentials. It preserves the authenticated original exchange time.
func gatewayCodexRetainedInfo(p GatewayNativeOAuthPhysical, bundle GatewayNativeOAuthBundle, custody *GatewayNativeCredentialCustody) []GatewayAccountInfoObservation {
	if _, valid := gatewayOAuthBundleDue(bundle, time.Now(), custody); !valid {
		return nil
	}
	metadata, err := gatewayOAuthJSON(bundle.SensitiveMetadata)
	if err != nil {
		return nil
	}
	var timing gatewayOAuthTiming
	if json.Unmarshal(metadata[gatewayOAuthTimingMember], &timing) != nil {
		return nil
	}
	observed, err := time.Parse(time.RFC3339Nano, timing.RequestStarted)
	if err != nil || observed.IsZero() {
		return nil
	}
	expires, err := time.Parse(time.RFC3339Nano, timing.IDExpires)
	if err != nil || expires.IsZero() {
		return nil
	}
	parts := strings.Split(bundle.IDToken, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil
	}
	claims, err := gatewayOAuthJSON(raw)
	issuer, _ := gatewayOAuthString(claims, "iss")
	subject, _ := gatewayOAuthString(claims, "sub")
	if err != nil || issuer != p.Issuer || subject != p.Subject || issuer != GatewayOAuthIssuer {
		return nil
	}
	return []GatewayAccountInfoObservation{
		{Source: "verified_claims", CredentialRevision: p.CredentialRevision, ValidUntil: &expires, Fields: gatewayVerifiedCodexInfo(claims, observed)},
		{Source: "credential", CredentialRevision: p.CredentialRevision, Fields: gatewayCodexCredentialInfo(bundle, custody, observed)},
	}
}

// Called by the existing explicit maintenance mutation only for a qualified
// physical row with no initialized snapshot. A second idle maintenance uses
// the indexed hint from its normal locked read and never enters this path.
func (s *GatewayNativeOAuthRefresh) HydrateAccountInfo(ctx context.Context, scope GatewayNativeCredentialScope, operation string) error {
	if s == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) || !GatewayNativeCredentialRefValid(operation) {
		return ErrGatewayNativeIdentity
	}
	repository, ok := s.repository.(GatewayNativeOAuthDispatchRepository)
	writer, writable := s.repository.(GatewayAccountInfoWriter)
	if !ok || !writable {
		return ErrGatewayNativeIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	row, err := repository.ReadGatewayNativeOAuthDispatch(ctx, scope, operation)
	if err != nil || row.State != "completed" || row.AccountID < 1 {
		return ErrGatewayNativeIdentity
	}
	a, p, release, err := repository.LockGatewayNativeOAuthDispatch(ctx, scope, operation, row.AccountID)
	if err != nil || release == nil {
		return ErrGatewayNativeIdentity
	}
	if gatewayOAuthPhysicalValid(a, p) != nil || p.Scope != scope || p.Operation != operation || p.QualifiedAt.IsZero() {
		release()
		return ErrGatewayNativeIdentity
	}
	version, err := gatewayOAuthCredentialVersion(a)
	var bundle GatewayNativeOAuthBundle
	if err == nil {
		bundle, err = s.custody.openOAuthVersion(a.GetCredential("oauth_bundle"), scope, version)
	}
	release()
	if err != nil {
		return ErrGatewayNativeIdentity
	}
	p.CredentialRevision = version
	observations := gatewayCodexRetainedInfo(p, bundle, s.custody)
	if len(observations) == 0 {
		return nil
	}
	// The initialized hint must never suppress a missing second source after a
	// partial write. Reuse the same physical transaction for the whole snapshot.
	return writer.StoreGatewayAccountInfo(ctx, p, true, observations...)
}
