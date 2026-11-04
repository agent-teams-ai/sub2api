package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

const GatewayAccountLimitsRefreshContract = "account-limits-refresh/v1"

type GatewayAccountLimitsRefreshCapabilities struct {
	Contract         string   `json:"contract"`
	QuotaOnlyRefresh bool     `json:"quotaOnlyRefresh"`
	ProfileIDs       []string `json:"profileIds"`
}

// Refresh is an explicit custody-bound GET. The cached reader retains no
// credential or provider capability, and failure never rewrites its observation.
type GatewayAccountLimitsRefresher struct {
	dispatch   *GatewayNativeOAuthDispatch
	repository GatewayAccountLimitsRepository
	reader     *GatewayAccountLimitsReader
	authorize  GatewayAccountLimitsAuthorizer
}

func NewGatewayAccountLimitsRefresher(d *GatewayNativeOAuthDispatch, r GatewayAccountLimitsRepository, a GatewayAccountLimitsAuthorizer) (*GatewayAccountLimitsRefresher, error) {
	if d == nil || r == nil || a == nil {
		return nil, ErrGatewayNativeIdentity
	}
	reader, err := NewGatewayAccountLimitsReader(r, a)
	if err != nil {
		return nil, err
	}
	return &GatewayAccountLimitsRefresher{d, r, reader, a}, nil
}

func (s *GatewayAccountLimitsRefresher) Refresh(ctx context.Context, in GatewayAccountLimitsInput) GatewayAccountLimitsResult {
	unavailable := GatewayAccountLimitsResult{Status: "unavailable"}
	if s == nil || !in.Valid() {
		return unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	before, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil {
		return unavailable
	}
	if in.ProfileID != GatewayCodexOAuthResponsesProfile {
		return GatewayAccountLimitsResult{Status: "unsupported"}
	}
	if !gatewayAccountLimitsRouteValid(before, in) {
		return unavailable
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, in.OwnerRef)
	if err != nil {
		return unavailable
	}
	canonical, ok := s.dispatch.repository.(GatewayNativeOAuthCanonicalRepository)
	if !ok {
		return unavailable
	}
	scope, operation, err := canonical.ResolveGatewayNativeOAuthCanonical(ctx, before, in.AccountRef)
	if err != nil || scope.Owner != in.OwnerRef || scope.Account != in.AccountRef || scope.Generation != before.Generation || !GatewayNativeOAuthScopeAuthorized(ctx, scope) {
		return unavailable
	}
	a, p, release, err := s.dispatch.repository.LockGatewayNativeOAuthDispatch(ctx, scope, operation, before.AccountID)
	if err != nil || release == nil {
		return unavailable
	}
	if a == nil {
		release()
		return unavailable
	}
	// Keep the native birth/refresh lock through GET entry and response. This
	// excludes credential rotation while using the current sealed version.
	a = snapshotGatewayNativeAccount(a)
	raw, observed, err := func() (GatewayCodexRawLimits, time.Time, error) {
		defer release()
		if gatewayOAuthPhysicalValid(a, p) != nil || p.QualifiedAt.IsZero() || !SameGatewayNativeDescriptor(before, p.Route) || p.RefreshFence == nil || p.RefreshFence.Check(ctx) != nil {
			return GatewayCodexRawLimits{}, time.Time{}, ErrGatewayNativeIdentity
		}
		entry, err := s.authorize(ctx, in)
		if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, entry) {
			return GatewayCodexRawLimits{}, time.Time{}, ErrGatewayNativeIdentity
		}
		return s.dispatch.fetchAccountLimits(ctx, a, p)
	}()
	if err != nil {
		return unavailable
	}
	after, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, after) {
		return unavailable
	}
	fresh, current, release, err := s.dispatch.repository.LockGatewayNativeOAuthDispatch(ctx, scope, operation, before.AccountID)
	if err != nil || release == nil {
		return unavailable
	}
	valid := gatewayOAuthPhysicalValid(fresh, current) == nil && sameGatewayOAuthPhysical(p, current) && current.RefreshFence != nil && current.RefreshFence.Check(ctx) == nil
	oldVersion, oldErr := gatewayOAuthCredentialVersion(a)
	version, versionErr := gatewayOAuthCredentialVersion(fresh)
	release()
	if !valid || oldErr != nil || versionErr != nil || oldVersion != version || ctx.Err() != nil {
		return unavailable
	}
	if s.repository.StoreGatewayAccountLimits(ctx, p, raw, observed) != nil {
		return unavailable
	}
	return s.reader.Read(ctx, in)
}

func (s *GatewayNativeOAuthDispatch) fetchAccountLimits(ctx context.Context, a *Account, p GatewayNativeOAuthPhysical) (GatewayCodexRawLimits, time.Time, error) {
	invalid := func() (GatewayCodexRawLimits, time.Time, error) {
		return GatewayCodexRawLimits{}, time.Time{}, ErrGatewayNativeIdentity
	}
	version, err := gatewayOAuthCredentialVersion(a)
	if err != nil || a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now()) {
		return invalid()
	}
	bundle, err := s.custody.openOAuthVersion(a.GetCredential("oauth_bundle"), p.Scope, version)
	if err != nil {
		return invalid()
	}
	identity, err := s.verifier.Verify(ctx, bundle.IDToken)
	issuer, subject := identity.Principal()
	if err != nil || issuer != p.Issuer || subject != p.Subject {
		return invalid()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, chatGPTUsageURL, nil)
	if err != nil {
		return invalid()
	}
	for name, value := range buildCodexCommonHeaders(bundle.AccessToken, p.ProviderAccount, false) {
		request.Header.Set(name, value)
	}
	bundle = GatewayNativeOAuthBundle{}
	if p.RefreshFence.Check(ctx) != nil {
		return invalid()
	}
	response, err := s.client.Do(request)
	if err != nil {
		return invalid()
	}
	if response.Body == nil {
		return invalid()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != chatGPTUsageURL {
		return invalid()
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 || ctx.Err() != nil {
		return invalid()
	}
	observed := time.Now().UTC()
	raw, err := projectGatewayCodexQuota(body, p.ProviderAccount, observed)
	if err != nil {
		return invalid()
	}
	return raw, observed, nil
}

// Only the ordinary subscription windows are admitted. Additional/Spark and
// credits metadata cannot masquerade as these percentages. Missing fields are
// retained as unknown rather than Go's numeric zero value.
func projectGatewayCodexQuota(body []byte, provider string, observed time.Time) (GatewayCodexRawLimits, error) {
	invalid := func() (GatewayCodexRawLimits, error) { return GatewayCodexRawLimits{}, ErrGatewayNativeIdentity }
	fields, ok := GatewayNativePayloadFields(body, "account_id", "rate_limit")
	if !ok {
		return invalid()
	}
	if value := fields["account_id"]; value != nil {
		var account string
		if json.Unmarshal(value, &account) != nil || account != provider {
			return invalid()
		}
	}
	limits, ok := GatewayNativePayloadFields(fields["rate_limit"], "primary_window", "secondary_window")
	if !ok {
		return invalid()
	}
	raw := GatewayCodexRawLimits{}
	for _, id := range []string{"primary", "secondary"} {
		value := limits[id+"_window"]
		if len(value) == 0 || string(value) == "null" {
			continue
		}
		window, ok := GatewayNativePayloadFields(value, "used_percent", "limit_window_seconds", "reset_after_seconds", "reset_at")
		if !ok {
			return invalid()
		}
		w := GatewayCodexRawWindow{ID: id, ObservedAt: observed.Format(time.RFC3339Nano)}
		present := false
		for _, key := range []string{"used_percent", "limit_window_seconds", "reset_after_seconds", "reset_at"} {
			v := window[key]
			if len(v) == 0 || string(v) == "null" {
				continue
			}
			present = true
			// Decode numbers only; quoted values, overflow and negatives are refused.
			var number json.Number
			if v[0] == '"' || json.Unmarshal(v, &number) != nil {
				return invalid()
			}
			text := number.String()
			if key == "used_percent" {
				n := limitsNumber(&text)
				if n == nil || *n > 100 {
					return invalid()
				}
				w.Used = &text
				continue
			}
			n := limitsInteger(&text)
			if n == nil {
				return invalid()
			}
			switch key {
			case "limit_window_seconds":
				if *n <= 0 || *n%60 != 0 {
					return invalid()
				}
				minutes := strconv.FormatInt(*n/60, 10)
				w.WindowMinutes = &minutes
			case "reset_after_seconds":
				if *n > 253402300799-observed.Unix() {
					return invalid()
				}
				w.ResetAfterSeconds = &text
			case "reset_at":
				if *n > 253402300799 {
					return invalid()
				}
				w.ResetAt = &text
			}
		}
		if present {
			raw.Windows = append(raw.Windows, w)
		}
	}
	if len(raw.Windows) == 0 {
		return invalid()
	}
	return raw, nil
}
