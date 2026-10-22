package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"
)

const GatewayAccountLimitsContract = "account-limits/v1"
const gatewayLimitsMaxInteger = int64(9007199254740991)

type GatewayAccountLimitsInput struct {
	OwnerRef                   string `json:"ownerRef"`
	AccountRef                 string `json:"accountRef"`
	ProfileID                  string `json:"profileId"`
	ExpectedAuthorizationEpoch int64  `json:"expectedAuthorizationEpoch"`
}

func (in GatewayAccountLimitsInput) Valid() bool {
	return GatewayNativeCredentialRefValid(in.OwnerRef) && GatewayNativeCredentialRefValid(in.AccountRef) &&
		GatewayNativeCredentialRefValid(in.ProfileID) && in.ExpectedAuthorizationEpoch >= 0 && in.ExpectedAuthorizationEpoch <= gatewayLimitsMaxInteger
}

type GatewayAccountLimitsCapabilities struct {
	Contract         string `json:"contract"`
	CachedRead       bool   `json:"cachedRead"`
	QuotaOnlyRefresh bool   `json:"quotaOnlyRefresh"`
}
type GatewayAccountLimitWindow struct {
	ID              string   `json:"id"`
	Family          string   `json:"family"`
	DurationSeconds *int64   `json:"durationSeconds"`
	UsedPercent     *float64 `json:"usedPercent"`
	ObservedAt      *string  `json:"observedAt"`
	ResetAt         *string  `json:"resetAt"`
	Basis           string   `json:"basis"`
	Reason          string   `json:"reason,omitempty"`
}
type GatewayAccountLimitsResult struct {
	Status             string                      `json:"status"`
	PhysicalGeneration string                      `json:"physicalGeneration,omitempty"`
	PrincipalVersion   string                      `json:"principalVersion,omitempty"`
	Revision           int64                       `json:"revision,omitempty"`
	Scope              string                      `json:"scope,omitempty"`
	Windows            []GatewayAccountLimitWindow `json:"windows,omitempty"`
}

// Raw values are retained only from the fixed ordinary Codex response header
// allowlist, never Extra, local stats, Spark/metered buckets or provider bodies.
// Missing and malformed values remain distinct from a reported zero.
type GatewayCodexRawWindow struct {
	ID                string  `json:"id"`
	Used              *string `json:"used,omitempty"`
	WindowMinutes     *string `json:"windowMinutes,omitempty"`
	ObservedAt        string  `json:"observedAt"`
	ResetAt           *string `json:"resetAt,omitempty"`
	ResetAfterSeconds *string `json:"resetAfterSeconds,omitempty"`
}
type GatewayCodexRawLimits struct {
	Windows []GatewayCodexRawWindow `json:"windows"`
}
type GatewayAccountLimitsStored struct {
	PrincipalVersion string
	Revision         int64
	Raw              *GatewayCodexRawLimits
}

// This repository has no network, credential decryption, refresh or admin API.
// Read must authenticate the exact durable qualified birth/principal even when
// no snapshot exists. The separate writer is used only by passive dispatch.
type GatewayAccountLimitsCache interface {
	ReadGatewayAccountLimits(context.Context, GatewayAccountLimitsInput, GatewayNativeRoute) (GatewayAccountLimitsStored, error)
}
type GatewayAccountLimitsRepository interface {
	GatewayAccountLimitsCache
	StoreGatewayAccountLimits(context.Context, GatewayNativeOAuthPhysical, GatewayCodexRawLimits, time.Time) error
}
type GatewayAccountLimitsAuthorizer func(context.Context, GatewayAccountLimitsInput) (GatewayNativeRoute, error)
type GatewayAccountLimitsReader struct {
	repository GatewayAccountLimitsCache
	authorize  GatewayAccountLimitsAuthorizer
}

func NewGatewayAccountLimitsReader(r GatewayAccountLimitsCache, authorize GatewayAccountLimitsAuthorizer) (*GatewayAccountLimitsReader, error) {
	if r == nil || authorize == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return &GatewayAccountLimitsReader{r, authorize}, nil
}
func (s *GatewayAccountLimitsReader) Read(ctx context.Context, in GatewayAccountLimitsInput) GatewayAccountLimitsResult {
	unavailable := GatewayAccountLimitsResult{Status: "unavailable"}
	if s == nil || !in.Valid() {
		return unavailable
	}
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
	stored, err := s.repository.ReadGatewayAccountLimits(ctx, in, before)
	if err != nil {
		return unavailable
	}
	after, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, after) {
		return unavailable
	}
	// A second fresh source identity read fences deletion/principal loss while
	// waiting on the external owner authority. A newer observation may be ignored.
	current, err := s.repository.ReadGatewayAccountLimits(ctx, in, after)
	if err != nil || ctx.Err() != nil || current.PrincipalVersion != stored.PrincipalVersion || stored.PrincipalVersion == "" {
		return unavailable
	}
	if stored.Raw == nil {
		return GatewayAccountLimitsResult{Status: "unknown"}
	}
	if stored.Revision < 1 || stored.Revision > gatewayLimitsMaxInteger || current.Raw == nil || current.Revision < stored.Revision || current.Revision > gatewayLimitsMaxInteger {
		return unavailable
	}
	windows := NormalizeGatewayCodexLimits(*stored.Raw)
	if len(windows) == 0 {
		return GatewayAccountLimitsResult{Status: "unknown"}
	}
	return GatewayAccountLimitsResult{Status: "snapshot", PhysicalGeneration: before.Generation, PrincipalVersion: stored.PrincipalVersion, Revision: stored.Revision, Scope: "account", Windows: windows}
}
func gatewayAccountLimitsRouteValid(route GatewayNativeRoute, in GatewayAccountLimitsInput) bool {
	consumer := "validation"
	return route.AccountID > 0 && !route.CreatedAt.IsZero() && route.CreatedAt.Nanosecond()%1000 == 0 &&
		route.Profile == in.ProfileID && route.BaseURL == GatewayCodexOAuthBaseURL && route.Model == GatewayCodexOAuthModel &&
		GatewayNativeOAuthScopeValid(GatewayNativeCredentialScope{consumer, in.OwnerRef, in.AccountRef, route.Generation, GatewayOAuthBundlePurpose})
}

// Domain-separated framing binds immutable qualified principal+physical birth.
// Rename and encrypted token version deliberately never enter this digest.
func GatewayAccountLimitsPrincipal(p GatewayNativeOAuthPhysical) string {
	raw, _ := json.Marshal([]any{p.Scope.Consumer, p.Scope.Owner, p.Scope.Account, p.Scope.Generation, p.Route.AccountID, p.Route.CreatedAt.UTC().Format(time.RFC3339Nano), p.Issuer, p.Subject, p.ProviderAccount})
	digest := sha256.Sum256(append([]byte("account-limits/principal/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func CaptureGatewayCodexLimits(headers http.Header, observed time.Time) GatewayCodexRawLimits {
	raw := GatewayCodexRawLimits{}
	for _, id := range []string{"primary", "secondary"} {
		get := func(suffix string) *string {
			values := headers.Values("x-codex-" + id + "-" + suffix)
			if len(values) == 0 {
				return nil
			}
			value := "invalid"
			if len(values) == 1 && len(values[0]) <= 128 {
				value = values[0]
			}
			return &value
		}
		w := GatewayCodexRawWindow{ID: id, Used: get("used-percent"), WindowMinutes: get("window-minutes"), ObservedAt: observed.UTC().Format(time.RFC3339Nano), ResetAt: get("reset-at"), ResetAfterSeconds: get("reset-after-seconds")}
		if w.Used != nil || w.WindowMinutes != nil || w.ResetAt != nil || w.ResetAfterSeconds != nil {
			raw.Windows = append(raw.Windows, w)
		}
	}
	return raw
}
func limitsNumber(raw *string) *float64 {
	if raw == nil {
		return nil
	}
	value, err := strconv.ParseFloat(*raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return nil
	}
	return &value
}
func limitsInteger(raw *string) *int64 {
	n := limitsNumber(raw)
	if n == nil || *n > float64(gatewayLimitsMaxInteger) || math.Trunc(*n) != *n {
		return nil
	}
	v := int64(*n)
	return &v
}
func limitsInstant(raw string) *time.Time {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		t = t.UTC()
		if t.Year() >= 1 && t.Year() <= 9999 {
			return &t
		}
		return nil
	}
	// The raw quota protocol uses Unix seconds, never milliseconds.
	n := limitsInteger(&raw)
	if n == nil || *n > 253402300799 {
		return nil
	}
	t := time.Unix(*n, 0).UTC()
	return &t
}
func limitsISO(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}
func NormalizeGatewayCodexLimits(raw GatewayCodexRawLimits) []GatewayAccountLimitWindow {
	if len(raw.Windows) > 2 {
		return nil
	}
	out := []GatewayAccountLimitWindow{}
	seen := map[string]bool{}
	for _, w := range raw.Windows {
		if (w.ID != "primary" && w.ID != "secondary") || seen[w.ID] {
			return nil
		}
		seen[w.ID] = true
		normalized := GatewayAccountLimitWindow{ID: w.ID, Family: "codex", UsedPercent: limitsNumber(w.Used), Basis: "legacy_alias"}
		if minutes := limitsInteger(w.WindowMinutes); minutes != nil && *minutes > 0 && *minutes <= gatewayLimitsMaxInteger/60 {
			seconds := *minutes * 60
			normalized.DurationSeconds = &seconds
			normalized.Basis = "duration"
		}
		observed := limitsInstant(w.ObservedAt)
		normalized.ObservedAt = limitsISO(observed)
		var absolute, relative *time.Time
		if w.ResetAt != nil {
			absolute = limitsInstant(*w.ResetAt)
		}
		if seconds := limitsInteger(w.ResetAfterSeconds); seconds != nil && observed != nil && *seconds <= 253402300799-observed.Unix() {
			t := time.Unix(observed.Unix()+*seconds, int64(observed.Nanosecond())).UTC()
			relative = &t
		}
		reset := absolute
		if reset == nil {
			reset = relative
		}
		if absolute != nil && relative != nil && math.Abs(absolute.Sub(*relative).Seconds()) > 60 {
			reset = nil
			normalized.Reason = "reset_conflict"
		}
		normalized.ResetAt = limitsISO(reset)
		out = append(out, normalized)
	}
	return out
}

// Called only after a qualified ordinary Codex response, never by Read. A cache
// failure cannot change inference settlement or retry a provider request.
func (s *OpenAIGatewayService) captureGatewayAccountLimits(ctx context.Context, headers http.Header) {
	state, _ := ctx.Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	if state == nil || state.oauth == nil || !state.entered.Load() || state.route.Profile != GatewayCodexOAuthResponsesProfile || state.route.Model != GatewayCodexOAuthModel {
		return
	}
	binding, ok := ctx.Value(gatewayOAuthDispatchBindingKey{}).(gatewayOAuthDispatchBinding)
	if !ok || binding.dispatch == nil {
		return
	}
	repository, ok := binding.dispatch.repository.(GatewayAccountLimitsRepository)
	if !ok {
		return
	}
	observed := time.Now().UTC()
	raw := CaptureGatewayCodexLimits(headers, observed)
	if len(raw.Windows) == 0 {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = repository.StoreGatewayAccountLimits(bounded, *state.oauth, raw, observed)
}
