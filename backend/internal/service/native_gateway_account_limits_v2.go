package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"
)

const GatewayAccountLimitsContractV2 = "account-limits/v2"

type GatewayAccountLimitPeriodV2 struct {
	Kind            string `json:"kind"`
	DurationSeconds *int64 `json:"durationSeconds,omitempty"`
}
type GatewayAccountLimitWindowV2 struct {
	ID          string                      `json:"id"`
	Provider    string                      `json:"provider"`
	Dimension   string                      `json:"dimension"`
	Unit        string                      `json:"unit"`
	Period      GatewayAccountLimitPeriodV2 `json:"period"`
	Label       *string                     `json:"label"`
	UsedPercent *float64                    `json:"usedPercent"`
	ObservedAt  *string                     `json:"observedAt"`
	ResetAt     *string                     `json:"resetAt"`
}
type GatewayAccountLimitsSnapshotV2 struct {
	Scope   string                        `json:"scope"`
	Windows []GatewayAccountLimitWindowV2 `json:"windows"`
}
type GatewayAccountLimitsResultV2 struct {
	Status             string                        `json:"status"`
	PhysicalGeneration string                        `json:"physicalGeneration,omitempty"`
	PrincipalVersion   string                        `json:"principalVersion,omitempty"`
	Revision           int64                         `json:"revision,omitempty"`
	Scope              string                        `json:"scope,omitempty"`
	Windows            []GatewayAccountLimitWindowV2 `json:"windows,omitempty"`
}
type GatewayAccountLimitsStoredV2 struct {
	PrincipalVersion string
	Revision         int64
	Snapshot         *GatewayAccountLimitsSnapshotV2
}

// Cache reads have no credential, refresh, provider HTTP or inference capability.
type GatewayAccountLimitsCacheV2 interface {
	ReadGatewayAccountLimitsV2(context.Context, GatewayAccountLimitsInput, GatewayNativeRoute) (GatewayAccountLimitsStoredV2, error)
}
type GatewayAccountLimitsRepositoryV2 interface {
	GatewayAccountLimitsCacheV2
	StoreGatewayAccountLimitsV2(context.Context, GatewayNativeOAuthPhysical, GatewayAccountLimitsSnapshotV2, time.Time) error
}
type GatewayAccountLimitsReaderV2 struct {
	repository GatewayAccountLimitsCacheV2
	authorize  GatewayAccountLimitsAuthorizer
}

func NewGatewayAccountLimitsReaderV2(r GatewayAccountLimitsCacheV2, authorize GatewayAccountLimitsAuthorizer) (*GatewayAccountLimitsReaderV2, error) {
	if r == nil || authorize == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return &GatewayAccountLimitsReaderV2{r, authorize}, nil
}
func GatewayAccountLimitsProviderV2(profile string) string {
	switch profile {
	case GatewayKimiCodeResponsesProfile:
		return "kimi"
	case GatewayGLMCodingResponsesProfile:
		return "glm"
	case GatewayMiniMaxMPlanResponsesProfile:
		return "minimax"
	case GatewayGrokOAuthResponsesProfile:
		return "grok"
	}
	return ""
}
func GatewayAccountLimitsRouteValidV2(route GatewayNativeRoute, in GatewayAccountLimitsInput) bool {
	if !in.Valid() || route.Profile != in.ProfileID || GatewayAccountLimitsProviderV2(route.Profile) == "" || route.AccountID <= 0 || route.CreatedAt.IsZero() || route.CreatedAt.Nanosecond()%1000 != 0 {
		return false
	}
	scope := GatewayNativeCredentialScope{Consumer: "validation", Owner: in.OwnerRef, Account: in.AccountRef, Generation: route.Generation, Purpose: GatewayOAuthBundlePurpose}
	if !GatewayNativeOAuthScopeValid(scope) {
		return false
	}
	if GatewayAccountLimitsProviderV2(route.Profile) == "grok" {
		return route.BaseURL == GatewayGrokOAuthBaseURL && route.Model == GatewayGrokOAuthModel
	}
	return GatewayNativeAPIKeyProfileValid(route.Profile, route.BaseURL, route.Model)
}
func (s *GatewayAccountLimitsReaderV2) Read(ctx context.Context, in GatewayAccountLimitsInput) GatewayAccountLimitsResultV2 {
	unavailable := GatewayAccountLimitsResultV2{Status: "unavailable"}
	if s == nil || !in.Valid() {
		return unavailable
	}
	before, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil {
		return unavailable
	}
	if GatewayAccountLimitsProviderV2(in.ProfileID) == "" {
		return GatewayAccountLimitsResultV2{Status: "unsupported"}
	}
	if !GatewayAccountLimitsRouteValidV2(before, in) {
		return unavailable
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, in.OwnerRef)
	if err != nil {
		return unavailable
	}
	stored, err := s.repository.ReadGatewayAccountLimitsV2(ctx, in, before)
	if err != nil {
		return unavailable
	}
	after, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, after) {
		return unavailable
	}
	current, err := s.repository.ReadGatewayAccountLimitsV2(ctx, in, after)
	if err != nil || ctx.Err() != nil || stored.PrincipalVersion == "" || current.PrincipalVersion != stored.PrincipalVersion {
		return unavailable
	}
	if stored.Snapshot == nil {
		return GatewayAccountLimitsResultV2{Status: "unknown"}
	}
	if current.Snapshot == nil || stored.Revision < 1 || stored.Revision > gatewayLimitsMaxInteger || current.Revision < stored.Revision || current.Revision > gatewayLimitsMaxInteger || !ValidateGatewayAccountLimitsSnapshotV2(*stored.Snapshot, before.Profile) {
		return unavailable
	}
	// A newer complete observation may remove an old window, so return the fresh
	// snapshot from the identity recheck rather than resurrecting stale windows.
	if !ValidateGatewayAccountLimitsSnapshotV2(*current.Snapshot, after.Profile) {
		return unavailable
	}
	if len(current.Snapshot.Windows) == 0 {
		return GatewayAccountLimitsResultV2{Status: "unknown"}
	}
	return GatewayAccountLimitsResultV2{Status: "snapshot", PhysicalGeneration: after.Generation, PrincipalVersion: current.PrincipalVersion, Revision: current.Revision, Scope: current.Snapshot.Scope, Windows: current.Snapshot.Windows}
}

// API-key identity is the protected credential generation and exact physical
// birth. Only Grok adds its verified immutable provider principal; no token bytes,
// mutable name, email or credential refresh revision enter this digest.
func GatewayAccountLimitsPrincipalV2(p GatewayNativeOAuthPhysical) string {
	values := []any{p.Scope.Consumer, p.Scope.Owner, p.Scope.Account, p.Scope.Generation, p.Scope.Purpose, p.Route.AccountID, p.Route.CreatedAt.UTC().Format(time.RFC3339Nano), p.Route.Profile, p.Route.BaseURL, p.Route.Model}
	if GatewayAccountLimitsProviderV2(p.Route.Profile) == "grok" {
		values = append(values, p.Issuer, p.Subject, p.ProviderAccount)
	}
	raw, _ := json.Marshal(values)
	digest := sha256.Sum256(append([]byte("account-limits/principal/v2\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func ValidateGatewayAccountLimitsSnapshotV2(snapshot GatewayAccountLimitsSnapshotV2, profile string) bool {
	provider := GatewayAccountLimitsProviderV2(profile)
	if provider == "" || snapshot.Scope != "account" && snapshot.Scope != "subscription" || !ValidateGatewayAccountLimitWindowsV2(snapshot.Windows) {
		return false
	}
	for _, w := range snapshot.Windows {
		if w.Provider != provider {
			return false
		}
	}
	return true
}
func ValidateGatewayAccountLimitWindowsV2(windows []GatewayAccountLimitWindowV2) bool {
	if len(windows) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, w := range windows {
		switch w.ID {
		case "five_hour", "weekly", "monthly", "primary", "secondary", "unknown", "request_rate", "token_rate":
		default:
			return false
		}
		switch w.Provider {
		case "kimi", "glm", "minimax", "grok":
		default:
			return false
		}
		identity := w.Provider + "/" + w.ID + "/" + w.Dimension + "/" + w.Unit
		if seen[identity] {
			return false
		}
		seen[identity] = true
		if w.Dimension != "plan_quota" && w.Dimension != "rate_limit" {
			return false
		}
		switch w.Unit {
		case "credits", "tokens", "requests", "unknown":
		default:
			return false
		}
		switch w.Period.Kind {
		case "duration":
			if w.Period.DurationSeconds == nil || *w.Period.DurationSeconds <= 0 || *w.Period.DurationSeconds > gatewayLimitsMaxInteger {
				return false
			}
		case "monthly_billing_cycle", "unknown":
			if w.Period.DurationSeconds != nil {
				return false
			}
		default:
			return false
		}
		if w.Label != nil {
			switch *w.Label {
			case "5h":
				if w.Period.Kind != "duration" || *w.Period.DurationSeconds != 18000 {
					return false
				}
			case "Week":
				if w.Period.Kind != "duration" || *w.Period.DurationSeconds != 604800 {
					return false
				}
			case "Month":
				if w.Period.Kind != "monthly_billing_cycle" {
					return false
				}
			default:
				return false
			}
		}
		if w.UsedPercent != nil && (math.IsNaN(*w.UsedPercent) || math.IsInf(*w.UsedPercent, 0) || *w.UsedPercent < 0) {
			return false
		}
		for _, raw := range []*string{w.ObservedAt, w.ResetAt} {
			if raw != nil {
				t, err := time.Parse(time.RFC3339Nano, *raw)
				if err != nil || t.Year() < 1 || t.Year() > 9999 {
					return false
				}
			}
		}
		if w.UsedPercent != nil && w.ObservedAt == nil {
			return false
		}
		// Rate observations cannot masquerade as subscription quota windows.
		if (w.ID == "request_rate" || w.ID == "token_rate") && w.Dimension != "rate_limit" {
			return false
		}
		if w.Dimension == "rate_limit" && w.Label != nil {
			return false
		}
	}
	return true
}
