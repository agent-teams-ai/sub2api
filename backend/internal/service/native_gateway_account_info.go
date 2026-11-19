package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const GatewayAccountInfoContract = "account-info/v1"

// Only these positive-allowlist values cross the native metadata boundary.
// An absent value is represented by status, never a zero-value guessed fact.
type GatewayAccountFact[T any] struct {
	Status     string `json:"status"`
	Value      *T     `json:"value,omitempty"`
	Source     string `json:"source,omitempty"`
	ObservedAt string `json:"observedAt,omitempty"`
	Freshness  string `json:"freshness,omitempty"`
}
type GatewayAccountInfoDate struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type GatewayAccountSubscription struct {
	Code   string                  `json:"code"`
	Label  string                  `json:"label"`
	Scope  string                  `json:"scope"`
	EndsAt *GatewayAccountInfoDate `json:"endsAt"`
}
type GatewayAccountInfoFields struct {
	Email               GatewayAccountFact[string]                     `json:"email"`
	AccountLabel        GatewayAccountFact[string]                     `json:"accountLabel"`
	Subscription        GatewayAccountFact[GatewayAccountSubscription] `json:"subscription"`
	CredentialExpiresAt GatewayAccountFact[string]                     `json:"credentialExpiresAt"`
	PrivacyMode         GatewayAccountFact[string]                     `json:"privacyMode"`
}
type GatewayAccountInfo struct {
	Status       string                    `json:"status"`
	InfoRevision string                    `json:"infoRevision,omitempty"`
	Fields       *GatewayAccountInfoFields `json:"fields,omitempty"`
}
type GatewayAccountInfoResult struct {
	Info               GatewayAccountInfo `json:"info"`
	PhysicalGeneration string             `json:"physicalGeneration,omitempty"`
	PrincipalVersion   string             `json:"principalVersion,omitempty"`
}

// The stored source records are private. Source order is reserved BEFORE the
// provider read; an authoritative unknown remains a tombstone at that order.
type GatewayAccountInfoObservation struct {
	Source             string                   `json:"source"`
	Order              int64                    `json:"order"`
	CredentialRevision int64                    `json:"credentialRevision"`
	ValidUntil         *time.Time               `json:"validUntil,omitempty"`
	Fields             GatewayAccountInfoFields `json:"fields"`
}
type GatewayAccountInfoStored struct {
	PrincipalVersion   string
	Revision           int64
	CredentialRevision int64
	Sources            map[string]GatewayAccountInfoObservation
}
type GatewayAccountInfoCache interface {
	ReadGatewayAccountInfo(context.Context, GatewayAccountLimitsInput, GatewayNativeRoute) (GatewayAccountInfoStored, error)
}
type GatewayAccountInfoWriter interface {
	ReserveGatewayAccountInfoOrder(context.Context) (int64, error)
	StoreGatewayAccountInfo(context.Context, GatewayNativeOAuthPhysical, GatewayAccountInfoObservation, bool) error
}
type GatewayAccountInfoReader struct {
	cache     GatewayAccountInfoCache
	authorize GatewayAccountLimitsAuthorizer
	now       func() time.Time
	mu        sync.Mutex
	active    map[string]int
}

func NewGatewayAccountInfoReader(cache GatewayAccountInfoCache, authorize GatewayAccountLimitsAuthorizer) (*GatewayAccountInfoReader, error) {
	if cache == nil || authorize == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return &GatewayAccountInfoReader{cache: cache, authorize: authorize, now: time.Now, active: map[string]int{}}, nil
}

func GatewayAccountInfoProvider(profile string) string {
	switch profile {
	case GatewayCodexOAuthResponsesProfile:
		return "openai"
	case GatewayClaudeOAuthMessagesProfile:
		return "anthropic"
	case GatewayGrokOAuthResponsesProfile:
		return "grok"
	case GatewayOpenRouterResponsesProfile:
		return "openrouter"
	case GatewayNVIDIABuildChatProfile:
		return "nvidia"
	case GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile:
		return "mimo"
	case GatewayKimiCodeResponsesProfile:
		return "kimi"
	case GatewayGLMCodingResponsesProfile:
		return "glm"
	case GatewayMiniMaxMPlanResponsesProfile:
		return "minimax"
	default:
		return ""
	}
}
func GatewayAccountInfoRouteValid(route GatewayNativeRoute, in GatewayAccountLimitsInput) bool {
	if !in.Valid() || route.Profile != in.ProfileID || GatewayAccountInfoProvider(route.Profile) == "" || route.AccountID <= 0 || route.CreatedAt.IsZero() || route.CreatedAt.Nanosecond()%1000 != 0 {
		return false
	}
	scope := GatewayNativeCredentialScope{Consumer: "validation", Owner: in.OwnerRef, Account: in.AccountRef, Generation: route.Generation, Purpose: GatewayOAuthBundlePurpose}
	if !GatewayNativeOAuthScopeValid(scope) {
		return false
	}
	switch route.Profile {
	case GatewayCodexOAuthResponsesProfile:
		return route.BaseURL == GatewayCodexOAuthBaseURL && route.Model == GatewayCodexOAuthModel
	case GatewayClaudeOAuthMessagesProfile:
		return route.BaseURL == GatewayClaudeOAuthBaseURL && route.Model == GatewayClaudeOAuthModel
	case GatewayGrokOAuthResponsesProfile:
		return route.BaseURL == GatewayGrokOAuthBaseURL && route.Model == GatewayGrokOAuthModel
	default:
		return GatewayNativeAPIKeyProfileValid(route.Profile, route.BaseURL, route.Model)
	}
}
func GatewayAccountInfoPrincipal(p GatewayNativeOAuthPhysical) string {
	values := []any{p.Scope.Consumer, p.Scope.Owner, p.Scope.Account, p.Scope.Generation, p.Scope.Purpose, p.Route.AccountID, p.Route.CreatedAt.UTC().Format(time.RFC3339Nano), p.Route.Profile, p.Route.BaseURL, p.Route.Model, p.Issuer, p.Subject, p.ProviderAccount}
	raw, _ := json.Marshal(values)
	digest := sha256.Sum256(append([]byte("account-info/principal/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func (s *GatewayAccountInfoReader) Read(ctx context.Context, in GatewayAccountLimitsInput) GatewayAccountInfoResult {
	unavailable := GatewayAccountInfoResult{Info: GatewayAccountInfo{Status: "unavailable"}}
	if s == nil || !in.Valid() {
		return unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	consumer, err := GatewayNativeConsumer(ctx)
	if err != nil {
		return unavailable
	}
	key := consumer + "\x00" + in.OwnerRef
	s.mu.Lock()
	if s.active[key] >= 2 {
		s.mu.Unlock()
		return unavailable
	}
	s.active[key]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active[key]--
		if s.active[key] == 0 {
			delete(s.active, key)
		}
		s.mu.Unlock()
	}()
	before, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil {
		return unavailable
	}
	if GatewayAccountInfoProvider(in.ProfileID) == "" {
		return GatewayAccountInfoResult{Info: GatewayAccountInfo{Status: "unsupported"}}
	}
	if !GatewayAccountInfoRouteValid(before, in) {
		return unavailable
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, in.OwnerRef)
	if err != nil {
		return unavailable
	}
	stored, err := s.cache.ReadGatewayAccountInfo(ctx, in, before)
	if err != nil {
		return unavailable
	}
	after, err := s.authorize(ctx, in)
	if err != nil || ctx.Err() != nil || !SameGatewayNativeDescriptor(before, after) {
		return unavailable
	}
	current, err := s.cache.ReadGatewayAccountInfo(ctx, in, after)
	if err != nil || ctx.Err() != nil || stored.PrincipalVersion == "" || current.PrincipalVersion != stored.PrincipalVersion || current.Revision < stored.Revision || current.Revision > gatewayLimitsMaxInteger {
		return unavailable
	}
	fields, valid := GatewayAccountInfoProject(in.ProfileID, current, s.now())
	if !valid {
		return unavailable
	}
	result := GatewayAccountInfoResult{Info: GatewayAccountInfo{Status: "available", InfoRevision: strconv.FormatInt(current.Revision, 10), Fields: &fields}, PhysicalGeneration: after.Generation, PrincipalVersion: current.PrincipalVersion}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 8192 {
		return unavailable
	}
	return result
}

func gatewayInfoText(value string, limit int) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
func gatewayInfoInstant(value string) bool {
	at, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && at.Year() >= 1 && at.Year() <= 9999 && strings.HasSuffix(value, "Z")
}
func gatewayInfoFactValid[T any](fact GatewayAccountFact[T], valueValid func(T) bool) bool {
	if fact.Status != "known" {
		return (fact.Status == "unknown" || fact.Status == "unsupported" || fact.Status == "unavailable") && fact.Value == nil && fact.Source == "" && fact.ObservedAt == "" && fact.Freshness == ""
	}
	if fact.Value == nil || !valueValid(*fact.Value) || !gatewayInfoInstant(fact.ObservedAt) || (fact.Freshness != "current" && fact.Freshness != "stale") {
		return false
	}
	switch fact.Source {
	case "provider_api", "verified_claim", "imported", "user_supplied", "inferred":
		return true
	}
	return false
}
func GatewayAccountInfoFieldsValid(f GatewayAccountInfoFields) bool {
	return gatewayInfoFactValid(f.Email, func(s string) bool { return gatewayInfoText(s, 320) }) && gatewayInfoFactValid(f.AccountLabel, func(s string) bool { return gatewayInfoText(s, 200) }) &&
		gatewayInfoFactValid(f.Subscription, func(v GatewayAccountSubscription) bool {
			if !gatewayInfoText(v.Code, 100) || !gatewayInfoText(v.Label, 160) || (v.Scope != "personal" && v.Scope != "organization" && v.Scope != "workspace" && v.Scope != "unknown") {
				return false
			}
			if v.EndsAt == nil {
				return true
			}
			if v.EndsAt.Kind == "instant" {
				return gatewayInfoInstant(v.EndsAt.Value)
			}
			if v.EndsAt.Kind != "date" {
				return false
			}
			t, e := time.Parse("2006-01-02", v.EndsAt.Value)
			return e == nil && t.Year() >= 1 && t.Format("2006-01-02") == v.EndsAt.Value
		}) && gatewayInfoFactValid(f.CredentialExpiresAt, gatewayInfoInstant) && gatewayInfoFactValid(f.PrivacyMode, func(s string) bool { return s == "private" || s == "public" })
}
func GatewayAccountInfoEmptyFields(profile string) GatewayAccountInfoFields {
	u := GatewayAccountFact[string]{Status: "unsupported"}
	f := GatewayAccountInfoFields{Email: u, AccountLabel: u, CredentialExpiresAt: u, PrivacyMode: u, Subscription: GatewayAccountFact[GatewayAccountSubscription]{Status: "unsupported"}}
	switch profile {
	case GatewayCodexOAuthResponsesProfile, GatewayClaudeOAuthMessagesProfile, GatewayGrokOAuthResponsesProfile:
		f.Email.Status = "unknown"
		f.AccountLabel.Status = "unknown"
		f.Subscription.Status = "unknown"
		f.CredentialExpiresAt.Status = "unknown"
	case GatewayGLMCodingResponsesProfile, GatewayMiniMaxMPlanResponsesProfile:
		f.Subscription.Status = "unknown"
	}
	return f
}
func gatewayInfoRefresh[T any](fact GatewayAccountFact[T], ttl time.Duration, validUntil *time.Time, now time.Time) GatewayAccountFact[T] {
	if fact.Status != "known" {
		return fact
	}
	at, _ := time.Parse(time.RFC3339Nano, fact.ObservedAt)
	if !now.Before(at.Add(ttl)) || validUntil != nil && !now.Before(*validUntil) {
		fact.Freshness = "stale"
	}
	return fact
}

// Source priority is closed and field-specific. A higher-priority unknown is
// authoritative omission, so it deliberately suppresses an older lower source.
func GatewayAccountInfoProject(profile string, stored GatewayAccountInfoStored, now time.Time) (GatewayAccountInfoFields, bool) {
	f := GatewayAccountInfoEmptyFields(profile)
	if len(stored.Sources) > 4 || stored.Revision < 0 || stored.Revision > gatewayLimitsMaxInteger {
		return f, false
	}
	for source, o := range stored.Sources {
		if source != o.Source || !GatewayAccountInfoObservationValid(profile, o) {
			return f, false
		}
	}
	for _, source := range []string{"verified_claims", "account_check", "plan_quota", "credential"} {
		o, ok := stored.Sources[source]
		if !ok {
			continue
		}
		switch source {
		case "verified_claims":
			f.Email = gatewayInfoRefresh(o.Fields.Email, 24*time.Hour, o.ValidUntil, now)
			f.AccountLabel = gatewayInfoRefresh(o.Fields.AccountLabel, 24*time.Hour, o.ValidUntil, now)
			f.Subscription = gatewayInfoRefresh(o.Fields.Subscription, 15*time.Minute, o.ValidUntil, now)
		case "account_check":
			f.AccountLabel = gatewayInfoRefresh(o.Fields.AccountLabel, 24*time.Hour, o.ValidUntil, now)
			f.Subscription = gatewayInfoRefresh(o.Fields.Subscription, 15*time.Minute, o.ValidUntil, now)
		case "plan_quota":
			f.Subscription = gatewayInfoRefresh(o.Fields.Subscription, 15*time.Minute, o.ValidUntil, now)
		case "credential":
			if o.CredentialRevision == stored.CredentialRevision {
				f.CredentialExpiresAt = gatewayInfoRefresh(o.Fields.CredentialExpiresAt, 24*time.Hour, o.ValidUntil, now)
			}
		}
	}
	return f, GatewayAccountInfoFieldsValid(f)
}
func GatewayAccountInfoObservationValid(profile string, o GatewayAccountInfoObservation) bool {
	if o.Order < 0 || o.Order > gatewayLimitsMaxInteger || o.CredentialRevision < 0 || !GatewayAccountInfoFieldsValid(o.Fields) {
		return false
	}
	if o.ValidUntil != nil && (o.ValidUntil.IsZero() || o.ValidUntil.Year() < 1 || o.ValidUntil.Year() > 9999) {
		return false
	}
	switch o.Source {
	case "verified_claims", "account_check", "credential":
		return profile == GatewayCodexOAuthResponsesProfile || profile == GatewayClaudeOAuthMessagesProfile || profile == GatewayGrokOAuthResponsesProfile
	case "plan_quota":
		return profile == GatewayGLMCodingResponsesProfile || profile == GatewayMiniMaxMPlanResponsesProfile
	}
	return false
}
func gatewayKnownFact[T any](value T, source string, at time.Time) GatewayAccountFact[T] {
	return GatewayAccountFact[T]{Status: "known", Value: &value, Source: source, ObservedAt: at.UTC().Format(time.RFC3339Nano), Freshness: "current"}
}
