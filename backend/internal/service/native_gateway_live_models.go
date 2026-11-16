package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
)

// Live model lists for the API-key coding plans (GLM, MiniMax, Kimi). The
// provider's own /models answer is read through Sub2API's existing builders and
// parser, with the key furnished only by the read-only quota credential lease.
// The list is never evidence of plan membership: it is the owner's decision that
// the provider decides, with the static catalogue as the lower bound. Dispatch
// never reads the network and never takes this lease (see peek).
const (
	gatewayCodingPlanModelsMax        = 8 // the Gateway contract bounds a snapshot to 8 models
	gatewayCodingPlanModelsFreshFor   = 5 * time.Minute
	gatewayCodingPlanModelsAdmitFor   = 24 * time.Hour
	gatewayCodingPlanModelsEntriesMax = 256
	gatewayCodingPlanModelsFetchSlots = 2
	gatewayCodingPlanModelsTimeout    = 2 * time.Second
)

// gatewayCodingPlanLiveEntry keeps the last SUCCESSFUL provider list; a failed
// fetch never replaces it.
type gatewayCodingPlanLiveEntry struct {
	models  []string
	fetched time.Time
}

// GatewayCodingPlanLiveModels is a small in-memory store: one entry per
// encrypted physical principal, single-flight refresh, bounded concurrency.
type GatewayCodingPlanLiveModels struct {
	mu      sync.Mutex
	entries map[string]gatewayCodingPlanLiveEntry
	pending map[string]chan struct{}
	slots   chan struct{}
	now     func() time.Time
	client  *GatewayProviderQuotaCollector
}

// NewGatewayCodingPlanLiveModels builds the store. A supplied transport is a
// trusted fixture composition only; the host, deadline and redirect policy stay
// fixed in the collector.
func NewGatewayCodingPlanLiveModels(transport http.RoundTripper) *GatewayCodingPlanLiveModels {
	return &GatewayCodingPlanLiveModels{
		entries: map[string]gatewayCodingPlanLiveEntry{},
		pending: map[string]chan struct{}{},
		slots:   make(chan struct{}, gatewayCodingPlanModelsFetchSlots),
		now:     time.Now,
		client:  NewGatewayProviderQuotaCollector(transport),
	}
}

// codingPlanLive returns the store, creating the default one on first use.
func (s *OpenAIGatewayService) codingPlanLive() *GatewayCodingPlanLiveModels {
	s.gatewayCodingPlanLiveOnce.Do(func() {
		if s.gatewayCodingPlanLive == nil {
			s.gatewayCodingPlanLive = NewGatewayCodingPlanLiveModels(nil)
		}
	})
	return s.gatewayCodingPlanLive
}

// gatewayCodingPlanLivePrincipal binds an entry to the exact encrypted account
// row: a rotated key or a new generation is a new principal.
func gatewayCodingPlanLivePrincipal(scope GatewayNativeCredentialScope, envelope string) string {
	encoded, _ := json.Marshal(scope)
	digest := sha256.Sum256(append(append(encoded, 0), envelope...))
	return "coding_plan_models_" + hex.EncodeToString(digest[:])
}

// peek never waits and never fetches: it is the only live read dispatch uses.
func (l *GatewayCodingPlanLiveModels) peek(key string) []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok || l.now().Sub(entry.fetched) >= gatewayCodingPlanModelsAdmitFor {
		return nil
	}
	return slices.Clone(entry.models)
}

func (l *GatewayCodingPlanLiveModels) fresh(key string, force bool) ([]string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		return nil, false
	}
	return slices.Clone(entry.models), !force && l.now().Sub(entry.fetched) < gatewayCodingPlanModelsFreshFor
}

func (l *GatewayCodingPlanLiveModels) store(key string, models []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= gatewayCodingPlanModelsEntriesMax {
		for old, entry := range l.entries {
			if l.now().Sub(entry.fetched) >= gatewayCodingPlanModelsAdmitFor {
				delete(l.entries, old)
			}
		}
	}
	if len(l.entries) >= gatewayCodingPlanModelsEntriesMax {
		for old := range l.entries {
			delete(l.entries, old)
			break
		}
	}
	l.entries[key] = gatewayCodingPlanLiveEntry{models: slices.Clone(models), fetched: l.now()}
}

// refresh updates the entry from the provider when it is not fresh. Failure,
// a busy slot or a concurrent refresh keeps whatever was last stored.
func (l *GatewayCodingPlanLiveModels) refresh(ctx context.Context, key string, force bool, fetch func(context.Context) ([]string, error)) {
	if l == nil || fetch == nil {
		return
	}
	for {
		if _, fresh := l.fresh(key, force); fresh {
			return
		}
		l.mu.Lock()
		if wait := l.pending[key]; wait != nil {
			l.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-wait:
				force = false
				continue
			}
		}
		select {
		case l.slots <- struct{}{}:
		default:
			l.mu.Unlock()
			return
		}
		done := make(chan struct{})
		l.pending[key] = done
		l.mu.Unlock()
		models, err := fetch(ctx)
		<-l.slots
		if err == nil {
			l.store(key, models)
		}
		l.mu.Lock()
		delete(l.pending, key)
		l.mu.Unlock()
		close(done)
		return
	}
}

// gatewayCodingPlanBaseURL is source-owned: the endpoint comes from the profile,
// never from the account, the request or a caller.
func gatewayCodingPlanBaseURL(profile string) string {
	switch profile {
	case GatewayKimiCodeResponsesProfile:
		return GatewayKimiCodeResponsesBaseURL
	case GatewayGLMCodingResponsesProfile:
		return GatewayGLMCodingResponsesBaseURL
	case GatewayMiniMaxMPlanResponsesProfile:
		return GatewayMiniMaxMPlanResponsesBaseURL
	}
	return ""
}

// FetchModels reads the provider's own model list with the key furnished by the
// current scoped lease. It reuses Sub2API's models URL builder and parser; only
// the entry id is used (no name fallback). Any non-2xx, redirect, malformed or
// empty answer is an error.
func (c *GatewayProviderQuotaCollector) FetchModels(ctx context.Context, profile string, credential []byte) ([]string, error) {
	base := gatewayCodingPlanBaseURL(profile)
	if c == nil || c.client == nil || base == "" || !gatewayCredentialSafeForHeader(credential) {
		return nil, ErrGatewayProviderQuota
	}
	bounded, cancel := context.WithTimeout(ctx, gatewayCodingPlanModelsTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(bounded, http.MethodGet, buildOpenAIModelsURL(base), nil)
	if err != nil {
		return nil, ErrGatewayProviderQuota
	}
	req.Header.Set("Authorization", "Bearer "+string(credential))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", xai.ProtectedUserAgent)
	resp, err := c.client.Do(req)
	if err != nil || resp == nil || resp.Body == nil {
		return nil, ErrGatewayProviderQuota
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrGatewayProviderQuota
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, gatewayProviderQuotaMaxBytes+1))
	if err != nil || len(body) > gatewayProviderQuotaMaxBytes || bounded.Err() != nil {
		return nil, ErrGatewayProviderQuota
	}
	ids, err := extractUpstreamModelIDsWithSelector(body, func(e upstreamModelEntry) string { return e.ID })
	if err != nil {
		return nil, ErrGatewayProviderQuota
	}
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if GatewayAccountModelIDValid(id) && !slices.Contains(valid, id) {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return nil, ErrGatewayProviderQuota
	}
	sort.Strings(valid)
	return valid, nil
}

func gatewayCredentialSafeForHeader(credential []byte) bool {
	text := string(credential)
	return len(credential) > 0 && len(credential) <= 16384 && strings.TrimSpace(text) == text && !strings.ContainsAny(text, "\r\n")
}

// gatewayCodingPlanCatalogue is the account-models answer: the anchor first, the
// static documented models, then the last good live list, deduplicated and
// bounded. It is never empty and never an error status.
func gatewayCodingPlanCatalogue(profile, anchor string, live []string) []string {
	out := []string{anchor}
	add := func(id string) {
		if len(out) < gatewayCodingPlanModelsMax && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, id := range gatewayCodingPlanStaticModelIDs(profile) {
		add(id)
	}
	for _, id := range live {
		add(id)
	}
	return out
}

// gatewayCodingPlanAdmitted is the one dispatch-time membership rule: the anchor,
// the static documented models or the last good live list (kept for 24 hours).
// It is read-only: no network, no lease, no waiting.
func (s *OpenAIGatewayService) gatewayCodingPlanAdmitted(scope GatewayNativeCredentialScope, envelope, profile, model string) bool {
	if !GatewayCodingPlanCatalogProfile(profile) || !GatewayAccountModelIDValid(model) {
		return false
	}
	if GatewayCodingPlanStaticModelAdmitted(profile, model) {
		return true
	}
	return slices.Contains(s.codingPlanLive().peek(gatewayCodingPlanLivePrincipal(scope, envelope)), model)
}

// codingPlanCatalogueModels builds the catalogue for one authorized account,
// refreshing the live list when it is not fresh. Failure is invisible to callers.
func (s *OpenAIGatewayService) codingPlanCatalogueModels(ctx context.Context, in GatewayAccountModelsInput, route GatewayNativeRoute, account *Account, scope GatewayNativeCredentialScope) []GatewayAccountModel {
	live := s.codingPlanLive()
	envelope := account.GetCredential("api_key")
	key := gatewayCodingPlanLivePrincipal(scope, envelope)
	custody := gatewayNativeCustody(ctx)
	live.refresh(ctx, key, in.ForceRefresh, func(fetchCtx context.Context) ([]string, error) {
		var models []string
		err := s.WithGatewayNativeQuotaCredential(fetchCtx, scope, route, custody, func(credential []byte, _ GatewayNativeOAuthPhysical) error {
			var e error
			models, e = live.client.FetchModels(fetchCtx, route.Profile, credential)
			return e
		})
		return models, err
	})
	return gatewayCodingPlanAccountModels(route.Profile, route.Model, live.peek(key))
}
