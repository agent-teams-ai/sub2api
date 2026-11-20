package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func anthropicLongContextCacheKey(group *Group, models []string) string {
	var groupID *int64
	if group != nil {
		groupID = &group.ID
	}
	var signature strings.Builder
	for _, model := range models {
		// Include both the requested model list and per-model routing so distinct
		// allowlists and route settings cannot reuse the same cached expansion.
		signature.WriteString(strconv.Itoa(len(model)))
		signature.WriteByte(':')
		signature.WriteString(model)
		if group != nil {
			signature.WriteByte('/')
			for _, id := range group.GetRoutingAccountIDs(model) {
				signature.WriteString(strconv.FormatInt(id, 10))
				signature.WriteByte(',')
			}
		}
		signature.WriteByte(';')
	}
	digest := sha256.Sum256([]byte(signature.String()))
	return fmt.Sprintf("%s|long:%x", modelsListCacheKey(groupID, PlatformAnthropic), digest)
}

func (s *GatewayService) ExpandAnthropicLongContextModels(ctx context.Context, group *Group, models []string) []string {
	if s == nil || s.accountRepo == nil || len(models) == 0 {
		return models
	}
	cacheKey := anthropicLongContextCacheKey(group, models)
	if s.modelsListCache != nil {
		if cached, ok := s.modelsListCache.Get(cacheKey); ok {
			if result, valid := cached.([]string); valid {
				return cloneStringSlice(result)
			}
		}
	}

	var accounts []Account
	var err error
	if group != nil {
		accounts, err = s.accountRepo.ListSchedulableByGroupID(ctx, group.ID)
	} else {
		accounts, err = s.accountRepo.ListSchedulable(ctx)
	}
	if err != nil {
		// Never cache a transient repository failure.
		return models
	}

	result := cloneStringSlice(models)
	seen := make(map[string]bool, len(models))
	metadataByAccount := make(map[int64]*UpstreamModelMetadataSnapshot, len(accounts))
	for _, model := range models {
		seen[strings.ToLower(model)] = true
	}
	for _, model := range models {
		variant := model + claudeCodeLongContextModelSuffix
		variantKey := strings.ToLower(variant)
		if strings.HasSuffix(strings.ToLower(model), claudeCodeLongContextModelSuffix) || seen[variantKey] || strings.Contains(model, "*") {
			continue
		}
		var routedAccountIDs []int64
		if group != nil {
			routedAccountIDs = group.GetRoutingAccountIDs(model)
		}
		// The scheduler may select ANY eligible account for the base model.
		// Advertising [1m] when only one account supports the large window
		// misrepresents capabilities and can route to a smaller context. Only
		// advertise when every eligible/routed account has a 900k+ observation.
		eligible := false
		allLarge := true
		for i := range accounts {
			account := &accounts[i]
			if !account.IsAnthropic() || !account.IsModelSupported(model) ||
				(len(routedAccountIDs) > 0 && !slices.Contains(routedAccountIDs, account.ID)) {
				continue
			}
			eligible = true
			snapshot, parsed := metadataByAccount[account.ID]
			if !parsed {
				// Snapshot decoding is expensive; do it at most once per account.
				snapshot = account.GetUpstreamModelMetadataSnapshot()
				metadataByAccount[account.ID] = snapshot
			}
			if snapshot == nil {
				allLarge = false
				break
			}
			metadata, ok := snapshot.Models[strings.TrimSpace(account.GetMappedModel(model))]
			if !ok || metadata.ContextWindow < 900_000 {
				allLarge = false
				break
			}
		}
		if eligible && allLarge {
			result = append(result, variant)
			seen[variantKey] = true
		}
	}
	if s.modelsListCache != nil {
		s.modelsListCache.Set(cacheKey, cloneStringSlice(result), s.modelsListCacheTTL)
	}
	return result
}
