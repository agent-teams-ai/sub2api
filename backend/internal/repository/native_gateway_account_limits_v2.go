package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type gatewayAccountLimitsRepositoryV2 struct{ db *sql.DB }

func NewGatewayAccountLimitsRepositoryV2(db *sql.DB) service.GatewayAccountLimitsRepositoryV2 {
	if db == nil {
		return nil
	}
	return &gatewayAccountLimitsRepositoryV2{db}
}

// This narrow query validates encrypted custody shape but never projects its
// ciphertext, plaintext or ordinary Extra statistics into the cache reader.
const gatewayLimitsKeyPhysicalSQLV2 = `SELECT a.id FROM accounts a
 WHERE a.id=$1 AND a.created_at=$2 AND a.deleted_at IS NULL
 AND a.status IN ('active','disabled') AND NOT a.schedulable
 AND a.platform='openai' AND a.type='apikey'
 AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra->>'gateway_generation_v1'=$3 AND a.extra->>'gateway_profile_v1'=$4
 AND a.extra->>'gateway_model_v1'=$5 AND a.credentials->>'base_url'=$6
 AND a.extra->'gateway_credential_scope_v1'=jsonb_build_object(
 'consumer',$7::text,'owner',$8::text,'account',$9::text,'generation',$3::text,'purpose','provider-authorization-v1')
 AND jsonb_typeof(a.credentials)='object'
 AND (a.credentials - ARRAY['api_key','base_url'])='{}'::jsonb
 AND public.gateway_native_envelope_valid(a.credentials->'api_key')
 AND (a.extra - ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_model_v1','gateway_credential_scope_v1',
 'openai_responses_mode','openai_passthrough','native_api_key_cancel_on_disconnect','openai_preserve_compatible_reasoning'])='{}'::jsonb
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 FOR SHARE OF a`

func (r *gatewayAccountLimitsRepositoryV2) physicalTx(ctx context.Context, s service.GatewayNativeCredentialScope, route service.GatewayNativeRoute, exclusive bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, error) {
	p := service.GatewayNativeOAuthPhysical{Scope: s, Route: route}
	in := service.GatewayAccountLimitsInput{OwnerRef: s.Owner, AccountRef: s.Account, ProfileID: route.Profile}
	authScope := s
	authScope.Purpose = service.GatewayOAuthBundlePurpose
	if !service.GatewayAccountLimitsRouteValidV2(route, in) || s.Generation != route.Generation || !service.GatewayNativeOAuthScopeAuthorized(ctx, authScope) {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	if service.GatewayAccountLimitsProviderV2(route.Profile) == "grok" {
		if s.Purpose != service.GatewayOAuthBundlePurpose {
			return nil, p, service.ErrGatewayNativeIdentity
		}
		source := &gatewayGrokRepository{r.db}
		op, err := source.resolve(ctx, s, route)
		if err != nil {
			return nil, p, service.ErrGatewayNativeIdentity
		}
		tx, current, _, err := source.physicalTxMode(ctx, s, op, &route, exclusive, true, true)
		return tx, current, err
	}
	if s.Purpose != service.GatewayCredentialPurpose {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	var locked int64
	// Writers serialize on exact birth, including the first snapshot insert.
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 AND created_at=$2 AND deleted_at IS NULL`+lock, route.AccountID, route.CreatedAt).Scan(&locked)
	if err == nil {
		err = tx.QueryRowContext(ctx, gatewayLimitsKeyPhysicalSQLV2, route.AccountID, route.CreatedAt, route.Generation, route.Profile, route.Model, route.BaseURL, s.Consumer, s.Owner, s.Account).Scan(&locked)
	}
	if err != nil {
		tx.Rollback()
		return nil, p, service.ErrGatewayNativeIdentity
	}
	return tx, p, nil
}
func (r *gatewayAccountLimitsRepositoryV2) ReadGatewayAccountLimitsV2(ctx context.Context, in service.GatewayAccountLimitsInput, route service.GatewayNativeRoute) (service.GatewayAccountLimitsStoredV2, error) {
	var out service.GatewayAccountLimitsStoredV2
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !in.Valid() || in.ProfileID != route.Profile {
		return out, service.ErrGatewayNativeIdentity
	}
	purpose := service.GatewayCredentialPurpose
	if service.GatewayAccountLimitsProviderV2(route.Profile) == "grok" {
		purpose = service.GatewayOAuthBundlePurpose
	}
	scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.OwnerRef, Account: in.AccountRef, Generation: route.Generation, Purpose: purpose}
	tx, p, err := r.physicalTx(ctx, scope, route, false)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.PrincipalVersion = service.GatewayAccountLimitsPrincipalV2(p)
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT revision,snapshot FROM gateway_account_limits_v2_snapshots
 WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND principal_version=$4`, route.AccountID, route.CreatedAt, route.Generation, out.PrincipalVersion).Scan(&out.Revision, &raw)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil || len(raw) > 8192 {
		return service.GatewayAccountLimitsStoredV2{}, service.ErrGatewayNativeIdentity
	}
	var snapshot service.GatewayAccountLimitsSnapshotV2
	if json.Unmarshal(raw, &snapshot) != nil || !service.ValidateGatewayAccountLimitsSnapshotV2(snapshot, route.Profile) {
		return service.GatewayAccountLimitsStoredV2{}, service.ErrGatewayNativeIdentity
	}
	out.Snapshot = &snapshot
	return out, nil
}

// Each collector owns a single dimension. Replacing that complete source set
// removes disappeared windows while leaving independently observed sources intact.
func (r *gatewayAccountLimitsRepositoryV2) StoreGatewayAccountLimitsV2(ctx context.Context, expected service.GatewayNativeOAuthPhysical, snapshot service.GatewayAccountLimitsSnapshotV2, observed time.Time) error {
	if observed.IsZero() || observed.Year() < 1 || observed.Year() > 9999 || observed.After(time.Now().Add(time.Minute)) || !service.ValidateGatewayAccountLimitsSnapshotV2(snapshot, expected.Route.Profile) {
		return service.ErrGatewayNativeIdentity
	}
	dimension := "plan_quota"
	if len(snapshot.Windows) > 0 {
		dimension = snapshot.Windows[0].Dimension
	}
	for _, w := range snapshot.Windows {
		if w.Dimension != dimension {
			return service.ErrGatewayNativeIdentity
		}
		if w.ObservedAt != nil {
			at, err := time.Parse(time.RFC3339Nano, *w.ObservedAt)
			if err != nil || !at.Equal(observed) {
				return service.ErrGatewayNativeIdentity
			}
		}
	}
	tx, current, err := r.physicalTx(ctx, expected.Scope, expected.Route, true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	principal := service.GatewayAccountLimitsPrincipalV2(current)
	if principal != service.GatewayAccountLimitsPrincipalV2(expected) || current.Operation != expected.Operation || current.CredentialRevision != expected.CredentialRevision {
		return service.ErrGatewayNativeIdentity
	}
	var birth time.Time
	var generation, storedPrincipal string
	var revision int64
	var existingRaw, sourceRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT native_created_at,generation,principal_version,revision,snapshot,source_observations
 FROM gateway_account_limits_v2_snapshots WHERE account_id=$1 FOR UPDATE`, current.Route.AccountID).Scan(&birth, &generation, &storedPrincipal, &revision, &existingRaw, &sourceRaw)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return service.ErrGatewayNativeIdentity
	}
	observations := map[string]string{}
	merged := service.GatewayAccountLimitsSnapshotV2{Scope: snapshot.Scope, Windows: []service.GatewayAccountLimitWindowV2{}}
	if exists {
		if !birth.Equal(current.Route.CreatedAt) || generation != current.Route.Generation || storedPrincipal != principal || revision < 1 || revision > 9007199254740991 || len(existingRaw) > 8192 || len(sourceRaw) > 512 {
			return service.ErrGatewayNativeIdentity
		}
		var existing service.GatewayAccountLimitsSnapshotV2
		if json.Unmarshal(existingRaw, &existing) != nil || !service.ValidateGatewayAccountLimitsSnapshotV2(existing, current.Route.Profile) || json.Unmarshal(sourceRaw, &observations) != nil || observations == nil || len(observations) > 2 {
			return service.ErrGatewayNativeIdentity
		}
		for source, raw := range observations {
			if source != "plan_quota" && source != "rate_limit" {
				return service.ErrGatewayNativeIdentity
			}
			at, e := time.Parse(time.RFC3339Nano, raw)
			if e != nil || at.Year() < 1 || at.Year() > 9999 {
				return service.ErrGatewayNativeIdentity
			}
		}
		for _, w := range existing.Windows {
			raw, ok := observations[w.Dimension]
			if !ok {
				return service.ErrGatewayNativeIdentity
			}
			if w.ObservedAt != nil {
				at, e := time.Parse(time.RFC3339Nano, *w.ObservedAt)
				sourceAt, _ := time.Parse(time.RFC3339Nano, raw)
				if e != nil || !at.Equal(sourceAt) {
					return service.ErrGatewayNativeIdentity
				}
			}
			if w.Dimension != dimension {
				merged.Windows = append(merged.Windows, w)
			}
		}
		if previous, ok := observations[dimension]; ok {
			at, _ := time.Parse(time.RFC3339Nano, previous)
			if !observed.After(at) {
				return nil
			}
		}
		if revision == 9007199254740991 {
			return nil
		}
		// A passive rate observation does not alter the established quota scope.
		if dimension == "rate_limit" {
			merged.Scope = existing.Scope
		}
	}
	merged.Windows = append(merged.Windows, snapshot.Windows...)
	if !service.ValidateGatewayAccountLimitsSnapshotV2(merged, current.Route.Profile) {
		return service.ErrGatewayNativeIdentity
	}
	observations[dimension] = observed.UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(merged)
	if err != nil || len(raw) > 8192 {
		return service.ErrGatewayNativeIdentity
	}
	sources, err := json.Marshal(observations)
	if err != nil || len(sources) > 512 {
		return service.ErrGatewayNativeIdentity
	}
	var result sql.Result
	if !exists {
		result, err = tx.ExecContext(ctx, `INSERT INTO gateway_account_limits_v2_snapshots
 (account_id,native_created_at,generation,principal_version,revision,observed_at,snapshot,source_observations)
 VALUES ($1,$2,$3,$4,1,$5,$6::jsonb,$7::jsonb)`, current.Route.AccountID, current.Route.CreatedAt, current.Route.Generation, principal, observed, string(raw), string(sources))
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE gateway_account_limits_v2_snapshots
 SET revision=revision+1,observed_at=GREATEST(observed_at,$5),snapshot=$6::jsonb,source_observations=$7::jsonb
 WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND principal_version=$4 AND revision=$8`, current.Route.AccountID, current.Route.CreatedAt, current.Route.Generation, principal, observed, string(raw), string(sources), revision)
	}
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	if rows, e := result.RowsAffected(); e != nil || rows != 1 {
		return service.ErrGatewayNativeIdentity
	}
	if tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayAccountLimitsRepositoryV2 = (*gatewayAccountLimitsRepositoryV2)(nil)
