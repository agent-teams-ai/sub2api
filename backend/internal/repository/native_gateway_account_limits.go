package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// No credential values or legacy usage/Extra statistics are selected. Exact
// qualification, enrollment commitment and physical birth own this provenance.
const gatewayLimitsPhysicalSQL = `SELECT q.issuer,q.subject,q.provider_account_id,q.operation_ref
 FROM gateway_oauth_profile_qualifications q
 JOIN accounts a ON a.id=q.account_id AND a.created_at=q.native_created_at
 JOIN gateway_oauth_identity_reservations r ON r.account_id=q.account_id
 JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
 AND c.account_ref=r.account_ref AND c.generation=r.generation
 AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
 AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
 AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 WHERE q.account_id=$1 AND q.native_created_at=$2 AND q.consumer=$3 AND q.owner_ref=$4
 AND q.account_ref=$5 AND q.generation=$6 AND q.profile=$7 AND q.base_url=$8 AND q.model=$9
 AND q.qualification='controlled-source-v1' AND q.issuer=r.issuer AND q.subject=r.subject
 AND q.consumer=r.consumer AND q.owner_ref=r.owner_ref AND q.account_ref=r.account_ref
 AND q.generation=r.generation AND q.operation_ref=c.operation_ref
 AND c.state='completed' AND NOT c.recovery_denied AND c.purpose='provider-oauth-bundle-v1'
 AND a.deleted_at IS NULL AND a.platform='openai' AND a.type='oauth' AND a.status='disabled'
 AND NOT a.schedulable AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND a.extra->>'gateway_generation_v1'=q.generation
 AND a.extra->'gateway_credential_scope_v1'->>'consumer'=q.consumer
 AND a.extra->'gateway_credential_scope_v1'->>'owner'=q.owner_ref
 AND a.extra->'gateway_credential_scope_v1'->>'account'=q.account_ref
 AND a.extra->'gateway_credential_scope_v1'->>'generation'=q.generation
 AND a.extra->'gateway_credential_scope_v1'->>'purpose'=c.purpose
 AND gateway_oauth_credential_version(a.credentials)>0
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 FOR SHARE OF a,r,c,q`

func (r *accountRepository) gatewayLimitsTransaction(ctx context.Context, scope service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (*sql.Tx, service.GatewayNativeOAuthPhysical, error) {
	p := service.GatewayNativeOAuthPhysical{Scope: scope, Route: route}
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || route.Generation != scope.Generation || route.AccountID <= 0 || route.CreatedAt.IsZero() || route.CreatedAt.Nanosecond()%1000 != 0 ||
		route.Profile != service.GatewayCodexOAuthResponsesProfile || route.BaseURL != service.GatewayCodexOAuthBaseURL || route.Model != service.GatewayCodexOAuthModel {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	// Acquire physical birth first. The provenance SELECT below starts a fresh
	// READ COMMITTED statement after any concurrent delete/refresh lock wait.
	var locked int64
	if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 AND created_at=$2 AND deleted_at IS NULL FOR SHARE`, route.AccountID, route.CreatedAt).Scan(&locked) != nil {
		_ = tx.Rollback()
		return nil, p, service.ErrGatewayNativeIdentity
	}
	err = tx.QueryRowContext(ctx, gatewayLimitsPhysicalSQL, route.AccountID, route.CreatedAt, scope.Consumer, scope.Owner, scope.Account, scope.Generation, route.Profile, route.BaseURL, route.Model).Scan(&p.Issuer, &p.Subject, &p.ProviderAccount, &p.Operation)
	if err != nil {
		_ = tx.Rollback()
		return nil, p, service.ErrGatewayNativeIdentity
	}
	return tx, p, nil
}
func (r *accountRepository) ReadGatewayAccountLimits(ctx context.Context, in service.GatewayAccountLimitsInput, route service.GatewayNativeRoute) (service.GatewayAccountLimitsStored, error) {
	var out service.GatewayAccountLimitsStored
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !in.Valid() || route.Profile != in.ProfileID {
		return out, service.ErrGatewayNativeIdentity
	}
	scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.OwnerRef, Account: in.AccountRef, Generation: route.Generation, Purpose: service.GatewayOAuthBundlePurpose}
	tx, p, err := r.gatewayLimitsTransaction(ctx, scope, route)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	out.PrincipalVersion = service.GatewayAccountLimitsPrincipal(p)
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT revision,raw_snapshot FROM gateway_account_limits_snapshots
 WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND principal_version=$4`, route.AccountID, route.CreatedAt, route.Generation, out.PrincipalVersion).Scan(&out.Revision, &raw)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil || len(raw) > 8192 {
		return service.GatewayAccountLimitsStored{}, service.ErrGatewayNativeIdentity
	}
	var snapshot service.GatewayCodexRawLimits
	if json.Unmarshal(raw, &snapshot) != nil {
		return service.GatewayAccountLimitsStored{}, service.ErrGatewayNativeIdentity
	}
	out.Raw = &snapshot
	return out, nil
}
func (r *accountRepository) StoreGatewayAccountLimits(ctx context.Context, expected service.GatewayNativeOAuthPhysical, raw service.GatewayCodexRawLimits, observed time.Time) error {
	if len(raw.Windows) == 0 || len(raw.Windows) > 2 || observed.IsZero() || observed.After(time.Now().Add(time.Minute)) {
		return service.ErrGatewayNativeIdentity
	}
	// The producer's timestamps all refer to this response receipt, never read time.
	for _, w := range raw.Windows {
		if w.ObservedAt != observed.UTC().Format(time.RFC3339Nano) {
			return service.ErrGatewayNativeIdentity
		}
	}
	data, err := json.Marshal(raw)
	if err != nil || len(data) > 8192 {
		return service.ErrGatewayNativeIdentity
	}
	tx, current, err := r.gatewayLimitsTransaction(ctx, expected.Scope, expected.Route)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	principal := service.GatewayAccountLimitsPrincipal(current)
	if principal != service.GatewayAccountLimitsPrincipal(expected) || current.Operation != expected.Operation {
		return service.ErrGatewayNativeIdentity
	}
	// One atomic source revision per physical generation. Late responses never
	// move observation time backwards, and safe-integer exhaustion preserves cache.
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_account_limits_snapshots
 (account_id,native_created_at,generation,principal_version,revision,observed_at,raw_snapshot)
 VALUES ($1,$2,$3,$4,1,$5,$6::jsonb)
 ON CONFLICT (account_id) DO UPDATE SET revision=gateway_account_limits_snapshots.revision+1,
 observed_at=EXCLUDED.observed_at,raw_snapshot=EXCLUDED.raw_snapshot
 WHERE gateway_account_limits_snapshots.native_created_at=EXCLUDED.native_created_at
 AND gateway_account_limits_snapshots.generation=EXCLUDED.generation
 AND gateway_account_limits_snapshots.principal_version=EXCLUDED.principal_version
 AND gateway_account_limits_snapshots.revision<9007199254740991
 AND gateway_account_limits_snapshots.observed_at<EXCLUDED.observed_at`, current.Route.AccountID, current.Route.CreatedAt, current.Route.Generation, principal, observed, string(data))
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	if tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayAccountLimitsRepository = (*accountRepository)(nil)
