package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Qualification lives beside the inert row, not in Extra/credentials. Existing
// 243/244 account/principal guards and the engine refresh writer are unchanged.
func (r *accountRepository) ReadGatewayNativeOAuthDispatch(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthOutcome, error) {
	var out service.GatewayNativeOAuthOutcome
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || !service.GatewayNativeCredentialRefValid(operation) {
		return out, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	})
	if !ok {
		return out, service.ErrGatewayNativeIdentity
	}
	err := db.QueryRowContext(ctx, `SELECT c.operation_ref,COALESCE(r.account_id,0),c.generation,c.state
 FROM gateway_oauth_connect_intents c LEFT JOIN gateway_oauth_identity_reservations r
 ON c.state='completed' AND NOT c.recovery_denied AND c.enrollment_mac=r.intent_mac
 AND c.enrollment_operation=r.operation_ref AND c.outcome_operation=r.operation_ref
 AND c.outcome_account_id=r.account_id AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 AND r.consumer=c.consumer AND r.owner_ref=c.owner_ref AND r.account_ref=c.account_ref AND r.generation=c.generation
 WHERE c.consumer=$1 AND c.owner_ref=$2 AND c.account_ref=$3 AND c.generation=$4
 AND c.operation_ref=$5 AND c.purpose=$6`, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation, scope.Purpose).Scan(
		&out.Operation, &out.AccountID, &out.Generation, &out.State)
	if err != nil {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return out, nil
}

func gatewayOAuthPhysicalRead(ctx context.Context, tx *sql.Tx, scope service.GatewayNativeCredentialScope, operation string, id int64) (*service.Account, service.GatewayNativeOAuthPhysical, error) {
	// READ COMMITTED snapshots are statement scoped: acquire the physical lock
	// first, then read journal/identity in a new statement after any lock wait.
	var locked int64
	if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, id).Scan(&locked) != nil {
		return nil, service.GatewayNativeOAuthPhysical{}, service.ErrGatewayNativeIdentity
	}
	fence := &gatewayOAuthDispatchFence{tx: tx, id: id}
	if fence.Check(ctx) != nil {
		return nil, service.GatewayNativeOAuthPhysical{}, service.ErrGatewayNativeIdentity
	}
	a := &service.Account{}
	p := service.GatewayNativeOAuthPhysical{Scope: scope, Operation: operation}
	var credentials, extra []byte
	err := tx.QueryRowContext(ctx, `SELECT a.id,a.created_at,a.platform,a.type,a.status,a.schedulable,
 a.proxy_id,a.parent_account_id,a.expires_at,a.credentials,a.extra,r.issuer,r.subject
 FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
 JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
 AND c.account_ref=r.account_ref AND c.generation=r.generation AND c.purpose='provider-oauth-bundle-v1'
 AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
 AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
 AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 AND c.state='completed' AND NOT c.recovery_denied
 WHERE a.id=$1 AND r.consumer=$2 AND r.owner_ref=$3 AND r.account_ref=$4
 AND r.generation=$5 AND c.operation_ref=$6 AND a.deleted_at IS NULL
 AND a.status='disabled' AND NOT a.schedulable AND a.platform='openai' AND a.type='oauth'
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND a.extra->>'gateway_generation_v1'=r.generation
 AND a.extra->'gateway_credential_scope_v1'->>'consumer'=r.consumer
 AND a.extra->'gateway_credential_scope_v1'->>'owner'=r.owner_ref
 AND a.extra->'gateway_credential_scope_v1'->>'account'=r.account_ref
 AND gateway_oauth_credential_version(a.credentials)>0
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 FOR SHARE OF a,r,c`, id, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation).Scan(
		&a.ID, &a.CreatedAt, &a.Platform, &a.Type, &a.Status, &a.Schedulable, &a.ProxyID, &a.ParentAccountID, &a.ExpiresAt, &credentials, &extra, &p.Issuer, &p.Subject)
	if err != nil || json.Unmarshal(credentials, &a.Credentials) != nil || json.Unmarshal(extra, &a.Extra) != nil {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	p.RefreshFence = fence
	p.Route = service.GatewayNativeRoute{AccountID: a.ID, Generation: scope.Generation, CreatedAt: a.CreatedAt, Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}
	err = tx.QueryRowContext(ctx, `SELECT provider_account_id,qualified_at FROM gateway_oauth_profile_qualifications
 WHERE account_id=$1 AND native_created_at=$2 AND consumer=$3 AND owner_ref=$4 AND account_ref=$5
 AND generation=$6 AND operation_ref=$7 AND issuer=$8 AND subject=$9
 FOR SHARE`, a.ID, a.CreatedAt, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation, p.Issuer, p.Subject).Scan(&p.ProviderAccount, &p.QualifiedAt)
	if err != nil && err != sql.ErrNoRows {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	return a, p, nil
}

// This guard never releases/reacquires the account lock. UNKNOWN publication
// need not update accounts, so each check uses a fresh journal snapshot and the
// database wall clock; entered is ambiguous even before its deadline.
type gatewayOAuthDispatchFence struct {
	tx *sql.Tx
	id int64
}

func (f *gatewayOAuthDispatchFence) Check(ctx context.Context) error {
	var allowed bool
	err := f.tx.QueryRowContext(ctx, `SELECT NOT EXISTS (
 SELECT 1 FROM gateway_oauth_refresh_attempts WHERE account_id=$1
 AND (state IN ('unknown','entered') OR state='prepared' AND deadline<=clock_timestamp()))`, f.id).Scan(&allowed)
	if err != nil || !allowed {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

func (r *accountRepository) LockGatewayNativeOAuthDispatch(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string, id int64) (*service.Account, service.GatewayNativeOAuthPhysical, func(), error) {
	var empty service.GatewayNativeOAuthPhysical
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || !service.GatewayNativeCredentialRefValid(operation) || id <= 0 {
		return nil, empty, nil, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return nil, empty, nil, service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, empty, nil, service.ErrGatewayNativeIdentity
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback() }) }
	a, p, err := gatewayOAuthPhysicalRead(ctx, tx, scope, operation, id)
	if err != nil {
		release()
		return nil, empty, nil, service.ErrGatewayNativeIdentity
	}
	return a, p, release, nil
}

func (r *accountRepository) QualifyGatewayNativeOAuthDispatch(ctx context.Context, p service.GatewayNativeOAuthPhysical, version int64) error {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, p.Scope) || !p.QualificationValid(version) {
		return service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	// Secondary cleanup must preserve the original operation/commit result.
	defer func() { _ = tx.Rollback() }()
	_, current, err := gatewayOAuthPhysicalRead(ctx, tx, p.Scope, p.Operation, p.Route.AccountID)
	if err != nil || !service.SameGatewayNativeDescriptor(current.Route, p.Route) || current.Issuer != p.Issuer || current.Subject != p.Subject {
		return service.ErrGatewayNativeIdentity
	}
	if !current.QualifiedAt.IsZero() {
		if current.ProviderAccount != p.ProviderAccount {
			return service.ErrGatewayOAuthConflict
		}
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO gateway_oauth_profile_qualifications
 (account_id,native_created_at,consumer,owner_ref,account_ref,generation,operation_ref,
 issuer,subject,provider_account_id,profile,base_url,model,qualification,qualified_at)
 SELECT a.id,a.created_at,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
 FROM accounts a WHERE a.id=$1 AND a.created_at=$2 AND gateway_oauth_credential_version(a.credentials)=$16
 ON CONFLICT DO NOTHING`, p.Route.AccountID, p.Route.CreatedAt, p.Scope.Consumer, p.Scope.Owner, p.Scope.Account, p.Scope.Generation, p.Operation, p.Issuer, p.Subject, p.ProviderAccount, p.Route.Profile, p.Route.BaseURL, p.Route.Model, service.GatewayCodexOAuthQualification, p.QualifiedAt, version)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return service.ErrGatewayOAuthConflict
	}
	if tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayNativeOAuthDispatchRepository = (*accountRepository)(nil)

// Resolve only the completed F3 commitment and qualified exact physical birth.
// No owner/operation comes from an invocation DTO, token, name or latest row.
func (r *accountRepository) ResolveGatewayNativeOAuthCanonical(ctx context.Context, route service.GatewayNativeRoute, account string) (service.GatewayNativeCredentialScope, string, error) {
	var empty service.GatewayNativeCredentialScope
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !service.GatewayNativeCredentialRefValid(account) || route.AccountID <= 0 || route.Profile != service.GatewayCodexOAuthResponsesProfile || route.BaseURL != service.GatewayCodexOAuthBaseURL || route.Model != service.GatewayCodexOAuthModel || route.CreatedAt.IsZero() || route.CreatedAt.Nanosecond()%1000 != 0 {
		return empty, "", service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	})
	if !ok {
		return empty, "", service.ErrGatewayNativeIdentity
	}
	rows, err := db.QueryContext(ctx, `SELECT c.owner_ref,c.operation_ref,c.purpose
 FROM gateway_oauth_profile_qualifications q
 JOIN gateway_oauth_identity_reservations r ON r.account_id=q.account_id
 JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
 AND c.account_ref=r.account_ref AND c.generation=r.generation
 AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
 AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
 AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 JOIN accounts a ON a.id=r.account_id
 WHERE c.consumer=$1 AND c.account_ref=$2 AND c.generation=$3 AND c.state='completed'
 AND NOT c.recovery_denied AND c.purpose='provider-oauth-bundle-v1'
 AND q.consumer=c.consumer AND q.owner_ref=c.owner_ref AND q.account_ref=c.account_ref
 AND q.generation=c.generation AND q.operation_ref=c.operation_ref
 AND q.issuer=r.issuer AND q.subject=r.subject
 AND a.id=$4 AND a.created_at=$5 AND q.native_created_at=a.created_at
 AND q.profile=$6 AND q.base_url=$7 AND q.model=$8 AND q.qualification=$9
 AND a.deleted_at IS NULL AND a.status='disabled' AND NOT a.schedulable
 AND a.platform='openai' AND a.type='oauth' AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND a.extra->>'gateway_generation_v1'=r.generation
 AND a.extra->'gateway_credential_scope_v1'->>'consumer'=c.consumer
 AND a.extra->'gateway_credential_scope_v1'->>'owner'=c.owner_ref
 AND a.extra->'gateway_credential_scope_v1'->>'account'=c.account_ref
 AND a.extra->'gateway_credential_scope_v1'->>'generation'=c.generation
 AND a.extra->'gateway_credential_scope_v1'->>'purpose'=c.purpose
 AND gateway_oauth_credential_version(a.credentials)>0
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 LIMIT 2`, consumer, account, route.Generation, route.AccountID, route.CreatedAt, route.Profile, route.BaseURL, route.Model, service.GatewayCodexOAuthQualification)
	if err != nil {
		return empty, "", service.ErrGatewayNativeIdentity
	}
	// Rows.Err below is authoritative; preserve it during secondary close.
	defer func() { _ = rows.Close() }()
	scope := service.GatewayNativeCredentialScope{Consumer: consumer, Account: account, Generation: route.Generation}
	var operation string
	if !rows.Next() || rows.Scan(&scope.Owner, &operation, &scope.Purpose) != nil || rows.Next() || rows.Err() != nil || !service.GatewayNativeOAuthScopeValid(scope) || !service.GatewayNativeCredentialRefValid(operation) {
		return empty, "", service.ErrGatewayNativeIdentity
	}
	return scope, operation, nil
}

var _ service.GatewayNativeOAuthCanonicalRepository = (*accountRepository)(nil)
