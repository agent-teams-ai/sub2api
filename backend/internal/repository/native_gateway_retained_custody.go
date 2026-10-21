package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func retainedCustodyBegin(ctx context.Context, r *accountRepository) (*sql.Tx, func(), error) {
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback() }) }
	return tx, release, nil
}

func scanRetainedCustodyAccount(row *sql.Row) (*service.Account, error) {
	a := &service.Account{}
	var credentials, extra []byte
	var grouped bool
	err := row.Scan(&a.ID, &a.CreatedAt, &a.Platform, &a.Type, &a.Status, &a.Schedulable,
		&a.ProxyID, &a.ParentAccountID, &a.ExpiresAt, &credentials, &extra, &grouped)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, service.ErrGatewayNativeIdentity
		}
		return nil, service.ErrGatewayNativeIdentity
	}
	if grouped || json.Unmarshal(credentials, &a.Credentials) != nil || json.Unmarshal(extra, &a.Extra) != nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	return a, nil
}

// The SQL projection is an exact locked physical lookup. Metadata GET remains
// key-independent; this separately requires retained encrypted API-key material.
func (r *accountRepository) LockGatewayNativeRetainedAPIKeyCustody(ctx context.Context, scope service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (*service.Account, func(), error) {
	if !service.GatewayNativeCredentialRefValid(scope.Consumer) || !service.GatewayNativeCredentialRefValid(scope.Owner) ||
		!service.GatewayNativeCredentialRefValid(scope.Account) || scope.Purpose != service.GatewayCredentialPurpose ||
		route.Generation != scope.Generation || route.AccountID <= 0 ||
		route.CreatedAt.IsZero() || route.CreatedAt.Nanosecond()%1000 != 0 {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	tx, release, err := retainedCustodyBegin(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	a, err := scanRetainedCustodyAccount(tx.QueryRowContext(ctx, `SELECT a.id,a.created_at,a.platform,a.type,a.status,a.schedulable,
 a.proxy_id,a.parent_account_id,a.expires_at,a.credentials,a.extra,
 EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 FROM accounts a
 WHERE a.id=$1 AND a.created_at=$2 AND a.deleted_at IS NULL
 AND a.status IN ('active','disabled') AND NOT a.schedulable
 AND a.platform='openai' AND a.type='apikey'
 AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra->>'gateway_generation_v1'=$3
 AND a.extra->>'gateway_profile_v1'=$4
 AND a.extra->>'gateway_model_v1'=$5
 AND a.credentials->>'base_url'=$6
 AND a.extra->'gateway_credential_scope_v1'->>'consumer'=$7
 AND a.extra->'gateway_credential_scope_v1'->>'owner'=$8
 AND a.extra->'gateway_credential_scope_v1'->>'account'=$9
 AND a.extra->'gateway_credential_scope_v1'->>'generation'=$3
 AND a.extra->'gateway_credential_scope_v1'->>'purpose'='provider-authorization-v1'
 AND jsonb_typeof(a.credentials)='object'
 AND a.credentials ? 'api_key' AND a.credentials ? 'base_url'
 AND (a.credentials - ARRAY['api_key','base_url'])='{}'::jsonb
 AND (a.extra - ARRAY['gateway_generation_v1','gateway_profile_v1','gateway_model_v1','gateway_credential_scope_v1',
   'openai_responses_mode','openai_passthrough','native_api_key_cancel_on_disconnect','openai_preserve_compatible_reasoning'])='{}'::jsonb
 FOR SHARE OF a`,
		route.AccountID, route.CreatedAt, route.Generation, route.Profile, route.Model, route.BaseURL,
		scope.Consumer, scope.Owner, scope.Account))
	if err != nil {
		release()
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	return a, release, nil
}

// OAuth lookup binds the original operation, completed enrollment commitment,
// immutable owner/account/consumer/generation scope, exact qualified physical
// birth and the current encrypted credential version under one row lock.
func (r *accountRepository) LockGatewayNativeRetainedOAuthCustody(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string, route service.GatewayNativeRoute) (*service.Account, func(), error) {
	if !service.GatewayNativeOAuthScopeValid(scope) || !service.GatewayNativeCredentialRefValid(operation) ||
		route.Generation != scope.Generation || route.AccountID <= 0 || route.CreatedAt.IsZero() ||
		route.CreatedAt.Nanosecond()%1000 != 0 || route.Profile != service.GatewayCodexOAuthResponsesProfile ||
		route.BaseURL != service.GatewayCodexOAuthBaseURL || route.Model != service.GatewayCodexOAuthModel {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	tx, release, err := retainedCustodyBegin(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	a, err := scanRetainedCustodyAccount(tx.QueryRowContext(ctx, `SELECT a.id,a.created_at,a.platform,a.type,a.status,a.schedulable,
 a.proxy_id,a.parent_account_id,a.expires_at,a.credentials,a.extra,
 EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 FROM accounts a
 JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
 JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
  AND c.account_ref=r.account_ref AND c.generation=r.generation
  AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
  AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
  AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 JOIN gateway_oauth_profile_qualifications q ON q.account_id=a.id
 WHERE a.id=$1 AND a.created_at=$2 AND a.deleted_at IS NULL
 AND a.status='disabled' AND NOT a.schedulable
 AND a.platform='openai' AND a.type='oauth'
 AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND r.consumer=$3 AND r.owner_ref=$4 AND r.account_ref=$5 AND r.generation=$6
 AND c.operation_ref=$7 AND c.state='completed' AND NOT c.recovery_denied
 AND c.purpose='provider-oauth-bundle-v1'
 AND q.native_created_at=a.created_at AND q.consumer=r.consumer AND q.owner_ref=r.owner_ref
 AND q.account_ref=r.account_ref AND q.generation=r.generation AND q.operation_ref=c.operation_ref
 AND q.issuer=r.issuer AND q.subject=r.subject
 AND q.profile=$8 AND q.base_url=$9 AND q.model=$10
 AND q.qualification='controlled-source-v1'
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND a.extra->>'gateway_generation_v1'=r.generation
 AND a.extra->'gateway_credential_scope_v1'->>'consumer'=r.consumer
 AND a.extra->'gateway_credential_scope_v1'->>'owner'=r.owner_ref
 AND a.extra->'gateway_credential_scope_v1'->>'account'=r.account_ref
 AND a.extra->'gateway_credential_scope_v1'->>'generation'=r.generation
 AND a.extra->'gateway_credential_scope_v1'->>'purpose'=c.purpose
 AND gateway_oauth_credential_version(a.credentials)>0
 AND NOT EXISTS(SELECT 1 FROM gateway_oauth_refresh_attempts f WHERE f.account_id=a.id
   AND (f.state IN ('unknown','entered') OR f.state='prepared' AND f.deadline<=clock_timestamp()))
 FOR SHARE OF a,r,c,q`,
		route.AccountID, route.CreatedAt, scope.Consumer, scope.Owner, scope.Account, scope.Generation,
		operation, route.Profile, route.BaseURL, route.Model))
	if err != nil {
		release()
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	return a, release, nil
}
