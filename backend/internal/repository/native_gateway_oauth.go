package repository

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Reservation and inert native birth are one atomic transaction. PostgreSQL's
// unique principal constraint serializes cross-consumer/owner contenders. No
// reconnect, replacement, refresh writer or inferred owner is implemented.
func (r *accountRepository) StageGatewayNativeOAuth(ctx context.Context, in service.GatewayNativeOAuthReservation) (out service.GatewayNativeOAuthOutcome, retErr error) {
	deny := func() (service.GatewayNativeOAuthOutcome, error) {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	digest, err := hex.DecodeString(in.IntentMAC)
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, in.Scope) || !in.Identity.Verified() || !service.GatewayNativeCredentialRefValid(in.Operation) || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != in.IntentMAC {
		return deny()
	}
	// Structural validation is not identity or cryptographic authority; the
	// protected enrollment boundary has verified and sealed this input already.
	if len(in.Envelope) < 40 || len(in.Envelope) > 87600 {
		return deny()
	}
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return deny()
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return deny()
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			out, retErr = deny()
		}
	}()
	issuer, subject := in.Identity.Principal()
	result, err := tx.ExecContext(ctx, `INSERT INTO gateway_oauth_identity_reservations
 (issuer,subject,consumer,owner_ref,account_ref,generation,operation_ref,intent_mac)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, issuer, subject, in.Scope.Consumer, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, in.Operation, in.IntentMAC)
	if err != nil {
		return deny()
	}
	count, err := result.RowsAffected()
	if err != nil {
		return deny()
	}
	if count == 0 {
		var accepted string
		var outcome service.GatewayNativeOAuthOutcome
		err = tx.QueryRowContext(ctx, `SELECT r.intent_mac,r.operation_ref,r.account_id,r.generation,
 'staged'
 FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id
 WHERE r.consumer=$1 AND r.operation_ref=$2 AND r.owner_ref=$3 AND r.account_ref=$4
 AND r.generation=$5 AND r.issuer=$6 AND r.subject=$7`, in.Scope.Consumer, in.Operation, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, issuer, subject).Scan(&accepted, &outcome.Operation, &outcome.AccountID, &outcome.Generation, &outcome.State)
		if err != nil || accepted != in.IntentMAC {
			return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayOAuthConflict
		}
		if tx.Commit() != nil {
			return deny()
		}
		return outcome, nil
	}
	extra, _ := json.Marshal(map[string]any{service.GatewayGenerationExtraKey: in.Scope.Generation, service.GatewayProfileExtraKey: service.GatewayOAuthStagingProfile, service.GatewayCredentialScopeExtraKey: in.Scope.Metadata()})
	credentials, _ := json.Marshal(map[string]string{"oauth_bundle": in.Envelope})
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO accounts
 (name,platform,type,status,schedulable,concurrency,priority,credentials,extra,created_at,updated_at)
 VALUES ('protected OAuth staging','openai','oauth','disabled',false,1,0,$1::jsonb,$2::jsonb,NOW(),NOW()) RETURNING id`, string(credentials), string(extra)).Scan(&id)
	if err != nil {
		return deny()
	}
	_, err = tx.ExecContext(ctx, `UPDATE gateway_oauth_identity_reservations SET account_id=$1
 WHERE consumer=$2 AND operation_ref=$3 AND account_id IS NULL`, id, in.Scope.Consumer, in.Operation)
	if err != nil || tx.Commit() != nil {
		return deny()
	}
	return service.GatewayNativeOAuthOutcome{Operation: in.Operation, AccountID: id, Generation: in.Scope.Generation, State: "staged"}, nil
}

func (r *accountRepository) ReadGatewayNativeOAuth(ctx context.Context, s service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthOutcome, error) {
	var out service.GatewayNativeOAuthOutcome
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || !service.GatewayNativeCredentialRefValid(operation) {
		return out, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	})
	if !ok {
		return out, service.ErrGatewayNativeIdentity
	}
	err := db.QueryRowContext(ctx, `SELECT r.operation_ref,r.account_id,r.generation,
 CASE WHEN a.deleted_at IS NULL THEN 'staged' ELSE 'erased' END
 FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id
 WHERE r.consumer=$1 AND r.owner_ref=$2 AND r.account_ref=$3 AND r.generation=$4 AND r.operation_ref=$5`, s.Consumer, s.Owner, s.Account, s.Generation, operation).Scan(&out.Operation, &out.AccountID, &out.Generation, &out.State)
	if err != nil {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return out, nil
}

// Exact-owner cleanup requires no decrypt key and cannot delete a competitor's
// reservation. The principal remains reserved after credential erasure.
func (r *accountRepository) EraseGatewayNativeOAuth(ctx context.Context, s service.GatewayNativeCredentialScope, operation string) error {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || !service.GatewayNativeCredentialRefValid(operation) {
		return service.ErrGatewayNativeIdentity
	}
	result, err := r.sql.ExecContext(ctx, `UPDATE accounts a SET credentials='{}'::jsonb,
 deleted_at=COALESCE(a.deleted_at,NOW()),updated_at=NOW()
 FROM gateway_oauth_identity_reservations r
 WHERE a.id=r.account_id AND r.consumer=$1 AND r.owner_ref=$2 AND r.account_ref=$3
 AND r.generation=$4 AND r.operation_ref=$5 AND a.status='disabled' AND NOT a.schedulable
 AND a.extra->>'gateway_generation_v1'=r.generation
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)`, s.Consumer, s.Owner, s.Account, s.Generation, operation)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayNativeOAuthRepository = (*accountRepository)(nil)

// Read only the stable operation commitment before verification on retries.
// No provider call, credential decode, new reservation or second writer.
func (r *accountRepository) ReplayGatewayNativeOAuth(ctx context.Context, s service.GatewayNativeCredentialScope, operation, commitment string) (service.GatewayNativeOAuthOutcome, bool, error) {
	var out service.GatewayNativeOAuthOutcome
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || !service.GatewayNativeCredentialRefValid(operation) {
		return out, false, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	})
	if !ok {
		return out, false, service.ErrGatewayNativeIdentity
	}
	var owner, account, digest string
	err := db.QueryRowContext(ctx, `SELECT r.owner_ref,r.account_ref,r.intent_mac,r.operation_ref,r.account_id,r.generation,'staged'
 FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id
 WHERE r.consumer=$1 AND r.operation_ref=$2`, s.Consumer, operation).Scan(&owner, &account, &digest, &out.Operation, &out.AccountID, &out.Generation, &out.State)
	if err == sql.ErrNoRows {
		return service.GatewayNativeOAuthOutcome{}, false, nil
	}
	if err != nil {
		return service.GatewayNativeOAuthOutcome{}, false, service.ErrGatewayNativeIdentity
	}
	if owner != s.Owner || account != s.Account || out.Generation != s.Generation || digest != commitment {
		return service.GatewayNativeOAuthOutcome{}, false, service.ErrGatewayOAuthConflict
	}
	return out, true, nil
}
