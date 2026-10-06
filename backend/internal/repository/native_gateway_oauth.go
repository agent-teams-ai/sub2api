package repository

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Reservation and inert native birth are one atomic transaction. PostgreSQL's
// unique principal constraint serializes cross-consumer/owner contenders. No
// reconnect, promotion or inferred owner is implemented. F2 refresh uses a separate ledger.
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

// The native SQL repository is the sole F2 writer. All mutations lock the same
// physical account first, then its attempt; no reservation spine is updated.
func (r *accountRepository) gatewayRefreshTx(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent) (*sql.Tx, error) {
	if !in.Authorized(ctx) {
		return nil, service.ErrGatewayNativeIdentity
	}
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return nil, service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	var id int64
	if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, in.AccountID).Scan(&id) != nil {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return nil, service.ErrGatewayNativeIdentity
		}
		return nil, service.ErrGatewayNativeIdentity
	}
	return tx, nil
}
func gatewayRefreshRead(ctx context.Context, tx *sql.Tx, in service.GatewayNativeOAuthRefreshIntent) (service.GatewayNativeOAuthRefreshPrepared, bool, error) {
	var out service.GatewayNativeOAuthRefreshPrepared
	var id, version int64
	var birth time.Time
	var owner, account, generation, intent string
	err := tx.QueryRowContext(ctx, `SELECT account_id,native_created_at,owner_ref,account_ref,generation,intent_ref,
 expected_version,fence,state,deadline,COALESCE(result_version,0),operation_ref
 FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2 FOR UPDATE`, in.Scope.Consumer, in.Operation).
		Scan(&id, &birth, &owner, &account, &generation, &intent, &version, &out.Fence, &out.Outcome.State, &out.Deadline, &out.Outcome.Version, &out.Outcome.Operation)
	if err == sql.ErrNoRows {
		return out, false, nil
	}
	if err != nil {
		return out, false, service.ErrGatewayNativeIdentity
	}
	if id != in.AccountID || !birth.Equal(in.CreatedAt) || owner != in.Scope.Owner || account != in.Scope.Account || generation != in.Scope.Generation || intent != in.Intent || version != in.ExpectedVersion {
		return service.GatewayNativeOAuthRefreshPrepared{}, false, service.ErrGatewayOAuthConflict
	}
	return out, true, nil
}
func (r *accountRepository) PrepareGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent) (result service.GatewayNativeOAuthRefreshPrepared, retErr error) {
	var empty service.GatewayNativeOAuthRefreshPrepared
	tx, err := r.gatewayRefreshTx(ctx, in)
	if err != nil {
		return empty, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			result, retErr = empty, service.ErrGatewayNativeIdentity
		}
	}()
	out, found, err := gatewayRefreshRead(ctx, tx, in)
	if err != nil {
		return empty, err
	}
	if found {
		// SQL time decides expiry. ENTERED is terminal for replay even if the engine
		// died before the provider call; absence of an ACK never proves non-entry.
		if out.Outcome.State == "entered" {
			_, err = tx.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='unknown'
    WHERE consumer=$1 AND operation_ref=$2 AND state='entered' AND deadline<=clock_timestamp()`, in.Scope.Consumer, in.Operation)
			if err != nil {
				return empty, service.ErrGatewayNativeIdentity
			}
			out, _, err = gatewayRefreshRead(ctx, tx, in)
			if err != nil {
				return empty, err
			}
		}
		if out.Outcome.State != "prepared" {
			if tx.Commit() != nil {
				return empty, service.ErrGatewayNativeIdentity
			}
			return out, nil
		}
		result, err := tx.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET fence=fence+1,deadline=clock_timestamp()+interval '15 seconds'
   WHERE consumer=$1 AND operation_ref=$2 AND state='prepared' AND deadline<=clock_timestamp()`, in.Scope.Consumer, in.Operation)
		if err != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
		n, err := result.RowsAffected()
		if err != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
		out.Claimed = n == 1
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO gateway_oauth_refresh_attempts
   (account_id,native_created_at,consumer,owner_ref,account_ref,generation,operation_ref,intent_ref,expected_version,fence,state,deadline)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,(SELECT COALESCE(max(fence),0)+1 FROM gateway_oauth_refresh_attempts WHERE account_id=$1),'prepared',clock_timestamp()+interval '15 seconds')`, in.AccountID, in.CreatedAt, in.Scope.Consumer, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, in.Operation, in.Intent, in.ExpectedVersion)
		if err != nil {
			return empty, service.ErrGatewayOAuthConflict
		}
		out.Claimed = true
	}
	claimed := out.Claimed
	out, _, err = gatewayRefreshRead(ctx, tx, in)
	if err != nil {
		return empty, err
	}
	out.Claimed = claimed
	if claimed {
		err = tx.QueryRowContext(ctx, `SELECT a.credentials->>'oauth_bundle',r.issuer,r.subject
   FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
   WHERE a.id=$1 AND a.created_at=$2 AND gateway_oauth_credential_version(a.credentials)=$3`, in.AccountID, in.CreatedAt, in.ExpectedVersion).
			Scan(&out.Envelope, &out.Issuer, &out.Subject)
		if err != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
	}
	if tx.Commit() != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	return out, nil
}
func (r *accountRepository) EnterGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent, fence int64) (entered bool, retErr error) {
	tx, err := r.gatewayRefreshTx(ctx, in)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			entered, retErr = false, service.ErrGatewayNativeIdentity
		}
	}()
	out, found, err := gatewayRefreshRead(ctx, tx, in)
	if err != nil {
		return false, err
	}
	if !found || out.Fence != fence || out.Outcome.State != "prepared" {
		return false, service.ErrGatewayOAuthConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='entered'
  WHERE consumer=$1 AND operation_ref=$2 AND fence=$3 AND state='prepared' AND deadline>clock_timestamp()`, in.Scope.Consumer, in.Operation, fence)
	if err != nil {
		return false, service.ErrGatewayNativeIdentity
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, service.ErrGatewayNativeIdentity
	}
	if tx.Commit() != nil {
		return false, service.ErrGatewayNativeIdentity
	}
	return n == 1, nil
}
func (r *accountRepository) CompleteGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent, fence int64, envelope string) (outcome service.GatewayNativeOAuthRefreshOutcome, retErr error) {
	var empty service.GatewayNativeOAuthRefreshOutcome
	tx, err := r.gatewayRefreshTx(ctx, in)
	if err != nil {
		return empty, err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			outcome, retErr = empty, service.ErrGatewayNativeIdentity
		}
	}()
	out, found, err := gatewayRefreshRead(ctx, tx, in)
	if err != nil {
		return empty, err
	}
	if !found || out.Fence != fence {
		return empty, service.ErrGatewayOAuthConflict
	}
	if out.Outcome.State == "completed" {
		return out.Outcome, nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='completed',result_version=expected_version+1,publication_xid=pg_current_xact_id()
  WHERE consumer=$1 AND operation_ref=$2 AND fence=$3 AND state='entered' AND deadline>clock_timestamp()`, in.Scope.Consumer, in.Operation, fence)
	if err != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return empty, service.ErrGatewayOAuthConflict
	}
	credentials, _ := json.Marshal(map[string]string{"oauth_bundle": envelope, "credential_version": strconv.FormatInt(in.ExpectedVersion+1, 10)})
	result, err = tx.ExecContext(ctx, `UPDATE accounts SET credentials=$1::jsonb,updated_at=clock_timestamp()
  WHERE id=$2 AND created_at=$3 AND gateway_oauth_credential_version(credentials)=$4`, string(credentials), in.AccountID, in.CreatedAt, in.ExpectedVersion)
	if err != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	n, err = result.RowsAffected()
	if err != nil || n != 1 {
		return empty, service.ErrGatewayOAuthConflict
	}
	if tx.Commit() != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	return service.GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "completed", Version: in.ExpectedVersion + 1}, nil
}
func (r *accountRepository) UnknownGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent, fence int64) (retErr error) {
	tx, err := r.gatewayRefreshTx(ctx, in)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			retErr = service.ErrGatewayNativeIdentity
		}
	}()
	out, found, err := gatewayRefreshRead(ctx, tx, in)
	if err != nil {
		return err
	}
	if !found || out.Fence != fence {
		return service.ErrGatewayOAuthConflict
	}
	if out.Outcome.State == "completed" || out.Outcome.State == "unknown" {
		return nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='unknown'
  WHERE consumer=$1 AND operation_ref=$2 AND fence=$3 AND state IN ('prepared','entered')`, in.Scope.Consumer, in.Operation, fence)
	if err != nil || tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayNativeOAuthRefreshRepository = (*accountRepository)(nil)

// Resolve after locking the exact physical account. The completed F3 commitment
// and F4 qualification are read afresh after any dispatch/refresh lock wait.
func (r *accountRepository) ResolveGatewayNativeOAuthRefresh(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthRefreshResolution, error) {
	var out service.GatewayNativeOAuthRefreshResolution
	deny := func() (service.GatewayNativeOAuthRefreshResolution, error) {
		return service.GatewayNativeOAuthRefreshResolution{}, service.ErrGatewayNativeIdentity
	}
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || !service.GatewayNativeCredentialRefValid(operation) {
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
	defer func() { _ = tx.Rollback() }()
	// Find the one immutable connect birth, then lock before reading version/F2.
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT r.account_id FROM gateway_oauth_connect_intents c
 JOIN gateway_oauth_identity_reservations r ON r.consumer=c.consumer AND r.operation_ref=c.enrollment_operation
 WHERE c.consumer=$1 AND c.owner_ref=$2 AND c.account_ref=$3 AND c.generation=$4 AND c.operation_ref=$5
 AND c.state='completed' AND NOT c.recovery_denied AND c.purpose=$6`, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation, scope.Purpose).Scan(&id)
	if err != nil {
		return deny()
	}
	var locked int64
	if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, id).Scan(&locked) != nil {
		return deny()
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.created_at,gateway_oauth_credential_version(a.credentials),a.credentials->>'oauth_bundle'
 FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
 JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.owner_ref=r.owner_ref
 AND c.account_ref=r.account_ref AND c.generation=r.generation
 AND c.enrollment_operation=r.operation_ref AND c.enrollment_mac=r.intent_mac
 AND c.outcome_operation=r.operation_ref AND c.outcome_account_id=r.account_id
 AND c.outcome_generation=r.generation AND c.outcome_state='staged'
 JOIN gateway_oauth_profile_qualifications q ON q.account_id=a.id AND q.native_created_at=a.created_at
 AND q.consumer=c.consumer AND q.owner_ref=c.owner_ref AND q.account_ref=c.account_ref
 AND q.generation=c.generation AND q.operation_ref=c.operation_ref AND q.issuer=r.issuer AND q.subject=r.subject
 WHERE a.id=$1 AND c.consumer=$2 AND c.owner_ref=$3 AND c.account_ref=$4 AND c.generation=$5 AND c.operation_ref=$6
 AND c.state='completed' AND NOT c.recovery_denied AND c.purpose=$7
 AND q.profile=$8 AND q.base_url=$9 AND q.model=$10 AND q.qualification=$11
 AND q.qualified_at IS NOT NULL AND q.provider_account_id<>''
 AND a.deleted_at IS NULL AND a.status='disabled' AND NOT a.schedulable
 AND a.platform='openai' AND a.type='oauth' AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp())
 AND a.extra->>'gateway_profile_v1'='openai-oidc-oauth-staging-v1'
 AND a.extra->>'gateway_generation_v1'=r.generation
 AND a.extra->'gateway_credential_scope_v1'=jsonb_build_object('consumer',r.consumer,'owner',r.owner_ref,'account',r.account_ref,'generation',r.generation,'purpose',c.purpose)
 AND gateway_oauth_credential_version(a.credentials)>0
 AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id)
 LIMIT 2`, id, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation, scope.Purpose,
		service.GatewayCodexOAuthResponsesProfile, service.GatewayCodexOAuthBaseURL, service.GatewayCodexOAuthModel, service.GatewayCodexOAuthQualification)
	if err != nil {
		return deny()
	}
	if !rows.Next() || rows.Scan(&out.AccountID, &out.CreatedAt, &out.Version, &out.Envelope) != nil || rows.Next() || rows.Err() != nil {
		_ = rows.Close()
		return deny()
	}
	if rows.Close() != nil {
		return deny()
	}
	// UNIQUE(account_id,expected_version) is authoritative, including an old
	// reference whose completion ACK was lost and whose current version is newer.
	attempt := service.GatewayNativeOAuthRefreshIntent{}
	var consumer, owner, account, generation string
	err = tx.QueryRowContext(ctx, `SELECT account_id,native_created_at,consumer,owner_ref,account_ref,generation,
 expected_version,operation_ref,intent_ref,state FROM gateway_oauth_refresh_attempts
 WHERE account_id=$1 ORDER BY expected_version DESC LIMIT 1 FOR UPDATE`, id).Scan(
		&attempt.AccountID, &attempt.CreatedAt, &consumer, &owner, &account, &generation, &attempt.ExpectedVersion, &attempt.Operation, &attempt.Intent, &out.State)
	if err != nil && err != sql.ErrNoRows {
		return deny()
	}
	if err == nil {
		attempt.Scope = scope
		if consumer != scope.Consumer || owner != scope.Owner || account != scope.Account || generation != scope.Generation ||
			attempt.AccountID != out.AccountID || !attempt.CreatedAt.Equal(out.CreatedAt) || !attempt.Authorized(ctx) ||
			(out.State == "completed" && attempt.ExpectedVersion+1 != out.Version) || (out.State != "completed" && attempt.ExpectedVersion != out.Version) {
			return deny()
		}
		out.Attempt = &attempt
	}
	if tx.Commit() != nil {
		return deny()
	}
	return out, nil
}

var _ service.GatewayNativeOAuthRefreshResolver = (*accountRepository)(nil)
