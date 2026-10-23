package repository

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Grok has independent lifecycle journals and permanent provider principal claims.
// Every physical lock is taken account-first, then intent, including maintenance.
type gatewayGrokRepository struct{ db *sql.DB }

func NewGatewayNativeGrokRepository(db *sql.DB) (service.GatewayNativeGrokRepository, error) {
	if db == nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	return &gatewayGrokRepository{db}, nil
}
func grokArgs(s service.GatewayNativeCredentialScope, op string) []any {
	return []any{s.Consumer, op, s.Owner, s.Account, s.Generation, s.Purpose}
}

const grokWhere = ` WHERE consumer=$1 AND operation_ref=$2 AND owner_ref=$3 AND account_ref=$4 AND generation=$5 AND purpose=$6`
const grokColumns = `consumer,operation_ref,owner_ref,account_ref,generation,purpose,state_hash,material_envelope,state,deadline`

func scanGrok(row *sql.Row) (v service.GatewayGrokConnectIntent, err error) {
	err = row.Scan(&v.Scope.Consumer, &v.Operation, &v.Scope.Owner, &v.Scope.Account, &v.Scope.Generation, &v.Scope.Purpose, &v.StateHash, &v.Envelope, &v.State, &v.Deadline)
	if err != nil {
		err = service.ErrGatewayNativeIdentity
	}
	return
}
func grokAuthorized(ctx context.Context, s service.GatewayNativeCredentialScope, op string) bool {
	return service.GatewayNativeOAuthScopeAuthorized(ctx, s) && service.GatewayNativeCredentialRefValid(op)
}
func (r *gatewayGrokRepository) PutGatewayGrokConnect(ctx context.Context, in service.GatewayGrokConnectIntent) (service.GatewayGrokConnectIntent, error) {
	hash, e := hex.DecodeString(in.StateHash)
	if !grokAuthorized(ctx, in.Scope, in.Operation) || e != nil || len(hash) != 32 || hex.EncodeToString(hash) != in.StateHash || in.State != "prepared" || !strings.HasPrefix(in.Envelope, "gco1.") || !time.Now().Before(in.Deadline) || in.Deadline.After(time.Now().Add(10*time.Minute)) {
		return service.GatewayGrokConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	args := append(grokArgs(in.Scope, in.Operation), in.StateHash, in.Envelope, in.Deadline)
	_, err := r.db.ExecContext(ctx, `INSERT INTO gateway_grok_connect_intents (consumer,operation_ref,owner_ref,account_ref,generation,purpose,state_hash,material_envelope,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(consumer,operation_ref) DO NOTHING`, args...)
	if err != nil {
		return service.GatewayGrokConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.ReadGatewayGrokConnect(ctx, in.Scope, in.Operation)
}
func (r *gatewayGrokRepository) ReadGatewayGrokConnect(ctx context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayGrokConnectIntent, error) {
	if !grokAuthorized(ctx, s, op) {
		return service.GatewayGrokConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return scanGrok(r.db.QueryRowContext(ctx, `SELECT `+grokColumns+` FROM gateway_grok_connect_intents`+grokWhere, grokArgs(s, op)...))
}
func (r *gatewayGrokRepository) ClaimGatewayGrokConnect(ctx context.Context, s service.GatewayNativeCredentialScope, op, hash string) (service.GatewayGrokConnectIntent, error) {
	if !grokAuthorized(ctx, s, op) {
		return service.GatewayGrokConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	args := append(grokArgs(s, op), hash)
	return scanGrok(r.db.QueryRowContext(ctx, `UPDATE gateway_grok_connect_intents SET state='exchanging'`+grokWhere+` AND state='prepared' AND state_hash=$7 AND deadline>clock_timestamp() RETURNING `+grokColumns, args...))
}
func (r *gatewayGrokRepository) CompleteGatewayGrokConnect(ctx context.Context, in service.GatewayGrokEnrollment) (service.GatewayNativeOAuthOutcome, error) {
	out := service.GatewayNativeOAuthOutcome{}
	s := in.Intent.Scope
	op := in.Intent.Operation
	account, org := in.Identity.Principal()
	if !grokAuthorized(ctx, s, op) || !in.Identity.Verified() || !strings.HasPrefix(in.Envelope, "gco1.") {
		return out, service.ErrGatewayNativeIdentity
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	defer tx.Rollback()
	current, err := scanGrok(tx.QueryRowContext(ctx, `SELECT `+grokColumns+` FROM gateway_grok_connect_intents`+grokWhere+` FOR UPDATE`, grokArgs(s, op)...))
	if err != nil || current.State != "exchanging" || current.StateHash != in.Intent.StateHash || current.Envelope != in.Intent.Envelope {
		return out, service.ErrGatewayNativeIdentity
	}
	// Same principal may reconnect only to its original durable logical owner.
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_grok_principal_claims(subject_ref,team_ref,consumer,owner_ref,account_ref) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, account, org, s.Consumer, s.Owner, s.Account)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	var owned bool
	if tx.QueryRowContext(ctx, `SELECT consumer=$3 AND owner_ref=$4 AND account_ref=$5 FROM gateway_grok_principal_claims WHERE subject_ref=$1 AND team_ref=$2 FOR UPDATE`, account, org, s.Consumer, s.Owner, s.Account).Scan(&owned) != nil || !owned {
		return out, service.ErrGatewayNativeIdentity
	}
	var prior bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM gateway_grok_connect_intents c JOIN accounts a ON a.id=c.account_id WHERE c.consumer=$1 AND c.account_ref=$2 AND a.deleted_at IS NULL)`, s.Consumer, s.Account).Scan(&prior) != nil || prior {
		return out, service.ErrGatewayNativeIdentity
	}
	extra, _ := json.Marshal(map[string]any{"gateway_grok_profile_v1": service.GatewayGrokOAuthResponsesProfile, "gateway_grok_generation_v1": s.Generation, "gateway_grok_scope_v1": s.Metadata()})
	credentials, _ := json.Marshal(map[string]string{"oauth_bundle": in.Envelope})
	var id int64
	var birth time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra,concurrency,priority,rate_multiplier,created_at,updated_at) VALUES($1,'grok','oauth','disabled',false,$2::jsonb,$3::jsonb,1,50,1,clock_timestamp(),clock_timestamp()) RETURNING id,created_at`, "protected Grok OAuth staging", string(credentials), string(extra)).Scan(&id, &birth)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	args := append(grokArgs(s, op), id, birth, account, org)
	_, err = tx.ExecContext(ctx, `UPDATE gateway_grok_connect_intents SET state='completed',material_envelope='',account_id=$7,native_created_at=$8,subject_ref=$9,team_ref=$10`+grokWhere, args...)
	if err != nil || tx.Commit() != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	return service.GatewayNativeOAuthOutcome{Operation: op, AccountID: id, Generation: s.Generation, State: "staged"}, nil
}
func grokRoute(id int64, birth time.Time, generation string) service.GatewayNativeRoute {
	return service.GatewayNativeRoute{AccountID: id, CreatedAt: birth, Generation: generation, Profile: service.GatewayGrokOAuthResponsesProfile, BaseURL: service.GatewayGrokOAuthBaseURL, Model: service.GatewayGrokOAuthModel}
}
func (r *gatewayGrokRepository) physicalTx(ctx context.Context, s service.GatewayNativeCredentialScope, op string, expected *service.GatewayNativeRoute, exclusive, refresh bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
	return r.physicalTxMode(ctx, s, op, expected, exclusive, refresh, false)
}
func (r *gatewayGrokRepository) physicalTxMode(ctx context.Context, s service.GatewayNativeCredentialScope, op string, expected *service.GatewayNativeRoute, exclusive, refresh, cache bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
	p := service.GatewayNativeOAuthPhysical{Scope: s, Operation: op, Issuer: service.GatewayGrokOAuthIssuer}
	var envelope string
	deny := func(tx *sql.Tx) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
		if tx != nil {
			tx.Rollback()
		}
		return nil, p, "", service.ErrGatewayNativeIdentity
	}
	if !grokAuthorized(ctx, s, op) {
		return deny(nil)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return deny(nil)
	}
	var id int64
	if tx.QueryRowContext(ctx, `SELECT account_id FROM gateway_grok_connect_intents`+grokWhere, grokArgs(s, op)...).Scan(&id) != nil {
		return deny(tx)
	}
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	var locked int64
	if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 AND deleted_at IS NULL`+lock, id).Scan(&locked) != nil {
		return deny(tx)
	}
	var birth time.Time
	var state string
	projection := "a.credentials->>'oauth_bundle'"
	if cache {
		projection = "''"
	}
	err = tx.QueryRowContext(ctx, `SELECT a.created_at,c.subject_ref,c.team_ref,`+projection+`,c.refresh_state,c.credential_revision
 FROM gateway_grok_connect_intents c JOIN accounts a ON a.id=c.account_id AND a.created_at=c.native_created_at
 JOIN gateway_grok_principal_claims p ON p.subject_ref=c.subject_ref AND p.team_ref=c.team_ref AND p.consumer=c.consumer AND p.owner_ref=c.owner_ref AND p.account_ref=c.account_ref
 WHERE c.consumer=$1 AND c.operation_ref=$2 AND c.owner_ref=$3 AND c.account_ref=$4 AND c.generation=$5 AND c.purpose=$6 AND c.state='completed'
 AND a.deleted_at IS NULL AND a.platform='grok' AND a.type='oauth' AND a.status='disabled' AND NOT a.schedulable AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra=jsonb_build_object('gateway_grok_profile_v1',$7::text,'gateway_grok_generation_v1',c.generation::text,'gateway_grok_scope_v1',jsonb_build_object('consumer',c.consumer,'owner',c.owner_ref,'account',c.account_ref,'generation',c.generation::text,'purpose',c.purpose))
 AND public.gateway_oauth_envelope_valid(a.credentials->'oauth_bundle') AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id) FOR SHARE OF c,p`, append(grokArgs(s, op), service.GatewayGrokOAuthResponsesProfile)...).Scan(&birth, &p.Subject, &p.ProviderAccount, &envelope, &state, &p.CredentialRevision)
	p.Route = grokRoute(id, birth, s.Generation)
	if err != nil || !refresh && state == "exchanging" || expected != nil && !service.SameGatewayNativeDescriptor(*expected, p.Route) {
		return deny(tx)
	}
	return tx, p, envelope, nil
}
func (r *gatewayGrokRepository) LockGatewayGrokPhysical(ctx context.Context, s service.GatewayNativeCredentialScope, op string, route *service.GatewayNativeRoute) (service.GatewayNativeOAuthPhysical, string, func(), error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, route, false, false)
	if err != nil {
		return p, "", nil, err
	}
	var once sync.Once
	return p, envelope, func() { once.Do(func() { tx.Rollback() }) }, nil
}
func (r *gatewayGrokRepository) ClaimGatewayGrokRefresh(ctx context.Context, s service.GatewayNativeCredentialScope, op, attempt string, expectedRevision int64) (service.GatewayNativeOAuthPhysical, string, bool, error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, nil, true, true)
	if err != nil {
		return p, "", false, err
	}
	defer tx.Rollback()
	if !service.GatewayNativeCredentialRefValid(attempt) {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	var state string
	var exact bool
	err = tx.QueryRowContext(ctx, `SELECT state,account_id=$3 AND generation=$4 FROM gateway_grok_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, s.Consumer, attempt, p.Route.AccountID, s.Generation).Scan(&state, &exact)
	if err == nil {
		if exact && state == "completed" {
			return p, "", false, nil
		}
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	if err != sql.ErrNoRows {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	if p.CredentialRevision != expectedRevision || expectedRevision < 1 {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	var fence string
	if tx.QueryRowContext(ctx, `SELECT refresh_state FROM gateway_grok_connect_intents WHERE account_id=$1`, p.Route.AccountID).Scan(&fence) != nil || fence == "exchanging" {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_grok_refresh_attempts(consumer,operation_ref,account_id,generation,expected_revision,state) VALUES($1,$2,$3,$4,$5,'exchanging')`, s.Consumer, attempt, p.Route.AccountID, s.Generation, p.CredentialRevision)
	if err != nil {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `UPDATE gateway_grok_connect_intents SET refresh_state='exchanging',refresh_operation=$2 WHERE account_id=$1`, p.Route.AccountID, attempt)
	if err != nil || tx.Commit() != nil {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	return p, envelope, true, nil
}
func (r *gatewayGrokRepository) CompleteGatewayGrokRefresh(ctx context.Context, p service.GatewayNativeOAuthPhysical, attempt, envelope string) error {
	tx, current, _, err := r.physicalTx(ctx, p.Scope, p.Operation, &p.Route, true, true)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if current.Subject != p.Subject || current.ProviderAccount != p.ProviderAccount || current.CredentialRevision != p.CredentialRevision || !strings.HasPrefix(envelope, "gco1.") {
		return service.ErrGatewayNativeIdentity
	}
	result, err := tx.ExecContext(ctx, `UPDATE gateway_grok_refresh_attempts SET state='completed' WHERE consumer=$1 AND operation_ref=$2 AND account_id=$3 AND generation=$4 AND expected_revision=$5 AND state='exchanging'`, p.Scope.Consumer, attempt, p.Route.AccountID, p.Scope.Generation, p.CredentialRevision)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `UPDATE accounts SET credentials=jsonb_build_object('oauth_bundle',$2::text),updated_at=clock_timestamp() WHERE id=$1`, p.Route.AccountID, envelope)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	result, err = tx.ExecContext(ctx, `UPDATE gateway_grok_connect_intents SET refresh_state='completed',credential_revision=credential_revision+1 WHERE account_id=$1 AND refresh_operation=$2 AND refresh_state='exchanging' AND credential_revision=$3`, p.Route.AccountID, attempt, p.CredentialRevision)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, _ = result.RowsAffected()
	if n != 1 || tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}
func (r *gatewayGrokRepository) CleanupGatewayGrok(ctx context.Context, in service.GatewayNativeOAuthCleanupRequest, authorize service.GatewayNativeOAuthCleanupAuthorizer) (service.GatewayNativeOAuthCleanupResult, error) {
	empty := service.GatewayNativeOAuthCleanupResult{}
	if !grokAuthorized(ctx, in.Scope, in.Operation) || !service.GatewayNativeOAuthCleanupRequestValid(in) || authorize == nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	grant, err := authorize(ctx, in)
	if err != nil || grant.Owner != in.Scope.Owner || !time.Now().Before(grant.LeaseExpiresAt) {
		return empty, service.ErrGatewayNativeIdentity
	}
	ctx, cancel := context.WithDeadline(ctx, grant.LeaseExpiresAt)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	defer tx.Rollback()
	args := grokArgs(in.Scope, in.Operation)
	var id sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT account_id FROM gateway_grok_connect_intents`+grokWhere, args...).Scan(&id) != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	if id.Valid {
		var locked int64
		if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, id.Int64).Scan(&locked) != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
	}
	intent, err := scanGrok(tx.QueryRowContext(ctx, `SELECT `+grokColumns+` FROM gateway_grok_connect_intents`+grokWhere+` FOR UPDATE`, args...))
	if err != nil {
		return empty, err
	}
	var currentID sql.NullInt64
	var uncertain bool
	if tx.QueryRowContext(ctx, `SELECT account_id,recovery_uncertain FROM gateway_grok_connect_intents`+grokWhere, args...).Scan(&currentID, &uncertain) != nil || currentID != id {
		return empty, service.ErrGatewayNativeIdentity
	}
	out := service.GatewayNativeOAuthCleanupResult{Operation: in.Operation, Account: in.Scope.Account, Closure: "pending", CredentialsErased: intent.State == "erased"}
	var refresh string
	if id.Valid {
		var birth time.Time
		var erased bool
		if tx.QueryRowContext(ctx, `SELECT a.created_at,a.deleted_at IS NOT NULL AND a.credentials='{}'::jsonb,c.refresh_state FROM accounts a JOIN gateway_grok_connect_intents c ON c.account_id=a.id AND c.native_created_at=a.created_at WHERE a.id=$1`, id.Int64).Scan(&birth, &erased, &refresh) != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
		route := grokRoute(id.Int64, birth, in.Scope.Generation)
		out.Native = &route
		out.CredentialsErased = erased
	}
	if in.Action == "erase" {
		fresh, e := authorize(ctx, in)
		if e != nil || fresh.Owner != in.Scope.Owner || !time.Now().Before(fresh.LeaseExpiresAt) || ctx.Err() != nil || out.Native != nil && (fresh.Native == nil || !service.SameGatewayNativeDescriptor(*fresh.Native, *out.Native)) {
			return empty, service.ErrGatewayNativeIdentity
		}
		if id.Valid && !out.CredentialsErased {
			_, err = tx.ExecContext(ctx, `UPDATE accounts SET credentials='{}'::jsonb,deleted_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, id.Int64)
			if err != nil {
				return empty, service.ErrGatewayNativeIdentity
			}
		}
		if intent.State != "erased" {
			_, err = tx.ExecContext(ctx, `UPDATE gateway_grok_connect_intents SET state='erased',material_envelope='',recovery_uncertain=recovery_uncertain OR state='exchanging'`+grokWhere, args...)
			if err != nil {
				return empty, service.ErrGatewayNativeIdentity
			}
		}
		out.CredentialsErased = true
	}
	if out.CredentialsErased {
		out.Closure = "closed"
		if uncertain || intent.State == "exchanging" || refresh == "exchanging" {
			out.Closure = "unknown"
		}
	}
	if tx.Commit() != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	return out, nil
}
func (r *gatewayGrokRepository) resolve(ctx context.Context, s service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (string, error) {
	var op string
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || route.Generation != s.Generation {
		return "", service.ErrGatewayNativeIdentity
	}
	err := r.db.QueryRowContext(ctx, `SELECT operation_ref FROM gateway_grok_connect_intents WHERE consumer=$1 AND owner_ref=$2 AND account_ref=$3 AND generation=$4 AND account_id=$5 AND native_created_at=$6 AND state='completed'`, s.Consumer, s.Owner, s.Account, s.Generation, route.AccountID, route.CreatedAt).Scan(&op)
	if err != nil {
		return "", service.ErrGatewayNativeIdentity
	}
	return op, nil
}

var _ service.GatewayNativeGrokRepository = (*gatewayGrokRepository)(nil)

func (r *gatewayGrokRepository) ResolveGatewayGrokCanonical(ctx context.Context, route service.GatewayNativeRoute, account string) (service.GatewayNativeCredentialScope, string, error) {
	s := service.GatewayNativeCredentialScope{Account: account, Generation: route.Generation, Purpose: service.GatewayOAuthBundlePurpose}
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !service.GatewayNativeCredentialRefValid(account) {
		return s, "", service.ErrGatewayNativeIdentity
	}
	s.Consumer = consumer
	var op string
	err = r.db.QueryRowContext(ctx, `SELECT owner_ref,operation_ref FROM gateway_grok_connect_intents WHERE consumer=$1 AND account_ref=$2 AND generation=$3 AND account_id=$4 AND native_created_at=$5 AND state='completed'`, consumer, account, route.Generation, route.AccountID, route.CreatedAt).Scan(&s.Owner, &op)
	if err != nil {
		return s, "", service.ErrGatewayNativeIdentity
	}
	ownerCtx, err := service.WithGatewayNativeOAuthOwner(ctx, s.Owner)
	if err != nil {
		return s, "", err
	}
	_, _, release, err := r.LockGatewayGrokPhysical(ownerCtx, s, op, &route)
	if err != nil {
		return s, "", err
	}
	release()
	return s, op, nil
}

func (r *gatewayGrokRepository) ReadGatewayGrokRefresh(ctx context.Context, s service.GatewayNativeCredentialScope, connect, attempt string) (service.GatewayNativeOAuthRefreshOutcome, bool, error) {
	out := service.GatewayNativeOAuthRefreshOutcome{Operation: attempt}
	if !grokAuthorized(ctx, s, connect) || !service.GatewayNativeCredentialRefValid(attempt) {
		return out, false, service.ErrGatewayNativeIdentity
	}
	var state string
	var exact bool
	err := r.db.QueryRowContext(ctx, `SELECT r.state,r.expected_revision,r.account_id=c.account_id AND r.generation=c.generation FROM gateway_grok_refresh_attempts r LEFT JOIN gateway_grok_connect_intents c ON c.consumer=$1 AND c.operation_ref=$3 AND c.owner_ref=$4 AND c.account_ref=$5 AND c.generation=$6 AND c.purpose=$7 WHERE r.consumer=$1 AND r.operation_ref=$2`, s.Consumer, attempt, connect, s.Owner, s.Account, s.Generation, s.Purpose).Scan(&state, &out.Version, &exact)
	if err == sql.ErrNoRows {
		return out, false, nil
	}
	if err != nil || !exact {
		return out, false, service.ErrGatewayNativeIdentity
	}
	out.State = "unknown"
	if state == "completed" {
		out.State = "completed"
		out.Version++
	}
	return out, true, nil
}

func (r *gatewayGrokRepository) LockGatewayGrokMaintenance(ctx context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthPhysical, string, string, string, func(), error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, nil, false, true)
	if err != nil {
		return p, "", "", "", nil, err
	}
	var state, attempt string
	err = tx.QueryRowContext(ctx, `SELECT refresh_state,COALESCE(refresh_operation,'') FROM gateway_grok_connect_intents`+grokWhere, grokArgs(s, op)...).Scan(&state, &attempt)
	if err != nil {
		tx.Rollback()
		return p, "", "", "", nil, service.ErrGatewayNativeIdentity
	}
	var once sync.Once
	return p, envelope, state, attempt, func() { once.Do(func() { tx.Rollback() }) }, nil
}

// Cache readers retain exact birth/principal fencing without decrypting material.
func (r *gatewayGrokRepository) LockGatewayGrokCachedPhysical(ctx context.Context, s service.GatewayNativeCredentialScope, op string, route *service.GatewayNativeRoute) (service.GatewayNativeOAuthPhysical, func(), error) {
	tx, p, _, err := r.physicalTxMode(ctx, s, op, route, false, true, true)
	if err != nil {
		return p, nil, err
	}
	var once sync.Once
	return p, func() { once.Do(func() { tx.Rollback() }) }, nil
}

// ListGatewayGrokQuotaAccounts discovers only the authenticated consumer's
// protected completed births; the collector must reacquire a physical lease
// before credential access. Enumeration itself never projects credentials.
func (r *gatewayGrokRepository) ListGatewayGrokQuotaAccounts(ctx context.Context) ([]service.GatewayNativeOAuthPhysical, error) {
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	rows, err := r.db.QueryContext(ctx, `SELECT c.owner_ref,c.account_ref,c.generation::text,c.operation_ref,c.account_id,c.native_created_at,c.subject_ref,c.team_ref,c.credential_revision
 FROM gateway_grok_connect_intents c JOIN accounts a ON a.id=c.account_id AND a.created_at=c.native_created_at
 WHERE c.consumer=$1 AND c.state='completed' AND c.refresh_state<>'exchanging' AND a.deleted_at IS NULL
 AND a.platform='grok' AND a.type='oauth' AND a.status='disabled' AND NOT a.schedulable
 AND a.extra->>'gateway_grok_profile_v1'=$2 ORDER BY c.account_id LIMIT 1000`, consumer, service.GatewayGrokOAuthResponsesProfile)
	if err != nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	defer rows.Close()
	out := make([]service.GatewayNativeOAuthPhysical, 0)
	for rows.Next() {
		p := service.GatewayNativeOAuthPhysical{Scope: service.GatewayNativeCredentialScope{Consumer: consumer, Purpose: service.GatewayOAuthBundlePurpose}, Issuer: service.GatewayGrokOAuthIssuer}
		var id int64
		var birth time.Time
		if rows.Scan(&p.Scope.Owner, &p.Scope.Account, &p.Scope.Generation, &p.Operation, &id, &birth, &p.Subject, &p.ProviderAccount, &p.CredentialRevision) != nil {
			return nil, service.ErrGatewayNativeIdentity
		}
		p.Route = grokRoute(id, birth, p.Scope.Generation)
		out = append(out, p)
	}
	if rows.Err() != nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	return out, nil
}
