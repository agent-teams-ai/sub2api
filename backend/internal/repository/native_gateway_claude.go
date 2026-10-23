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

// Claude has independent lifecycle journals and permanent provider principal claims.
// Every physical lock is taken account-first, then intent, including maintenance.
type gatewayClaudeRepository struct{ db *sql.DB }

func NewGatewayNativeClaudeRepository(db *sql.DB) (service.GatewayNativeClaudeRepository, error) {
	if db == nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	return &gatewayClaudeRepository{db}, nil
}
func claudeArgs(s service.GatewayNativeCredentialScope, op string) []any {
	return []any{s.Consumer, op, s.Owner, s.Account, s.Generation, s.Purpose}
}

const claudeWhere = ` WHERE consumer=$1 AND operation_ref=$2 AND owner_ref=$3 AND account_ref=$4 AND generation=$5 AND purpose=$6`
const claudeColumns = `consumer,operation_ref,owner_ref,account_ref,generation,purpose,state_hash,material_envelope,state,deadline`

func scanClaude(row *sql.Row) (v service.GatewayClaudeConnectIntent, err error) {
	err = row.Scan(&v.Scope.Consumer, &v.Operation, &v.Scope.Owner, &v.Scope.Account, &v.Scope.Generation, &v.Scope.Purpose, &v.StateHash, &v.Envelope, &v.State, &v.Deadline)
	if err != nil {
		err = service.ErrGatewayNativeIdentity
	}
	return
}
func claudeAuthorized(ctx context.Context, s service.GatewayNativeCredentialScope, op string) bool {
	return service.GatewayNativeOAuthScopeAuthorized(ctx, s) && service.GatewayNativeCredentialRefValid(op)
}
func (r *gatewayClaudeRepository) PutGatewayClaudeConnect(ctx context.Context, in service.GatewayClaudeConnectIntent) (service.GatewayClaudeConnectIntent, error) {
	hash, e := hex.DecodeString(in.StateHash)
	if !claudeAuthorized(ctx, in.Scope, in.Operation) || e != nil || len(hash) != 32 || hex.EncodeToString(hash) != in.StateHash || in.State != "prepared" || !strings.HasPrefix(in.Envelope, "gco1.") || !time.Now().Before(in.Deadline) || in.Deadline.After(time.Now().Add(10*time.Minute)) {
		return service.GatewayClaudeConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	args := append(claudeArgs(in.Scope, in.Operation), in.StateHash, in.Envelope, in.Deadline)
	_, err := r.db.ExecContext(ctx, `INSERT INTO gateway_claude_connect_intents (consumer,operation_ref,owner_ref,account_ref,generation,purpose,state_hash,material_envelope,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(consumer,operation_ref) DO NOTHING`, args...)
	if err != nil {
		return service.GatewayClaudeConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.ReadGatewayClaudeConnect(ctx, in.Scope, in.Operation)
}
func (r *gatewayClaudeRepository) ReadGatewayClaudeConnect(ctx context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayClaudeConnectIntent, error) {
	if !claudeAuthorized(ctx, s, op) {
		return service.GatewayClaudeConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return scanClaude(r.db.QueryRowContext(ctx, `SELECT `+claudeColumns+` FROM gateway_claude_connect_intents`+claudeWhere, claudeArgs(s, op)...))
}
func (r *gatewayClaudeRepository) ClaimGatewayClaudeConnect(ctx context.Context, s service.GatewayNativeCredentialScope, op, hash string) (service.GatewayClaudeConnectIntent, error) {
	if !claudeAuthorized(ctx, s, op) {
		return service.GatewayClaudeConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	args := append(claudeArgs(s, op), hash)
	return scanClaude(r.db.QueryRowContext(ctx, `UPDATE gateway_claude_connect_intents SET state='exchanging'`+claudeWhere+` AND state='prepared' AND state_hash=$7 AND deadline>clock_timestamp() RETURNING `+claudeColumns, args...))
}
func (r *gatewayClaudeRepository) CompleteGatewayClaudeConnect(ctx context.Context, in service.GatewayClaudeEnrollment) (service.GatewayNativeOAuthOutcome, error) {
	out := service.GatewayNativeOAuthOutcome{}
	s := in.Intent.Scope
	op := in.Intent.Operation
	account, org := in.Identity.Principal()
	if !claudeAuthorized(ctx, s, op) || !in.Identity.Verified() || !strings.HasPrefix(in.Envelope, "gco1.") {
		return out, service.ErrGatewayNativeIdentity
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	defer func() { _ = tx.Rollback() }()
	current, err := scanClaude(tx.QueryRowContext(ctx, `SELECT `+claudeColumns+` FROM gateway_claude_connect_intents`+claudeWhere+` FOR UPDATE`, claudeArgs(s, op)...))
	if err != nil || current.State != "exchanging" || current.StateHash != in.Intent.StateHash || current.Envelope != in.Intent.Envelope {
		return out, service.ErrGatewayNativeIdentity
	}
	// Same principal may reconnect only to its original durable logical owner.
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_claude_principal_claims(account_uuid,organization_uuid,consumer,owner_ref,account_ref) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, account, org, s.Consumer, s.Owner, s.Account)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	var owned bool
	if tx.QueryRowContext(ctx, `SELECT consumer=$3 AND owner_ref=$4 AND account_ref=$5 FROM gateway_claude_principal_claims WHERE account_uuid=$1 AND organization_uuid=$2 FOR UPDATE`, account, org, s.Consumer, s.Owner, s.Account).Scan(&owned) != nil || !owned {
		return out, service.ErrGatewayNativeIdentity
	}
	var prior bool
	if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM gateway_claude_connect_intents c JOIN accounts a ON a.id=c.account_id WHERE c.consumer=$1 AND c.account_ref=$2 AND a.deleted_at IS NULL)`, s.Consumer, s.Account).Scan(&prior) != nil || prior {
		return out, service.ErrGatewayNativeIdentity
	}
	extra, _ := json.Marshal(map[string]any{"gateway_claude_profile_v1": service.GatewayClaudeOAuthMessagesProfile, "gateway_claude_generation_v1": s.Generation, "gateway_claude_scope_v1": s.Metadata()})
	credentials, _ := json.Marshal(map[string]string{"oauth_bundle": in.Envelope})
	var id int64
	var birth time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra,concurrency,priority,rate_multiplier,created_at,updated_at) VALUES($1,'anthropic','oauth','disabled',false,$2::jsonb,$3::jsonb,1,50,1,clock_timestamp(),clock_timestamp()) RETURNING id,created_at`, "protected Claude OAuth staging", string(credentials), string(extra)).Scan(&id, &birth)
	if err != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	args := append(claudeArgs(s, op), id, birth, account, org)
	_, err = tx.ExecContext(ctx, `UPDATE gateway_claude_connect_intents SET state='completed',material_envelope='',account_id=$7,native_created_at=$8,account_uuid=$9,organization_uuid=$10`+claudeWhere, args...)
	if err != nil || tx.Commit() != nil {
		return out, service.ErrGatewayNativeIdentity
	}
	return service.GatewayNativeOAuthOutcome{Operation: op, AccountID: id, Generation: s.Generation, State: "staged"}, nil
}
func claudeRoute(id int64, birth time.Time, generation string) service.GatewayNativeRoute {
	return service.GatewayNativeRoute{AccountID: id, CreatedAt: birth, Generation: generation, Profile: service.GatewayClaudeOAuthMessagesProfile, BaseURL: service.GatewayClaudeOAuthBaseURL, Model: service.GatewayClaudeOAuthModel}
}
func (r *gatewayClaudeRepository) physicalTx(ctx context.Context, s service.GatewayNativeCredentialScope, op string, expected *service.GatewayNativeRoute, exclusive, refresh bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
	return r.physicalTxMode(ctx, s, op, expected, exclusive, refresh, false)
}
func (r *gatewayClaudeRepository) physicalTxMode(ctx context.Context, s service.GatewayNativeCredentialScope, op string, expected *service.GatewayNativeRoute, exclusive, refresh, cache bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
	p := service.GatewayNativeOAuthPhysical{Scope: s, Operation: op, Issuer: service.GatewayClaudeOAuthIssuer}
	var envelope string
	deny := func(tx *sql.Tx) (*sql.Tx, service.GatewayNativeOAuthPhysical, string, error) {
		if tx != nil {
			_ = tx.Rollback()
		}
		return nil, p, "", service.ErrGatewayNativeIdentity
	}
	if !claudeAuthorized(ctx, s, op) {
		return deny(nil)
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return deny(nil)
	}
	var id int64
	if tx.QueryRowContext(ctx, `SELECT account_id FROM gateway_claude_connect_intents`+claudeWhere, claudeArgs(s, op)...).Scan(&id) != nil {
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
	err = tx.QueryRowContext(ctx, `SELECT a.created_at,c.account_uuid::text,c.organization_uuid::text,`+projection+`,c.refresh_state,c.credential_revision
 FROM gateway_claude_connect_intents c JOIN accounts a ON a.id=c.account_id AND a.created_at=c.native_created_at
 JOIN gateway_claude_principal_claims p ON p.account_uuid=c.account_uuid AND p.organization_uuid=c.organization_uuid AND p.consumer=c.consumer AND p.owner_ref=c.owner_ref AND p.account_ref=c.account_ref
 WHERE c.consumer=$1 AND c.operation_ref=$2 AND c.owner_ref=$3 AND c.account_ref=$4 AND c.generation=$5 AND c.purpose=$6 AND c.state='completed'
 AND a.deleted_at IS NULL AND a.platform='anthropic' AND a.type='oauth' AND a.status='disabled' AND NOT a.schedulable AND a.proxy_id IS NULL AND a.parent_account_id IS NULL
 AND a.extra=jsonb_build_object('gateway_claude_profile_v1',$7::text,'gateway_claude_generation_v1',c.generation::text,'gateway_claude_scope_v1',jsonb_build_object('consumer',c.consumer,'owner',c.owner_ref,'account',c.account_ref,'generation',c.generation::text,'purpose',c.purpose))
 AND public.gateway_oauth_envelope_valid(a.credentials->'oauth_bundle') AND NOT EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id=a.id) FOR SHARE OF c,p`, append(claudeArgs(s, op), service.GatewayClaudeOAuthMessagesProfile)...).Scan(&birth, &p.Subject, &p.ProviderAccount, &envelope, &state, &p.CredentialRevision)
	p.Route = claudeRoute(id, birth, s.Generation)
	if err != nil || !refresh && state == "exchanging" || expected != nil && !service.SameGatewayNativeDescriptor(*expected, p.Route) {
		return deny(tx)
	}
	return tx, p, envelope, nil
}
func (r *gatewayClaudeRepository) LockGatewayClaudePhysical(ctx context.Context, s service.GatewayNativeCredentialScope, op string, route *service.GatewayNativeRoute) (service.GatewayNativeOAuthPhysical, string, func(), error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, route, false, false)
	if err != nil {
		return p, "", nil, err
	}
	var once sync.Once
	return p, envelope, func() { once.Do(func() { _ = tx.Rollback() }) }, nil
}
func (r *gatewayClaudeRepository) ClaimGatewayClaudeRefresh(ctx context.Context, s service.GatewayNativeCredentialScope, op, attempt string, expectedRevision int64) (service.GatewayNativeOAuthPhysical, string, bool, error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, nil, true, true)
	if err != nil {
		return p, "", false, err
	}
	defer func() { _ = tx.Rollback() }()
	if !service.GatewayNativeCredentialRefValid(attempt) {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	var state string
	var exact bool
	err = tx.QueryRowContext(ctx, `SELECT state,account_id=$3 AND generation=$4 FROM gateway_claude_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, s.Consumer, attempt, p.Route.AccountID, s.Generation).Scan(&state, &exact)
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
	if tx.QueryRowContext(ctx, `SELECT refresh_state FROM gateway_claude_connect_intents WHERE account_id=$1`, p.Route.AccountID).Scan(&fence) != nil || fence == "exchanging" {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_claude_refresh_attempts(consumer,operation_ref,account_id,generation,expected_revision,state) VALUES($1,$2,$3,$4,$5,'exchanging')`, s.Consumer, attempt, p.Route.AccountID, s.Generation, p.CredentialRevision)
	if err != nil {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `UPDATE gateway_claude_connect_intents SET refresh_state='exchanging',refresh_operation=$2 WHERE account_id=$1`, p.Route.AccountID, attempt)
	if err != nil || tx.Commit() != nil {
		return p, "", false, service.ErrGatewayNativeIdentity
	}
	return p, envelope, true, nil
}
func (r *gatewayClaudeRepository) CompleteGatewayClaudeRefresh(ctx context.Context, p service.GatewayNativeOAuthPhysical, attempt, envelope string) error {
	tx, current, _, err := r.physicalTx(ctx, p.Scope, p.Operation, &p.Route, true, true)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if current.Subject != p.Subject || current.ProviderAccount != p.ProviderAccount || current.CredentialRevision != p.CredentialRevision || !strings.HasPrefix(envelope, "gco1.") {
		return service.ErrGatewayNativeIdentity
	}
	result, err := tx.ExecContext(ctx, `UPDATE gateway_claude_refresh_attempts SET state='completed' WHERE consumer=$1 AND operation_ref=$2 AND account_id=$3 AND generation=$4 AND expected_revision=$5 AND state='exchanging'`, p.Scope.Consumer, attempt, p.Route.AccountID, p.Scope.Generation, p.CredentialRevision)
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
	result, err = tx.ExecContext(ctx, `UPDATE gateway_claude_connect_intents SET refresh_state='completed',credential_revision=credential_revision+1 WHERE account_id=$1 AND refresh_operation=$2 AND refresh_state='exchanging' AND credential_revision=$3`, p.Route.AccountID, attempt, p.CredentialRevision)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, _ = result.RowsAffected()
	if n != 1 || tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}
func (r *gatewayClaudeRepository) CleanupGatewayClaude(ctx context.Context, in service.GatewayNativeOAuthCleanupRequest, authorize service.GatewayNativeOAuthCleanupAuthorizer) (service.GatewayNativeOAuthCleanupResult, error) {
	empty := service.GatewayNativeOAuthCleanupResult{}
	if !claudeAuthorized(ctx, in.Scope, in.Operation) || !service.GatewayNativeOAuthCleanupRequestValid(in) || authorize == nil {
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
	defer func() { _ = tx.Rollback() }()
	args := claudeArgs(in.Scope, in.Operation)
	var id sql.NullInt64
	if tx.QueryRowContext(ctx, `SELECT account_id FROM gateway_claude_connect_intents`+claudeWhere, args...).Scan(&id) != nil {
		return empty, service.ErrGatewayNativeIdentity
	}
	if id.Valid {
		var locked int64
		if tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, id.Int64).Scan(&locked) != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
	}
	intent, err := scanClaude(tx.QueryRowContext(ctx, `SELECT `+claudeColumns+` FROM gateway_claude_connect_intents`+claudeWhere+` FOR UPDATE`, args...))
	if err != nil {
		return empty, err
	}
	var currentID sql.NullInt64
	var uncertain bool
	if tx.QueryRowContext(ctx, `SELECT account_id,recovery_uncertain FROM gateway_claude_connect_intents`+claudeWhere, args...).Scan(&currentID, &uncertain) != nil || currentID != id {
		return empty, service.ErrGatewayNativeIdentity
	}
	out := service.GatewayNativeOAuthCleanupResult{Operation: in.Operation, Account: in.Scope.Account, Closure: "pending", CredentialsErased: intent.State == "erased"}
	var refresh string
	if id.Valid {
		var birth time.Time
		var erased bool
		if tx.QueryRowContext(ctx, `SELECT a.created_at,a.deleted_at IS NOT NULL AND a.credentials='{}'::jsonb,c.refresh_state FROM accounts a JOIN gateway_claude_connect_intents c ON c.account_id=a.id AND c.native_created_at=a.created_at WHERE a.id=$1`, id.Int64).Scan(&birth, &erased, &refresh) != nil {
			return empty, service.ErrGatewayNativeIdentity
		}
		route := claudeRoute(id.Int64, birth, in.Scope.Generation)
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
			_, err = tx.ExecContext(ctx, `UPDATE gateway_claude_connect_intents SET state='erased',material_envelope='',recovery_uncertain=recovery_uncertain OR state='exchanging'`+claudeWhere, args...)
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
func (r *gatewayClaudeRepository) resolve(ctx context.Context, s service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (string, error) {
	var op string
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || route.Generation != s.Generation {
		return "", service.ErrGatewayNativeIdentity
	}
	err := r.db.QueryRowContext(ctx, `SELECT operation_ref FROM gateway_claude_connect_intents WHERE consumer=$1 AND owner_ref=$2 AND account_ref=$3 AND generation=$4 AND account_id=$5 AND native_created_at=$6 AND state='completed'`, s.Consumer, s.Owner, s.Account, s.Generation, route.AccountID, route.CreatedAt).Scan(&op)
	if err != nil {
		return "", service.ErrGatewayNativeIdentity
	}
	return op, nil
}
func (r *gatewayClaudeRepository) ReadGatewayClaudeLimits(ctx context.Context, s service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (service.GatewayAccountLimitsStored, error) {
	out := service.GatewayAccountLimitsStored{}
	op, err := r.resolve(ctx, s, route)
	if err != nil {
		return out, err
	}
	tx, p, _, err := r.physicalTxMode(ctx, s, op, &route, false, true, true)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	out.PrincipalVersion = service.GatewayAccountLimitsPrincipal(p)
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT revision,raw_snapshot FROM gateway_claude_limits_snapshots WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND principal_version=$4`, route.AccountID, route.CreatedAt, route.Generation, out.PrincipalVersion).Scan(&out.Revision, &raw)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil || len(raw) > 8192 {
		return service.GatewayAccountLimitsStored{}, service.ErrGatewayNativeIdentity
	}
	var parsed service.GatewayClaudeRawLimits
	if json.Unmarshal(raw, &parsed) != nil {
		return service.GatewayAccountLimitsStored{}, service.ErrGatewayNativeIdentity
	}
	out.Claude = &parsed
	return out, nil
}
func (r *gatewayClaudeRepository) StoreGatewayClaudeLimits(ctx context.Context, p service.GatewayNativeOAuthPhysical, raw service.GatewayClaudeRawLimits, observed time.Time) error {
	if observed.IsZero() || observed.After(time.Now().Add(time.Minute)) || len(raw.Windows) == 0 || len(service.NormalizeGatewayClaudeLimits(raw)) != len(raw.Windows) {
		return service.ErrGatewayNativeIdentity
	}
	for _, w := range raw.Windows {
		if w.ObservedAt != observed.UTC().Format(time.RFC3339Nano) {
			return service.ErrGatewayNativeIdentity
		}
	}
	data, err := json.Marshal(raw)
	if err != nil || len(data) > 8192 {
		return service.ErrGatewayNativeIdentity
	}
	// Publication runs after dispatch releases its physical lock. Reacquiring
	// validates the birth/principal/revision after any queued erase or rotation.
	tx, current, _, err := r.physicalTxMode(ctx, p.Scope, p.Operation, &p.Route, false, false, true)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	principal := service.GatewayAccountLimitsPrincipal(current)
	if principal != service.GatewayAccountLimitsPrincipal(p) || current.CredentialRevision != p.CredentialRevision {
		return service.ErrGatewayNativeIdentity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_claude_limits_snapshots(account_id,native_created_at,generation,principal_version,revision,observed_at,raw_snapshot) VALUES($1,$2,$3,$4,1,$5,$6::jsonb) ON CONFLICT(account_id) DO UPDATE SET revision=gateway_claude_limits_snapshots.revision+1,observed_at=EXCLUDED.observed_at,raw_snapshot=EXCLUDED.raw_snapshot WHERE gateway_claude_limits_snapshots.native_created_at=EXCLUDED.native_created_at AND gateway_claude_limits_snapshots.generation=EXCLUDED.generation AND gateway_claude_limits_snapshots.principal_version=EXCLUDED.principal_version AND gateway_claude_limits_snapshots.revision<9007199254740991 AND gateway_claude_limits_snapshots.observed_at<EXCLUDED.observed_at`, p.Route.AccountID, p.Route.CreatedAt, p.Route.Generation, principal, observed, string(data))
	if err != nil || tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayNativeClaudeRepository = (*gatewayClaudeRepository)(nil)

func (r *gatewayClaudeRepository) ResolveGatewayClaudeCanonical(ctx context.Context, route service.GatewayNativeRoute, account string) (service.GatewayNativeCredentialScope, string, error) {
	s := service.GatewayNativeCredentialScope{Account: account, Generation: route.Generation, Purpose: service.GatewayOAuthBundlePurpose}
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !service.GatewayNativeCredentialRefValid(account) {
		return s, "", service.ErrGatewayNativeIdentity
	}
	s.Consumer = consumer
	var op string
	err = r.db.QueryRowContext(ctx, `SELECT owner_ref,operation_ref FROM gateway_claude_connect_intents WHERE consumer=$1 AND account_ref=$2 AND generation=$3 AND account_id=$4 AND native_created_at=$5 AND state='completed'`, consumer, account, route.Generation, route.AccountID, route.CreatedAt).Scan(&s.Owner, &op)
	if err != nil {
		return s, "", service.ErrGatewayNativeIdentity
	}
	ownerCtx, err := service.WithGatewayNativeOAuthOwner(ctx, s.Owner)
	if err != nil {
		return s, "", err
	}
	_, _, release, err := r.LockGatewayClaudePhysical(ownerCtx, s, op, &route)
	if err != nil {
		return s, "", err
	}
	release()
	return s, op, nil
}

func (r *gatewayClaudeRepository) ReadGatewayClaudeRefresh(ctx context.Context, s service.GatewayNativeCredentialScope, connect, attempt string) (service.GatewayNativeOAuthRefreshOutcome, bool, error) {
	out := service.GatewayNativeOAuthRefreshOutcome{Operation: attempt}
	if !claudeAuthorized(ctx, s, connect) || !service.GatewayNativeCredentialRefValid(attempt) {
		return out, false, service.ErrGatewayNativeIdentity
	}
	var state string
	var exact bool
	err := r.db.QueryRowContext(ctx, `SELECT r.state,r.expected_revision,r.account_id=c.account_id AND r.generation=c.generation FROM gateway_claude_refresh_attempts r LEFT JOIN gateway_claude_connect_intents c ON c.consumer=$1 AND c.operation_ref=$3 AND c.owner_ref=$4 AND c.account_ref=$5 AND c.generation=$6 AND c.purpose=$7 WHERE r.consumer=$1 AND r.operation_ref=$2`, s.Consumer, attempt, connect, s.Owner, s.Account, s.Generation, s.Purpose).Scan(&state, &out.Version, &exact)
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

func (r *gatewayClaudeRepository) LockGatewayClaudeMaintenance(ctx context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthPhysical, string, string, string, func(), error) {
	tx, p, envelope, err := r.physicalTx(ctx, s, op, nil, false, true)
	if err != nil {
		return p, "", "", "", nil, err
	}
	var state, attempt string
	err = tx.QueryRowContext(ctx, `SELECT refresh_state,COALESCE(refresh_operation,'') FROM gateway_claude_connect_intents`+claudeWhere, claudeArgs(s, op)...).Scan(&state, &attempt)
	if err != nil {
		_ = tx.Rollback()
		return p, "", "", "", nil, service.ErrGatewayNativeIdentity
	}
	var once sync.Once
	return p, envelope, state, attempt, func() { once.Do(func() { _ = tx.Rollback() }) }, nil
}
