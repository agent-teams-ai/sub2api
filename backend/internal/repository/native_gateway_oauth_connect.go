package repository

import (
	"context"
	"database/sql"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type gatewayOAuthConnectRepository struct{ db *sql.DB }

// Separate opt-in repository; stock constructors/Wire and F2 are unchanged.
func NewGatewayNativeOAuthConnectRepository(db *sql.DB) (service.GatewayNativeOAuthConnectRepository, error) {
	if db == nil {
		return nil, service.ErrGatewayNativeIdentity
	}
	return &gatewayOAuthConnectRepository{db: db}, nil
}

const connectColumns = `consumer,owner_ref,account_ref,generation,purpose,operation_ref,client_id,redirect_uri,deadline,state_hash,material_envelope,state,
 COALESCE(outcome_operation,''),COALESCE(outcome_account_id,0),COALESCE(outcome_generation,''),COALESCE(outcome_state,'')`

func scanConnect(row *sql.Row) (service.GatewayNativeOAuthConnectIntent, error) {
	var in service.GatewayNativeOAuthConnectIntent
	err := row.Scan(&in.Scope.Consumer, &in.Scope.Owner, &in.Scope.Account, &in.Scope.Generation, &in.Scope.Purpose,
		&in.Operation, &in.ClientID, &in.Redirect, &in.Deadline, &in.StateHash, &in.Envelope, &in.State,
		&in.Outcome.Operation, &in.Outcome.AccountID, &in.Outcome.Generation, &in.Outcome.State)
	if err != nil || !service.GatewayNativeOAuthConnectIntentValid(in) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return in, nil
}

func connectAuthorized(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) bool {
	return service.GatewayNativeOAuthConnectIntentValid(in) && service.GatewayNativeOAuthScopeAuthorized(ctx, in.Scope)
}

func (r *gatewayOAuthConnectRepository) PrepareConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) (service.GatewayNativeOAuthConnectIntent, error) {
	if !connectAuthorized(ctx, in) || in.State != "prepared" || len(in.Envelope) < 60 || len(in.Envelope) > 1024 || !strings.HasPrefix(in.Envelope, "gcc1.") {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	// ON CONFLICT never updates the accepted scope, capability, birth or TTL.
	_, err := r.db.ExecContext(ctx, `INSERT INTO gateway_oauth_connect_intents
 (consumer,owner_ref,account_ref,generation,purpose,operation_ref,client_id,redirect_uri,deadline,state_hash,material_envelope)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (consumer,operation_ref) DO NOTHING`,
		in.Scope.Consumer, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, in.Scope.Purpose, in.Operation, in.ClientID, in.Redirect, in.Deadline, in.StateHash, in.Envelope)
	if err != nil {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	saved, err := scanConnect(r.db.QueryRowContext(ctx, `SELECT `+connectColumns+` FROM gateway_oauth_connect_intents WHERE consumer=$1 AND operation_ref=$2`, in.Scope.Consumer, in.Operation))
	if err != nil {
		return saved, err
	}
	if !service.SameGatewayNativeOAuthConnectIntent(in, saved) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayOAuthConflict
	}
	return saved, nil
}

func (r *gatewayOAuthConnectRepository) ReadConnectIntent(ctx context.Context, s service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthConnectIntent, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || !service.GatewayNativeCredentialRefValid(operation) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return scanConnect(r.db.QueryRowContext(ctx, `SELECT `+connectColumns+` FROM gateway_oauth_connect_intents
 WHERE consumer=$1 AND operation_ref=$2 AND owner_ref=$3 AND account_ref=$4 AND generation=$5 AND purpose=$6`, s.Consumer, operation, s.Owner, s.Account, s.Generation, s.Purpose))
}

func (r *gatewayOAuthConnectRepository) FindConnectState(ctx context.Context, hash string) (service.GatewayNativeOAuthConnectIntent, error) {
	if len(hash) != 64 {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return scanConnect(r.db.QueryRowContext(ctx, `SELECT `+connectColumns+` FROM gateway_oauth_connect_intents WHERE state_hash=$1`, hash))
}

func (r *gatewayOAuthConnectRepository) EnterConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) (bool, error) {
	if !connectAuthorized(ctx, in) {
		return false, service.ErrGatewayNativeIdentity
	}
	result, err := r.db.ExecContext(ctx, `UPDATE gateway_oauth_connect_intents SET state='entered',entered_at=clock_timestamp()
 WHERE consumer=$1 AND operation_ref=$2 AND owner_ref=$3 AND account_ref=$4 AND generation=$5 AND purpose=$6
 AND state_hash=$7 AND deadline=$8 AND state='prepared' AND deadline>clock_timestamp()`,
		in.Scope.Consumer, in.Operation, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, in.Scope.Purpose, in.StateHash, in.Deadline)
	if err != nil {
		return false, service.ErrGatewayNativeIdentity
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, service.ErrGatewayNativeIdentity
	}
	return n == 1, nil
}

func (r *gatewayOAuthConnectRepository) FinishConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent, state string, out service.GatewayNativeOAuthOutcome) (service.GatewayNativeOAuthConnectIntent, error) {
	if !connectAuthorized(ctx, in) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	var operation, generation, outcome any
	var id any
	allowed := "state IN ('entered','unknown')"
	switch state {
	case "completed":
		if out.Operation != in.Operation || out.Generation != in.Scope.Generation || out.AccountID <= 0 || out.State != "staged" {
			return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
		}
		operation, id, generation, outcome = out.Operation, out.AccountID, out.Generation, out.State
	case "unknown":
		if out != (service.GatewayNativeOAuthOutcome{}) {
			return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
		}
	case "expired":
		if out != (service.GatewayNativeOAuthOutcome{}) {
			return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
		}
		allowed = "state='prepared' AND deadline<=clock_timestamp()"
	default:
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	_, err := r.db.ExecContext(ctx, `UPDATE gateway_oauth_connect_intents SET state=$9,material_envelope='',
 outcome_operation=$10,outcome_account_id=$11,outcome_generation=$12,outcome_state=$13
 WHERE consumer=$1 AND operation_ref=$2 AND owner_ref=$3 AND account_ref=$4 AND generation=$5 AND purpose=$6
 AND state_hash=$7 AND deadline=$8 AND (`+allowed+`)`, in.Scope.Consumer, in.Operation, in.Scope.Owner, in.Scope.Account, in.Scope.Generation, in.Scope.Purpose,
		in.StateHash, in.Deadline, state, operation, id, generation, outcome)
	if err != nil {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	// Lost/duplicate final ACK reads the immutable ORIGINAL completed result.
	return r.ReadConnectIntent(ctx, in.Scope, in.Operation)
}

var _ service.GatewayNativeOAuthConnectRepository = (*gatewayOAuthConnectRepository)(nil)
