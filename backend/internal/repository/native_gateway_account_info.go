package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type gatewayAccountInfoRepository struct{ db *sql.DB }

func NewGatewayAccountInfoRepository(db *sql.DB) *gatewayAccountInfoRepository {
	if db == nil {
		return nil
	}
	return &gatewayAccountInfoRepository{db: db}
}

func (r *gatewayAccountInfoRepository) physicalTx(ctx context.Context, s service.GatewayNativeCredentialScope, route service.GatewayNativeRoute, exclusive bool) (*sql.Tx, service.GatewayNativeOAuthPhysical, error) {
	p := service.GatewayNativeOAuthPhysical{Scope: s, Route: route}
	if r == nil || !service.GatewayAccountInfoRouteValid(route, service.GatewayAccountLimitsInput{OwnerRef: s.Owner, AccountRef: s.Account, ProfileID: route.Profile}) || s.Generation != route.Generation {
		return nil, p, service.ErrGatewayNativeIdentity
	}
	switch route.Profile {
	case service.GatewayCodexOAuthResponsesProfile:
		source := &accountRepository{sql: r.db}
		tx, current, err := source.gatewayLimitsTransactionMode(ctx, s, route, exclusive)
		if err != nil {
			return nil, p, err
		}
		if tx.QueryRowContext(ctx, `SELECT gateway_oauth_credential_version(credentials) FROM accounts WHERE id=$1 AND created_at=$2`, route.AccountID, route.CreatedAt).Scan(&current.CredentialRevision) != nil {
			_ = tx.Rollback()
			return nil, p, service.ErrGatewayNativeIdentity
		}
		return tx, current, nil
	case service.GatewayClaudeOAuthMessagesProfile:
		source := &gatewayClaudeRepository{r.db}
		op, err := source.resolve(ctx, s, route)
		if err != nil {
			return nil, p, err
		}
		tx, current, _, err := source.physicalTxMode(ctx, s, op, &route, exclusive, true, true)
		return tx, current, err
	case service.GatewayGrokOAuthResponsesProfile:
		source := &gatewayGrokRepository{r.db}
		op, err := source.resolve(ctx, s, route)
		if err != nil {
			return nil, p, err
		}
		tx, current, _, err := source.physicalTxMode(ctx, s, op, &route, exclusive, true, true)
		return tx, current, err
	default:
		return gatewayProtectedKeyPhysicalTx(ctx, r.db, s, route, exclusive)
	}
}
func accountInfoScope(ctx context.Context, in service.GatewayAccountLimitsInput, route service.GatewayNativeRoute) (service.GatewayNativeCredentialScope, error) {
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || !in.Valid() || in.ProfileID != route.Profile {
		return service.GatewayNativeCredentialScope{}, service.ErrGatewayNativeIdentity
	}
	purpose := service.GatewayCredentialPurpose
	switch route.Profile {
	case service.GatewayCodexOAuthResponsesProfile, service.GatewayClaudeOAuthMessagesProfile, service.GatewayGrokOAuthResponsesProfile:
		purpose = service.GatewayOAuthBundlePurpose
	}
	return service.GatewayNativeCredentialScope{Consumer: consumer, Owner: in.OwnerRef, Account: in.AccountRef, Generation: route.Generation, Purpose: purpose}, nil
}
func (r *gatewayAccountInfoRepository) ReadGatewayAccountInfo(ctx context.Context, in service.GatewayAccountLimitsInput, route service.GatewayNativeRoute) (service.GatewayAccountInfoStored, error) {
	var empty service.GatewayAccountInfoStored
	scope, err := accountInfoScope(ctx, in, route)
	if err != nil {
		return empty, err
	}
	tx, current, err := r.physicalTx(ctx, scope, route, false)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	return readGatewayAccountInfoTx(ctx, tx, current)
}
func readGatewayAccountInfoTx(ctx context.Context, tx *sql.Tx, p service.GatewayNativeOAuthPhysical) (service.GatewayAccountInfoStored, error) {
	out := service.GatewayAccountInfoStored{PrincipalVersion: service.GatewayAccountInfoPrincipal(p), CredentialRevision: p.CredentialRevision, Sources: map[string]service.GatewayAccountInfoObservation{}}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT revision,sources FROM gateway_account_info_snapshots WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND principal_version=$4`, p.Route.AccountID, p.Route.CreatedAt, p.Route.Generation, out.PrincipalVersion).Scan(&out.Revision, &raw)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil || len(raw) > 32768 || json.Unmarshal(raw, &out.Sources) != nil || out.Sources == nil || out.Revision < 1 || out.Revision > 9007199254740991 || len(out.Sources) > 4 {
		return service.GatewayAccountInfoStored{}, service.ErrGatewayNativeIdentity
	}
	for key, o := range out.Sources {
		if key != o.Source || !service.GatewayAccountInfoObservationValid(p.Route.Profile, o) {
			return service.GatewayAccountInfoStored{}, service.ErrGatewayNativeIdentity
		}
	}
	return out, nil
}
func (r *gatewayAccountInfoRepository) ReserveGatewayAccountInfoOrder(ctx context.Context) (int64, error) {
	if r == nil {
		return 0, service.ErrGatewayNativeIdentity
	}
	if _, err := service.GatewayNativeConsumer(ctx); err != nil {
		return 0, service.ErrGatewayNativeIdentity
	}
	var order int64
	if r.db.QueryRowContext(ctx, `SELECT nextval('gateway_account_info_source_order')`).Scan(&order) != nil || order < 1 || order > 9007199254740991 {
		return 0, service.ErrGatewayNativeIdentity
	}
	return order, nil
}
func (r *accountRepository) ReserveGatewayAccountInfoOrder(ctx context.Context) (int64, error) {
	db, ok := r.sql.(*sql.DB)
	if !ok {
		return 0, service.ErrGatewayNativeIdentity
	}
	return NewGatewayAccountInfoRepository(db).ReserveGatewayAccountInfoOrder(ctx)
}
func (r *gatewayAccountInfoRepository) StoreGatewayAccountInfo(ctx context.Context, p service.GatewayNativeOAuthPhysical, o service.GatewayAccountInfoObservation, initialize bool) error {
	if !service.GatewayAccountInfoObservationValid(p.Route.Profile, o) || o.CredentialRevision != p.CredentialRevision || !initialize && o.Order < 1 {
		return service.ErrGatewayNativeIdentity
	}
	tx, current, err := r.physicalTx(ctx, p.Scope, p.Route, true)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if service.GatewayAccountInfoPrincipal(current) != service.GatewayAccountInfoPrincipal(p) || current.CredentialRevision != p.CredentialRevision || current.Operation != p.Operation {
		return service.ErrGatewayNativeIdentity
	}
	if err = storeGatewayAccountInfoTx(ctx, tx, current, o, initialize); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

// Caller retains the exact account lock and has checked credential revision.
// Both native quota and enrollment writers use this same transaction leaf.
func storeGatewayAccountInfoTx(ctx context.Context, tx *sql.Tx, p service.GatewayNativeOAuthPhysical, o service.GatewayAccountInfoObservation, initialize bool) error {
	if !service.GatewayAccountInfoObservationValid(p.Route.Profile, o) || o.CredentialRevision != p.CredentialRevision || !initialize && o.Order < 1 {
		return service.ErrGatewayNativeIdentity
	}
	stored, err := readGatewayAccountInfoTx(ctx, tx, p)
	if err != nil {
		return err
	}
	if initialize && len(stored.Sources) > 0 {
		return nil
	}
	if prior, ok := stored.Sources[o.Source]; ok {
		if o.Order < prior.Order {
			return nil
		}
		if o.Order == prior.Order {
			a, _ := json.Marshal(o)
			b, _ := json.Marshal(prior)
			if string(a) != string(b) {
				return service.ErrGatewayNativeIdentity
			}
			return nil
		}
	}
	if stored.Revision == 9007199254740991 {
		return service.ErrGatewayNativeIdentity
	}
	stored.Sources[o.Source] = o
	raw, err := json.Marshal(stored.Sources)
	if err != nil || len(raw) > 32768 {
		return service.ErrGatewayNativeIdentity
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO gateway_account_info_snapshots(account_id,native_created_at,generation,principal_version,revision,sources)
 VALUES($1,$2,$3,$4,1,$5::jsonb) ON CONFLICT(account_id) DO UPDATE SET revision=gateway_account_info_snapshots.revision+1,sources=EXCLUDED.sources
 WHERE gateway_account_info_snapshots.native_created_at=EXCLUDED.native_created_at AND gateway_account_info_snapshots.generation=EXCLUDED.generation
 AND gateway_account_info_snapshots.principal_version=EXCLUDED.principal_version AND gateway_account_info_snapshots.revision=$6`, p.Route.AccountID, p.Route.CreatedAt, p.Route.Generation, stored.PrincipalVersion, string(raw), stored.Revision)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return service.ErrGatewayNativeIdentity
	}
	return nil
}

var _ service.GatewayAccountInfoCache = (*gatewayAccountInfoRepository)(nil)
var _ service.GatewayAccountInfoWriter = (*gatewayAccountInfoRepository)(nil)
