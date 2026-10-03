package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *accountRepository) LockGatewayNativeAccount(ctx context.Context, id int64) (*service.Account, func(), error) {
	db, ok := r.sql.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, nil, err
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback() }) }
	a := &service.Account{}
	var credentials, extra []byte
	var grouped bool
	err = tx.QueryRowContext(ctx, `SELECT id, created_at, platform, type, status,
 schedulable, proxy_id, parent_account_id, expires_at, credentials, extra,
 EXISTS(SELECT 1 FROM account_groups g WHERE g.account_id = accounts.id)
 FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR SHARE`, id).Scan(
		&a.ID, &a.CreatedAt, &a.Platform, &a.Type, &a.Status, &a.Schedulable,
		&a.ProxyID, &a.ParentAccountID, &a.ExpiresAt, &credentials, &extra, &grouped)
	if err == nil {
		err = json.Unmarshal(credentials, &a.Credentials)
	}
	if err == nil {
		err = json.Unmarshal(extra, &a.Extra)
	}
	if err != nil || grouped {
		release()
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	return a, release, nil
}

// Exact-owner cleanup survives lost acknowledgement: the retained descriptor
// still matches after erasure. It never replaces credentials or revives a row.
func (r *accountRepository) EraseGatewayNativeAccount(ctx context.Context, route service.GatewayNativeRoute) error {
	result, err := r.sql.ExecContext(ctx, `UPDATE accounts
 SET credentials = credentials - 'api_key', deleted_at = COALESCE(deleted_at, NOW()), updated_at = NOW()
 WHERE id = $1 AND created_at = $2 AND extra ->> 'gateway_generation_v1' = $3
 AND extra ->> 'gateway_profile_v1' = $4 AND credentials ->> 'base_url' = $5
 AND extra ->> 'gateway_model_v1' = $6 AND status = 'disabled' AND schedulable = false
 AND NOT EXISTS (SELECT 1 FROM account_groups g WHERE g.account_id = accounts.id)`,
		route.AccountID, route.CreatedAt, route.Generation, route.Profile, route.BaseURL, route.Model)
	if err != nil {
		return service.ErrGatewayNativeIdentity
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return service.ErrGatewayNativeIdentity
	}
	r.deleteSchedulerAccountSnapshot(ctx, route.AccountID)
	return nil
}
