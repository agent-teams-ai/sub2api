package service

import (
	"context"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

type scopedAccountOperationKey struct{}

// WithScopedAdminAccountOperation 仅供已完成动作验权的处理器传递同一操作的后续查询。
// 例如重置后的额度刷新仍属于重置操作，不要求额外授予读取权限。
func WithScopedAdminAccountOperation(ctx context.Context, action string) context.Context {
	return context.WithValue(ctx, scopedAccountOperationKey{}, action)
}
func scopedAccountOperation(ctx context.Context, fallback string) string {
	if action, ok := ctx.Value(scopedAccountOperationKey{}).(string); ok && action != "" {
		return action
	}
	return fallback
}

// CheckScopedAccountAccess is the shared, side-effect-free policy check for
// service and admin HTTP callers. Reader is deliberately a callback so the
// handler can use AdminService.GetAccount (which rejects native identities)
// while services may use their repository. Both paths enforce native identity
// exclusion before any account or parent credentials can be consulted.
func CheckScopedAccountAccess(ctx context.Context, a *Account, load func(context.Context, int64) (*Account, error), action string, parent bool) error {
	p := adminaccess.RestrictedFromContext(ctx)
	if p == nil {
		return nil
	}
	denied := func() error { return infraerrors.NotFound("SCOPED_ACCOUNT_NOT_FOUND", "账户不存在") }
	if a == nil || HasGatewayNativeIdentity(a) || !p.Policy.AllowsAccount(action, scopedAccountResource(a)) {
		return denied()
	}
	if parent && a.IsShadow() {
		if load == nil || a.ParentAccountID == nil || *a.ParentAccountID == a.ID {
			return denied()
		}
		source, err := load(ctx, *a.ParentAccountID)
		if err != nil {
			if errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrGatewayNativeIdentity) {
				return denied()
			}
			return err
		}
		if source == nil || HasGatewayNativeIdentity(source) || source.IsShadow() || !p.Policy.AllowsAccount(action, scopedAccountResource(source)) {
			return denied()
		}
	}
	return nil
}

func scopedAccountAccess(ctx context.Context, repo AccountRepository, a *Account, action string, parent bool) error {
	var load func(context.Context, int64) (*Account, error)
	if repo != nil {
		load = repo.GetByID
	}
	return CheckScopedAccountAccess(ctx, a, load, action, parent)
}
func scopedAccountIDAccess(ctx context.Context, repo AccountRepository, id int64, action string, parent bool) error {
	if adminaccess.RestrictedFromContext(ctx) == nil {
		return nil
	}
	if repo == nil {
		return infraerrors.NotFound("SCOPED_ACCOUNT_NOT_FOUND", "账户不存在")
	}
	a, err := repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return infraerrors.NotFound("SCOPED_ACCOUNT_NOT_FOUND", "账户不存在")
		}
		return err
	}
	return scopedAccountAccess(ctx, repo, a, action, parent)
}
