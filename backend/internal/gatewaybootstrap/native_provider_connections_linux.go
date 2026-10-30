//go:build linux

package gatewaybootstrap

import (
	"context"
	"database/sql"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func grokControlPath(path string) bool {
	return strings.HasPrefix(path, "/private/native/v1/grok/oauth/") && claudeControlPath(strings.Replace(path, "/grok/oauth/", "/claude/oauth/", 1))
}
func composePrivateGrok(out *privateOAuth, db *sql.DB, custody *service.GatewayNativeCredentialCustody, cfg *GrokConfig, owners NativeOAuthOwnerAuthority) error {
	cleanup, ok := owners.(NativeOAuthCleanupAuthority)
	if !ok || out == nil || cfg == nil {
		return ErrDenied
	}
	source, err := repository.NewGatewayNativeGrokRepository(db)
	if err != nil {
		return ErrDenied
	}
	out.grok, err = service.NewGatewayNativeGrokOAuth(source, custody, nil, service.GatewayNativeGrokOAuthQualification{ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, DeploymentQualified: cfg.DeploymentQualified})
	if err != nil {
		return ErrDenied
	}
	out.cleanup = cleanup.AuthorizeNativeOAuthCleanup
	authorize := func(refresh bool) service.GatewayNativeOAuthEntryAuthorizer {
		return func(ctx context.Context, scope service.GatewayNativeCredentialScope, op string) error {
			var owner string
			var e error
			if refresh {
				owner, e = owners.AuthorizeNativeOAuthRefreshOwner(ctx, scope.Consumer, op, scope.Account, scope.Generation)
			} else {
				owner, e = owners.AuthorizeNativeOAuthOwner(ctx, scope.Consumer, op, scope.Account, scope.Generation)
			}
			if e != nil || ctx.Err() != nil || owner != scope.Owner {
				return ErrDenied
			}
			return nil
		}
	}
	return out.grok.SetEntryAuthorizers(authorize(false), authorize(true))
}
func composePrivateLimitsV2(out *privateOAuth, db *sql.DB, owners NativeOAuthOwnerAuthority) error {
	authority, ok := owners.(NativeAccountLimitsAuthority)
	if !ok || out == nil {
		return ErrDenied
	}
	source := repository.NewGatewayAccountLimitsRepositoryV2(db)
	var err error
	out.limitsV2, err = service.NewGatewayAccountLimitsReaderV2(source, func(ctx context.Context, in service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		consumer, e := service.GatewayNativeConsumer(ctx)
		if e != nil {
			return service.GatewayNativeRoute{}, ErrDenied
		}
		return authority.AuthorizeNativeAccountLimits(ctx, consumer, in)
	})
	return err
}
