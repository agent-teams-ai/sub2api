//go:build linux

package gatewaybootstrap

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"net"
	"net/http"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// The fixed authenticated callback resolves the original committed TS relation.
// Selectors carry no owner authority, including before physical creation.
type NativeOAuthOwnerAuthority interface {
	AuthorizeNativeOAuthOwner(ctx context.Context, consumer, operation, account, generation string) (string, error)
	AuthorizeNativeOAuthRefreshOwner(ctx context.Context, consumer, operation, account, generation string) (string, error)
}
type nativeOAuthOwnerTuple struct {
	Operation  string `json:"operation"`
	OwnerRef   string `json:"owner_ref"`
	AccountRef string `json:"account_ref"`
	Generation string `json:"generation"`
}

func (t nativeOAuthOwnerTuple) valid() bool {
	return service.GatewayNativeCredentialRefValid(t.Operation) && service.GatewayNativeCredentialRefValid(t.OwnerRef) &&
		service.GatewayNativeCredentialRefValid(t.AccountRef) && incarnation.MatchString(t.Generation)
}

type NativeOAuthCleanupAuthority interface {
	AuthorizeNativeOAuthCleanup(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error)
}

type privateOAuth struct {
	connect  *service.GatewayNativeOAuthConnect
	dispatch *service.GatewayNativeOAuthDispatch
	owners   NativeOAuthOwnerAuthority
	refresh  *service.GatewayNativeOAuthRefresh
	cleanup  service.GatewayNativeOAuthCleanupAuthorizer
	limits   *service.GatewayAccountLimitsReader
	models   *service.GatewayAccountModelsReader
	claude   *service.GatewayNativeClaudeOAuth
	grok     *service.GatewayNativeGrokOAuth
	limitsV2 *service.GatewayAccountLimitsReaderV2
}

func composePrivateOAuth(repo service.AccountRepository, db *sql.DB, custody *service.GatewayNativeCredentialCustody, cfg *OAuthConfig, owners NativeOAuthOwnerAuthority) (*privateOAuth, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(cfg.IntentKey)
	if err != nil || len(key) != 32 {
		return nil, ErrDenied
	}
	f1, ok := repo.(service.GatewayNativeOAuthRepository)
	if !ok {
		return nil, ErrDenied
	}
	f4, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	if !ok {
		return nil, ErrDenied
	}
	providerTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 2, DisableKeepAlives: true}
	verifier := service.NewGatewayNativeOAuthVerifier(providerTransport)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, f1, key)
	if err != nil {
		return nil, ErrDenied
	}
	journal, err := repository.NewGatewayNativeOAuthConnectRepository(db)
	if err != nil {
		return nil, ErrDenied
	}
	connect, err := service.NewGatewayNativeOAuthConnect(key, providerTransport, journal, enrollment, f1)
	if err != nil {
		return nil, ErrDenied
	}
	versions := service.NewGatewayCodexVersionResolver(nil)
	service.SetCodexCanonicalUserAgentResolver(versions.CanonicalUserAgent)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(f4, custody, verifier, nil, versions)
	if err != nil {
		return nil, ErrDenied
	}
	f2, ok := repo.(service.GatewayNativeOAuthRefreshRepository)
	if !ok {
		return nil, ErrDenied
	}
	if _, ok := repo.(service.GatewayNativeOAuthRefreshResolver); !ok {
		return nil, ErrDenied
	}
	refresh, err := service.NewGatewayNativeOAuthRefresh(f2, custody, verifier, providerTransport)
	if err != nil {
		return nil, ErrDenied
	}
	cleanup, ok := owners.(NativeOAuthCleanupAuthority)
	if !ok || owners == nil {
		return nil, ErrDenied
	}
	connectCheck := func(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) error {
		owner, err := owners.AuthorizeNativeOAuthOwner(ctx, scope.Consumer, operation, scope.Account, scope.Generation)
		if err != nil || ctx.Err() != nil || owner != scope.Owner {
			return ErrDenied
		}
		return nil
	}
	refreshCheck := func(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) error {
		owner, err := owners.AuthorizeNativeOAuthRefreshOwner(ctx, scope.Consumer, operation, scope.Account, scope.Generation)
		if err != nil || ctx.Err() != nil || owner != scope.Owner {
			return ErrDenied
		}
		return nil
	}
	if connect.SetEntryAuthorizer(connectCheck) != nil || refresh.SetEntryAuthorizer(refreshCheck) != nil {
		return nil, ErrDenied
	}
	var limits *service.GatewayAccountLimitsReader
	if authority, ok := owners.(NativeAccountLimitsAuthority); ok {
		source, ok := repo.(service.GatewayAccountLimitsRepository)
		if !ok {
			return nil, ErrDenied
		}
		limits, err = service.NewGatewayAccountLimitsReader(source, func(ctx context.Context, in service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
			consumer, e := service.GatewayNativeConsumer(ctx)
			if e != nil {
				return service.GatewayNativeRoute{}, ErrDenied
			}
			return authority.AuthorizeNativeAccountLimits(ctx, consumer, in)
		})
		if err != nil {
			return nil, ErrDenied
		}
	}
	out := &privateOAuth{connect: connect, dispatch: dispatch, owners: owners, refresh: refresh, cleanup: cleanup.AuthorizeNativeOAuthCleanup, limits: limits}
	return out, nil
}

// privateGatewayServiceConfig keeps provider I/O bounded by the saved request
// context deadline. Non-streaming Responses may spend longer than five seconds
// generating before sending headers; do not impose a shorter header deadline.
func privateGatewayServiceConfig() *config.Config {
	return &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}}
}

func claudeControlPath(path string) bool {
	switch path {
	case "/private/native/v1/claude/oauth/connect", "/private/native/v1/claude/oauth/connect/read", "/private/native/v1/claude/oauth/connect/complete", "/private/native/v1/claude/oauth/connect/descriptor", "/private/native/v1/claude/oauth/connect/custody", "/private/native/v1/claude/oauth/refresh":
		return true
	}
	return false
}
func composePrivateClaude(out *privateOAuth, repo service.AccountRepository, db *sql.DB, custody *service.GatewayNativeCredentialCustody, owners NativeOAuthOwnerAuthority) error {
	cleanup, ok := owners.(NativeOAuthCleanupAuthority)
	if !ok || out == nil || owners == nil {
		return ErrDenied
	}
	out.cleanup = cleanup.AuthorizeNativeOAuthCleanup
	source, err := repository.NewGatewayNativeClaudeRepository(db)
	if err != nil {
		return ErrDenied
	}
	out.claude, err = service.NewGatewayNativeClaudeOAuth(source, custody, nil)
	if err != nil {
		return ErrDenied
	}
	check := func(refresh bool) service.GatewayNativeOAuthEntryAuthorizer {
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
	if out.claude.SetEntryAuthorizers(check(false), check(true)) != nil {
		return ErrDenied
	}
	if out.limits == nil {
		if authority, ok := owners.(NativeAccountLimitsAuthority); ok {
			cache, ok := repo.(service.GatewayAccountLimitsCache)
			if !ok {
				return ErrDenied
			}
			out.limits, err = service.NewGatewayAccountLimitsReader(cache, func(ctx context.Context, in service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
				consumer, e := service.GatewayNativeConsumer(ctx)
				if e != nil {
					return service.GatewayNativeRoute{}, ErrDenied
				}
				return authority.AuthorizeNativeAccountLimits(ctx, consumer, in)
			})
			if err != nil {
				return ErrDenied
			}
		}
	}
	return nil
}

// The same logical owner+epoch authority fences metadata reads across providers.
// Profiles without a supported catalogue retain the explicit unsupported union.
func composePrivateModels(out *privateOAuth, owners NativeOAuthOwnerAuthority, gateway *service.OpenAIGatewayService) error {
	if out == nil {
		return ErrDenied
	}
	authority, ok := owners.(NativeAccountLimitsAuthority)
	if !ok {
		return nil
	}
	var err error
	out.models, err = service.NewGatewayAccountModelsReader(out.dispatch, gateway, func(ctx context.Context, in service.GatewayAccountLimitsInput) (service.GatewayNativeRoute, error) {
		consumer, e := service.GatewayNativeConsumer(ctx)
		if e != nil {
			return service.GatewayNativeRoute{}, ErrDenied
		}
		return authority.AuthorizeNativeAccountLimits(ctx, consumer, in)
	})
	return err
}
