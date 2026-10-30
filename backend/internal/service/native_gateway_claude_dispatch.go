package service

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

type gatewayClaudeDispatchBindingKey struct{}
type gatewayClaudeDispatchBinding struct {
	dispatch             *GatewayNativeClaudeOAuth
	scope                GatewayNativeCredentialScope
	operation            string
	requestBytes, tokens int64
}

// BindApproved resolves the durable mapping only after the private kernel's
// admission. Caller-supplied owner/operation values never choose credentials.
func (s *GatewayNativeClaudeOAuth) BindApproved(ctx context.Context, route GatewayNativeRoute, account string, authorizationEpoch, requestBytes, tokens int64) (context.Context, error) {
	if s == nil || ctx == nil || authorizationEpoch < 0 || requestBytes < 1 || requestBytes > 4<<20 || tokens < 1 || tokens > 10000000 ||
		route.Profile != GatewayClaudeOAuthMessagesProfile || route.BaseURL != GatewayClaudeOAuthBaseURL || route.Model != GatewayClaudeOAuthModel || !GatewayNativeCredentialRefValid(account) {
		return nil, ErrGatewayNativeIdentity
	}
	scope, operation, err := s.repository.ResolveGatewayClaudeCanonical(ctx, route, account)
	consumer, consumerErr := GatewayNativeConsumer(ctx)
	if err != nil || consumerErr != nil || scope.Consumer != consumer || scope.Account != account || scope.Generation != route.Generation || !GatewayNativeOAuthScopeValid(scope) || !GatewayNativeCredentialRefValid(operation) {
		return nil, ErrGatewayNativeIdentity
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, scope.Owner)
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	return context.WithValue(ctx, gatewayClaudeDispatchBindingKey{}, gatewayClaudeDispatchBinding{s, scope, operation, requestBytes, tokens}), nil
}

type gatewayClaudeRoundTripper func(*http.Request) (*http.Response, error)

func (f gatewayClaudeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (s *OpenAIGatewayService) forwardGatewayClaudeRoute(ctx context.Context, c *gin.Context, route GatewayNativeRoute, body []byte) (*OpenAIForwardResult, bool, error) {
	binding, ok := ctx.Value(gatewayClaudeDispatchBindingKey{}).(gatewayClaudeDispatchBinding)
	life := gatewayNativeLifetime(ctx)
	if s == nil || !ok || binding.dispatch == nil || c == nil || c.Request == nil || life == nil || !life.matchesScope(binding.scope) ||
		!GatewayNativeOAuthScopeAuthorized(ctx, binding.scope) || int64(len(body)) > binding.requestBytes {
		return nil, false, ErrGatewayNativeIdentity
	}
	if _, owned := s.httpUpstream.(*gatewayNativeLifetimeUpstream); !owned {
		return nil, false, ErrGatewayNativeIdentity
	}
	nativeMessages := gatewayNativeClaudeMessagesMode(ctx)
	tokenField := "max_output_tokens"
	if nativeMessages {
		tokenField = "max_tokens"
	}
	fields, ok := GatewayNativePayloadFields(body, tokenField)
	var cap int64
	if !ok || json.Unmarshal(fields[tokenField], &cap) != nil || cap < 1 || cap > binding.tokens {
		return nil, false, ErrGatewayNativeIdentity
	}
	var wire []byte
	var headers map[string]string
	var err error
	if nativeMessages {
		wire, headers, err = gatewayClaudePrepareNativeMessages(body, binding.requestBytes, binding.tokens)
	} else {
		wire, headers, err = gatewayClaudePrepareResponses(body)
	}
	if err != nil || int64(len(wire)) > binding.requestBytes {
		return nil, false, ErrGatewayNativeIdentity
	}
	entry, err := binding.dispatch.Enter(ctx, binding.scope, binding.operation, route)
	if err != nil {
		return nil, false, ErrGatewayNativeIdentity
	}
	if entry.Release == nil || entry.Claim == nil || entry.Physical.Scope != binding.scope || entry.Physical.Operation != binding.operation || !SameGatewayNativeDescriptor(entry.Physical.Route, route) {
		if entry.Release != nil {
			entry.Release()
		}
		return nil, false, ErrGatewayNativeIdentity
	}
	ctx = WithHTTPUpstreamRedirectsDisabled(ctx)
	c.Request = c.Request.Clone(ctx)
	c.Request.Header = make(http.Header)
	var entered atomic.Bool
	transport := gatewayClaudeRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != gatewayClaudeMessagesURL || request.Context().Err() != nil || !entry.Claim() || !gatewayNativeEntered(request.Context(), &entered) {
			return nil, ErrGatewayNativeReplay
		}
		// The existing owned upstream attaches the physical body to this same
		// lifetime and disables redirects. No ordinary retry/failover path runs.
		return s.httpUpstream.Do(request, "", route.AccountID, 0)
	})
	result, err := gatewayNativeClaudeResponses(ctx, c, entry, wire, headers, transport)
	if err != nil {
		if entered.Load() {
			err = ErrGatewayNativeEffectUnknown
		} else {
			err = ErrGatewayNativeIdentity
		}
	} else {
		life.success()
	}
	return result, entered.Load(), err
}
