package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type gatewayGrokDispatchBindingKey struct{}
type gatewayGrokDispatchBinding struct {
	dispatch             *GatewayNativeGrokOAuth
	scope                GatewayNativeCredentialScope
	operation            string
	requestBytes, tokens int64
}

// Trusted composition after canonical resolution and kernel admission. This
// carries no refresh/replay authority, and cannot select an arbitrary endpoint.
func WithGatewayNativeGrokDispatch(ctx context.Context, dispatch *GatewayNativeGrokOAuth, scope GatewayNativeCredentialScope, operation string, requestBytes, tokens int64) (context.Context, error) {
	if ctx == nil || dispatch == nil || requestBytes < 1 || requestBytes > 4<<20 || tokens < 1 || tokens > 10000000 || !GatewayNativeCredentialRefValid(operation) {
		return nil, ErrGatewayNativeIdentity
	}
	consumer, err := GatewayNativeConsumer(ctx)
	if err != nil || consumer != scope.Consumer {
		return nil, ErrGatewayNativeIdentity
	}
	ctx, err = WithGatewayNativeOAuthOwner(ctx, scope.Owner)
	if err != nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) {
		return nil, ErrGatewayNativeIdentity
	}
	return context.WithValue(ctx, gatewayGrokDispatchBindingKey{}, gatewayGrokDispatchBinding{dispatch, scope, operation, requestBytes, tokens}), nil
}

func (s *OpenAIGatewayService) forwardGatewayGrokRoute(ctx context.Context, c *gin.Context, route GatewayNativeRoute, body []byte) (*OpenAIForwardResult, bool, error) {
	binding, ok := ctx.Value(gatewayGrokDispatchBindingKey{}).(gatewayGrokDispatchBinding)
	life := gatewayNativeLifetime(ctx)
	if s == nil || !ok || binding.dispatch == nil || c == nil || c.Request == nil || life == nil || !life.matchesScope(binding.scope) || !GatewayNativeOAuthScopeAuthorized(ctx, binding.scope) || route.Profile != GatewayGrokOAuthResponsesProfile || route.BaseURL != GatewayGrokOAuthBaseURL || route.Model != GatewayGrokOAuthModel || route.Generation != binding.scope.Generation {
		return nil, false, ErrGatewayNativeIdentity
	}
	if _, owned := s.httpUpstream.(*gatewayNativeLifetimeUpstream); !owned {
		return nil, false, ErrGatewayNativeIdentity
	}
	wire, mapping, err := gatewayNativePrepareProviderResponses(route.Profile, body, binding.requestBytes)
	fields, valid := GatewayNativePayloadFields(body, "max_output_tokens")
	cap, capped := gatewayOAuthSeconds(fields["max_output_tokens"])
	if err != nil || !valid || !capped || cap > binding.tokens {
		return nil, false, ErrGatewayNativeIdentity
	}
	// Inert transport descriptor only. The last common HTTP seam obtains the
	// fresh physical lock and scoped custody token; no plaintext Account exists.
	a := &Account{ID: route.AccountID, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{GatewayProfileExtraKey: GatewayGrokOAuthResponsesProfile}}
	state := &gatewayNativeDispatch{route: route, account: a, scope: binding.scope}
	ctx = WithHTTPUpstreamRedirectsDisabled(context.WithValue(ctx, gatewayNativeContextKey{}, state))
	c.Request = c.Request.Clone(ctx)
	c.Request.Header = make(http.Header)
	setGrokResponsesClientToolMapping(c, mapping)
	defer clearGrokResponsesClientToolMapping(c)
	result, err := s.forwardGatewayNativeResponses(ctx, c, a, wire)
	if err != nil {
		if state.entered.Load() {
			err = ErrGatewayNativeEffectUnknown
		} else {
			err = ErrGatewayNativeIdentity
		}
	} else {
		life.success()
	}
	return result, state.entered.Load(), err
}

func (s *OpenAIGatewayService) checkGatewayGrokDispatch(request *http.Request, a *Account, state *gatewayNativeDispatch) (func(), error) {
	noop := func() {}
	binding, ok := request.Context().Value(gatewayGrokDispatchBindingKey{}).(gatewayGrokDispatchBinding)
	if !ok || binding.dispatch == nil || state.account != a || state.scope != binding.scope || request.Method != http.MethodPost || request.URL.String() != GatewayGrokOAuthBaseURL+"/v1/responses" || request.Header.Get("Authorization") != "" || request.Context().Err() != nil {
		return noop, ErrGatewayNativeIdentity
	}
	entry, err := binding.dispatch.Enter(request.Context(), binding.scope, binding.operation, state.route)
	if err != nil {
		return noop, ErrGatewayNativeIdentity
	}
	deny := func() (func(), error) {
		if entry.Release != nil {
			entry.Release()
		}
		return noop, ErrGatewayNativeIdentity
	}
	if entry.Release == nil || entry.Claim == nil || entry.AccessToken == "" || strings.ContainsAny(entry.AccessToken, "\r\n") || entry.Physical.Scope != binding.scope || entry.Physical.Operation != binding.operation || !SameGatewayNativeDescriptor(entry.Physical.Route, state.route) {
		return deny()
	}
	if !entry.Claim() || !gatewayNativeEntered(request.Context(), &state.entered) {
		entry.Release()
		return noop, ErrGatewayNativeReplay
	}
	state.oauth = &entry.Physical
	request.Header = make(http.Header)
	request.Header.Set("Authorization", "Bearer "+entry.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Accept-Encoding", "identity")
	// Pin source identity directly. No environment, inbound UA, admin header or
	// ordinary account router can mutate this qualified subscription tuple.
	request.Header.Set("X-XAI-Token-Auth", xai.CLITokenAuth)
	request.Header.Set("x-grok-client-identifier", xai.ProtectedClientIdentifier)
	request.Header.Set("x-authenticateresponse", "authenticate-response")
	request.Header.Set("User-Agent", xai.ProtectedUserAgent)
	request.GetBody = nil
	return entry.Release, nil
}

// Reuse the source billing-ping classifier, in the finite reader's goroutine.
// No producer pipe, background reader or extra unbounded queue is introduced.
func gatewayNativeGrokPingFrame(frame []byte) bool {
	lines := bytes.SplitAfter(frame, []byte{'\n'})
	if len(lines) == 0 || string(trimSSELineEnding(lines[0])) != "event: ping" {
		return false
	}
	raw := [][]byte{lines[0]}
	for _, line := range lines[1:] {
		if len(trimSSELineEnding(line)) == 0 {
			continue
		}
		if !canExtendGrokResponsesPingFrame(line) {
			return false
		}
		raw = append(raw, line)
	}
	return isGrokResponsesPingEventFrame(raw)
}

// A custom-call delta can expand to several Responses events. Keep the same
// bounded frame budget and retain non-event fields once, never provider data.
func gatewayNativeGrokRestoredFrames(original []byte, payloads [][]byte) ([]byte, error) {
	var output bytes.Buffer
	for i, payload := range payloads {
		if !json.Valid(payload) {
			return nil, ErrGatewayNativeIdentity
		}
		if i == 0 {
			for _, line := range bytes.SplitAfter(original, []byte{'\n'}) {
				value := trimSSELineEnding(line)
				if len(value) == 0 || bytes.HasPrefix(value, []byte("data:")) || bytes.Equal(value, []byte("data")) || bytes.HasPrefix(value, []byte("event:")) || bytes.Equal(value, []byte("event")) {
					continue
				}
				output.Write(value)
				output.WriteByte('\n')
			}
		}
		kind := gjson.GetBytes(payload, "type").String()
		if kind == "" || strings.ContainsAny(kind, "\r\n") {
			return nil, ErrGatewayNativeIdentity
		}
		output.WriteString("event: ")
		output.WriteString(kind)
		output.WriteByte('\n')
		output.WriteString("data: ")
		output.Write(payload)
		output.WriteString("\n\n")
		if output.Len() > gatewayNativeSSEFrameLimit {
			return nil, ErrGatewayNativeIdentity
		}
	}
	return output.Bytes(), nil
}

type gatewayProviderLimitsWriterKey struct{}

// Private host wiring only. Saved limits reads remain cache-only; this writer
// observes the one already admitted inference response without another call.
func WithGatewayProviderLimitsWriter(ctx context.Context, writer GatewayAccountLimitsRepositoryV2) context.Context {
	if writer == nil {
		return ctx
	}
	return context.WithValue(ctx, gatewayProviderLimitsWriterKey{}, writer)
}

func captureGatewayGrokPassiveLimits(ctx context.Context, headers http.Header) {
	writer, ok := ctx.Value(gatewayProviderLimitsWriterKey{}).(GatewayAccountLimitsRepositoryV2)
	state, _ := ctx.Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	if !ok || state == nil || state.oauth == nil || state.route.Profile != GatewayGrokOAuthResponsesProfile || !state.entered.Load() || state.oauth.Scope != state.scope || !SameGatewayNativeDescriptor(state.route, state.oauth.Route) {
		return
	}
	observed := time.Now().UTC()
	snapshot := CaptureGatewayGrokRateLimits(headers, observed)
	if len(snapshot.Windows) == 0 {
		return
	}
	// Publication reacquires the native physical/revision fence after the HTTP
	// entry lock was released. An erase/refresh race cannot publish stale data.
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = writer.StoreGatewayAccountLimitsV2(bounded, *state.oauth, snapshot, observed)
}
