package service

import (
	"context"
	"time"
)

const GatewayNativeRetainedCustodyContract = "native-retained-custody/v1"
const GatewayNativeRetainedCustodyAPIKeyKind = "api_key"
const GatewayNativeRetainedCustodyOAuthKind = "oauth"

type GatewayNativeRetainedCustodyState struct {
	State      string `json:"state"`
	Credential string `json:"credential"`
}

// ExpiredButRefreshable is policy eligibility under the existing authenticated
// OAuth timing policy. It never asserts provider validity or performs refresh.
type GatewayNativeOAuthRetentionPolicy struct {
	ProviderValidity      string `json:"provider_validity"`
	ExpiredButRefreshable string `json:"expired_but_refreshable"`
}

type GatewayNativeRetainedCustodyProof struct {
	Authenticated bool `json:"authenticated"`
}

type GatewayNativeRetainedCustodyResult struct {
	Contract        string                             `json:"contract"`
	Generation      string                             `json:"generation"`
	Native          GatewayNativeRoute                 `json:"native"`
	CredentialKinds []string                           `json:"credential_kinds"`
	Retention       GatewayNativeRetainedCustodyState  `json:"retention"`
	Proof           GatewayNativeRetainedCustodyProof  `json:"proof"`
	OAuthPolicy     *GatewayNativeOAuthRetentionPolicy `json:"oauth_policy,omitempty"`
}

type GatewayNativeRetainedAPIKeyCustodyRepository interface {
	LockGatewayNativeRetainedAPIKeyCustody(context.Context, GatewayNativeCredentialScope, GatewayNativeRoute) (*Account, func(), error)
}

type GatewayNativeRetainedOAuthCustodyRepository interface {
	LockGatewayNativeRetainedOAuthCustody(context.Context, GatewayNativeCredentialScope, string, GatewayNativeRoute) (*Account, func(), error)
}

func retainedCustodyResult(route GatewayNativeRoute, kind, state string) GatewayNativeRetainedCustodyResult {
	return GatewayNativeRetainedCustodyResult{
		Contract:        GatewayNativeRetainedCustodyContract,
		Generation:      route.Generation,
		Native:          route,
		CredentialKinds: []string{kind},
		Retention:       GatewayNativeRetainedCustodyState{State: state, Credential: "retained"},
		Proof:           GatewayNativeRetainedCustodyProof{Authenticated: true},
	}
}

// This is the sole API-key retained-custody proof. It authenticates plaintext
// transiently inside the private custody adapter and returns no credential.
func (s *OpenAIGatewayService) ReadGatewayNativeRetainedAPIKeyCustody(ctx context.Context, scope GatewayNativeCredentialScope, route GatewayNativeRoute) (GatewayNativeRetainedCustodyResult, error) {
	var out GatewayNativeRetainedCustodyResult
	consumer, err := GatewayNativeConsumer(ctx)
	custody := gatewayNativeCustody(ctx)
	repository, ok := s.accountRepo.(GatewayNativeRetainedAPIKeyCustodyRepository)
	if err != nil || custody == nil || !ok || scope.Consumer != consumer || !scope.valid() ||
		scope.Purpose != GatewayCredentialPurpose || scope.Generation != route.Generation {
		return out, ErrGatewayNativeIdentity
	}
	a, release, err := repository.LockGatewayNativeRetainedAPIKeyCustody(ctx, scope, route)
	if err != nil || a == nil || release == nil {
		return out, ErrGatewayNativeIdentity
	}
	defer release()
	persistedScope, err := GatewayNativeCredentialScopeForAccount(a)
	persistedRoute, routeErr := GatewayNativeDescriptor(a)
	if err != nil || routeErr != nil || persistedScope != scope || !SameGatewayNativeDescriptor(route, persistedRoute) ||
		(a.Status != StatusActive && a.Status != StatusDisabled) {
		return out, ErrGatewayNativeIdentity
	}
	if err := custody.authenticateRetainedAPIKey(a.GetCredential("api_key"), persistedScope); err != nil {
		return out, err
	}
	state := "inactive"
	if a.Status == StatusActive {
		state = "active"
	}
	return retainedCustodyResult(persistedRoute, GatewayNativeRetainedCustodyAPIKeyKind, state), nil
}

func retainedOAuthPolicy(now time.Time, bundle GatewayNativeOAuthBundle, custody *GatewayNativeCredentialCustody) (GatewayNativeOAuthRetentionPolicy, error) {
	due, qualified := gatewayOAuthBundleDue(bundle, now, custody)
	policy := GatewayNativeOAuthRetentionPolicy{ProviderValidity: "unasserted"}
	switch {
	case !qualified:
		policy.ExpiredButRefreshable = "not-qualified-by-existing-policy"
	case !due:
		policy.ExpiredButRefreshable = "not-due-by-existing-policy"
	default:
		policy.ExpiredButRefreshable = "eligible-by-existing-policy"
	}
	return policy, nil
}

// OAuth readback authenticates retained bytes and applies the existing trusted
// timing policy only. It never verifies a token with the provider or refreshes.
func (s *GatewayNativeOAuthDispatch) RetainedCustody(ctx context.Context, scope GatewayNativeCredentialScope, operation string, route GatewayNativeRoute) (GatewayNativeRetainedCustodyResult, error) {
	var out GatewayNativeRetainedCustodyResult
	if s == nil || s.custody == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) ||
		!GatewayNativeCredentialRefValid(operation) || scope.Generation != route.Generation ||
		route.Profile != GatewayCodexOAuthResponsesProfile || route.BaseURL != GatewayCodexOAuthBaseURL ||
		route.Model != GatewayCodexOAuthModel {
		return out, ErrGatewayNativeIdentity
	}
	repository, ok := s.repository.(GatewayNativeRetainedOAuthCustodyRepository)
	if !ok {
		return out, ErrGatewayNativeIdentity
	}
	a, release, err := repository.LockGatewayNativeRetainedOAuthCustody(ctx, scope, operation, route)
	if err != nil || a == nil || release == nil {
		return out, ErrGatewayNativeIdentity
	}
	defer release()
	persistedScope, err := gatewayOAuthScopeForAccount(a)
	version, versionErr := gatewayOAuthCredentialVersion(a)
	if err != nil || versionErr != nil || persistedScope != scope || a.Status != StatusDisabled ||
		a.ID != route.AccountID || !a.CreatedAt.Equal(route.CreatedAt) || a.Platform != PlatformOpenAI ||
		a.Type != AccountTypeOAuth || a.Schedulable || a.ProxyID != nil || a.ParentAccountID != nil ||
		len(a.GroupIDs) != 0 || len(a.AccountGroups) != 0 || len(a.Extra) != 3 ||
		a.Extra[GatewayProfileExtraKey] != GatewayOAuthStagingProfile {
		return out, ErrGatewayNativeIdentity
	}
	policy, err := s.custody.inspectRetainedOAuth(a.GetCredential("oauth_bundle"), persistedScope, version, time.Now())
	if err != nil {
		return out, err
	}
	result := retainedCustodyResult(route, GatewayNativeRetainedCustodyOAuthKind, "inactive")
	result.OAuthPolicy = &policy
	return result, nil
}
