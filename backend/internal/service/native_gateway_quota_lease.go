package service

import "context"

// Quota collection is a separate read-only capability. It does not enter the
// inference transport, refresh OAuth, or expose a general secret-read method.
func (s *OpenAIGatewayService) WithGatewayNativeQuotaCredential(ctx context.Context, scope GatewayNativeCredentialScope, route GatewayNativeRoute, custody *GatewayNativeCredentialCustody, collect func([]byte, GatewayNativeOAuthPhysical) error) error {
	consumer, e := GatewayNativeConsumer(ctx)
	if e != nil || consumer != scope.Consumer || collect == nil || !GatewayNativeCodingPlanProfileIDValid(route.Profile) || !GatewayNativeCredentialCustodyReady(custody) {
		return ErrGatewayNativeIdentity
	}
	locker, ok := s.accountRepo.(GatewayNativeAccountLocker)
	if !ok {
		return ErrGatewayNativeIdentity
	}
	account, release, err := locker.LockGatewayNativeAccount(ctx, route.AccountID)
	if err != nil || release == nil {
		return ErrGatewayNativeIdentity
	}
	defer release()
	descriptor, err := GatewayNativeDescriptor(account)
	actual, scopeErr := GatewayNativeCredentialScopeForAccount(account)
	if err != nil || scopeErr != nil || actual != scope || !SameGatewayNativeDescriptor(descriptor, route) || validateGatewayNativeRoute(route, account) != nil {
		return ErrGatewayNativeIdentity
	}
	id, nonce, sealed, err := gatewayNativeParseEnvelope(account.GetCredential("api_key"))
	if err != nil || custody.keys[id] == nil {
		return ErrGatewayNativeIdentity
	}
	plain, err := custody.keys[id].Open(nil, nonce, sealed, gatewayCredentialAAD(scope, id))
	if err != nil {
		return ErrGatewayNativeIdentity
	}
	defer clear(plain)
	if !GatewayNativeIngressKeyValid(string(plain)) {
		return ErrGatewayNativeIdentity
	}
	return collect(plain, GatewayNativeOAuthPhysical{Scope: scope, Route: route})
}
