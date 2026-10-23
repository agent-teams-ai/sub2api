package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
)

// Only composition supplies a previously qualified public client and exact
// redirect policy. There is deliberately no implicit native CLI client fallback.
type GatewayNativeGrokOAuthQualification struct {
	ClientID            string
	RedirectURI         string
	DeploymentQualified bool
}

func (q GatewayNativeGrokOAuthQualification) valid() bool {
	if !q.DeploymentQualified || !grokPrincipal(q.ClientID) || len(q.RedirectURI) > 2048 || strings.Contains(q.RedirectURI, "#") {
		return false
	}
	u, err := url.Parse(q.RedirectURI)
	return err == nil && u.User == nil && u.Opaque == "" && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" && u.Path != "" && (u.Scheme == "https" && u.Hostname() != "" || q.RedirectURI == xai.DefaultRedirectURI)
}
func grokPrincipal(v string) bool { return xai.ProtectedPrincipalPart(v) }
func (s *GatewayNativeGrokOAuth) connectSecretValid(v gatewayGrokConnectSecret) bool {
	return v.Kind == "grok-connect/v1" && len(v.State) == 64 && len(v.Verifier) == 43 && len(v.Nonce) == 43 && v.ClientID == s.qualification.ClientID && v.RedirectURI == s.qualification.RedirectURI
}
func (s *GatewayNativeGrokOAuth) exchange(ctx context.Context, form url.Values, nonce string, previous *gatewayGrokBundle) (gatewayGrokBundle, error) {
	var empty gatewayGrokBundle
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, xai.DefaultTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", xai.ProtectedUserAgent)
	started := time.Now().UTC()
	res, err := s.client.Do(req)
	if err != nil || res == nil || res.Body == nil {
		return empty, ErrGatewayNativeIdentity
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 || res.StatusCode != http.StatusOK || res.Request == nil || res.Request.URL.String() != xai.DefaultTokenURL {
		return empty, ErrGatewayNativeIdentity
	}
	if _, err = gatewayOAuthJSON(raw); err != nil {
		return empty, ErrGatewayNativeIdentity
	}
	var token struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
		Type    string `json:"token_type"`
		Expiry  int64  `json:"expires_in"`
		Scope   string `json:"scope"`
	}
	if json.Unmarshal(raw, &token) != nil || !grokToken(token.Access) || !strings.EqualFold(token.Type, "bearer") || token.Expiry <= 0 || token.Expiry > 90*24*60*60 {
		return empty, ErrGatewayNativeIdentity
	}
	if previous != nil && token.Refresh == "" {
		token.Refresh = previous.RefreshToken
	}
	if !grokToken(token.Refresh) {
		return empty, ErrGatewayNativeIdentity
	}
	if token.Scope != "" {
		found := false
		for _, v := range strings.Fields(token.Scope) {
			if v == "grok-cli:access" {
				found = true
			}
		}
		if !found {
			return empty, ErrGatewayNativeIdentity
		}
	}
	b := gatewayGrokBundle{Kind: "grok-oauth/v1", Revision: 1, AccessToken: token.Access, RefreshToken: token.Refresh, ExpiresAt: started.Add(time.Duration(token.Expiry) * time.Second), Nonce: nonce, ClientID: s.qualification.ClientID}
	if previous != nil {
		b.Revision = previous.Revision + 1
		b.Nonce = previous.Nonce
	}
	if token.ID == "" && previous != nil {
		// OIDC refresh may omit id_token. Only previously verified identity survives;
		// authenticated userinfo must still confirm subject and team continuity.
		var user struct {
			Subject string `json:"sub"`
			Team    string `json:"team_id"`
		}
		if xai.FetchProtectedJSON(ctx, s.client, xai.ProtectedUserinfoURL, token.Access, &user) != nil || user.Subject != previous.Subject {
			return empty, ErrGatewayNativeIdentity
		}
		expected := "personal:" + user.Subject
		if user.Team != "" {
			if !grokPrincipal(user.Team) {
				return empty, ErrGatewayNativeIdentity
			}
			expected = "team:" + user.Team
		}
		if expected != previous.Team {
			return empty, ErrGatewayNativeIdentity
		}
		b.Subject, b.Team = previous.Subject, previous.Team
	} else {
		principal, e := xai.VerifyProtectedPrincipal(ctx, s.client, token.ID, token.Access, s.qualification.ClientID, b.Nonce, previous == nil)
		if e != nil {
			return empty, ErrGatewayNativeIdentity
		}
		b.Subject, b.Team = principal.Subject, principal.Account
	}
	if previous != nil && (b.Subject != previous.Subject || b.Team != previous.Team) {
		return empty, ErrGatewayNativeIdentity
	}
	return b, nil
}

func (s *GatewayNativeGrokOAuth) ResolveApproved(ctx context.Context, route GatewayNativeRoute, account string) (GatewayNativeCredentialScope, string, error) {
	if s == nil || route.Profile != GatewayGrokOAuthResponsesProfile || route.BaseURL != GatewayGrokOAuthBaseURL || route.Model != GatewayGrokOAuthModel {
		return GatewayNativeCredentialScope{}, "", ErrGatewayNativeIdentity
	}
	return s.repository.ResolveGatewayGrokCanonical(ctx, route, account)
}

// WithQuotaCredential is a read-only background lease. It neither claims an
// inference entry nor refreshes tokens. Exact birth/generation/principal locks
// remain held for the bounded collector callback.
func (s *GatewayNativeGrokOAuth) WithQuotaCredential(ctx context.Context, scope GatewayNativeCredentialScope, route GatewayNativeRoute, fn func([]byte, GatewayNativeOAuthPhysical) error) error {
	if s == nil || fn == nil || !GatewayNativeOAuthScopeAuthorized(ctx, scope) {
		return ErrGatewayNativeIdentity
	}
	resolved, op, err := s.repository.ResolveGatewayGrokCanonical(ctx, route, scope.Account)
	if err != nil || resolved != scope {
		return ErrGatewayNativeIdentity
	}
	physical, envelope, release, err := s.repository.LockGatewayGrokPhysical(ctx, scope, op, &route)
	if err != nil {
		return err
	}
	if release == nil || !grokPhysicalValid(physical, scope, op, &route) {
		if release != nil {
			release()
		}
		return ErrGatewayNativeIdentity
	}
	defer release()
	b, err := s.bundle(scope, envelope, physical)
	if err != nil || !time.Now().Before(b.ExpiresAt) {
		return ErrGatewayNativeIdentity
	}
	token := []byte(b.AccessToken)
	defer clear(token)
	return fn(token, physical)
}

func GatewayNativeGrokQualificationValid(q GatewayNativeGrokOAuthQualification) bool {
	return q.valid()
}

func (s *GatewayNativeGrokOAuth) ListQuotaAccounts(ctx context.Context) ([]GatewayNativeOAuthPhysical, error) {
	if s == nil {
		return nil, ErrGatewayNativeIdentity
	}
	return s.repository.ListGatewayGrokQuotaAccounts(ctx)
}
