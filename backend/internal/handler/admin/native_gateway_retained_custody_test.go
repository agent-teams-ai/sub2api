//go:build integration

package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type retainedAPIRepo struct {
	service.AdminAccountRepository
	row *service.Account
}

func (r *retainedAPIRepo) FindByExtraField(context.Context, string, any) ([]service.Account, error) {
	return []service.Account{*r.row}, nil
}

func (r *retainedAPIRepo) LockGatewayNativeRetainedAPIKeyCustody(_ context.Context, scope service.GatewayNativeCredentialScope, route service.GatewayNativeRoute) (*service.Account, func(), error) {
	if scope.Consumer != "consumer/api" || scope.Owner != "owner/api" || scope.Account != "account/api" ||
		scope.Generation != route.Generation || !service.SameGatewayNativeDescriptor(route, mustGatewayNativeDescriptor(r.row)) {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	return r.row, func() {}, nil
}

type retainedOAuthRepo struct {
	service.GatewayNativeOAuthDispatchRepository
	row *service.Account
}

func (r *retainedOAuthRepo) LockGatewayNativeRetainedOAuthCustody(_ context.Context, scope service.GatewayNativeCredentialScope, operation string, route service.GatewayNativeRoute) (*service.Account, func(), error) {
	if operation != "original-operation" || scope.Consumer != "consumer/oauth" || scope.Owner != "owner/oauth" ||
		scope.Account != "account/oauth" || scope.Generation != route.Generation ||
		route.AccountID != r.row.ID || !route.CreatedAt.Equal(r.row.CreatedAt) ||
		route.Profile != service.GatewayCodexOAuthResponsesProfile || route.BaseURL != service.GatewayCodexOAuthBaseURL ||
		route.Model != service.GatewayCodexOAuthModel {
		return nil, nil, service.ErrGatewayNativeIdentity
	}
	return r.row, func() {}, nil
}

func mustGatewayNativeDescriptor(a *service.Account) service.GatewayNativeRoute {
	d, err := service.GatewayNativeDescriptor(a)
	if err != nil {
		panic(err)
	}
	return d
}

func TestGatewayNativeRetainedCustodyPrivateHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := base64.RawURLEncoding.EncodeToString([]byte("synthetic-retained-secret"))
	birth := time.Date(2026, 10, 19, 12, 0, 0, 123456000, time.UTC)
	apiScope := service.GatewayNativeCredentialScope{Consumer: "consumer/api", Owner: "owner/api", Account: "account/api",
		Generation: "11111111-1111-4111-8111-111111111111", Purpose: service.GatewayCredentialPurpose}
	apiCustody := nativeReviewCustody(t)
	apiEnvelope, err := apiCustody.Seal(apiScope, secret)
	require.NoError(t, err)
	apiRow := &service.Account{ID: 42, Name: "retained", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
		Status: service.StatusActive, CreatedAt: birth, Credentials: map[string]any{"api_key": apiEnvelope, "base_url": "https://provider.invalid/v1"},
		Extra: map[string]any{service.GatewayGenerationExtraKey: apiScope.Generation, service.GatewayProfileExtraKey: service.GatewayMiMoResponsesProfile,
			service.GatewayModelExtraKey: "qualified-model", service.GatewayCredentialScopeExtraKey: apiScope.Metadata(),
			"openai_responses_mode": "force_responses", "openai_passthrough": true,
			"native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	apiRepo := &retainedAPIRepo{row: apiRow}
	apiGateway := nativeReviewGateway(apiRepo, nil, nil)
	apiAdmin := nativeReviewAdmin(apiRepo, nil)
	apiToken := "Bearer " + nativeReviewSyntheticKey(t)
	apiAuthorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != apiToken {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), apiScope.Consumer)
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	apiRouter := gin.New()
	RegisterGatewayNativeRoutes(apiRouter.Group(""), apiAdmin, apiGateway,
		GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: "https://provider.invalid/v1", Model: "qualified-model"},
		apiAuthorize, func(*gin.Context, service.GatewayNativeRoute) error { return nil }, func(*gin.Context, bool, error) {}, apiCustody)
	apiServer := httptest.NewServer(apiRouter)
	defer apiServer.Close()
	apiRoute := mustGatewayNativeDescriptor(apiRow)
	apiBody := gatewayNativeRetainedCustodyInput{Contract: service.GatewayNativeRetainedCustodyContract,
		OwnerRef: apiScope.Owner, AccountRef: apiScope.Account, Descriptor: apiRoute}
	status, raw := custodyAPIRequest(t, apiServer.Client(), http.MethodGet, apiServer.URL+"/private/native/v1/candidates/"+apiScope.Generation+"/custody", apiToken, apiBody)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, string(raw), secret)
	require.NotContains(t, string(raw), "gcn1.")
	require.Contains(t, string(raw), `"credential_kinds":["api_key"]`)

	oauthScope := service.GatewayNativeCredentialScope{Consumer: "consumer/oauth", Owner: "owner/oauth", Account: "account/oauth",
		Generation: "22222222-2222-4222-8222-222222222222", Purpose: service.GatewayOAuthBundlePurpose}
	oauthCustody := nativeReviewCustody(t)
	oauthSecret := base64.RawURLEncoding.EncodeToString([]byte("synthetic-oauth-retained-secret"))
	oauthBundle := service.GatewayNativeOAuthBundle{AccessToken: oauthSecret, RefreshToken: oauthSecret + "-refresh",
		IDToken: oauthSecret + "-id", SensitiveMetadata: json.RawMessage(`{"expires_in":3600}`)}
	oauthEnvelope, err := oauthCustody.SealOAuthBundle(oauthScope, oauthBundle)
	require.NoError(t, err)
	oauthRow := &service.Account{ID: 43, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		Status: service.StatusDisabled, CreatedAt: birth, Credentials: map[string]any{"oauth_bundle": oauthEnvelope},
		Extra: map[string]any{service.GatewayGenerationExtraKey: oauthScope.Generation, service.GatewayProfileExtraKey: service.GatewayOAuthStagingProfile,
			service.GatewayCredentialScopeExtraKey: oauthScope.Metadata()}}
	oauthRepo := &retainedOAuthRepo{row: oauthRow}
	var oauthNetworkCalls int
	oauthTransport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		oauthNetworkCalls++
		return nil, service.ErrGatewayNativeIdentity
	})
	oauthDispatch, err := service.NewGatewayNativeOAuthDispatch(oauthRepo, oauthCustody, service.NewGatewayNativeOAuthVerifier(nil), oauthTransport)
	require.NoError(t, err)
	oauthRouter := gin.New()
	oauthToken := "Bearer " + nativeReviewSyntheticKey(t)
	oauthAuthorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != oauthToken {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), oauthScope.Consumer)
		require.NoError(t, err)
		ctx, err = service.WithGatewayNativeOAuthOwner(ctx, oauthScope.Owner)
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	require.NoError(t, RegisterGatewayNativeOAuthRetainedCustodyRoute(oauthRouter.Group(""), oauthDispatch, oauthAuthorize))
	oauthServer := httptest.NewServer(oauthRouter)
	defer oauthServer.Close()
	oauthRoute := service.GatewayNativeRoute{AccountID: oauthRow.ID, Generation: oauthScope.Generation, CreatedAt: birth,
		Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}
	oauthInput := GatewayNativeOAuthRetainedCustodyInput{Contract: service.GatewayNativeRetainedCustodyContract,
		Operation: "original-operation", Owner: oauthScope.Owner, Account: oauthScope.Account, Generation: oauthScope.Generation, Descriptor: oauthRoute}
	status, raw = custodyAPIRequest(t, oauthServer.Client(), http.MethodPost, oauthServer.URL+"/private/native/v1/oauth/connect/custody", oauthToken, oauthInput)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, string(raw), oauthSecret)
	require.NotContains(t, string(raw), "gco1.")
	require.Contains(t, string(raw), `"credential_kinds":["oauth"]`)
	require.Zero(t, oauthNetworkCalls)

	// Same-ID wrong composition keys fail closed without any provider entry.
	wrong, err := service.NewGatewayNativeCredentialCustody("fixture-k1", map[string][]byte{"fixture-k1": nativeReviewSyntheticBytes(t, 32)})
	require.NoError(t, err)
	wrongRouter := gin.New()
	RegisterGatewayNativeRoutes(wrongRouter.Group(""), apiAdmin, apiGateway,
		GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: "https://provider.invalid/v1", Model: "qualified-model"},
		apiAuthorize, func(*gin.Context, service.GatewayNativeRoute) error { return nil }, func(*gin.Context, bool, error) {}, wrong)
	wrongServer := httptest.NewServer(wrongRouter)
	defer wrongServer.Close()
	status, raw = custodyAPIRequest(t, wrongServer.Client(), http.MethodGet, wrongServer.URL+"/private/native/v1/candidates/"+apiScope.Generation+"/custody", apiToken, apiBody)
	require.GreaterOrEqual(t, status, 400)
	require.NotContains(t, string(raw), secret)
	require.NotContains(t, string(raw), "gcn1.")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
