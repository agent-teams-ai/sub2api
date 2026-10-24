//go:build unit

package admin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type grokCodeHTTPRepository struct {
	service.GatewayNativeGrokRepository
	row   service.GatewayGrokConnectIntent
	reads int
}

func (r *grokCodeHTTPRepository) ReadGatewayGrokConnect(_ context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayGrokConnectIntent, error) {
	r.reads++
	if s != r.row.Scope || op != r.row.Operation {
		return service.GatewayGrokConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.row, nil
}

// Raw-code ingress must reach existing scoped readback even when an uncertain
// exchange cannot be restarted. It must never need provider callback state.
func TestGatewayNativeGrokAuthorizationCodeHTTP(t *testing.T) {
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: "fixture-account", Generation: "11111111-1111-4111-8111-111111111111", Purpose: service.GatewayOAuthBundlePurpose}
	repo := &grokCodeHTTPRepository{row: service.GatewayGrokConnectIntent{Scope: scope, Operation: "fixture-operation", State: "exchanging", Deadline: time.Now().Add(time.Minute)}}
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": bytes.Repeat([]byte("K"), 32)})
	require.NoError(t, err)
	grok, err := service.NewGatewayNativeGrokOAuth(repo, custody, nil, service.GatewayNativeGrokOAuthQualification{ClientID: "qualified-fixture-client", RedirectURI: xai.DefaultRedirectURI, DeploymentQualified: true})
	require.NoError(t, err)
	router := gin.New()
	authorize := func(c *gin.Context) {
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), scope.Consumer)
		require.NoError(t, err)
		ctx, err = service.WithGatewayNativeOAuthOwner(ctx, scope.Owner)
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	require.NoError(t, RegisterGatewayNativeGrokOAuthRoutes(router.Group(""), grok, authorize))
	body := `{"operation":"fixture-operation","owner_ref":"fixture-owner","account_ref":"fixture-account","generation":"11111111-1111-4111-8111-111111111111","authorizationCode":"fixture-code"}`
	request := func(raw string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/private/native/v1/grok/oauth/connect/complete", strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		return rec
	}
	rec := request(body)
	require.Equal(t, http.StatusOK, rec.Code, "Grok-only raw-code completion must reach scoped unknown readback")
	require.JSONEq(t, `{"operation":"fixture-operation","account_ref":"fixture-account","state":"unknown","method":"browser"}`, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "fixture-code")
	require.Equal(t, 1, repo.reads)
	for name, bad := range map[string]string{
		"mixed":     strings.Replace(body, `"authorizationCode":`, `"state":"`+strings.Repeat("a", 64)+`","code":"callback-code","authorizationCode":`, 1),
		"duplicate": strings.Replace(body, `"authorizationCode":`, `"authorizationCode":"other","authorizationCode":`, 1),
		"alias":     strings.Replace(body, `"authorizationCode":`, `"AuthorizationCode":`, 1),
		"unknown":   strings.Replace(body, `"authorizationCode":`, `"provider":"grok","authorizationCode":`, 1),
		"null":      strings.Replace(body, `"fixture-code"`, `null`, 1),
		"surrogate": strings.Replace(body, `"fixture-code"`, `"\ud800"`, 1),
		"trim":      strings.Replace(body, `"fixture-code"`, `" fixture-code"`, 1),
		"separator": strings.Replace(body, `"fixture-code"`, `"fixture#code"`, 1),
		"oversize":  strings.Replace(body, "fixture-code", strings.Repeat("x", 4097), 1),
	} {
		t.Run(name, func(t *testing.T) {
			before := repo.reads
			require.Equal(t, http.StatusNotFound, request(bad).Code)
			require.Equal(t, before, repo.reads)
		})
	}
	require.Equal(t, http.StatusNotFound, request(strings.Replace(body, "fixture-owner", "foreign-owner", 1)).Code)
	legacy := strings.Replace(body, `"authorizationCode":`, `"state":"`+strings.Repeat("a", 64)+`","code":`, 1)
	_, legacyValid := DecodeGatewayNativeGrokConnectCompletion([]byte(legacy))
	require.True(t, legacyValid, "existing callback state+code shape must remain accepted")
	_, unicodeValid := DecodeGatewayNativeGrokConnectCompletion([]byte(strings.Replace(body, `"fixture-code"`, `"\ud83d\ude00"`, 1)))
	require.True(t, unicodeValid, "paired Unicode scalar must remain lossless")
	_, valid := DecodeGatewayNativeOAuthConnectCompletion([]byte(body))
	require.False(t, valid, "other OAuth providers must still require state")
}
