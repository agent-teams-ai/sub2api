package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Reuse the existing signed TLS enrollment fixture to exercise the real protected
// HTTP authorization/decode boundary; transport semantics have their own test.
type descriptorHTTPStore struct {
	service.GatewayNativeOAuthDispatchRepository
	readCalls int
	state     string
}

func (r *descriptorHTTPStore) ReadGatewayNativeOAuthDispatch(ctx context.Context, s service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthOutcome, error) {
	r.readCalls++
	if r.state != "" {
		return service.GatewayNativeOAuthOutcome{Operation: operation, Generation: s.Generation, State: r.state}, nil
	}
	return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
}

func TestGatewayOAuthDescriptorHTTPProtectionAndSafePendingDTO(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := &descriptorHTTPStore{}
	key := connectHTTPRandom(t, 32)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(store, custody, service.NewGatewayNativeOAuthVerifier(nil), nil)
	require.NoError(t, err)
	consumer, owner, account, operation, generation := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	authorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+consumer {
			c.AbortWithStatus(403)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), consumer)
		require.NoError(t, err)
		ctx, err = service.WithGatewayNativeOAuthOwner(ctx, owner)
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
	}
	require.NoError(t, RegisterGatewayNativeOAuthDescriptorRoute(router.Group("/"), dispatch, authorize))
	valid, _ := json.Marshal(map[string]string{"operation": operation, "owner_ref": owner, "account_ref": account, "generation": generation})
	for _, tc := range []struct {
		name  string
		body  []byte
		auth  bool
		path  string
		want  int
		calls int
	}{
		{"unauthenticated", valid, false, "/private/native/v1/oauth/connect/descriptor", 403, 0},
		{"foreign owner", []byte(`{"operation":"operation","owner_ref":"foreign","account_ref":"logical","generation":"` + generation + `"}`), true, "/private/native/v1/oauth/connect/descriptor", 404, 0},
		{"foreign scope header is not authority", valid, false, "/private/native/v1/oauth/connect/descriptor", 403, 0},
		{"duplicate escaped operation", []byte(`{"operation":"op","\u006fperation":"op","owner_ref":"owner","account_ref":"account","generation":"` + generation + `"}`), true, "/private/native/v1/oauth/connect/descriptor", 404, 0},
		{"numeric selector", []byte(`{"operation":"op","owner_ref":"owner","account_ref":"account","generation":"` + generation + `","account_id":41}`), true, "/private/native/v1/oauth/connect/descriptor", 404, 0},
		{"query authority", valid, true, "/private/native/v1/oauth/connect/descriptor?owner_ref=foreign", 404, 0},
		{"canonical read failure stays nondisclosing", valid, true, "/private/native/v1/oauth/connect/descriptor", 404, 1},
		{"public path absent", valid, true, "/api/v1/admin/oauth/connect/descriptor", 404, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := store.readCalls
			request := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(tc.body))
			request.Header.Set("X-Consumer-Id", consumer)
			if tc.auth {
				request.Header.Set("Authorization", "Bearer "+consumer)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, request)
			require.Equal(t, tc.want, rec.Code)
			require.Equal(t, tc.calls, store.readCalls-before)
			for _, private := range []string{consumer, owner, account, operation, "account_id", "credential_version", "access_token", "native" + `":`} {
				require.NotContains(t, rec.Body.String(), private)
			}
		})
	}
	// Exercise actual protected HTTP readback for every noncompleted F3 state.
	// It must not call the lock/provider path or turn custody into qualification.
	for _, state := range []string{"prepared", "entered", "unknown", "expired"} {
		t.Run("safe pending "+state, func(t *testing.T) {
			store.state = state
			request := httptest.NewRequest(http.MethodPost, "/private/native/v1/oauth/connect/descriptor", bytes.NewReader(valid))
			request.Header.Set("Authorization", "Bearer "+consumer)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, request)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			var fields map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &fields))
			require.Equal(t, map[string]any{"operation": operation, "account_ref": account, "state": "staged", "qualification": "pending"}, fields)
			require.Equal(t, state, store.state)
		})
	}
	require.Error(t, RegisterGatewayNativeOAuthDescriptorRoute(router.Group("/api/v1/admin"), dispatch, authorize))
}

// Only the real descriptor service may produce qualification. The fixture
// retains accepted postimages; it does not inject a synthetic success tuple.
type joinedDescriptorHTTPStore struct {
	service.GatewayNativeOAuthDispatchRepository
	account  *service.Account
	physical service.GatewayNativeOAuthPhysical
}

func (r *joinedDescriptorHTTPStore) ReadGatewayNativeOAuthDispatch(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthOutcome, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || scope != r.physical.Scope || operation != r.physical.Operation {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return service.GatewayNativeOAuthOutcome{Operation: operation, AccountID: r.account.ID, Generation: scope.Generation, State: "completed"}, nil
}
func (r *joinedDescriptorHTTPStore) LockGatewayNativeOAuthDispatch(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string, id int64) (*service.Account, service.GatewayNativeOAuthPhysical, func(), error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || scope != r.physical.Scope || operation != r.physical.Operation || id != r.account.ID {
		return nil, service.GatewayNativeOAuthPhysical{}, nil, service.ErrGatewayNativeIdentity
	}
	return r.account, r.physical, func() {}, nil
}
func (r *joinedDescriptorHTTPStore) QualifyGatewayNativeOAuthDispatch(ctx context.Context, p service.GatewayNativeOAuthPhysical, version int64) error {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, p.Scope) || !p.QualificationValid(version) || !service.SameGatewayNativeDescriptor(p.Route, r.physical.Route) {
		return service.ErrGatewayNativeIdentity
	}
	r.physical = p
	return nil
}

// Failure: independently successful Go and TS suites missed the producer's
// actual staged/controlled-source-v1 tuple. Export first and cached protected
// HTTP output for the actual TS adapter in an explicitly owned test directory.
func TestGatewayOAuthDescriptorHTTPJoinedSuccessWire(t *testing.T) {
	f := newConnectHTTPFixture(t)
	state := f.begin(t)
	require.Equal(t, http.StatusOK, f.request(t, "/auth/callback?state="+state+"&code=fixture-code", "", false).Code)
	require.Equal(t, "completed", f.store.row.State)
	birth := time.Date(2026, 10, 8, 12, 34, 56, 123456000, time.UTC)
	route := service.GatewayNativeRoute{AccountID: 42, Generation: f.scope.Generation, CreatedAt: birth, Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}
	issuer, subject := f.enrolled.reservation.Identity.Principal()
	account := &service.Account{ID: 42, CreatedAt: birth, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusDisabled, Schedulable: false,
		Credentials: map[string]any{"oauth_bundle": f.enrolled.reservation.Envelope}, Extra: map[string]any{service.GatewayGenerationExtraKey: f.scope.Generation, service.GatewayProfileExtraKey: service.GatewayOAuthStagingProfile, service.GatewayCredentialScopeExtraKey: f.scope.Metadata()}}
	repository := &joinedDescriptorHTTPStore{account: account, physical: service.GatewayNativeOAuthPhysical{Scope: f.scope, Operation: "operation", Route: route, Issuer: issuer, Subject: subject}}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(repository, f.custody, service.NewGatewayNativeOAuthVerifier(f.transport), f.transport)
	require.NoError(t, err)
	authorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer fixture-owner" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, e := service.WithGatewayNativeConsumer(c.Request.Context(), f.scope.Consumer)
		require.NoError(t, e)
		ctx, e = service.WithGatewayNativeOAuthOwner(ctx, f.scope.Owner)
		require.NoError(t, e)
		c.Request = c.Request.WithContext(ctx)
	}
	require.NoError(t, RegisterGatewayNativeOAuthDescriptorRoute(f.router.Group(""), dispatch, authorize))
	outputs := map[string][]byte{}
	for _, name := range []string{"first.json", "cached.json"} {
		response := f.request(t, "/private/native/v1/oauth/connect/descriptor", f.input(), true)
		require.Equal(t, http.StatusOK, response.Code)
		var out map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &out))
		require.Equal(t, "staged", out["state"])
		require.Equal(t, "controlled-source-v1", out["qualification"])
		require.Equal(t, "operation", out["operation"])
		require.Equal(t, f.scope.Account, out["account_ref"])
		require.NotNil(t, out["native"])
		outputs[name] = append([]byte(nil), response.Body.Bytes()...)
	}
	require.Equal(t, outputs["first.json"], outputs["cached.json"])
	require.Equal(t, int32(1), f.checks.Load(), "cached proof cannot run another account-check")
	require.Equal(t, int32(1), f.tokens.Load())
	require.Equal(t, service.StatusDisabled, account.Status)
	require.False(t, account.Schedulable)
	require.Empty(t, account.GroupIDs)
	if dir := os.Getenv("AG_OAUTH_JOINED_DESCRIPTOR_FIXTURE_DIR"); dir != "" {
		require.True(t, filepath.IsAbs(dir))
		info, err := os.Stat(dir)
		require.NoError(t, err)
		require.True(t, info.IsDir())
		outputs["scope.json"], err = json.Marshal(map[string]string{"consumerId": f.scope.Consumer, "operationId": "operation", "ownerRef": f.scope.Owner, "accountRef": f.scope.Account, "generation": f.scope.Generation})
		require.NoError(t, err)
		// Expected identity comes from the accepted fixture birth, independently of
		// the production response parser or its selected state/qualification tuple.
		outputs["expected.json"], err = json.Marshal(route)
		require.NoError(t, err)
		for name, data := range outputs {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0600))
		}
	}
}
