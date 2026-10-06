package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
