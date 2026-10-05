package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/stretchr/testify/require"
)

// Genuine signed responses over controlled TLS exercise the transport and
// verifier together. SQL ownership/races are tested once at the PG boundary.
func TestGatewayNativeOAuthRefreshSignedHTTPContainment(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	var mode atomic.Int32
	var tokenCalls, jwksCalls, destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	refresh := gatewayOAuthGuardFixtureOpaque()
	signed := func(subject string) string {
		return oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims(subject, now))
	}
	goodID, badID := signed("reserved-subject"), signed("foreign-subject")
	nextAccess, nextRefresh := gatewayOAuthGuardFixtureOpaque(), gatewayOAuthGuardFixtureOpaque()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		if r.URL.Path == "/.well-known/jwks.json" {
			jwksCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
			return
		}
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, openai.ClientID, r.Form.Get("client_id"))
		require.Equal(t, "openid profile email", r.Form.Get("scope"))
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		require.Equal(t, refresh, r.Form.Get("refresh_token"))
		require.Empty(t, r.Header.Get("Authorization"))
		require.Len(t, r.Form, 4)
		tokenCalls.Add(1)
		response := map[string]any{"access_token": nextAccess, "refresh_token": nextRefresh, "id_token": goodID, "token_type": "Bearer", "expires_in": 3600, "private_account_hint": gatewayOAuthGuardFixtureOpaque()}
		switch mode.Load() {
		case 1:
			response["id_token"] = badID
		case 2:
			delete(response, "id_token")
		case 3:
			http.Redirect(w, r, destination.URL+"/stolen", http.StatusTemporaryRedirect)
			return
		case 4:
			_, _ = w.Write([]byte(strings.Repeat(" ", 65537)))
			return
		case 5:
			<-r.Context().Done()
			return
		case 6:
			delete(response, "refresh_token")
		case 8:
			response["expires_in"] = "malformed"
		case 7:
			_, _ = w.Write([]byte(`{"access_token":"a","Access_token":"b"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "auth.openai.com:443" {
			address = server.Listener.Addr().String()
		} else {
			require.Equal(t, destination.Listener.Addr().String(), address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	verifier := NewGatewayNativeOAuthVerifier(transport)
	// exchange shares the exact production constructor's fixed client policy.
	custodyKey := make([]byte, 32)
	_, err := rand.Read(custodyKey)
	require.NoError(t, err)
	custody, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": custodyKey})
	require.NoError(t, err)
	// A repository is not used by the transport-only scenario. The separate PG
	// scenario uses the real adapter to prove entry/unknown/atomic publication.
	s, err := NewGatewayNativeOAuthRefresh(&httpOnlyRefreshRepository{}, custody, verifier, transport)
	require.NoError(t, err)
	bundle, err := s.exchange(context.Background(), refresh, GatewayOAuthIssuer, "reserved-subject")
	require.NoError(t, err)
	require.Equal(t, nextAccess, bundle.AccessToken)
	require.Equal(t, nextRefresh, bundle.RefreshToken)
	require.Equal(t, goodID, bundle.IDToken)
	require.Contains(t, string(bundle.SensitiveMetadata), "private_account_hint")
	require.NotContains(t, string(bundle.SensitiveMetadata), nextAccess)
	require.Equal(t, int32(1), jwksCalls.Load())
	for _, tc := range []struct {
		name string
		mode int32
	}{{"signed foreign principal", 1}, {"missing fresh ID token", 2}, {"redirect", 3}, {"body overflow", 4}, {"body deadline", 5}, {"missing refresh token", 6}, {"ambiguous JSON", 7}, {"malformed expiry", 8}} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			budget := 100 * time.Millisecond
			if tc.mode == 5 {
				budget = 8 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			start := time.Now()
			bundle, err := s.exchange(ctx, refresh, GatewayOAuthIssuer, "reserved-subject")
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Equal(t, GatewayNativeOAuthBundle{}, bundle)
			if tc.mode == 5 {
				require.GreaterOrEqual(t, time.Since(start), 4*time.Second)
				require.Less(t, time.Since(start), 6*time.Second, "production HTTP/body timeout must enforce 5s")
			} else {
				require.Less(t, time.Since(start), time.Second)
			}
			require.Zero(t, destinationCalls.Load(), "redirect denial must precede destination contact")
		})
	}
	require.Equal(t, int32(9), tokenCalls.Load())
	require.Equal(t, int32(2), jwksCalls.Load(), "only complete ID tokens require fixed trusted verification")
	// Negative control: dropping the production redirect policy really contacts
	// the destination before the eventual fixed-origin check rejects its response.
	mode.Store(3)
	s.client.CheckRedirect = nil
	_, err = s.exchange(context.Background(), refresh, GatewayOAuthIssuer, "reserved-subject")
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.Equal(t, int32(1), destinationCalls.Load())
}

// This sentinel has no successful behavior and prevents a transport-only test
// from silently acquiring repository authority. SQL is not mocked in this suite.
type httpOnlyRefreshRepository struct{}

func (*httpOnlyRefreshRepository) PrepareGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent) (GatewayNativeOAuthRefreshPrepared, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) EnterGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) (bool, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) CompleteGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64, string) (GatewayNativeOAuthRefreshOutcome, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) UnknownGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) error {
	panic("SQL scenario must use real PG")
}
