//go:build integration

package repository

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
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Real migrated FSM + F1 custody + fixed-origin TLS exchange. Only the final
// ACK is lost; reconciliation must find the committed receipt without exchange.
func TestGatewayNativeOAuthImportPostgresClaimsReplayAndLostACK(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_IMPORT_TEST_DSN", "gateway_import_test_")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	repository, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	f1 := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	verifier, bundleFor := oauthPGFixture(t)
	var exchanges atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Len(t, r.PostForm, 4)
		require.Equal(t, "refresh_token", r.PostForm.Get("grant_type"))
		require.Equal(t, openai.ClientID, r.PostForm.Get("client_id"))
		require.Equal(t, openai.RefreshScopes, r.PostForm.Get("scope"))
		refresh := r.PostForm.Get("refresh_token")
		if refresh == "blocked-refresh" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			http.Error(w, "synthetic uncertainty", 502)
			return
		}
		b := bundleFor("import-principal-" + refresh)
		// A lawful nonrotating response must retain the submitted RT. Supplied
		// expired ID/AT from auth.json cannot satisfy the verifier instead.
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": b.AccessToken, "id_token": b.IDToken, "token_type": "Bearer", "expires_in": 3600, "scope": openai.RefreshScopes})
	}))
	defer server.Close()
	base := server.Client().Transport.(*http.Transport)
	transport := base.Clone()
	transport.DisableKeepAlives = true
	transport.TLSClientConfig.ServerName = "example.com"
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("import-fixture", map[string][]byte{"import-fixture": key})
	require.NoError(t, err)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, f1, key)
	require.NoError(t, err)
	build := func(repo service.GatewayNativeOAuthConnectRepository) *service.GatewayNativeOAuthConnect {
		connect, e := service.NewGatewayNativeOAuthConnect(key, transport, repo, enrollment, f1)
		require.NoError(t, e)
		require.NoError(t, connect.SetEntryAuthorizer(func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }))
		return connect
	}
	connect := build(connectLostFinalACK{repository})
	owner, scope := oauthPGScope(t, "import-consumer", "import-owner", "import-account")
	_, err = connect.ImportConnect(owner, scope, "import-operation", "refresh_token", "fixture-refresh")
	require.Error(t, err, "lost final ACK requires durable receipt readback")
	restarted := build(repository)
	recovered, err := restarted.ReadConnect(owner, scope, "import-operation")
	require.NoError(t, err)
	require.Equal(t, "completed", recovered.State)
	require.EqualValues(t, 1, exchanges.Load())
	for i := 0; i < 2; i++ {
		replay, e := restarted.ImportConnect(owner, scope, "import-operation", "refresh_token", "fixture-refresh")
		require.NoError(t, e)
		require.Equal(t, recovered, replay)
	}
	_, err = restarted.ImportConnect(owner, scope, "import-operation", "refresh_token", "other-refresh")
	require.Error(t, err)
	_, err = restarted.ImportConnect(owner, scope, "import-operation", "auth_json", `{"tokens":{"refresh_token":"fixture-refresh"}}`)
	require.Error(t, err)
	require.EqualValues(t, 1, exchanges.Load())
	saved, err := repository.ReadConnectIntent(owner, scope, "import-operation")
	require.NoError(t, err)
	require.Empty(t, saved.Envelope)
	require.NotEmpty(t, saved.ImportClaimMAC)
	// The completed claim is no blacklist: a new explicit operation reaches
	// exchange. Existing F1 principal ownership still decides custody outcome.
	_, _ = restarted.ImportConnect(owner, scope, "explicit-next-operation", "refresh_token", "fixture-refresh")
	require.EqualValues(t, 2, exchanges.Load())
	jsonOwner, jsonScope := oauthPGScope(t, "import-consumer", "import-owner", "json-account")
	jsonOut, err := restarted.ImportConnect(jsonOwner, jsonScope, "json-operation", "auth_json", `{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"refresh_token":"json-refresh","id_token":"expired-id","access_token":"expired-access"}}`)
	require.NoError(t, err)
	require.Equal(t, "completed", jsonOut.State)
	require.Empty(t, jsonOut.Method, "old receipt decoder must not see an import enum")
	blockedOwner, blockedScope := oauthPGScope(t, "import-consumer", "import-owner", "blocked-account")
	done := make(chan error, 1)
	go func() {
		_, e := restarted.ImportConnect(blockedOwner, blockedScope, "blocked-operation", "refresh_token", "blocked-refresh")
		done <- e
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("exchange did not enter")
	}
	before := exchanges.Load()
	otherOwner, otherScope := oauthPGScope(t, "other-consumer", "other-owner", "other-account")
	_, err = restarted.ImportConnect(otherOwner, otherScope, "other-operation", "auth_json", `{"tokens":{"refresh_token":"blocked-refresh"}}`)
	require.Error(t, err)
	require.Equal(t, before, exchanges.Load(), "shared claim prevents cross-owner and cross-method exchange")
	close(release)
	require.NoError(t, <-done)
	unknown, err := restarted.ReadConnect(blockedOwner, blockedScope, "blocked-operation")
	require.NoError(t, err)
	require.Equal(t, "unknown", unknown.State)
	_, err = restarted.ImportConnect(otherOwner, otherScope, "other-operation", "auth_json", `{"tokens":{"refresh_token":"blocked-refresh"}}`)
	require.Error(t, err)
	require.Equal(t, before, exchanges.Load(), "unknown retains its claim")
	var plaintext int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_connect_intents WHERE material_envelope LIKE '%refresh%' OR material_envelope LIKE '%expired-id%'`).Scan(&plaintext))
	require.Zero(t, plaintext)
	var imports int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_connect_intents WHERE method IN ('refresh_token','auth_json') AND state IN ('unknown','completed') AND material_envelope<>''`).Scan(&imports))
	require.Zero(t, imports)
	require.NotContains(t, strings.ToLower(recovered.Outcome), "token")
}
