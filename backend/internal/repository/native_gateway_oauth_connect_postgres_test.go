package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Inject only the separate final connect write loss; actual F1 Stage commits
// against migrated PG. This is not a claim of a cross-repository transaction.
type connectLostFinalACK struct {
	service.GatewayNativeOAuthConnectRepository
}
type connectLostStageACK struct {
	service.GatewayNativeOAuthRepository
}

func (r connectLostStageACK) StageGatewayNativeOAuth(ctx context.Context, in service.GatewayNativeOAuthReservation) (service.GatewayNativeOAuthOutcome, error) {
	out, err := r.GatewayNativeOAuthRepository.StageGatewayNativeOAuth(ctx, in)
	if err == nil {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return out, err
}

func (r connectLostFinalACK) FinishConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent, state string, out service.GatewayNativeOAuthOutcome) (service.GatewayNativeOAuthConnectIntent, error) {
	if state == "completed" {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.GatewayNativeOAuthConnectRepository.FinishConnect(ctx, in, state, out)
}

// Failure: competing callbacks/restart/lost final ACK could exchange twice,
// create another physical birth or lose/change the original accepted result.
// This is the closest durable boundary; no same race is mirrored in fake stores.
func TestGatewayNativeOAuthConnectPostgresOneEntryLostACKAndRestart(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OAUTH_CONNECT_TEST_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: disposable F3 OAuth connect PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_oauth_connect_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(2)
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables))
	require.Zero(t, tables, "new isolated database required")
	require.NoError(t, ApplyMigrations(ctx, db))
	repository, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	f1 := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	verifier, bundleFor := oauthPGFixture(t)
	bundle := bundleFor("f3-controlled-principal")
	var exchanges atomic.Int32
	var challenge string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Len(t, r.PostForm, 5)
		require.True(t, openai.GenerateCodeChallenge(r.PostForm.Get("code_verifier")) == challenge)
		require.Equal(t, service.GatewayOAuthConnectRedirect, r.PostForm.Get("redirect_uri"))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "id_token": bundle.IDToken, "token_type": "Bearer", "expires_in": 3600, "scope": openai.DefaultScopes, "private": "f3-controlled-metadata"})
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
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
	custody, err := service.NewGatewayNativeCredentialCustody("f3-fixture", map[string][]byte{"f3-fixture": key})
	require.NoError(t, err)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, connectLostStageACK{f1}, key)
	require.NoError(t, err)
	connect, err := service.NewGatewayNativeOAuthConnect(key, transport, connectLostFinalACK{repository}, enrollment, f1)
	require.NoError(t, err)
	owner, scope := oauthPGScope(t, "f3-consumer", "f3-owner", "f3-logical")
	begin, err := connect.BeginConnect(owner, scope, "f3-operation")
	require.NoError(t, err)
	authorize, err := url.Parse(begin.AuthorizeURL)
	require.NoError(t, err)
	state := authorize.Query().Get("state")
	challenge = authorize.Query().Get("code_challenge")
	prepared, err := repository.ReadConnectIntent(owner, scope, "f3-operation")
	require.NoError(t, err)
	repeat, err := connect.BeginConnect(owner, scope, "f3-operation")
	require.NoError(t, err)
	require.True(t, begin == repeat)
	for _, field := range []string{"account", "generation", "owner"} {
		changed := scope
		changedCtx := owner
		switch field {
		case "account":
			changed.Account = "other"
		case "generation":
			changed.Generation = uuid.NewString()
		case "owner":
			changed.Owner = "other"
			changedCtx, err = service.WithGatewayNativeOAuthOwner(owner, changed.Owner)
			require.NoError(t, err)
		}
		_, err = connect.BeginConnect(changedCtx, changed, "f3-operation")
		require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	}
	foreign, _ := oauthPGScope(t, "other-consumer", "other-owner", "other-account")
	_, err = connect.ReadConnect(foreign, scope, "f3-operation")
	require.Error(t, err)
	require.Zero(t, exchanges.Load())
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, _ = connect.CompleteCallback(ctx, state, "fixture-code") }()
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(1), exchanges.Load())
	original, err := f1.ReadGatewayNativeOAuth(owner, scope, "f3-operation")
	require.NoError(t, err)
	restartedRepo, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	restarted, err := service.NewGatewayNativeOAuthConnect(key, transport, restartedRepo, enrollment, f1)
	require.NoError(t, err)
	recovered, err := restarted.ReadConnect(owner, scope, "f3-operation")
	require.NoError(t, err)
	require.Equal(t, "completed", recovered.State)
	completed, err := restartedRepo.ReadConnectIntent(owner, scope, "f3-operation")
	require.NoError(t, err)
	require.True(t, original == completed.Outcome)
	require.Empty(t, completed.Envelope)
	_, err = restarted.CompleteCallback(ctx, state, "another-code")
	require.NoError(t, err)
	require.Equal(t, int32(1), exchanges.Load())
	// Completed readback survives later safe F1 erasure without changing outcome.
	require.NoError(t, f1.EraseGatewayNativeOAuth(owner, scope, "f3-operation"))
	afterErase, err := restarted.ReadConnect(owner, scope, "f3-operation")
	require.NoError(t, err)
	require.True(t, recovered == afterErase)
	for _, query := range []string{`UPDATE gateway_oauth_connect_intents SET state='prepared' WHERE consumer=$1`, `DELETE FROM gateway_oauth_connect_intents WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET outcome_account_id=123 WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET owner_ref='other' WHERE consumer=$1`} {
		_, err = db.ExecContext(ctx, query, scope.Consumer)
		require.Error(t, err)
	}
	// Exact crash-after-enter case: no token/Stage outcome; fresh service must
	// retain unknown evidence indefinitely, not use TTL to rearm or delete it.
	unknownOwner, unknownScope := oauthPGScope(t, "crash-consumer", "crash-owner", "crash-logical")
	unknownBegin, err := restarted.BeginConnect(unknownOwner, unknownScope, "crash-operation")
	require.NoError(t, err)
	unknownIntent, err := restartedRepo.ReadConnectIntent(unknownOwner, unknownScope, "crash-operation")
	require.NoError(t, err)
	won, err := restartedRepo.EnterConnect(unknownOwner, unknownIntent)
	require.NoError(t, err)
	require.True(t, won)
	unknown, err := restarted.ReadConnect(unknownOwner, unknownScope, "crash-operation")
	require.NoError(t, err)
	require.Equal(t, "unknown", unknown.State)
	unknownURL, err := url.Parse(unknownBegin.AuthorizeURL)
	require.NoError(t, err)
	_, err = restarted.CompleteCallback(ctx, unknownURL.Query().Get("state"), "fixture-code")
	require.NoError(t, err)
	require.Equal(t, int32(1), exchanges.Load())
	evidence, err := restartedRepo.ReadConnectIntent(unknownOwner, unknownScope, "crash-operation")
	require.NoError(t, err)
	require.Equal(t, unknownIntent.StateHash, evidence.StateHash)
	require.Empty(t, evidence.Envelope)
	var entries int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_connect_intents WHERE entered_at IS NOT NULL`).Scan(&entries))
	require.Equal(t, 2, entries)
	require.NotEqual(t, prepared.StateHash, evidence.StateHash)
}
