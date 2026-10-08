package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
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
	"github.com/lib/pq"
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
	// lib/pq sends this startup parameter on every pooled connection, including
	// connections opened later by the migration runner or competing callbacks.
	query := u.Query()
	query.Set("search_path", "public")
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	db.SetMaxOpenConns(2)
	// Full migrations can be destructive. Reject user objects in every schema,
	// including routines/types/extensions, before the first migration. PG17
	// allocates ordinary user OIDs from 16384. Dependencies on pinned builtins
	// are suppressed, so also inventory schema-less object catalogs directly.
	// Check large objects regardless of OID (they can be caller-assigned), and
	// database-bound subscriptions whose ownership dependencies are shared.
	errFixtureNotEmpty := errors.New("empty isolated database without non-system user objects required")
	requireEmptyDatabase := func(queryer interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) error {
		var userObjects int
		if err := queryer.QueryRowContext(ctx, `SELECT count(*) FROM (
	 SELECT oid FROM pg_catalog.pg_namespace
	 WHERE nspname NOT IN ('public','pg_catalog','pg_toast','information_schema') OR oid >= 16384
	 UNION ALL
	 SELECT objid FROM pg_catalog.pg_depend WHERE objid >= 16384
	 UNION ALL
	 SELECT objid FROM pg_catalog.pg_shdepend
	 WHERE dbid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) AND objid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_cast WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_language WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_transform WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_am WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_default_acl WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_ts_template WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_ts_parser WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_ts_dict WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_ts_config WHERE oid >= 16384
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_largeobject_metadata
	 UNION ALL
	 SELECT oid FROM pg_catalog.pg_subscription
	 WHERE subdbid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
	) AS user_objects`).Scan(&userObjects); err != nil {
			return err
		}
		if userObjects != 0 {
			return errFixtureNotEmpty
		}
		return nil
	}
	require.NoError(t, requireEmptyDatabase(db))
	require.True(t, t.Run("dependency-free cast denies migrations", func(t *testing.T) {
		// Builtin types are pinned, and casts have neither namespace nor owner
		// dependencies. The old dependency-only inventory misses this object.
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { require.NoError(t, tx.Rollback()) }()
		_, err = tx.ExecContext(ctx, `CREATE CAST (integer AS text) WITH INOUT`)
		require.NoError(t, err, "fixture role must be able to create the regression cast")
		require.ErrorIs(t, requireEmptyDatabase(tx), errFixtureNotEmpty)
	}), "cast guard and checked rollback must pass before any migration")
	require.True(t, t.Run("pinned text-search template denies migrations", func(t *testing.T) {
		// PG17 suppresses dependencies on pinned builtin namespace/functions.
		// Templates have no owner; the direct high-OID guard must still deny.
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				t.Errorf("rollback template fixture: %v", rollbackErr)
			}
		}()
		_, err = tx.ExecContext(ctx, `CREATE TEXT SEARCH TEMPLATE pg_catalog.oauth_empty_template_fixture (INIT = pg_catalog.dsimple_init, LEXIZE = pg_catalog.dsimple_lexize)`)
		require.NoError(t, err, "fixture role must be able to create the regression template")
		require.ErrorIs(t, requireEmptyDatabase(tx), errFixtureNotEmpty)
	}), "template guard and checked rollback must pass before any migration")
	require.NoError(t, requireEmptyDatabase(db))
	require.NoError(t, ApplyMigrations(ctx, db))
	t.Run("material envelope SQL constraint", func(t *testing.T) {
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
		payload := strings.Repeat(alphabet, 16)
		for _, tc := range []struct {
			name     string
			envelope string
			accepted bool
		}{
			{"payload60", "gcc1." + payload[:60], true},
			{"payload1019", "gcc1." + payload[:1019], true},
			{"payload59", "gcc1." + payload[:59], false},
			{"payload1020", "gcc1." + payload[:1020], false},
			{"invalid character", "gcc1." + payload[:59] + "/", false},
			{"newline", "gcc1." + payload[:60] + "\n", false},
			{"non ASCII", "gcc1." + payload[:59] + "é", false},
			{"wrong prefix", "gcc2." + payload[:60], false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// Exercise the actual migrated table/guard, then roll back so
				// the existing first-Begin/custody flow retains its exact fixture.
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { require.NoError(t, tx.Rollback()) }()
				result, err := tx.ExecContext(ctx, `INSERT INTO gateway_oauth_connect_intents
				 (consumer,owner_ref,account_ref,generation,purpose,operation_ref,enrollment_operation,
				 client_id,redirect_uri,deadline,state_hash,material_envelope)
				 VALUES ('envelope-fixture','envelope-owner','envelope-account',$1,'provider-oauth-bundle-v1',
				 'envelope-operation',$2,'app_EMoamEEZ73f0CkXaXp7hrann','http://localhost:1455/auth/callback',
				 clock_timestamp()+interval '5 minutes',repeat('0',64),$3)`, uuid.NewString(), "connect-"+uuid.NewString(), tc.envelope)
				if tc.accepted {
					require.NoError(t, err)
					rows, err := result.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, rows)
				} else {
					var pgErr *pq.Error
					require.ErrorAs(t, err, &pgErr)
					require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
				}
			})
		}
	})
	repository, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	f1, ok := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
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
	transportBase, ok := server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := transportBase.Clone()
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
	original, err := f1.ReadGatewayNativeOAuth(owner, scope, prepared.EnrollmentOperation)
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
	require.NotEqual(t, completed.Operation, completed.EnrollmentOperation)
	require.NotEmpty(t, completed.EnrollmentMAC)
	var acceptedMAC string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT intent_mac FROM gateway_oauth_identity_reservations WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, completed.EnrollmentOperation).Scan(&acceptedMAC))
	require.Equal(t, acceptedMAC, completed.EnrollmentMAC)
	require.Empty(t, completed.Envelope)
	_, err = restarted.CompleteCallback(ctx, state, "another-code")
	require.NoError(t, err)
	require.Equal(t, int32(1), exchanges.Load())

	// Failure: actual accepted custody can be unknown to the consumer after a
	// lost mapping ACK; unbound cleanup must discover the same birth without
	// deleting it, then a fresh mapped lease can erase it idempotently.
	t.Run("purpose cleanup discovers unbound custody and retains birth", func(t *testing.T) {
		in := service.GatewayNativeOAuthCleanupRequest{Scope: scope, Operation: "f3-operation", Action: "read", CleanupRef: "cleanup-ref", CleanupToken: "current-token"}
		var mapped *service.GatewayNativeRoute
		var callbacks int
		authority := func(_ context.Context, got service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			callbacks++
			require.Equal(t, in, got)
			return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: time.Now().Add(time.Second), Native: mapped}, nil
		}
		read, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.NotNil(t, read.Native)
		require.Equal(t, original.AccountID, read.Native.AccountID)
		require.Equal(t, "f3-operation", read.Operation)
		require.Equal(t, scope.Account, read.Account)
		require.False(t, read.CredentialsErased)
		require.Equal(t, "pending", read.Closure)
		originalBirth := *read.Native
		in.Action = "erase"
		unbound, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.Equal(t, &originalBirth, unbound.Native)
		require.False(t, unbound.CredentialsErased)
		var custodyPresent bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT deleted_at IS NULL AND credentials ? 'oauth_bundle' FROM accounts WHERE id=$1`, original.AccountID).Scan(&custodyPresent))
		require.True(t, custodyPresent)
		mapped = &originalBirth
		// Post-lock callback denial cannot produce a mutation or closed receipt.
		checks := 0
		_, err = restarted.Cleanup(owner, in, func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			checks++
			if checks > 1 {
				return service.GatewayNativeOAuthCleanupAuthority{}, service.ErrGatewayNativeIdentity
			}
			return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: time.Now().Add(time.Second), Native: mapped}, nil
		})
		require.Error(t, err)
		require.Equal(t, 2, checks)
		require.NoError(t, db.QueryRowContext(ctx, `SELECT deleted_at IS NULL AND credentials ? 'oauth_bundle' FROM accounts WHERE id=$1`, original.AccountID).Scan(&custodyPresent))
		require.True(t, custodyPresent)

		// Failure: a short cleanup lease may expire while the account lock is held.
		// Cancellation must release the waiter without any ciphertext mutation.
		lock, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		var locked int64
		require.NoError(t, lock.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, original.AccountID).Scan(&locked))
		lease := time.Now().Add(100 * time.Millisecond)
		authorized := make(chan struct{}, 1)
		finished := make(chan error, 1)
		go func() {
			_, cleanupErr := restarted.Cleanup(owner, in, func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
				select {
				case authorized <- struct{}{}:
				default:
				}
				return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: lease, Native: mapped}, nil
			})
			finished <- cleanupErr
		}()
		select {
		case <-authorized:
		case <-ctx.Done():
			t.Fatal("cleanup authority did not enter")
		}
		select {
		case cleanupErr := <-finished:
			require.Error(t, cleanupErr)
		case <-time.After(time.Second):
			t.Fatal("cleanup exceeded exact lease while waiting for account lock")
		}
		require.NoError(t, lock.Commit())
		require.NoError(t, db.QueryRowContext(ctx, `SELECT deleted_at IS NULL AND credentials ? 'oauth_bundle' FROM accounts WHERE id=$1`, original.AccountID).Scan(&custodyPresent))
		require.True(t, custodyPresent)
		refreshRepo, ok := f1.(service.GatewayNativeOAuthRefreshRepository)
		require.True(t, ok)
		rotation := service.GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: originalBirth.AccountID, CreatedAt: originalBirth.CreatedAt, ExpectedVersion: 1, Operation: "prepared-before-cleanup", Intent: "rotation-intent"}

		// A short accepted fixture deadline exercises the real migration244 fence
		// without waiting the production15s TTL. This INSERT is fixture setup only.
		_, err = db.ExecContext(ctx, `INSERT INTO gateway_oauth_refresh_attempts(account_id,native_created_at,consumer,owner_ref,account_ref,generation,operation_ref,intent_ref,expected_version,fence,state,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,1,'prepared',clock_timestamp()+interval '1 second')`, rotation.AccountID, rotation.CreatedAt, scope.Consumer, scope.Owner, scope.Account, scope.Generation, rotation.Operation, rotation.Intent)
		require.NoError(t, err)
		preparedRefresh, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(owner, rotation)
		require.NoError(t, err)
		require.False(t, preparedRefresh.Claimed)
		// Owner/decrypt/Enter denial before a committed entry preserves prepared.
		require.NoError(t, refreshRepo.UnknownGatewayNativeOAuthRefresh(owner, rotation, preparedRefresh.Fence))
		var attemptState string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT state FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, rotation.Operation).Scan(&attemptState))
		require.Equal(t, "prepared", attemptState)
		erased, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.True(t, erased.CredentialsErased)
		require.Equal(t, "closed", erased.Closure)
		require.Equal(t, &originalBirth, erased.Native)
		// A stale worker failure cannot degrade prepared+tombstone NoEffect proof.
		require.NoError(t, refreshRepo.UnknownGatewayNativeOAuthRefresh(owner, rotation, preparedRefresh.Fence))
		require.NoError(t, db.QueryRowContext(ctx, `SELECT state FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, rotation.Operation).Scan(&attemptState))
		require.Equal(t, "prepared", attemptState)
		entered, err := refreshRepo.EnterGatewayNativeOAuthRefresh(owner, rotation, preparedRefresh.Fence)
		require.Error(t, err)
		require.False(t, entered)
		_, err = refreshRepo.CompleteGatewayNativeOAuthRefresh(owner, rotation, preparedRefresh.Fence, preparedRefresh.Envelope)
		require.Error(t, err)
		wrongFence := preparedRefresh.Fence + 1
		require.Error(t, refreshRepo.UnknownGatewayNativeOAuthRefresh(owner, rotation, wrongFence))

		replay, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.Equal(t, erased, replay)
		in.Action = "read"
		retained, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.Equal(t, erased, retained)
		require.GreaterOrEqual(t, callbacks, 7)
		saved, err := restartedRepo.ReadConnectIntent(owner, scope, "f3-operation")
		require.NoError(t, err)
		require.Equal(t, completed, saved)
		var reservations int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_identity_reservations WHERE consumer=$1 AND operation_ref=$2 AND account_id=$3`, scope.Consumer, prepared.EnrollmentOperation, original.AccountID).Scan(&reservations))
		require.Equal(t, 1, reservations)

		// Expired prepared cannot reclaim a deleted birth or change its fence, and
		// stale failure handling cannot destroy the retained no-entry evidence.
		timer := time.NewTimer(time.Until(preparedRefresh.Deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("short prepared expiry interrupted")
		}
		_, err = refreshRepo.PrepareGatewayNativeOAuthRefresh(owner, rotation)
		require.Error(t, err)
		var retainedFence int64
		require.NoError(t, db.QueryRowContext(ctx, `SELECT state,fence FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, rotation.Operation).Scan(&attemptState, &retainedFence))
		require.Equal(t, "prepared", attemptState)
		require.Equal(t, preparedRefresh.Fence, retainedFence)
		in.Action = "read"
		expiredRead, err := restarted.Cleanup(owner, in, authority)
		require.NoError(t, err)
		require.Equal(t, "closed", expiredRead.Closure)
		require.True(t, expiredRead.CredentialsErased)
		require.Equal(t, int32(1), exchanges.Load())
	})
	// Completed readback survives later safe F1 erasure without changing outcome.
	require.NoError(t, f1.EraseGatewayNativeOAuth(owner, scope, prepared.EnrollmentOperation))
	afterErase, err := restarted.ReadConnect(owner, scope, "f3-operation")
	require.NoError(t, err)
	require.True(t, recovered == afterErase)
	for _, query := range []string{`UPDATE gateway_oauth_connect_intents SET state='prepared' WHERE consumer=$1`, `DELETE FROM gateway_oauth_connect_intents WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET outcome_account_id=123 WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET owner_ref='other' WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET enrollment_mac=repeat('0',64) WHERE consumer=$1`, `UPDATE gateway_oauth_connect_intents SET enrollment_operation='connect-00000000-0000-0000-0000-000000000001' WHERE consumer=$1`} {
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

	// Failure: sealing an entered unknown intent could discard provider ambiguity,
	// rewrite an immutable replay tombstone or allow late Stage to acquire custody.
	t.Run("entered unknown cleanup seals without fake closure", func(t *testing.T) {
		in := service.GatewayNativeOAuthCleanupRequest{Scope: unknownScope, Operation: "crash-operation", Action: "erase", CleanupRef: "crash-cleanup", CleanupToken: "current-token"}
		authority := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			return service.GatewayNativeOAuthCleanupAuthority{Owner: unknownScope.Owner, LeaseExpiresAt: time.Now().Add(time.Second)}, nil
		}
		sealed, err := restarted.Cleanup(unknownOwner, in, authority)
		require.NoError(t, err)
		require.Equal(t, "unknown", sealed.Closure)
		require.True(t, sealed.CredentialsErased)
		require.Nil(t, sealed.Native)
		saved, err := restartedRepo.ReadConnectIntent(unknownOwner, unknownScope, "crash-operation")
		require.NoError(t, err)
		require.True(t, saved.RecoveryDenied)
		require.Empty(t, saved.Envelope)
		repeat, err := restarted.Cleanup(unknownOwner, in, authority)
		require.NoError(t, err)
		require.Equal(t, sealed, repeat)
		retained, err := restartedRepo.ReadConnectIntent(unknownOwner, unknownScope, "crash-operation")
		require.NoError(t, err)
		require.Equal(t, saved, retained)
		_, err = restartedRepo.BindConnectEnrollment(unknownOwner, saved, strings.Repeat("a", 64))
		require.Error(t, err)
	})

	// Failure: a committed refresh Enter may lose its ACK; erasure must fence
	// publication while retaining unknown effect and the exact physical birth.
	t.Run("entered refresh cleanup never claims closure or republishes", func(t *testing.T) {
		enteredOwner, enteredScope := oauthPGScope(t, "entered-cleanup-consumer", "entered-cleanup-owner", "entered-cleanup-account")
		_, err := restarted.BeginConnect(enteredOwner, enteredScope, "entered-cleanup-operation")
		require.NoError(t, err)
		intent, err := restartedRepo.ReadConnectIntent(enteredOwner, enteredScope, "entered-cleanup-operation")
		require.NoError(t, err)
		won, err := restartedRepo.EnterConnect(enteredOwner, intent)
		require.NoError(t, err)
		require.True(t, won)
		binding := &oauthRefreshConnectBinding{GatewayNativeOAuthRepository: f1, journal: restartedRepo, intent: intent}
		bound, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, binding, key)
		require.NoError(t, err)
		native, err := bound.Stage(enteredOwner, enteredScope, intent.EnrollmentOperation, bundleFor("entered-cleanup-principal"))
		require.NoError(t, err)
		_, err = restartedRepo.FinishConnect(enteredOwner, binding.intent, "completed", native)
		require.NoError(t, err)
		request := service.GatewayNativeOAuthCleanupRequest{Scope: enteredScope, Operation: intent.Operation, Action: "read", CleanupRef: "entered-cleanup", CleanupToken: "current-token"}
		var mapped *service.GatewayNativeRoute
		authority := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			return service.GatewayNativeOAuthCleanupAuthority{Owner: enteredScope.Owner, LeaseExpiresAt: time.Now().Add(time.Second), Native: mapped}, nil
		}
		read, err := restarted.Cleanup(enteredOwner, request, authority)
		require.NoError(t, err)
		require.NotNil(t, read.Native)
		mapped = read.Native
		refreshRepo, ok := f1.(service.GatewayNativeOAuthRefreshRepository)
		require.True(t, ok)
		rotation := service.GatewayNativeOAuthRefreshIntent{Scope: enteredScope, AccountID: mapped.AccountID, CreatedAt: mapped.CreatedAt, ExpectedVersion: 1, Operation: "lost-enter-ack", Intent: "rotation-intent"}
		prepared, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(enteredOwner, rotation)
		require.NoError(t, err)
		entered, err := refreshRepo.EnterGatewayNativeOAuthRefresh(enteredOwner, rotation, prepared.Fence)
		require.NoError(t, err)
		require.True(t, entered)
		request.Action = "erase"
		erased, err := restarted.Cleanup(enteredOwner, request, authority)
		require.NoError(t, err)
		require.True(t, erased.CredentialsErased)
		require.Equal(t, "unknown", erased.Closure)
		require.Equal(t, mapped, erased.Native)
		require.NoError(t, refreshRepo.UnknownGatewayNativeOAuthRefresh(enteredOwner, rotation, prepared.Fence))
		replay, err := restarted.Cleanup(enteredOwner, request, authority)
		require.NoError(t, err)
		require.Equal(t, erased, replay)
		_, err = refreshRepo.CompleteGatewayNativeOAuthRefresh(enteredOwner, rotation, prepared.Fence, prepared.Envelope)
		require.Error(t, err)
		entered, err = refreshRepo.EnterGatewayNativeOAuthRefresh(enteredOwner, rotation, prepared.Fence)
		require.Error(t, err)
		require.False(t, entered)
		var retainedState string
		var erasedBirth bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT f.state,a.credentials='{}'::jsonb AND a.deleted_at IS NOT NULL FROM gateway_oauth_refresh_attempts f JOIN accounts a ON a.id=f.account_id WHERE f.consumer=$1 AND f.operation_ref=$2`, enteredScope.Consumer, rotation.Operation).Scan(&retainedState, &erasedBirth))
		require.Equal(t, "unknown", retainedState)
		require.True(t, erasedBirth)
		require.Equal(t, int32(1), exchanges.Load())
	})
	// Failure: early prepared cancellation violates immutable TTL and could forge
	// NoEffect. Real expiry is positive no-entry; no polling/sleep is necessary.
	t.Run("prepared cleanup preserves TTL then proves real expiry", func(t *testing.T) {
		expiredOwner, expiredScope := oauthPGScope(t, "expiry-cleanup-consumer", "expiry-cleanup-owner", "expiry-cleanup-account")
		_, err := restarted.BeginConnect(expiredOwner, expiredScope, "expiry-cleanup-operation")
		require.NoError(t, err)
		live, err := restartedRepo.ReadConnectIntent(expiredOwner, expiredScope, "expiry-cleanup-operation")
		require.NoError(t, err)
		in := service.GatewayNativeOAuthCleanupRequest{Scope: expiredScope, Operation: live.Operation, Action: "erase", CleanupRef: "expiry-cleanup", CleanupToken: "current-token"}
		authority := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			return service.GatewayNativeOAuthCleanupAuthority{Owner: expiredScope.Owner, LeaseExpiresAt: time.Now().Add(time.Second)}, nil
		}
		pending, err := restarted.Cleanup(expiredOwner, in, authority)
		require.NoError(t, err)
		require.Equal(t, "pending", pending.Closure)
		require.False(t, pending.CredentialsErased)
		saved, err := restartedRepo.ReadConnectIntent(expiredOwner, expiredScope, live.Operation)
		require.NoError(t, err)
		require.Equal(t, live, saved)
		// The existing fixture may INSERT a fresh shorter deadline under migration
		// 245; it must never UPDATE an already accepted prepared deadline.
		expiredOperation := "short-expiry-operation"
		short := live
		short.Operation = expiredOperation
		short.EnrollmentOperation = "connect-" + uuid.NewString()
		short.StateHash = strings.Repeat("b", 64)
		short.Deadline = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
		_, err = restartedRepo.PrepareConnect(expiredOwner, short)
		require.NoError(t, err)
		// Wait only the accepted short test TTL, never poll inside the handler.
		timer := time.NewTimer(time.Until(short.Deadline))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("fixture expiry deadline interrupted")
		}
		in.Operation = expiredOperation
		closed, err := restarted.Cleanup(expiredOwner, in, authority)
		require.NoError(t, err)
		require.Equal(t, "closed", closed.Closure)
		require.True(t, closed.CredentialsErased)
		require.Nil(t, closed.Native)
		after, err := restartedRepo.ReadConnectIntent(expiredOwner, expiredScope, expiredOperation)
		require.NoError(t, err)
		require.Equal(t, "expired", after.State)
		require.Empty(t, after.Envelope)
		won, err := restartedRepo.EnterConnect(expiredOwner, after)
		require.NoError(t, err)
		require.False(t, won)
	})
	// Real F1 A exists under the same caller operation/scope. F3 B exchanges
	// once and hits the actual principal/generation conflict; A is never B's ACK.
	priorOwner, priorScope := oauthPGScope(t, "prior-consumer", "prior-owner", "prior-logical")
	priorEnrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, f1, key)
	require.NoError(t, err)
	bundle = bundleFor("f3-prior-principal")
	prior, err := priorEnrollment.Stage(priorOwner, priorScope, "prior-operation", bundle)
	require.NoError(t, err)
	bundle.AccessToken += "-new-B"
	priorBegin, err := restarted.BeginConnect(priorOwner, priorScope, "prior-operation")
	require.NoError(t, err)
	priorURL, err := url.Parse(priorBegin.AuthorizeURL)
	require.NoError(t, err)
	challenge = priorURL.Query().Get("code_challenge")
	failed, err := restarted.CompleteCallback(ctx, priorURL.Query().Get("state"), "fixture-code")
	require.NoError(t, err)
	require.Equal(t, "unknown", failed.State)
	priorIntent, err := restartedRepo.ReadConnectIntent(priorOwner, priorScope, "prior-operation")
	require.NoError(t, err)
	require.NotEmpty(t, priorIntent.EnrollmentMAC)
	stillPrior, err := f1.ReadGatewayNativeOAuth(priorOwner, priorScope, "prior-operation")
	require.NoError(t, err)
	require.Equal(t, prior, stillPrior)
	_, err = restartedRepo.FinishConnect(priorOwner, priorIntent, "completed", prior)
	require.Error(t, err)
	// Even a forged operation/generation cannot turn the wrong physical row
	// into this intent's result; the DB verifies the actual commitment and birth.
	forged := prior
	forged.Operation = priorIntent.EnrollmentOperation
	_, err = restartedRepo.FinishConnect(priorOwner, priorIntent, "completed", forged)
	require.Error(t, err)
	for _, field := range []string{"consumer", "owner", "account", "generation", "commitment"} {
		changed := completed.Scope
		mac := completed.EnrollmentMAC
		changedCtx := owner
		switch field {
		case "consumer":
			changed.Consumer = "foreign"
			changedCtx, err = service.WithGatewayNativeConsumer(owner, changed.Consumer)
			require.NoError(t, err)
		case "owner":
			changed.Owner = "foreign"
			changedCtx, err = service.WithGatewayNativeOAuthOwner(owner, changed.Owner)
			require.NoError(t, err)
		case "account":
			changed.Account = "foreign"
		case "generation":
			changed.Generation = uuid.NewString()
		case "commitment":
			mac = strings.Repeat("0", 64)
		}
		_, found, err := f1.ReplayGatewayNativeOAuth(changedCtx, changed, completed.EnrollmentOperation, mac)
		require.False(t, found)
		if field == "consumer" {
			require.NoError(t, err) // scoped absence yields no custody result
		} else {
			require.Error(t, err)
		}
	}
	_, err = restarted.CompleteCallback(ctx, priorURL.Query().Get("state"), "another-code")
	require.NoError(t, err)
	require.Equal(t, int32(2), exchanges.Load())

	// A prepared private operation cannot be used by an independent F1 writer.
	// The guard also denies a mismatched commitment after the entry is bound.
	exclusiveOwner, exclusiveScope := oauthPGScope(t, "exclusive-consumer", "exclusive-owner", "exclusive-logical")
	_, err = restarted.BeginConnect(exclusiveOwner, exclusiveScope, "exclusive-operation")
	require.NoError(t, err)
	exclusiveIntent, err := restartedRepo.ReadConnectIntent(exclusiveOwner, exclusiveScope, "exclusive-operation")
	require.NoError(t, err)
	exclusiveBundle := bundleFor("f3-exclusive-principal")
	_, err = priorEnrollment.Stage(exclusiveOwner, exclusiveScope, exclusiveIntent.EnrollmentOperation, exclusiveBundle)
	require.Error(t, err)
	won, err = restartedRepo.EnterConnect(exclusiveOwner, exclusiveIntent)
	require.NoError(t, err)
	require.True(t, won)
	exclusiveIntent, err = restartedRepo.BindConnectEnrollment(exclusiveOwner, exclusiveIntent, strings.Repeat("0", 64))
	require.NoError(t, err)
	_, err = priorEnrollment.Stage(exclusiveOwner, exclusiveScope, exclusiveIntent.EnrollmentOperation, exclusiveBundle)
	require.Error(t, err)
	var candidates int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_identity_reservations WHERE consumer=$1`, exclusiveScope.Consumer).Scan(&candidates))
	require.Zero(t, candidates)
	sealed, err := restartedRepo.FinishConnect(exclusiveOwner, exclusiveIntent, "quarantined", service.GatewayNativeOAuthOutcome{})
	require.NoError(t, err)
	require.True(t, sealed.RecoveryDenied)
	_, err = restartedRepo.BindConnectEnrollment(exclusiveOwner, sealed, strings.Repeat("1", 64))
	require.Error(t, err)
	// Actual accepted F1 operation collision at Prepare is denied by SQL,
	// rather than relying on the probability of a fresh private UUID alone.
	collision := exclusiveIntent
	collision.Operation = "collision-operation"
	collision.EnrollmentOperation = completed.EnrollmentOperation
	collision.Scope = completed.Scope
	collision.StateHash = strings.Repeat("1", 64)
	collision.State = "prepared"
	collision.Envelope = prepared.Envelope
	collision.EnrollmentMAC = ""
	collision.RecoveryDenied = false
	_, err = restartedRepo.PrepareConnect(owner, collision)
	require.Error(t, err)
}
