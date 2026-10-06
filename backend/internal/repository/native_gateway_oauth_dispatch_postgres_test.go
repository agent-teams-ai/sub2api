package repository

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// One real migrated boundary: controlled qualification CAS, immutable physical
// identity, existing refresh publication under the same row lock, and unknown
// refresh fencing. No provisioning and no mock SQL acceptance.
func TestGatewayNativeOAuthDispatchPostgresQualificationRefreshFence(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OAUTH_DISPATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: disposable OAuth dispatch PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_oauth_dispatch_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close fixture database: %v", closeErr)
		}
	}()
	db.SetMaxOpenConns(4)
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	// Safety qualification uses rollback-only objects before ANY migration. No
	// DROP/reset; the same empty purpose database remains available to the root.
	for _, ddl := range []string{
		`CREATE SCHEMA inherited_object_fixture; CREATE TABLE inherited_object_fixture.accounts(id bigint)`,
		`CREATE SCHEMA inherited_function_fixture; CREATE FUNCTION inherited_function_fixture.fixture() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`CREATE FUNCTION public.fixture() RETURNS int LANGUAGE sql AS 'SELECT 1'`,
	} {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, ddl)
		require.NoError(t, err)
		require.Error(t, requireOAuthDispatchEmptyObjects(ctx, tx))
		require.NoError(t, tx.Rollback())
	}
	var superuser bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&superuser))
	if superuser {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func(tx *sql.Tx) {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				t.Errorf("rollback regression fixture: %v", rollbackErr)
			}
		}(tx)
		_, err = tx.ExecContext(ctx, `CREATE FUNCTION pg_catalog.oauth_empty_guard_fixture() RETURNS int LANGUAGE sql AS 'SELECT 1';
 ALTER EXTENSION plpgsql ADD FUNCTION pg_catalog.oauth_empty_guard_fixture()`)
		require.NoError(t, err)
		require.Error(t, requireOAuthDispatchEmptyObjects(ctx, tx), "user function added to default extension must deny before migrations")
		require.NoError(t, tx.Rollback())
		require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db), "rollback must restore the original empty database")

		tx, err = db.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `CREATE LANGUAGE oauth_empty_guard_fixture HANDLER pg_catalog.plpgsql_call_handler`)
		require.NoError(t, err)
		require.Error(t, requireOAuthDispatchEmptyObjects(ctx, tx), "schema-less user language must deny before migrations")
		require.NoError(t, tx.Rollback())
		require.True(t, t.Run("pinned text-search template denies migrations", func(t *testing.T) {
			// Pinned namespace/function dependencies are omitted by PG17.
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() {
				if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					t.Errorf("rollback template fixture: %v", rollbackErr)
				}
			}()
			_, err = tx.ExecContext(ctx, `CREATE TEXT SEARCH TEMPLATE pg_catalog.oauth_empty_template_fixture (INIT = pg_catalog.dsimple_init, LEXIZE = pg_catalog.dsimple_lexize)`)
			require.NoError(t, err)
			require.Error(t, requireOAuthDispatchEmptyObjects(ctx, tx), "pinned template must deny before migrations")
		}), "template guard and checked rollback must pass before migrations")
		require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db), "rollback must restore the empty database")
	} else {
		t.Log("PG_OBJECT_SUBCASE_NOT_RUN: purpose DB role cannot create system-schema function/extension member or procedural language")
	}
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	repo := NewAccountRepository(nil, db, nil)
	stageRepo, ok := repo.(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	dispatchRepo, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok)
	refreshRepo, ok := repo.(service.GatewayNativeOAuthRefreshRepository)
	require.True(t, ok)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	verifier, bundleFor, jwksGate := oauthDispatchPGSignedFixture(t)
	subject := uuid.NewString()
	bundle := bundleFor(subject)
	bundle.AccessToken = uuid.NewString()
	bundle.RefreshToken = uuid.NewString()
	bundle.SensitiveMetadata = json.RawMessage(`{"expires_in":3600}`)
	ownerCtx, scope := oauthPGScope(t, uuid.NewString(), uuid.NewString(), uuid.NewString())
	operation := uuid.NewString()
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, stageRepo, key)
	require.NoError(t, err)
	connectRepo, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connectTokens := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "id_token": bundle.IDToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	defer connectTokens.Close()
	connectBaseTransport, ok := connectTokens.Client().Transport.(*http.Transport)
	require.True(t, ok)
	connectTransport := connectBaseTransport.Clone()
	connectTransport.TLSClientConfig.ServerName = "example.com"
	connectTransport.DisableKeepAlives = true
	defer connectTransport.CloseIdleConnections()
	connectTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, connectTokens.Listener.Addr().String())
	}
	connect, err := service.NewGatewayNativeOAuthConnect(key, connectTransport, connectRepo, enrollment, stageRepo)
	require.NoError(t, err)
	begun, err := connect.BeginConnect(ownerCtx, scope, operation)
	require.NoError(t, err)
	authorizeURL, err := url.Parse(begun.AuthorizeURL)
	require.NoError(t, err)
	provider := uuid.NewString()
	var checks atomic.Int32
	check := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks.Add(1)
		require.Equal(t, "chatgpt.com", r.Host)
		require.Equal(t, "/backend-api/accounts/check/v4-2023-04-27", r.URL.Path)
		require.Equal(t, "Bearer "+bundle.AccessToken, r.Header.Get("Authorization"))
		_, _ = fmt.Fprintf(w, `{"accounts":{"unrelated-workspace":{"account":{"account_id":%q}}}}`, provider)
	}))
	defer check.Close()
	baseTransport, ok := check.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "chatgpt.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, check.Listener.Addr().String())
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(dispatchRepo, custody, verifier, transport)
	require.NoError(t, err)
	pending, err := dispatch.Descriptor(ownerCtx, scope, operation)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.Qualification)
	require.Nil(t, pending.Native)
	require.Zero(t, checks.Load())
	completed, err := connect.CompleteCallback(ownerCtx, authorizeURL.Query().Get("state"), uuid.NewString())
	require.NoError(t, err)
	require.Equal(t, "completed", completed.State)
	require.Equal(t, operation, completed.Operation)
	saved, err := connectRepo.ReadConnectIntent(ownerCtx, scope, operation)
	require.NoError(t, err)
	staged := saved.Outcome
	require.Equal(t, saved.EnrollmentOperation, staged.Operation)
	require.NotEqual(t, operation, staged.Operation)
	out, err := dispatch.Descriptor(ownerCtx, scope, operation)
	require.NoError(t, err)
	require.NotNil(t, out.Native)
	consumerCtx, err := service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	canonical, ok := repo.(service.GatewayNativeOAuthCanonicalRepository)
	require.True(t, ok)
	selected, selectedOperation, err := canonical.ResolveGatewayNativeOAuthCanonical(consumerCtx, *out.Native, scope.Account)
	require.NoError(t, err)
	require.Equal(t, scope, selected)
	require.Equal(t, operation, selectedOperation)
	for _, wrong := range []service.GatewayNativeRoute{
		{AccountID: out.Native.AccountID, Generation: out.Native.Generation, CreatedAt: out.Native.CreatedAt.Add(time.Microsecond), Profile: out.Native.Profile, BaseURL: out.Native.BaseURL, Model: out.Native.Model},
		{AccountID: out.Native.AccountID, Generation: uuid.NewString(), CreatedAt: out.Native.CreatedAt, Profile: out.Native.Profile, BaseURL: out.Native.BaseURL, Model: out.Native.Model},
	} {
		_, _, err = canonical.ResolveGatewayNativeOAuthCanonical(consumerCtx, wrong, scope.Account)
		require.Error(t, err)
	}
	foreignCtx, err := service.WithGatewayNativeConsumer(ctx, "foreign-consumer")
	require.NoError(t, err)
	_, _, err = canonical.ResolveGatewayNativeOAuthCanonical(foreignCtx, *out.Native, scope.Account)
	require.Error(t, err)
	require.Equal(t, staged.AccountID, out.Native.AccountID)
	require.Equal(t, operation, out.Operation)
	// Neither the hidden enrollment operation nor an F1-only custody row is an
	// original completed connect operation. They cannot mint a descriptor.
	_, err = dispatch.Descriptor(ownerCtx, scope, staged.Operation)
	require.Error(t, err)
	orphanCtx, orphanScope := oauthPGScope(t, scope.Consumer, scope.Owner, uuid.NewString())
	orphanOperation := uuid.NewString()
	orphan, err := enrollment.Stage(orphanCtx, orphanScope, orphanOperation, bundleFor(uuid.NewString()))
	require.NoError(t, err)
	_, err = dispatch.Descriptor(orphanCtx, orphanScope, orphanOperation)
	require.Error(t, err)
	_, _, _, err = dispatchRepo.LockGatewayNativeOAuthDispatch(orphanCtx, orphanScope, orphanOperation, orphan.AccountID)
	require.Error(t, err)
	require.EqualValues(t, 1, checks.Load())
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, staged.AccountID).Scan(&count))
	require.Equal(t, 1, count)
	var receiptOperation, receiptOwner, receiptAccount, receiptGeneration string
	var receiptBirth time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT operation_ref,owner_ref,account_ref,generation,native_created_at
 FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, staged.AccountID).Scan(&receiptOperation, &receiptOwner, &receiptAccount, &receiptGeneration, &receiptBirth))
	require.Equal(t, operation, receiptOperation)
	require.Equal(t, scope.Owner, receiptOwner)
	require.Equal(t, scope.Account, receiptAccount)
	require.Equal(t, scope.Generation, receiptGeneration)
	require.True(t, out.Native.CreatedAt.Equal(receiptBirth))
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_profile_qualifications SET provider_account_id=$1 WHERE account_id=$2`, uuid.NewString(), staged.AccountID)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `DELETE FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, staged.AccountID)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `UPDATE accounts SET status='active' WHERE id=$1`, staged.AccountID)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `UPDATE accounts SET created_at=created_at+interval '1 microsecond' WHERE id=$1`, staged.AccountID)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_identity_reservations SET subject=$1 WHERE account_id=$2`, uuid.NewString(), staged.AccountID)
	require.Error(t, err)
	_, _, release, err := dispatchRepo.LockGatewayNativeOAuthDispatch(ownerCtx, scope, operation, staged.AccountID)
	require.NoError(t, err)
	defer release()
	wrong := scope
	wrong.Owner = uuid.NewString()
	_, _, _, err = dispatchRepo.LockGatewayNativeOAuthDispatch(ownerCtx, wrong, operation, staged.AccountID)
	require.Error(t, err)
	// Real F2 refresh must publish only after the dispatch lock is released,
	// while retaining the qualified native birth/provider account and owner.
	next := bundleFor(subject)
	next.AccessToken = uuid.NewString()
	next.RefreshToken = uuid.NewString()
	tokens := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, bundle.RefreshToken, r.PostForm.Get("refresh_token"))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": next.AccessToken, "refresh_token": next.RefreshToken, "id_token": next.IDToken, "token_type": "Bearer", "expires_in": 3600})
	}))
	defer tokens.Close()
	tokenTransport := tokens.Client().Transport.(*http.Transport).Clone()
	tokenTransport.TLSClientConfig.ServerName = "example.com"
	defer tokenTransport.CloseIdleConnections()
	tokenTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, tokens.Listener.Addr().String())
	}
	refresh, err := service.NewGatewayNativeOAuthRefresh(refreshRepo, custody, verifier, tokenTransport)
	require.NoError(t, err)
	intent := service.GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: staged.AccountID, CreatedAt: out.Native.CreatedAt, ExpectedVersion: 1, Operation: uuid.NewString(), Intent: uuid.NewString()}
	refreshCtx, stopRefresh := context.WithTimeout(ownerCtx, 5*time.Second)
	defer stopRefresh()
	done := make(chan error, 1)
	refreshReturned := make(chan struct{})
	go func() {
		defer close(refreshReturned)
		result, err := refresh.Refresh(refreshCtx, intent)
		if err == nil && (result.State != "completed" || result.Version != 2) {
			err = fmt.Errorf("refresh did not complete version2")
		}
		done <- err
	}()
	firstRelease := release
	defer func() {
		firstRelease()
		stopRefresh()
		select {
		case <-refreshReturned:
		case <-time.After(5 * time.Second):
			t.Error("refresh goroutine did not stop")
		}
	}()
	select {
	case err := <-done:
		release()
		t.Fatalf("refresh crossed held physical row lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-refreshCtx.Done():
		t.Fatal("refresh did not complete after row lock release")
	}
	a, p, release, err := dispatchRepo.LockGatewayNativeOAuthDispatch(ownerCtx, scope, operation, staged.AccountID)
	require.NoError(t, err)
	if release != nil {
		defer release()
	}
	require.Equal(t, "2", a.GetCredential("credential_version"))
	require.Equal(t, provider, p.ProviderAccount)
	require.True(t, service.SameGatewayNativeDescriptor(*out.Native, p.Route))
	require.Equal(t, scope, p.Scope)
	require.Equal(t, operation, p.Operation)
	require.Equal(t, service.StatusDisabled, a.Status)
	require.False(t, a.Schedulable)
	release()
	// Engine ambiguity is a fence, never automatic qualification or recovery.
	intent.ExpectedVersion = 2
	intent.Operation = uuid.NewString()
	intent.Intent = uuid.NewString()
	prepared, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(ownerCtx, intent)
	require.NoError(t, err)
	require.True(t, prepared.Claimed)
	// Exact F2 UNKNOWN publication: physical FOR UPDATE acquired, but only the
	// journal tuple changes. A concurrent dispatch must wait for that row lock
	// and then see the newly committed UNKNOWN in a fresh statement snapshot.
	gate := &oauthDispatchPGEntryGate{GatewayNativeOAuthDispatchRepository: dispatchRepo, waiting: make(chan struct{}), proceed: make(chan struct{})}
	gatedDispatch, err := service.NewGatewayNativeOAuthDispatch(gate, custody, verifier, transport)
	require.NoError(t, err)
	blocked := make(chan oauthDispatchPGForwardResult, 1)
	blockedCtx, stopBlocked := context.WithTimeout(ownerCtx, 4*time.Second)
	defer stopBlocked()
	blockedReturned := make(chan struct{})
	var providerEntries atomic.Int32
	gateway := oauthDispatchPGGateway(t, repo, &providerEntries)
	go func() {
		defer close(blockedReturned)
		blocked <- oauthDispatchPGForward(blockedCtx, gatedDispatch, gateway, scope, operation, *out.Native)
	}()
	defer func() {
		stopBlocked()
		select {
		case <-blockedReturned:
		case <-time.After(5 * time.Second):
			t.Error("blocked dispatch goroutine did not stop")
		}
	}()
	// The initial snapshot has returned/released. Pause only the actual second,
	// pre-entry physical read; a later reread cannot mask a stale first snapshot.
	select {
	case <-gate.waiting:
	case <-blockedCtx.Done():
		t.Fatal("pre-entry gate not reached")
	}
	writer, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	require.NoError(t, err)
	defer func() {
		if rollbackErr := writer.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			t.Errorf("rollback held writer: %v", rollbackErr)
		}
	}()
	var writerPID int
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
	var id int64
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, staged.AccountID).Scan(&id))
	close(gate.proceed)
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
   AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))`, writerPID).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond, "dispatch must actually wait on physical row")
	result, err := writer.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='unknown'
  WHERE consumer=$1 AND operation_ref=$2 AND fence=$3 AND state='prepared'`, scope.Consumer, intent.Operation, prepared.Fence)
	require.NoError(t, err)
	changed, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, changed)
	require.NoError(t, writer.Commit())
	var blockedResult oauthDispatchPGForwardResult
	select {
	case blockedResult = <-blocked:
	case <-blockedCtx.Done():
		t.Fatal("blocked dispatch did not return")
	}
	require.False(t, blockedResult.entered, "returned entry flag must deny UNKNOWN")
	require.False(t, blockedResult.lifetime.Entered, "lifetime must deny UNKNOWN independently")
	require.Error(t, blockedResult.err)
	require.True(t, gate.denied.Load(), "fresh SQL pre-entry read must itself deny committed UNKNOWN before JWKS")
	require.EqualValues(t, 2, gate.calls.Load())
	require.Zero(t, providerEntries.Load())
	_, _, _, err = dispatchRepo.LockGatewayNativeOAuthDispatch(ownerCtx, scope, operation, staged.AccountID)
	require.Error(t, err)
	_, err = dispatch.Descriptor(ownerCtx, scope, operation)
	require.Error(t, err)

	// A distinct completed connect is required: UNKNOWN is retained and never
	// rearmed. Delay a genuine signed JWKS answer across the fresh SQL deadline.
	secondCtx, secondScope := oauthPGScope(t, scope.Consumer, scope.Owner, uuid.NewString())
	secondOperation := uuid.NewString()
	bundle = bundleFor(uuid.NewString())
	provider = uuid.NewString()
	secondBegin, err := connect.BeginConnect(secondCtx, secondScope, secondOperation)
	require.NoError(t, err)
	secondAuthorize, err := url.Parse(secondBegin.AuthorizeURL)
	require.NoError(t, err)
	_, err = connect.CompleteCallback(secondCtx, secondAuthorize.Query().Get("state"), uuid.NewString())
	require.NoError(t, err)
	secondDescriptor, err := dispatch.Descriptor(secondCtx, secondScope, secondOperation)
	require.NoError(t, err)
	require.NotNil(t, secondDescriptor.Native)
	secondIntent := service.GatewayNativeOAuthRefreshIntent{Scope: secondScope, AccountID: secondDescriptor.Native.AccountID, CreatedAt: secondDescriptor.Native.CreatedAt, ExpectedVersion: 1, Operation: uuid.NewString(), Intent: uuid.NewString()}
	secondPrepared, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(secondCtx, secondIntent)
	require.NoError(t, err)
	require.True(t, secondPrepared.Claimed)
	var sqlNow time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&sqlNow))
	// Leave enough time for genuine verification to arrive. Arrival is mandatory:
	// a late initial SQL read/early rejection cannot satisfy this regression.
	if wait := secondPrepared.Deadline.Sub(sqlNow) - 2*time.Second; wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("SQL deadline approach timed out")
		}
	}
	forwardCtx, stopForward := context.WithTimeout(secondCtx, 4*time.Second)
	defer stopForward()
	jwksGate.enabled.Store(true)
	expired := make(chan oauthDispatchPGForwardResult, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		expired <- oauthDispatchPGForward(forwardCtx, dispatch, gateway, secondScope, secondOperation, *secondDescriptor.Native)
	}()
	defer func() {
		jwksGate.releaseOnce.Do(func() { close(jwksGate.release) })
		stopForward()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Error("expiry dispatch goroutine did not stop")
		}
	}()
	var jwksCtx context.Context
	select {
	case jwksCtx = <-jwksGate.arrived:
	case early := <-expired:
		t.Fatalf("dispatch returned before genuine JWKS arrival: entered=%v lifetime=%+v err=%v", early.entered, early.lifetime, early.err)
	case <-forwardCtx.Done():
		t.Fatal("genuine JWKS verification did not arrive")
	}
	require.NoError(t, db.QueryRowContext(forwardCtx, `SELECT clock_timestamp()`).Scan(&sqlNow))
	require.True(t, sqlNow.Before(secondPrepared.Deadline), "JWKS verification must start before the actual SQL deadline")
	require.NoError(t, forwardCtx.Err())
	require.NoError(t, jwksCtx.Err())
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for sqlNow.Before(secondPrepared.Deadline) {
		select {
		case <-tick.C:
		case <-forwardCtx.Done():
			t.Fatal("caller expired before SQL deadline crossed")
		}
		require.NoError(t, db.QueryRowContext(forwardCtx, `SELECT clock_timestamp()`).Scan(&sqlNow))
	}
	require.False(t, sqlNow.Before(secondPrepared.Deadline), "actual SQL clock must cross the saved deadline before JWKS release")
	require.NoError(t, forwardCtx.Err(), "caller must remain valid across SQL expiry")
	require.NoError(t, jwksCtx.Err(), "JWKS request must remain live at release")
	jwksGate.releaseOnce.Do(func() { close(jwksGate.release) })
	select {
	case responseErr := <-jwksGate.responded:
		require.NoError(t, responseErr, "genuine signed JWKS must be delivered")
	case <-forwardCtx.Done():
		t.Fatal("JWKS delivery did not finish")
	}
	select {
	case rejected := <-expired:
		require.False(t, rejected.entered, "returned entry flag must deny SQL expiry")
		require.False(t, rejected.lifetime.Entered, "lifetime must deny SQL expiry independently")
		// Forward finishes/cancels its owned lifetime even on rejection; the
		// caller's independent deadline must still be valid after that return.
		require.NoError(t, forwardCtx.Err(), "rejection must occur while caller is valid")
		require.Error(t, rejected.err)
	case <-forwardCtx.Done():
		t.Fatal("dispatch did not reject while caller was valid")
	}
	require.Zero(t, providerEntries.Load())
}

// Provider inference goes only to this counting fixture; any Do call means
// the retained entry fence failed. No real origin or ordinary fallback exists.
type oauthDispatchPGUpstream struct{ client *http.Client }

func (u *oauthDispatchPGUpstream) Do(r *http.Request, _ string, _ int64, concurrency int) (*http.Response, error) {
	if concurrency != 0 {
		return nil, fmt.Errorf("ordinary OAuth limiter entered")
	}
	return u.client.Do(r)
}
func (u *oauthDispatchPGUpstream) DoWithTLS(r *http.Request, p string, id int64, c int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(r, p, id, c)
}
func oauthDispatchPGGateway(t *testing.T, repo service.AccountRepository, entries *atomic.Int32) *service.OpenAIGatewayService {
	t.Helper()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "chatgpt.com", r.Host)
		require.Equal(t, "/backend-api/codex/responses", r.URL.Path)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(provider.Close)
	transport := provider.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "chatgpt.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, provider.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	upstream, err := service.NewGatewayNativeLifetimeUpstream(&oauthDispatchPGUpstream{client: &http.Client{Transport: transport, Timeout: time.Second}})
	require.NoError(t, err)
	cfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}}
	return service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
}

type oauthDispatchPGForwardResult struct {
	entered  bool
	lifetime service.GatewayNativeLifetimeSnapshot
	err      error
}

func oauthDispatchPGForward(ctx context.Context, dispatch *service.GatewayNativeOAuthDispatch, gateway *service.OpenAIGatewayService, scope service.GatewayNativeCredentialScope, operation string, route service.GatewayNativeRoute) (result oauthDispatchPGForwardResult) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	life, err := service.NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
	if err != nil {
		result.err = err
		return
	}
	defer func() { result.lifetime = life.Snapshot() }()
	life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
	if !life.Admit(time.Now().Add(4 * time.Second)) {
		result.err = service.ErrGatewayNativeIdentity
		return
	}
	ctx = service.WithGatewayNativeLifetime(ctx, life)
	ctx, err = service.WithGatewayNativeOAuthDispatch(ctx, dispatch, scope, operation, 4096, 128)
	if err != nil {
		result.err = err
		return
	}
	body := []byte(`{"model":"gpt-6.1-sol","stream":true,"store":false,"service_tier":"default","max_output_tokens":128,"input":"controlled fence"}`)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
	_, result.entered, result.err = gateway.ForwardGatewayRoute(ctx, c, route, body)
	return
}

type oauthDispatchPGJWKSGate struct {
	enabled     atomic.Bool
	arrived     chan context.Context
	release     chan struct{}
	releaseOnce sync.Once
	responded   chan error
}

func oauthDispatchPGSignedFixture(t *testing.T) (*service.GatewayNativeOAuthVerifier, func(string) service.GatewayNativeOAuthBundle, *oauthDispatchPGJWKSGate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	gate := &oauthDispatchPGJWKSGate{arrived: make(chan context.Context, 1), release: make(chan struct{}), responded: make(chan error, 1)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/.well-known/jwks.json", r.URL.Path)
		gated := gate.enabled.Load()
		if gated {
			select {
			case gate.arrived <- r.Context():
			case <-r.Context().Done():
				return
			case <-time.After(4 * time.Second):
				return
			}
			select {
			case <-gate.release:
			case <-r.Context().Done():
				return
			case <-time.After(4 * time.Second):
				return
			}
		}
		err := json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "fixture", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		if gated {
			select {
			case gate.responded <- err:
			case <-r.Context().Done():
			case <-time.After(4 * time.Second):
			}
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { gate.releaseOnce.Do(func() { close(gate.release) }) })
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	sign := func(subject string) service.GatewayNativeOAuthBundle {
		claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":"app_EMoamEEZ73f0CkXaXp7hrann","exp":%d}`, service.GatewayOAuthIssuer, subject, time.Now().Add(time.Hour).Unix())
		body := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)
		return service.GatewayNativeOAuthBundle{AccessToken: uuid.NewString(), RefreshToken: uuid.NewString(), IDToken: body + "." + base64.RawURLEncoding.EncodeToString(signature), SensitiveMetadata: json.RawMessage(`{"expires_in":3600}`)}
	}
	return service.NewGatewayNativeOAuthVerifier(transport), sign, gate
}

// Applied by lib/pq startup to EVERY connection, including migration pool
// replacements. No inherited search_path and no one-session SET workaround.
func openOAuthDispatchFixtureDB(dsn string) (*sql.DB, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	values := u.Query()
	values.Set("search_path", "public,pg_catalog")
	values.Set("options", "-c search_path=public,pg_catalog")
	u.RawQuery = values.Encode()
	connector, err := pq.NewConnector(u.String())
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// Namespace dependencies cover tables/views/sequences, functions, types,
// operators, collations, conversions, statistics and text-search objects.
// Include global objects and extension-owned objects, even in system schemas;
// Only default initdb objects below FirstNormalObjectId (16384) are allowed
// in system schemas. Extension membership never exempts a user-created object.
// An empty non-public user schema is also refused. Never reset/drop anything.
const oauthDispatchEmptyObjectsSQL = `SELECT
 (SELECT count(*) FROM pg_namespace WHERE nspname <> 'public' AND nspname <> 'information_schema' AND nspname !~ '^pg_') +
 (SELECT count(*) FROM pg_depend d JOIN pg_namespace n ON d.refclassid='pg_namespace'::regclass AND d.refobjid=n.oid
  WHERE (n.nspname <> 'information_schema' AND n.nspname !~ '^pg_') OR d.objid>=16384) +
 (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql' OR oid>=16384) +
 (SELECT count(*) FROM pg_foreign_data_wrapper) + (SELECT count(*) FROM pg_foreign_server) +
 (SELECT count(*) FROM pg_event_trigger) + (SELECT count(*) FROM pg_publication) +
 (SELECT count(*) FROM pg_subscription) + (SELECT count(*) FROM pg_largeobject_metadata) +
 (SELECT count(*) FROM pg_cast WHERE oid>=16384) +
 (SELECT count(*) FROM pg_language WHERE lanname NOT IN ('internal','c','sql','plpgsql') OR oid>=16384) +
 (SELECT count(*) FROM pg_transform) + (SELECT count(*) FROM pg_am WHERE oid>=16384) +
 (SELECT count(*) FROM pg_default_acl) +
 (SELECT count(*) FROM pg_proc WHERE oid>=16384) +
 (SELECT count(*) FROM pg_ts_template WHERE oid>=16384) +
 (SELECT count(*) FROM pg_ts_parser WHERE oid>=16384) +
 (SELECT count(*) FROM pg_ts_dict WHERE oid>=16384) +
 (SELECT count(*) FROM pg_ts_config WHERE oid>=16384)`

func requireOAuthDispatchEmptyObjects(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var objects int64
	if db.QueryRowContext(ctx, oauthDispatchEmptyObjectsSQL).Scan(&objects) != nil || objects != 0 {
		return errors.New("new isolated database with no user objects required")
	}
	return nil
}

// Actual lib/pq protocol check; it proves startup configuration for two pooled
// connections. This loopback protocol fixture is NOT PostgreSQL execution.
func TestOAuthDispatchFixturePinsEveryPQConnection(t *testing.T) {
	t.Setenv("PGOPTIONS", "-c search_path=inherited_foreign,public")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Errorf("close fixture listener: %v", closeErr)
		}
	}()
	seen := make(chan string, 2)
	failures := make(chan error, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				failures <- err
				return
			}
			go func(conn net.Conn) {
				// Background protocol teardown must not report after test completion.
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					failures <- err
					return
				}
				size := binary.BigEndian.Uint32(header)
				if size < 8 || size > 8192 {
					failures <- errors.New("invalid startup size")
					return
				}
				body := make([]byte, size-4)
				if _, err := io.ReadFull(conn, body); err != nil {
					failures <- err
					return
				}
				fields := strings.Split(string(body[4:]), "\x00")
				path := ""
				options := ""
				for i := 0; i+1 < len(fields); i += 2 {
					if fields[i] == "options" {
						options = fields[i+1]
					}
					if fields[i] == "search_path" {
						path = fields[i+1]
					}
				}
				seen <- path + "|" + options
				// AuthenticationOk, BackendKeyData, ReadyForQuery.
				_, err = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2, 'Z', 0, 0, 0, 5, 'I'})
				if err != nil {
					failures <- err
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}(conn)
		}
	}()
	db, err := openOAuthDispatchFixtureDB("postgres://fixture@" + listener.Addr().String() + "/gateway_oauth_dispatch_test_protocol?sslmode=disable")
	require.NoError(t, err)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close fixture database: %v", closeErr)
		}
	}()
	db.SetMaxOpenConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() {
		if closeErr := first.Close(); closeErr != nil {
			t.Errorf("close first fixture connection: %v", closeErr)
		}
	}()
	second, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() {
		if closeErr := second.Close(); closeErr != nil {
			t.Errorf("close second fixture connection: %v", closeErr)
		}
	}()
	for range 2 {
		select {
		case path := <-seen:
			require.Equal(t, "public,pg_catalog|-c search_path=public,pg_catalog", path)
		case err := <-failures:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("controlled lib/pq startup did not complete")
		}
	}
}

// Only timing is injected: both reads, locks, snapshots, journal transitions
// and account verification still execute the real repository on the purpose DB.
type oauthDispatchPGEntryGate struct {
	service.GatewayNativeOAuthDispatchRepository
	calls   atomic.Int32
	denied  atomic.Bool
	waiting chan struct{}
	proceed chan struct{}
}

func (g *oauthDispatchPGEntryGate) LockGatewayNativeOAuthDispatch(ctx context.Context, s service.GatewayNativeCredentialScope, op string, id int64) (*service.Account, service.GatewayNativeOAuthPhysical, func(), error) {
	second := g.calls.Add(1) == 2
	if second {
		close(g.waiting)
		select {
		case <-g.proceed:
		case <-ctx.Done():
			return nil, service.GatewayNativeOAuthPhysical{}, nil, ctx.Err()
		}
	}
	a, p, release, err := g.GatewayNativeOAuthDispatchRepository.LockGatewayNativeOAuthDispatch(ctx, s, op, id)
	if second {
		g.denied.Store(err != nil)
	}
	return a, p, release, err
}
