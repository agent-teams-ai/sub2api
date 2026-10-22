package repository

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// One real old-schema -> 249 boundary. The fixed historical birth below is
// fixture data, admitted by all original 243/245/246 guards. New births use the
// actual connect/enrollment/Descriptor path; no refresh fixture is repeated.
func TestGatewayNativeOAuthReconnectPostgresClaimsAndBackfill(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OAUTH_RECONNECT_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: disposable OAuth reconnect PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_oauth_reconnect_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	db.SetMaxOpenConns(4)
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	before := fstest.MapFS{}
	names, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	for _, name := range names {
		if name == "249_gateway_oauth_reconnect_claims.sql" || name == "250_gateway_oauth_supported_codex_model.sql" {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		require.NoError(t, err)
		before[name] = &fstest.MapFile{Data: body, Mode: 0444}
	}
	require.NoError(t, applyMigrationsFS(ctx, db, before))
	repo := NewAccountRepository(nil, db, nil)
	stageRepo, ok := repo.(service.GatewayNativeOAuthRepository)
	require.True(t, ok, "account repository must support native OAuth enrollment")
	dispatchRepo, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok, "account repository must support native OAuth dispatch")
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	verifier, bundleFor, _ := oauthDispatchPGSignedFixture(t)
	subject := uuid.NewString()
	bundle := bundleFor(subject)
	ownerCtx, scope := oauthPGScope(t, uuid.NewString(), uuid.NewString(), uuid.NewString())
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, stageRepo, key)
	require.NoError(t, err)
	connectRepo, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	tokens := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "id_token": bundle.IDToken, "token_type": "Bearer", "expires_in": 3600}))
	}))
	defer tokens.Close()
	tokenBaseTransport, ok := tokens.Client().Transport.(*http.Transport)
	require.True(t, ok, "TLS token fixture must expose its HTTP transport")
	tokenTransport := tokenBaseTransport.Clone()
	tokenTransport.TLSClientConfig.ServerName = "example.com"
	tokenTransport.DisableKeepAlives = true
	defer tokenTransport.CloseIdleConnections()
	tokenTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, tokens.Listener.Addr().String())
	}
	connect, err := service.NewGatewayNativeOAuthConnect(key, tokenTransport, connectRepo, enrollment, stageRepo)
	require.NoError(t, err)
	provider := uuid.NewString()
	check := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "chatgpt.com", r.Host)
		require.Equal(t, "/backend-api/accounts/check/v4-2023-04-27", r.URL.Path)
		require.Equal(t, "Bearer "+bundle.AccessToken, r.Header.Get("Authorization"))
		_, err := fmt.Fprintf(w, `{"accounts":{"workspace":{"account":{"account_id":%q}}}}`, provider)
		require.NoError(t, err)
	}))
	defer check.Close()
	checkBaseTransport, ok := check.Client().Transport.(*http.Transport)
	require.True(t, ok, "TLS account-check fixture must expose its HTTP transport")
	checkTransport := checkBaseTransport.Clone()
	checkTransport.TLSClientConfig.ServerName = "example.com"
	defer checkTransport.CloseIdleConnections()
	checkTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "chatgpt.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, check.Listener.Addr().String())
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(dispatchRepo, custody, verifier, checkTransport)
	require.NoError(t, err)

	// Seed a historical 248 birth and its old fixed-model receipt. The unchanged
	// database guard verifies its completed enrollment/birth before insertion.
	operation := uuid.NewString()
	_, err = connect.BeginConnect(ownerCtx, scope, operation)
	require.NoError(t, err)
	intent, err := connectRepo.ReadConnectIntent(ownerCtx, scope, operation)
	require.NoError(t, err)
	entered, err := connectRepo.EnterConnect(ownerCtx, intent)
	require.NoError(t, err)
	require.True(t, entered)
	intent, err = connectRepo.ReadConnectIntent(ownerCtx, scope, operation)
	require.NoError(t, err)
	intent, err = connectRepo.BindConnectEnrollment(ownerCtx, intent, strings.Repeat("a", 64))
	require.NoError(t, err)
	envelope, err := custody.SealOAuthBundle(scope, bundle)
	require.NoError(t, err)
	extra, err := json.Marshal(map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: service.GatewayOAuthStagingProfile, service.GatewayCredentialScopeExtraKey: scope.Metadata()})
	require.NoError(t, err)
	credentials, err := json.Marshal(map[string]string{"oauth_bundle": envelope})
	require.NoError(t, err)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_oauth_identity_reservations (issuer,subject,consumer,owner_ref,account_ref,generation,operation_ref,intent_mac) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, service.GatewayOAuthIssuer, subject, scope.Consumer, scope.Owner, scope.Account, scope.Generation, intent.EnrollmentOperation, intent.EnrollmentMAC)
	require.NoError(t, err)
	var oldID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO accounts (name,platform,type,status,schedulable,concurrency,priority,credentials,extra,created_at,updated_at) VALUES ('historical reconnect fixture','openai','oauth','disabled',false,1,0,$1::jsonb,$2::jsonb,NOW(),NOW()) RETURNING id`, string(credentials), string(extra)).Scan(&oldID)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE gateway_oauth_identity_reservations SET account_id=$1 WHERE consumer=$2 AND operation_ref=$3`, oldID, scope.Consumer, intent.EnrollmentOperation)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	oldOutcome := service.GatewayNativeOAuthOutcome{Operation: intent.EnrollmentOperation, AccountID: oldID, Generation: scope.Generation, State: "staged"}
	_, err = connectRepo.FinishConnect(ownerCtx, intent, "completed", oldOutcome)
	require.NoError(t, err)
	insertReceipt := func(model string) error {
		_, err := db.ExecContext(ctx, `INSERT INTO gateway_oauth_profile_qualifications
 (account_id,native_created_at,consumer,owner_ref,account_ref,generation,operation_ref,issuer,subject,provider_account_id,profile,base_url,model,qualification,qualified_at)
 SELECT a.id,a.created_at,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,clock_timestamp() FROM accounts a WHERE a.id=$1`,
			oldID, scope.Consumer, scope.Owner, scope.Account, scope.Generation, operation, service.GatewayOAuthIssuer, subject, provider,
			service.GatewayCodexOAuthResponsesProfile, service.GatewayCodexOAuthBaseURL, model, service.GatewayCodexOAuthQualification)
		return err
	}
	// The real pre250 constraint rejects the new model before the additive DDL.
	err = insertReceipt(service.GatewayCodexOAuthModel)
	var constraint *pq.Error
	require.True(t, errors.As(err, &constraint))
	require.Equal(t, "23514", string(constraint.Code))
	require.Equal(t, "gateway_oauth_profile_qualifications_model_check", constraint.Constraint)
	require.NoError(t, insertReceipt("gpt-6.1-sol"))
	var oldBirth time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at FROM accounts WHERE id=$1`, oldID).Scan(&oldBirth))
	oldRoute := service.GatewayNativeRoute{AccountID: oldID, CreatedAt: oldBirth, Generation: scope.Generation,
		Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: "gpt-6.1-sol"}
	snapshot := func() string {
		var value string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object('reservation',to_jsonb(r),'qualification',to_jsonb(q),'account',to_jsonb(a),'connect',to_jsonb(c))::text FROM gateway_oauth_identity_reservations r JOIN accounts a ON a.id=r.account_id JOIN gateway_oauth_profile_qualifications q ON q.account_id=a.id JOIN gateway_oauth_connect_intents c ON c.consumer=r.consumer AND c.enrollment_operation=r.operation_ref WHERE a.id=$1`, oldID).Scan(&value))
		return value
	}
	original := snapshot()
	require.NoError(t, ApplyMigrations(ctx, db))
	require.Equal(t, original, snapshot())
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_principal_claims WHERE issuer=$1 AND subject=$2 AND consumer=$3 AND owner_ref=$4 AND account_ref=$5`, service.GatewayOAuthIssuer, subject, scope.Consumer, scope.Owner, scope.Account).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_provider_claims WHERE provider_account_id=$1 AND issuer=$2 AND subject=$3 AND consumer=$4 AND owner_ref=$5 AND account_ref=$6`, provider, service.GatewayOAuthIssuer, subject, scope.Consumer, scope.Owner, scope.Account).Scan(&count))
	require.Equal(t, 1, count)

	// Reconnect has the same owner/account/principal/provider, a new operation
	// and generation, and a separate inert physical birth and qualification.
	_, nextScope := oauthPGScope(t, scope.Consumer, scope.Owner, scope.Account)
	nextOperation := uuid.NewString()
	begun, err := connect.BeginConnect(ownerCtx, nextScope, nextOperation)
	require.NoError(t, err)
	authorize, err := url.Parse(begun.AuthorizeURL)
	require.NoError(t, err)
	completed, err := connect.CompleteCallback(ownerCtx, authorize.Query().Get("state"), uuid.NewString())
	require.NoError(t, err)
	require.Equal(t, "completed", completed.State)
	current, err := dispatch.Descriptor(ownerCtx, nextScope, nextOperation)
	require.NoError(t, err)
	require.NotNil(t, current.Native)
	require.Equal(t, "gpt-5.6-sol", current.Native.Model)
	require.NotEqual(t, oldID, current.Native.AccountID)
	require.NotEqual(t, scope.Generation, current.Native.Generation)
	require.Equal(t, original, snapshot())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_profile_qualifications WHERE consumer=$1 AND account_ref=$2 AND provider_account_id=$3`, scope.Consumer, scope.Account, provider).Scan(&count))
	require.Equal(t, 2, count)
	// Both retained and new model receipts exist; every other model stays denied.
	var oldModel, currentModel string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT model FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, oldID).Scan(&oldModel))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT model FROM gateway_oauth_profile_qualifications WHERE account_id=$1`, current.Native.AccountID).Scan(&currentModel))
	require.Equal(t, "gpt-6.1-sol", oldModel)
	require.Equal(t, "gpt-5.6-sol", currentModel)
	err = insertReceipt("gpt-5.6")
	require.True(t, errors.As(err, &constraint))
	require.Equal(t, "23514", string(constraint.Code))
	require.Equal(t, "gateway_oauth_profile_qualifications_model_check", constraint.Constraint)
	require.Equal(t, original, snapshot())
	replay, err := connect.CompleteCallback(ownerCtx, authorize.Query().Get("state"), uuid.NewString())
	require.NoError(t, err)
	require.Equal(t, completed, replay)

	// Neither foreign owners nor a different principal can appropriate the
	// permanent account. Rejected stages leave claims/births/receipts unchanged.
	for _, foreign := range []struct{ consumer, owner, account, subject string }{
		{uuid.NewString(), scope.Owner, scope.Account, subject},
		{scope.Consumer, uuid.NewString(), scope.Account, subject},
		{scope.Consumer, scope.Owner, uuid.NewString(), subject},
		{scope.Consumer, scope.Owner, scope.Account, uuid.NewString()},
	} {
		foreignCtx, foreignScope := oauthPGScope(t, foreign.consumer, foreign.owner, foreign.account)
		_, err = enrollment.Stage(foreignCtx, foreignScope, uuid.NewString(), bundleFor(foreign.subject))
		require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	}
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_principal_claims`).Scan(&count))
	require.Equal(t, 1, count)
	require.Equal(t, original, snapshot())

	// A new operation cannot pass deferred completion using a prior linked
	// birth of this principal. Its own account link must complete atomically.
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_oauth_identity_reservations (issuer,subject,consumer,owner_ref,account_ref,generation,operation_ref,intent_mac) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, service.GatewayOAuthIssuer, subject, scope.Consumer, scope.Owner, scope.Account, uuid.NewString(), uuid.NewString(), strings.Repeat("b", 64))
	require.NoError(t, err)
	require.Error(t, tx.Commit())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_identity_reservations`).Scan(&count))
	require.Equal(t, 2, count)

	// An account cannot switch provider identity; rejected normal qualification
	// leaves its permanent provider claim and existing receipts unchanged.
	_, badScope := oauthPGScope(t, scope.Consumer, scope.Owner, scope.Account)
	badOperation := uuid.NewString()
	begun, err = connect.BeginConnect(ownerCtx, badScope, badOperation)
	require.NoError(t, err)
	authorize, err = url.Parse(begun.AuthorizeURL)
	require.NoError(t, err)
	_, err = connect.CompleteCallback(ownerCtx, authorize.Query().Get("state"), uuid.NewString())
	require.NoError(t, err)
	provider = uuid.NewString()
	_, err = dispatch.Descriptor(ownerCtx, badScope, badOperation)
	require.Error(t, err)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_provider_claims`).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_profile_qualifications`).Scan(&count))
	require.Equal(t, 2, count)
	for _, table := range []string{"gateway_oauth_principal_claims", "gateway_oauth_provider_claims"} {
		_, err = db.ExecContext(ctx, `UPDATE `+table+` SET owner_ref=owner_ref`)
		require.Error(t, err)
		_, err = db.ExecContext(ctx, `DELETE FROM `+table)
		require.Error(t, err)
	}
	require.Equal(t, original, snapshot())
	// Cleanup uses the retained model only for this exact old birth. A current-
	// model grant cannot erase it; the matching historical grant can, without
	// altering either immutable qualification or the new account credentials.
	cleanupRepo, ok := repo.(service.GatewayNativeOAuthCleanupRepository)
	require.True(t, ok, "account repository must support exact-birth native OAuth cleanup")
	request := service.GatewayNativeOAuthCleanupRequest{Scope: scope, Operation: operation, Action: "erase", CleanupRef: uuid.NewString(), CleanupToken: uuid.NewString()}
	grant := func(route service.GatewayNativeRoute) service.GatewayNativeOAuthCleanupAuthorizer {
		return func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
			return service.GatewayNativeOAuthCleanupAuthority{Owner: scope.Owner, LeaseExpiresAt: time.Now().Add(5 * time.Second), Native: &route}, nil
		}
	}
	wrongModel := oldRoute
	wrongModel.Model = service.GatewayCodexOAuthModel
	_, err = cleanupRepo.CleanupGatewayNativeOAuth(ownerCtx, request, grant(wrongModel))
	require.Error(t, err)
	require.Equal(t, original, snapshot())
	qualification := func() string {
		var raw string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(q)::text FROM gateway_oauth_profile_qualifications q WHERE account_id=$1`, oldID).Scan(&raw))
		return raw
	}
	beforeCleanup := qualification()
	var currentCredentials string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials::text FROM accounts WHERE id=$1`, current.Native.AccountID).Scan(&currentCredentials))
	closed, err := cleanupRepo.CleanupGatewayNativeOAuth(ownerCtx, request, grant(oldRoute))
	require.NoError(t, err)
	require.True(t, closed.CredentialsErased)
	require.Equal(t, "closed", closed.Closure)
	require.NotNil(t, closed.Native)
	require.Equal(t, oldRoute.Model, closed.Native.Model)
	require.Equal(t, beforeCleanup, qualification())
	var afterCredentials string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials::text FROM accounts WHERE id=$1`, current.Native.AccountID).Scan(&afterCredentials))
	require.Equal(t, currentCredentials, afterCredentials)
}
