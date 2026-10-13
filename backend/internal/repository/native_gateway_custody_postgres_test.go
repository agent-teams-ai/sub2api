//go:build integration || gatewaycustody

package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func custodyPGBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	_, err := rand.Read(value)
	require.NoError(t, err)
	return value
}

func custodyPGDSN(t *testing.T, variable, prefix string) string {
	t.Helper()
	dsn := os.Getenv(variable)
	if dsn == "" {
		t.Skip("NOT_RUN: dedicated disposable custody PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid disposable PostgreSQL URL")
	}
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), prefix))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	return dsn
}

func custodyPGOpen(t *testing.T, ctx context.Context, dsn string) (*sql.DB, service.AccountRepository) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&tables))
	require.Zero(t, tables, "database must be new and empty")
	require.NoError(t, ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { _ = client.Close() })
	return db, NewAccountRepository(client, db, nil)
}

func custodyPGRow(scope service.GatewayNativeCredentialScope, envelope, baseURL string) *service.Account {
	return &service.Account{Name: "custody 世界 é", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
		Status: service.StatusDisabled, Concurrency: 1, Schedulable: false,
		Credentials: map[string]any{"api_key": envelope, "base_url": baseURL},
		Extra: map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: service.GatewayMiMoResponsesProfile,
			service.GatewayModelExtraKey: "synthetic-model", service.GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses",
			"openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
}

// This exercises the real PostgreSQL driver row boundary, not the ORM create
// constructor or provider transport. The dedicated F4 database is already
// populated/migrated; every row, function and history change is rollback-only.
// PostgreSQL sequence values consumed by INSERT are not transactional.
func TestGatewayNativeOpenRouterProfilePostgresRollback(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_PROFILE_PG_DSN", "gateway_oauth_dispatch_test_f4_")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	require.True(t, err == nil, "open dedicated profile PostgreSQL database")
	db.SetMaxOpenConns(1)
	defer func() {
		if db.Close() != nil {
			t.Error("close dedicated profile PostgreSQL database failed")
		}
	}()
	tx, err := db.BeginTx(ctx, nil)
	require.True(t, err == nil, "begin rollback-only profile transaction")
	defer func() {
		// ErrTxDone is expected after the explicit rollback below or the
		// database/sql context-cancellation rollback. No path commits this tx.
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("rollback-only profile transaction cleanup failed")
		}
	}()
	_, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='2s';
		SET LOCAL idle_in_transaction_session_timeout='20s'; SET LOCAL search_path=pg_catalog,public;
		LOCK TABLE public.accounts IN SHARE ROW EXCLUSIVE MODE;
		LOCK TABLE public.schema_migrations IN SHARE MODE`)
	require.True(t, err == nil, "bound and isolate profile regression transaction")
	var database string
	var populated bool
	err = tx.QueryRowContext(ctx, `SELECT current_database(), EXISTS(SELECT 1 FROM public.accounts)`).Scan(&database, &populated)
	require.True(t, err == nil, "read purpose database precondition")
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, strings.TrimPrefix(u.Path, "/"), database)
	require.True(t, populated, "profile regression requires the existing populated F4 database")

	const oldFile = "244_gateway_oauth_fenced_refresh.sql"
	const newFile = "247_gateway_native_openrouter_profile.sql"
	const nanoFile = "248_gateway_native_openrouter_nano_model.sql"
	const reconnectFile = "249_gateway_oauth_reconnect_claims.sql"
	const supportedModelFile = "250_gateway_oauth_supported_codex_model.sql"
	oldSQL, err := migrations.FS.ReadFile(oldFile)
	require.NoError(t, err)
	newSQL, err := migrations.FS.ReadFile(newFile)
	require.NoError(t, err)
	nanoSQL, err := migrations.FS.ReadFile(nanoFile)
	require.NoError(t, err)
	guardStart := strings.Index(string(oldSQL), "CREATE OR REPLACE FUNCTION public.gateway_native_account_guard()")
	require.GreaterOrEqual(t, guardStart, 0)
	oldGuard := string(oldSQL)[guardStart:]
	var newApplied, nanoApplied bool
	for _, file := range []string{oldFile, "246_gateway_oauth_profile_qualification.sql", newFile, nanoFile, reconnectFile, supportedModelFile} {
		content, readErr := migrations.FS.ReadFile(file)
		require.NoError(t, readErr)
		digest := sha256.Sum256([]byte(strings.TrimSpace(string(content))))
		var checksum string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM public.schema_migrations WHERE filename=$1`, file).Scan(&checksum)
		if (file == newFile || file == nanoFile || file == reconnectFile || file == supportedModelFile) && errors.Is(err, sql.ErrNoRows) {
			continue
		}
		require.True(t, err == nil, "known profile migration history required")
		require.Equal(t, hex.EncodeToString(digest[:]), checksum, "migration checksum precondition")
		if file == newFile {
			newApplied = true
		}
		if file == nanoFile {
			nanoApplied = true
		}
	}
	var later int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.schema_migrations
		WHERE substring(filename from '^([0-9]{3})_')::integer>246 AND filename NOT IN ($1,$2,$3,$4)`, newFile, nanoFile, reconnectFile, supportedModelFile).Scan(&later)
	require.True(t, err == nil, "read later migration precondition")
	require.Zero(t, later, "future schema requires separate qualification")
	var originalFunction, originalBody, originalHistory string
	err = tx.QueryRowContext(ctx, `SELECT pg_get_functiondef(oid), prosrc FROM pg_proc
		WHERE oid='public.gateway_native_account_guard()'::regprocedure AND prorettype='trigger'::regtype`).Scan(&originalFunction, &originalBody)
	require.True(t, err == nil, "read current account guard precondition")
	expectedGuard := oldGuard
	if newApplied {
		expectedGuard = string(newSQL)
	}
	if nanoApplied {
		require.True(t, newApplied, "248 requires the preceding 247 history")
		expectedGuard = string(nanoSQL)
	}
	parts := strings.Split(expectedGuard, "$$")
	require.Len(t, parts, 3)
	require.True(t, originalBody == parts[1], "current guard must exactly match known migration history")
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger
		WHERE tgrelid='public.accounts'::regclass AND tgname='gateway_native_account_guard'
		AND tgfoid='public.gateway_native_account_guard()'::regprocedure
		AND tgtype=31 AND tgenabled IN ('O','A') AND NOT tgisinternal)
		AND current_setting('session_replication_role')='origin'`).Scan(&enabled)
	require.True(t, err == nil && enabled, "actual protected INSERT/UPDATE/DELETE trigger must be enabled")
	const historySQL = `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY filename),'[]'::jsonb)::text FROM public.schema_migrations m`
	err = tx.QueryRowContext(ctx, historySQL).Scan(&originalHistory)
	require.True(t, err == nil, "snapshot existing migration history")

	custody, err := service.NewGatewayNativeCredentialCustody("pg-profile", map[string][]byte{"pg-profile": custodyPGBytes(t, 32)})
	require.NoError(t, err)
	fixture := func(profile, baseURL, model string) *service.Account {
		var scope service.GatewayNativeCredentialScope
		var key string
		err := tx.QueryRowContext(ctx, `SELECT 'consumer/'||gen_random_uuid()::text,
			'owner/'||gen_random_uuid()::text, 'account/'||gen_random_uuid()::text,
			gen_random_uuid()::text, gen_random_uuid()::text||gen_random_uuid()::text`).Scan(
			&scope.Consumer, &scope.Owner, &scope.Account, &scope.Generation, &key)
		require.True(t, err == nil, "generate server-side profile fixture identity")
		scope.Purpose = service.GatewayCredentialPurpose
		envelope, err := custody.Seal(scope, key)
		require.NoError(t, err)
		a := custodyPGRow(scope, envelope, baseURL)
		a.Name = "profile/" + scope.Generation
		a.Extra[service.GatewayProfileExtraKey] = profile
		a.Extra[service.GatewayModelExtraKey] = model
		return a
	}
	const insertSQL = `INSERT INTO public.accounts
		(name,platform,type,credentials,extra,status,concurrency,schedulable)
		VALUES ($1,'openai','apikey',$2::jsonb,$3::jsonb,'disabled',1,false) RETURNING id,created_at`
	original := fixture(service.GatewayOpenRouterResponsesProfile, service.GatewayOpenRouterBaseURL, service.GatewayOpenRouterModel)
	credentials, err := json.Marshal(original.Credentials)
	require.NoError(t, err)
	extra, err := json.Marshal(original.Extra)
	require.NoError(t, err)
	// Only the real 244 guard suffix is installed, never its table DDL.
	_, err = tx.ExecContext(ctx, oldGuard)
	require.True(t, err == nil, "install actual old guard inside rollback transaction")
	reject := func(statement string, args ...any) {
		_, err := tx.ExecContext(ctx, "SAVEPOINT profile_rejected_write")
		require.True(t, err == nil, "savepoint protected negative write")
		_, denied := tx.ExecContext(ctx, statement, args...)
		_, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT profile_rejected_write")
		require.True(t, err == nil, "recover rejected write before any further guard execution")
		_, err = tx.ExecContext(ctx, "RELEASE SAVEPOINT profile_rejected_write")
		require.True(t, err == nil, "release recovered negative savepoint")
		var pgErr *pq.Error
		// Do not print driver details: unrelated constraint errors can include
		// the entire row, including the encrypted credential envelope.
		require.True(t, errors.As(denied, &pgErr), "protected write must return a PostgreSQL error")
		require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
	}
	reject(insertSQL, original.Name, string(credentials), string(extra))
	_, err = tx.ExecContext(ctx, string(newSQL))
	require.True(t, err == nil, "execute actual additive 247 SQL")
	// Use the exact encrypted row rejected above; ID and birth come from PG.
	err = tx.QueryRowContext(ctx, insertSQL, original.Name, string(credentials), string(extra)).Scan(&original.ID, &original.CreatedAt)
	require.True(t, err == nil, "247 must accept the protected OpenRouter physical row")
	require.Positive(t, original.ID)
	require.False(t, original.CreatedAt.IsZero())
	var stored service.Account
	var storedCredentials, storedExtra []byte
	var grouped bool
	err = tx.QueryRowContext(ctx, `SELECT id,created_at,platform,type,status,schedulable,credentials,extra,
		EXISTS(SELECT 1 FROM public.account_groups g WHERE g.account_id=a.id)
		FROM public.accounts a WHERE id=$1`, original.ID).Scan(&stored.ID, &stored.CreatedAt,
		&stored.Platform, &stored.Type, &stored.Status, &stored.Schedulable, &storedCredentials, &storedExtra, &grouped)
	require.True(t, err == nil, "read back actual protected physical row")
	require.NoError(t, json.Unmarshal(storedCredentials, &stored.Credentials))
	require.NoError(t, json.Unmarshal(storedExtra, &stored.Extra))
	require.Equal(t, original.ID, stored.ID)
	require.True(t, original.CreatedAt.Equal(stored.CreatedAt), "database birth must survive readback")
	require.Equal(t, service.StatusDisabled, stored.Status)
	require.False(t, stored.Schedulable || grouped)
	require.True(t, stored.GetCredential("api_key") == original.GetCredential("api_key"), "encrypted envelope must survive readback")
	require.NoError(t, custody.ValidateEnvelope(stored.GetCredential("api_key")))
	expectedScope, err := service.GatewayNativeCredentialScopeForAccount(original)
	require.NoError(t, err)
	storedScope, err := service.GatewayNativeCredentialScopeForAccount(&stored)
	require.NoError(t, err)
	require.Equal(t, expectedScope, storedScope)
	route, err := service.GatewayNativeDescriptor(&stored)
	require.NoError(t, err)
	require.Equal(t, original.ID, route.AccountID)
	require.True(t, stored.CreatedAt.Equal(route.CreatedAt))
	require.Equal(t, service.GatewayOpenRouterResponsesProfile, route.Profile)
	require.Equal(t, service.GatewayOpenRouterBaseURL, route.BaseURL)
	require.Equal(t, service.GatewayOpenRouterModel, route.Model)

	nano := fixture(service.GatewayOpenRouterResponsesProfile, service.GatewayOpenRouterBaseURL, "openai/gpt-5.4-nano")
	nanoCredentials, err := json.Marshal(nano.Credentials)
	require.NoError(t, err)
	nanoExtra, err := json.Marshal(nano.Extra)
	require.NoError(t, err)
	reject(insertSQL, nano.Name, string(nanoCredentials), string(nanoExtra))
	_, err = tx.ExecContext(ctx, string(nanoSQL))
	require.True(t, err == nil, "execute actual additive 248 SQL")
	err = tx.QueryRowContext(ctx, insertSQL, nano.Name, string(nanoCredentials), string(nanoExtra)).Scan(&nano.ID, &nano.CreatedAt)
	require.True(t, err == nil, "248 must accept the same protected nano row rejected by 247")
	nanoRoute, err := service.GatewayNativeDescriptor(nano)
	require.NoError(t, err)
	require.Equal(t, "openai/gpt-5.4-nano", nanoRoute.Model)

	mimo := fixture(service.GatewayMiMoResponsesProfile, "https://configured-mimo.invalid/v1", "configured-mimo-model")
	mimoCredentials, err := json.Marshal(mimo.Credentials)
	require.NoError(t, err)
	mimoExtra, err := json.Marshal(mimo.Extra)
	require.NoError(t, err)
	err = tx.QueryRowContext(ctx, insertSQL, mimo.Name, string(mimoCredentials), string(mimoExtra)).Scan(&mimo.ID, &mimo.CreatedAt)
	require.True(t, err == nil, "248 must preserve MiMo configured origin/model support")
	require.Positive(t, mimo.ID)
	require.NotEqual(t, original.ID, mimo.ID)
	require.False(t, mimo.CreatedAt.IsZero())
	// Fresh generation/scope prevents uniqueness errors from hiding an
	// incorrect OpenRouter tuple's guard rejection.
	wrong := fixture(service.GatewayOpenRouterResponsesProfile, "https://wrong-origin.invalid/v1", service.GatewayOpenRouterModel)
	wrongCredentials, err := json.Marshal(wrong.Credentials)
	require.NoError(t, err)
	wrongExtra, err := json.Marshal(wrong.Extra)
	require.NoError(t, err)
	reject(insertSQL, wrong.Name, string(wrongCredentials), string(wrongExtra))
	wrong.Credentials["base_url"] = service.GatewayOpenRouterBaseURL
	wrong.Extra[service.GatewayModelExtraKey] = "unapproved-model"
	wrongCredentials, err = json.Marshal(wrong.Credentials)
	require.NoError(t, err)
	wrongExtra, err = json.Marshal(wrong.Extra)
	require.NoError(t, err)
	reject(insertSQL, wrong.Name, string(wrongCredentials), string(wrongExtra))
	reject(`UPDATE public.accounts SET created_at=created_at+interval '1 microsecond' WHERE id=$1`, original.ID)

	require.NoError(t, tx.Rollback(), "explicit rollback is part of the regression")
	var restoredFunction, restoredHistory string
	var fixtures int
	err = db.QueryRowContext(ctx, `SELECT pg_get_functiondef('public.gateway_native_account_guard()'::regprocedure)`).Scan(&restoredFunction)
	require.True(t, err == nil, "read guard after rollback")
	err = db.QueryRowContext(ctx, historySQL).Scan(&restoredHistory)
	require.True(t, err == nil, "read history after rollback")
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.accounts WHERE extra->>'gateway_generation_v1' IN ($1,$2,$3,$4)`,
		original.Extra[service.GatewayGenerationExtraKey], mimo.Extra[service.GatewayGenerationExtraKey], wrong.Extra[service.GatewayGenerationExtraKey], nano.Extra[service.GatewayGenerationExtraKey]).Scan(&fixtures)
	require.True(t, err == nil, "read fixture absence after rollback")
	require.Zero(t, fixtures)
	require.True(t, originalFunction == restoredFunction, "rollback must restore the original guard")
	require.True(t, originalHistory == restoredHistory, "rollback must preserve migration history")
}

func custodyPGGateway(repo service.AccountRepository, transport service.HTTPUpstream) *service.OpenAIGatewayService {
	cfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false, AllowInsecureHTTP: true}}}
	return service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, transport, nil, nil, nil, nil, nil, nil, nil, nil)
}

type custodyPGHTTP struct {
	service.HTTPUpstream
	client *http.Client
}

func (h *custodyPGHTTP) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return h.client.Do(req)
}

func custodyPGForward(t *testing.T, ctx context.Context, gateway *service.OpenAIGatewayService, route service.GatewayNativeRoute) (bool, error) {
	t.Helper()
	body := []byte(`{"model":"synthetic-model","input":"fixture","store":false,"service_tier":"default"}`)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
	_, entered, err := gateway.ForwardGatewayRoute(ctx, c, route, body)
	return entered, err
}

// Regression: checking Go DTOs alone misses plaintext in real JSONB/backup,
// bypassable SQL scope guards, missing row locks, and revived restored keys.
// All SQL uses the stock migration runner and actual repository/driver.
func TestGatewayNativeCustodyPostgresAndRestore(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_CUSTODY_PG_DSN", "native_custody_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, repo := custodyPGOpen(t, ctx, dsn)
	custody, err := service.NewGatewayNativeCredentialCustody("pg-old", map[string][]byte{"pg-old": custodyPGBytes(t, 32)})
	require.NoError(t, err)
	scope := service.GatewayNativeCredentialScope{Consumer: "consumer/custody", Owner: "owner/世界", Account: "account/é",
		Generation: "e5555555-5555-4555-8555-555555555555", Purpose: service.GatewayCredentialPurpose}
	key := base64.RawURLEncoding.EncodeToString(custodyPGBytes(t, 32))
	envelope, err := custody.Seal(scope, key)
	require.NoError(t, err)
	var entries atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "Bearer "+key, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer upstream.Close()
	transport := &custodyPGHTTP{client: upstream.Client()}
	gateway := custodyPGGateway(repo, transport)
	principal, err := service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	control := service.WithGatewayNativeCustody(principal, custody)
	a := custodyPGRow(scope, envelope, upstream.URL)
	require.NoError(t, repo.Create(ctx, a))
	stored, err := repo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	route, err := service.GatewayNativeDescriptor(stored)
	require.NoError(t, err)
	var dump []byte
	// Regression: ORM readback is encrypted but the actual stored row still leaks.
	t.Run("real JSONB and repository readback contain no plaintext", func(t *testing.T) {
		var raw string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", a.ID).Scan(&raw))
		require.NotContains(t, raw, key)
		require.Contains(t, raw, envelope)
		encoded, err := json.Marshal(stored)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), key)
		require.Equal(t, envelope, stored.GetCredential("api_key"))
		require.Equal(t, scope.Metadata(), stored.Extra[service.GatewayCredentialScopeExtraKey])
	})
	// Regression: a real backup can leak plaintext despite a sanitized API DTO.
	t.Run("actual pg_dump contains encrypted envelope only", func(t *testing.T) {
		binary, err := exec.LookPath("pg_dump")
		if err != nil {
			t.Skip("NOT_RUN: pg_dump unavailable")
		}
		command := exec.CommandContext(ctx, binary, "--data-only", "--column-inserts", "--no-owner", "--no-privileges", "--table=public.accounts", "--dbname="+dsn)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "PGPASSFILE=/dev/null", "PGSSLMODE=disable"}
		dump, err = command.Output()
		require.NoError(t, err)
		require.NotContains(t, string(dump), key)
		require.Contains(t, string(dump), envelope)
	})
	// Regression: a marked insert/update or copied envelope bypasses SQL242.
	t.Run("SQL refuses plaintext and frozen-scope replacement", func(t *testing.T) {
		assertGuard := func(err error) {
			t.Helper()
			var pgErr *pq.Error
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
		}
		_, err := db.ExecContext(ctx, `INSERT INTO accounts(name,platform,type,credentials,extra,status,schedulable,concurrency)
 SELECT 'plaintext rejection',platform,type,jsonb_build_object('api_key',$1::text,'base_url',credentials->>'base_url'),
 jsonb_set(jsonb_set(extra,'{gateway_generation_v1}',to_jsonb($2::text)), '{gateway_credential_scope_v1,generation}',to_jsonb($2::text)),
 'disabled',false,1 FROM accounts WHERE id=$3`, key, "f6666666-6666-4666-8666-666666666666", a.ID)
		assertGuard(err)
		_, err = db.ExecContext(ctx, "UPDATE accounts SET credentials=jsonb_set(credentials,'{api_key}',to_jsonb($1::text)) WHERE id=$2", key, a.ID)
		assertGuard(err)
		for _, member := range []string{"consumer", "owner", "account", "generation", "purpose"} {
			_, err = db.ExecContext(ctx, "UPDATE accounts SET extra=jsonb_set(extra,ARRAY['gateway_credential_scope_v1',$1],to_jsonb('foreign'::text)) WHERE id=$2", member, a.ID)
			assertGuard(err)
		}
		resealed, err := custody.Seal(scope, key)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, "UPDATE accounts SET credentials=jsonb_set(credentials,'{api_key}',to_jsonb($1::text)) WHERE id=$2", resealed, a.ID)
		assertGuard(err)
	})
	// Regression: a GetByID freshness check does not hold the row through entry.
	// Observe the writer actually waiting on a PostgreSQL lock, then release it.
	t.Run("real fresh snapshot holds row lock", func(t *testing.T) {
		locked, release, err := repo.(service.GatewayNativeAccountLocker).LockGatewayNativeAccount(control, a.ID)
		require.NoError(t, err)
		defer release()
		require.Equal(t, envelope, locked.GetCredential("api_key"))
		require.Equal(t, stored.Extra, locked.Extra)
		writer, err := db.Conn(ctx)
		require.NoError(t, err)
		defer writer.Close()
		var pid int
		require.NoError(t, writer.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid))
		done := make(chan error, 1)
		go func() {
			_, err := writer.ExecContext(ctx, "UPDATE accounts SET name='renamed 世界 é' WHERE id=$1", a.ID)
			done <- err
		}()
		require.Eventually(t, func() bool {
			var waiting bool
			err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", pid).Scan(&waiting)
			return err == nil && waiting
		}, time.Second, 10*time.Millisecond)
		release()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("writer did not finish after row release")
		}
	})
	// Regression: a correctly shaped ciphertext copied into a different protected
	// owner passes structural SQL validation and dispatches without real AAD auth.
	t.Run("wrong owner AAD gives zero actual HTTP entries", func(t *testing.T) {
		birth := scope
		birth.Generation = "f7777777-7777-4777-8777-777777777777"
		ciphertext, err := custody.Seal(birth, key)
		require.NoError(t, err)
		birth.Owner = "owner/foreign"
		foreign := custodyPGRow(birth, ciphertext, upstream.URL)
		require.NoError(t, repo.Create(ctx, foreign))
		_, err = db.ExecContext(ctx, "UPDATE accounts SET status='active' WHERE id=$1", foreign.ID)
		require.NoError(t, err)
		fresh, err := repo.GetByID(ctx, foreign.ID)
		require.NoError(t, err)
		descriptor, err := service.GatewayNativeDescriptor(fresh)
		require.NoError(t, err)
		entered, err := custodyPGForward(t, control, gateway, descriptor)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		require.False(t, entered)
		require.Zero(t, entries.Load())
	})
	// Regression: a real backup restored under a retired/wrong key dispatches.
	// Restore the original inactive row into a separate newly migrated database,
	// explicitly activate the synthetic fixture, then observe zero provider entry.
	t.Run("actual dump restore cannot dispatch with unavailable or wrong key", func(t *testing.T) {
		if len(dump) == 0 {
			t.Skip("NOT_RUN: actual pg_dump receipt unavailable")
		}
		restoreDSN := custodyPGDSN(t, "GATEWAY_NATIVE_CUSTODY_RESTORE_PG_DSN", "native_custody_restore_")
		binary, err := exec.LookPath("psql")
		if err != nil {
			t.Skip("NOT_RUN: psql unavailable")
		}
		restoreDB, restoredRepo := custodyPGOpen(t, ctx, restoreDSN)
		command := exec.CommandContext(ctx, binary, "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--dbname="+restoreDSN)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "PGPASSFILE=/dev/null", "PGSSLMODE=disable"}
		command.Stdin = bytes.NewReader(dump)
		output, err := command.CombinedOutput()
		require.NoError(t, err, "restore failed: %s", output)
		_, err = restoreDB.ExecContext(ctx, "UPDATE accounts SET status='active' WHERE id=$1", a.ID)
		require.NoError(t, err)
		restoredGateway := custodyPGGateway(restoredRepo, transport)
		for _, id := range []string{"new-only", "pg-old"} {
			adapter, err := service.NewGatewayNativeCredentialCustody(id, map[string][]byte{id: custodyPGBytes(t, 32)})
			require.NoError(t, err)
			entered, err := custodyPGForward(t, service.WithGatewayNativeCustody(principal, adapter), restoredGateway, route)
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
			require.False(t, entered)
			require.Zero(t, entries.Load())
		}
	})
	// Regression: erasure requires the unavailable key, loses identity, rounds a
	// forged birth, or restoring deleted/credential fields revives the tombstone.
	t.Run("exact erasure retains immutable identity and safe metadata", func(t *testing.T) {
		eraser := repo.(service.GatewayNativeAccountEraser)
		bad := route
		bad.CreatedAt = bad.CreatedAt.Add(time.Nanosecond)
		require.ErrorIs(t, eraser.EraseGatewayNativeAccount(control, bad), service.ErrGatewayNativeIdentity)
		other, err := service.WithGatewayNativeConsumer(ctx, "consumer/foreign")
		require.NoError(t, err)
		require.ErrorIs(t, eraser.EraseGatewayNativeAccount(other, route), service.ErrGatewayNativeIdentity)
		missing, err := service.NewGatewayNativeCredentialCustody("new-only", map[string][]byte{"new-only": custodyPGBytes(t, 32)})
		require.NoError(t, err)
		cleanup := service.WithGatewayNativeCustody(principal, missing)
		require.NoError(t, gateway.EraseGatewayCandidate(cleanup, route))
		require.NoError(t, gateway.EraseGatewayCandidate(cleanup, route))
		var erased bool
		var extra []byte
		require.NoError(t, db.QueryRowContext(ctx, "SELECT NOT (credentials ? 'api_key'), extra FROM accounts WHERE id=$1", a.ID).Scan(&erased, &extra))
		require.True(t, erased)
		var retained map[string]any
		require.NoError(t, json.Unmarshal(extra, &retained))
		require.Equal(t, stored.Extra, retained)
		for _, query := range []string{"UPDATE accounts SET deleted_at=NULL,status='active' WHERE id=$1", "DELETE FROM accounts WHERE id=$1"} {
			_, err := db.ExecContext(ctx, query, a.ID)
			var pgErr *pq.Error
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
		}
		entered, err := custodyPGForward(t, cleanup, gateway, route)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		require.False(t, entered)
		require.Zero(t, entries.Load())
	})
}

type oauthTransportEntryCounter struct {
	transport http.RoundTripper
	entries   atomic.Int32
}

func (c *oauthTransportEntryCounter) RoundTrip(request *http.Request) (*http.Response, error) {
	c.entries.Add(1)
	return c.transport.RoundTrip(request)
}

// Regression: an actual data-only backup must retain the encrypted v2 native
// OAuth row and its immutable claims/history, while restore-time key loss,
// replay, foreign scope and erasure cannot revive or republish credentials.
func TestGatewayNativeOAuthBackupRestoreAndRedisCustody(t *testing.T) {
	sourceDSN := custodyPGDSN(t, "GATEWAY_NATIVE_OAUTH_TEST_DSN", "gateway_oauth_test_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, accountRepo := custodyPGOpen(t, ctx, sourceDSN)
	repo, ok := accountRepo.(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	refreshRepo, ok := repo.(service.GatewayNativeOAuthRefreshRepository)
	require.True(t, ok)
	dispatchRepo, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok)

	oldKey := custodyPGBytes(t, 32)
	newKey := custodyPGBytes(t, 32)
	oldCustody, err := service.NewGatewayNativeCredentialCustody("old", map[string][]byte{"old": oldKey})
	require.NoError(t, err)
	rotatedCustody, err := service.NewGatewayNativeCredentialCustody("new", map[string][]byte{"new": newKey, "old": oldKey})
	require.NoError(t, err)
	intentKey := custodyPGBytes(t, 32)

	var tokenCalls, accountChecks atomic.Int32
	providerAccount := uuid.NewString()
	var originalBundle, returnedBundle service.GatewayNativeOAuthBundle
	_, fixtureTransport, bundleFor := oauthPGRefreshFixture(t, func(w http.ResponseWriter, r *http.Request, next func(string) service.GatewayNativeOAuthBundle) {
		tokenCalls.Add(1)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		require.Equal(t, originalBundle.RefreshToken, r.Form.Get("refresh_token"))
		require.Equal(t, "app_EMoamEEZ73f0CkXaXp7hrann", r.Form.Get("client_id"))
		require.Equal(t, "openid profile email", r.Form.Get("scope"))
		returnedBundle = next("subject-backup-restore")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": returnedBundle.AccessToken, "refresh_token": returnedBundle.RefreshToken,
			"id_token": returnedBundle.IDToken, "token_type": "Bearer", "expires_in": 3600,
			"protected_hint": "f2-sensitive-metadata",
		})
	}, func(w http.ResponseWriter, r *http.Request) {
		accountChecks.Add(1)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer "+originalBundle.AccessToken, r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		_, _ = fmt.Fprintf(w, `{"accounts":{"unrelated-workspace":{"account":{"account_id":%q}}}}`, providerAccount)
	})
	counter := &oauthTransportEntryCounter{transport: fixtureTransport}
	verifier := service.NewGatewayNativeOAuthVerifier(counter)

	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, oldCustody, repo, intentKey)
	require.NoError(t, err)
	principal, scope := oauthPGScope(t, "consumer-backup-restore", "owner-backup-restore", "logical-backup-restore")
	principal, cancelPrincipal := context.WithTimeout(principal, 90*time.Second)
	defer cancelPrincipal()
	originalBundle = bundleFor("subject-backup-restore")

	journal, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connector, err := service.NewGatewayNativeOAuthConnect(intentKey, counter, journal, enrollment, repo)
	require.NoError(t, err)
	const connectOperation = "backup-restore-connect"
	_, err = connector.BeginConnect(principal, scope, connectOperation)
	require.NoError(t, err)
	connectIntent, err := journal.ReadConnectIntent(principal, scope, connectOperation)
	require.NoError(t, err)
	won, err := journal.EnterConnect(principal, connectIntent)
	require.NoError(t, err)
	require.True(t, won)
	binding := &oauthRefreshConnectBinding{GatewayNativeOAuthRepository: repo, journal: journal, intent: connectIntent}
	boundEnrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, oldCustody, binding, intentKey)
	require.NoError(t, err)
	staged, err := boundEnrollment.Stage(principal, scope, connectIntent.EnrollmentOperation, originalBundle)
	require.NoError(t, err)
	finished, err := journal.FinishConnect(principal, binding.intent, "completed", staged)
	require.NoError(t, err)
	require.Equal(t, "completed", finished.State)
	require.Equal(t, staged, finished.Outcome)

	_, physical, release, err := dispatchRepo.LockGatewayNativeOAuthDispatch(principal, scope, connectOperation, staged.AccountID)
	require.NoError(t, err)
	release()
	require.False(t, physical.QualificationValid(1))
	require.ErrorIs(t, dispatchRepo.QualifyGatewayNativeOAuthDispatch(principal, physical, 1), service.ErrGatewayNativeIdentity)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(dispatchRepo, oldCustody, verifier, counter)
	require.NoError(t, err)
	descriptor, err := dispatch.Descriptor(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, service.GatewayCodexOAuthQualification, descriptor.Qualification)
	require.Equal(t, connectOperation, descriptor.Operation)
	require.Equal(t, scope.Account, descriptor.Account)
	require.NotNil(t, descriptor.Native)
	require.Equal(t, physical.Route, *descriptor.Native)
	require.Equal(t, staged.AccountID, descriptor.Native.AccountID)
	require.Equal(t, staged.Generation, descriptor.Native.Generation)
	require.Equal(t, service.GatewayCodexOAuthResponsesProfile, descriptor.Native.Profile)
	require.Equal(t, service.GatewayCodexOAuthBaseURL, descriptor.Native.BaseURL)
	require.Equal(t, service.GatewayCodexOAuthModel, descriptor.Native.Model)

	var sourceID int64
	var sourceBirth time.Time
	var sourceCredentials, sourceExtra []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id,created_at,credentials,extra FROM accounts WHERE id=$1`, staged.AccountID).
		Scan(&sourceID, &sourceBirth, &sourceCredentials, &sourceExtra))
	var originalStored struct {
		Envelope string `json:"oauth_bundle"`
	}
	require.NoError(t, json.Unmarshal(sourceCredentials, &originalStored))
	require.Equal(t, staged.AccountID, sourceID)
	require.True(t, sourceBirth.Equal(descriptor.Native.CreatedAt))
	require.True(t, strings.HasPrefix(originalStored.Envelope, "gco1.old."))
	require.NoError(t, oldCustody.ValidateOAuthEnvelope(originalStored.Envelope))
	require.NoError(t, rotatedCustody.ValidateOAuthEnvelope(originalStored.Envelope), "rotation must retain the old read key")

	in := service.GatewayNativeOAuthRefreshIntent{
		Scope: scope, AccountID: staged.AccountID, CreatedAt: sourceBirth,
		ExpectedVersion: 1, Operation: "backup-restore-refresh-one", Intent: "rotate-whole-bundle",
	}
	refresher, err := service.NewGatewayNativeOAuthRefresh(refreshRepo, rotatedCustody, verifier, counter)
	require.NoError(t, err)
	refreshed, err := refresher.Refresh(principal, in)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "completed", Version: 2}, refreshed)
	require.NotEmpty(t, returnedBundle.AccessToken)
	require.NotEmpty(t, returnedBundle.RefreshToken)
	require.NotEmpty(t, returnedBundle.IDToken)
	require.True(t, originalBundle.AccessToken != returnedBundle.AccessToken)
	require.True(t, originalBundle.RefreshToken != returnedBundle.RefreshToken)
	require.EqualValues(t, 1, tokenCalls.Load())
	require.EqualValues(t, 1, accountChecks.Load())
	require.EqualValues(t, 5, counter.entries.Load(), "positive control is three JWKS, one account check and one token exchange")

	var afterID int64
	var afterBirth time.Time
	var afterCredentials, afterExtra []byte
	var afterVersion int64
	var status string
	var schedulable, undeleted bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id,created_at,credentials,extra,
 gateway_oauth_credential_version(credentials),status,schedulable,deleted_at IS NULL
 FROM accounts WHERE id=$1`, staged.AccountID).
		Scan(&afterID, &afterBirth, &afterCredentials, &afterExtra, &afterVersion, &status, &schedulable, &undeleted))
	require.Equal(t, sourceID, afterID)
	require.True(t, sourceBirth.Equal(afterBirth))
	require.True(t, bytes.Equal(sourceExtra, afterExtra))
	require.Equal(t, int64(2), afterVersion)
	require.Equal(t, service.StatusDisabled, status)
	require.False(t, schedulable)
	require.True(t, undeleted)
	var refreshedStored struct {
		Envelope string `json:"oauth_bundle"`
	}
	require.NoError(t, json.Unmarshal(afterCredentials, &refreshedStored))
	require.True(t, strings.HasPrefix(refreshedStored.Envelope, "gco2.new.2."))
	require.True(t, originalStored.Envelope != refreshedStored.Envelope)
	sourcePositive, err := refresher.Maintain(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, "completed", sourcePositive.State)
	require.Equal(t, in.Operation, sourcePositive.RefreshRef)
	require.EqualValues(t, 5, counter.entries.Load(), "current v2 custody authenticity must need no additional transport entry")

	refreshedRow, err := accountRepo.GetByID(ctx, staged.AccountID)
	require.NoError(t, err)
	oauthPGRedisGuards(t, refreshedRow, originalBundle, returnedBundle.AccessToken, returnedBundle.RefreshToken,
		returnedBundle.IDToken, "f2-sensitive-metadata")
	counter.entries.Store(0)

	dumpBinary, err := exec.LookPath("pg_dump")
	require.NoError(t, err)
	dumpCommand := exec.CommandContext(ctx, dumpBinary,
		"--data-only", "--column-inserts", "--no-owner", "--no-privileges", "--disable-triggers",
		"--table=public.accounts", "--table=public.gateway_oauth_*", "--dbname="+sourceDSN)
	dumpCommand.Env = []string{"PATH=" + os.Getenv("PATH"), "PGPASSFILE=/dev/null", "PGSSLMODE=disable"}
	dump, err := dumpCommand.Output()
	require.NoError(t, err)
	for _, secret := range []string{
		originalBundle.AccessToken, originalBundle.RefreshToken, originalBundle.IDToken,
		returnedBundle.AccessToken, returnedBundle.RefreshToken, returnedBundle.IDToken,
		"f2-sensitive-metadata",
	} {
		require.False(t, bytes.Contains(dump, []byte(secret)), "backup contains a controlled plaintext secret")
	}
	require.False(t, bytes.Contains(dump, []byte(originalStored.Envelope)), "backup retains the spent v1 envelope")
	require.True(t, bytes.Contains(dump, []byte(refreshedStored.Envelope)), "backup omits the actual v2 envelope")

	restoreDSN := custodyPGDSN(t, "GATEWAY_NATIVE_CUSTODY_RESTORE_PG_DSN", "native_custody_restore_")
	restoreDB, restoredAccountRepo := custodyPGOpen(t, ctx, restoreDSN)
	psqlBinary, err := exec.LookPath("psql")
	require.NoError(t, err)
	restoreCommand := exec.CommandContext(ctx, psqlBinary, "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--dbname="+restoreDSN)
	restoreCommand.Env = []string{"PATH=" + os.Getenv("PATH"), "PGPASSFILE=/dev/null", "PGSSLMODE=disable"}
	restoreCommand.Stdin = bytes.NewReader(dump)
	require.NoError(t, restoreCommand.Run())

	var restoredID int64
	var restoredBirth time.Time
	var restoredCredentials, restoredExtra []byte
	var restoredVersion int64
	var restoredStatus string
	var restoredSchedulable, restoredUndeleted bool
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT id,created_at,credentials,extra,
 gateway_oauth_credential_version(credentials),status,schedulable,deleted_at IS NULL
 FROM accounts WHERE id=$1`, staged.AccountID).
		Scan(&restoredID, &restoredBirth, &restoredCredentials, &restoredExtra, &restoredVersion,
			&restoredStatus, &restoredSchedulable, &restoredUndeleted))
	require.Equal(t, sourceID, restoredID)
	require.True(t, sourceBirth.Equal(restoredBirth))
	require.True(t, bytes.Equal(sourceExtra, restoredExtra))
	sourceDigest := sha256.Sum256(afterCredentials)
	restoredDigest := sha256.Sum256(restoredCredentials)
	require.Equal(t, sourceDigest, restoredDigest)
	require.Equal(t, int64(2), restoredVersion)
	require.Equal(t, service.StatusDisabled, restoredStatus)
	require.False(t, restoredSchedulable)
	require.True(t, restoredUndeleted)
	var restoredStored struct {
		Envelope string `json:"oauth_bundle"`
	}
	require.NoError(t, json.Unmarshal(restoredCredentials, &restoredStored))
	require.True(t, refreshedStored.Envelope == restoredStored.Envelope)

	var accountRows, reservationRows, principalRows, providerRows, connectRows, qualificationRows, refreshRows int
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM accounts),
 (SELECT count(*) FROM gateway_oauth_identity_reservations),
 (SELECT count(*) FROM gateway_oauth_principal_claims),
 (SELECT count(*) FROM gateway_oauth_provider_claims),
 (SELECT count(*) FROM gateway_oauth_connect_intents),
 (SELECT count(*) FROM gateway_oauth_profile_qualifications),
 (SELECT count(*) FROM gateway_oauth_refresh_attempts)`).
		Scan(&accountRows, &reservationRows, &principalRows, &providerRows, &connectRows, &qualificationRows, &refreshRows))
	require.Equal(t, 1, accountRows)
	require.Equal(t, 1, reservationRows)
	require.Equal(t, 1, principalRows)
	require.Equal(t, 1, providerRows)
	require.Equal(t, 1, connectRows)
	require.Equal(t, 1, qualificationRows)
	require.Equal(t, 1, refreshRows)
	var principalIssuer, providerIssuer string
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT
 (SELECT issuer FROM gateway_oauth_principal_claims),
 (SELECT issuer FROM gateway_oauth_provider_claims)`).Scan(&principalIssuer, &providerIssuer))
	require.Equal(t, service.GatewayOAuthIssuer, principalIssuer)
	require.Equal(t, service.GatewayOAuthIssuer, providerIssuer)

	var connectState, connectOutcomeOperation, connectOutcomeGeneration, connectOutcomeState string
	var connectOutcomeAccount int64
	var refreshState string
	var expectedVersion, resultVersion int64
	var publicationRecorded bool
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT c.state,c.outcome_operation,c.outcome_account_id,
 c.outcome_generation,c.outcome_state,f.state,f.expected_version,f.result_version,f.publication_xid IS NOT NULL
 FROM gateway_oauth_connect_intents c,gateway_oauth_refresh_attempts f
 WHERE c.consumer=$1 AND c.operation_ref=$2 AND f.consumer=$1 AND f.operation_ref=$3`,
		scope.Consumer, connectOperation, in.Operation).
		Scan(&connectState, &connectOutcomeOperation, &connectOutcomeAccount, &connectOutcomeGeneration,
			&connectOutcomeState, &refreshState, &expectedVersion, &resultVersion, &publicationRecorded))
	require.Equal(t, "completed", connectState)
	require.Equal(t, connectIntent.EnrollmentOperation, connectOutcomeOperation)
	require.Equal(t, staged.AccountID, connectOutcomeAccount)
	require.Equal(t, staged.Generation, connectOutcomeGeneration)
	require.Equal(t, "staged", connectOutcomeState)
	require.Equal(t, "completed", refreshState)
	require.Equal(t, int64(1), expectedVersion)
	require.Equal(t, int64(2), resultVersion)
	require.True(t, publicationRecorded)

	var enabledGuards, disabledGuards int
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE tgenabled<>'O')
 FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = ANY(ARRAY[
 'accounts'::regclass,'gateway_oauth_identity_reservations'::regclass,
 'gateway_oauth_principal_claims'::regclass,'gateway_oauth_provider_claims'::regclass,
 'gateway_oauth_connect_intents'::regclass,'gateway_oauth_profile_qualifications'::regclass,
 'gateway_oauth_refresh_attempts'::regclass])`).Scan(&enabledGuards, &disabledGuards))
	require.Positive(t, enabledGuards)
	require.Zero(t, disabledGuards)
	_, err = restoreDB.ExecContext(ctx, `INSERT INTO accounts
 (name,platform,type,status,schedulable,concurrency,priority,credentials,extra)
 SELECT 'rejected-v2-insert',platform,type,status,schedulable,concurrency,priority,$1::jsonb,extra
 FROM accounts WHERE id=$2`, string(restoredCredentials), staged.AccountID)
	require.Error(t, err, "SQL244 must reject a direct v2 account insert")
	_, err = restoreDB.ExecContext(ctx, `UPDATE gateway_oauth_refresh_attempts SET state='unknown' WHERE account_id=$1`, staged.AccountID)
	require.Error(t, err, "completed refresh history must remain immutable")

	restoredRepo, ok := restoredAccountRepo.(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	restoredRefreshRepo, ok := restoredRepo.(service.GatewayNativeOAuthRefreshRepository)
	require.True(t, ok)
	restoredDispatchRepo, ok := restoredRepo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok)
	readback, err := restoredRepo.ReadGatewayNativeOAuth(principal, scope, connectIntent.EnrollmentOperation)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeOAuthOutcome{
		Operation: connectIntent.EnrollmentOperation, AccountID: staged.AccountID,
		Generation: staged.Generation, State: "staged",
	}, readback)

	missingKey := custodyPGBytes(t, 32)
	missingCustody, err := service.NewGatewayNativeCredentialCustody("missing", map[string][]byte{
		"missing": missingKey, "old": oldKey,
	})
	require.NoError(t, err)
	wrongCustody, err := service.NewGatewayNativeCredentialCustody("new", map[string][]byte{
		"new": custodyPGBytes(t, 32), "old": oldKey,
	})
	require.NoError(t, err)
	missingRefresh, err := service.NewGatewayNativeOAuthRefresh(restoredRefreshRepo, missingCustody, verifier, counter)
	require.NoError(t, err)
	_, err = missingRefresh.Maintain(principal, scope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	wrongRefresh, err := service.NewGatewayNativeOAuthRefresh(restoredRefreshRepo, wrongCustody, verifier, counter)
	require.NoError(t, err)
	_, err = wrongRefresh.Maintain(principal, scope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)

	restoredDispatch, err := service.NewGatewayNativeOAuthDispatch(restoredDispatchRepo, rotatedCustody, verifier, counter)
	require.NoError(t, err)
	restoredRefresh, err := service.NewGatewayNativeOAuthRefresh(restoredRefreshRepo, rotatedCustody, verifier, counter)
	require.NoError(t, err)
	restoredPositive, err := restoredRefresh.Maintain(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, "completed", restoredPositive.State)
	require.Equal(t, in.Operation, restoredPositive.RefreshRef)
	require.Zero(t, counter.entries.Load(), "restored v2 custody authenticity must precede and suppress transport")
	foreignPrincipal, _ := oauthPGScope(t, scope.Consumer, "owner-foreign", scope.Account)
	_, err = restoredDispatch.Descriptor(foreignPrincipal, scope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	foreignScope := scope
	foreignScope.Owner = "owner-foreign"
	_, err = restoredDispatch.Descriptor(principal, foreignScope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	_, err = restoredRefresh.Maintain(foreignPrincipal, scope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	_, err = restoredRefresh.Maintain(principal, foreignScope, connectOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)

	replayed, err := restoredRefresh.Refresh(principal, in)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "completed", Version: 2}, replayed)
	spent := in
	spent.Operation = "spent-refresh-revival"
	_, err = restoredRefresh.Refresh(principal, spent)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	require.Zero(t, counter.entries.Load(), "restore denials and completed replay must precede every controlled transport entry")
	require.EqualValues(t, 1, tokenCalls.Load(), "exact replay must not perform another exchange")

	err = restoredRepo.EraseGatewayNativeOAuth(foreignPrincipal, scope, connectIntent.EnrollmentOperation)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.NoError(t, restoredRepo.EraseGatewayNativeOAuth(principal, scope, connectIntent.EnrollmentOperation))
	require.NoError(t, restoredRepo.EraseGatewayNativeOAuth(principal, scope, connectIntent.EnrollmentOperation))
	erased, err := restoredRepo.ReadGatewayNativeOAuth(principal, scope, connectIntent.EnrollmentOperation)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeOAuthOutcome{
		Operation: connectIntent.EnrollmentOperation, AccountID: staged.AccountID,
		Generation: staged.Generation, State: "erased",
	}, erased)
	var erasedCredentials []byte
	var erasedTombstone, envelopeAbsent bool
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT credentials,deleted_at IS NOT NULL,NOT credentials ? 'oauth_bundle'
 FROM accounts WHERE id=$1`, staged.AccountID).Scan(&erasedCredentials, &erasedTombstone, &envelopeAbsent))
	require.Equal(t, "{}", string(erasedCredentials))
	require.True(t, erasedTombstone)
	require.True(t, envelopeAbsent)

	counter.entries.Store(0)
	restoredEnrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, oldCustody, restoredRepo, intentKey)
	require.NoError(t, err)
	recreated, err := restoredEnrollment.Stage(principal, scope, connectIntent.EnrollmentOperation, originalBundle)
	require.NoError(t, err)
	require.Equal(t, staged, recreated)
	var finalAccounts, finalReservations int
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM accounts),(SELECT count(*) FROM gateway_oauth_identity_reservations)`).
		Scan(&finalAccounts, &finalReservations))
	require.Equal(t, 1, finalAccounts)
	require.Equal(t, 1, finalReservations)
	require.NoError(t, restoreDB.QueryRowContext(ctx, `SELECT credentials,deleted_at IS NOT NULL,NOT credentials ? 'oauth_bundle'
 FROM accounts WHERE id=$1`, staged.AccountID).Scan(&erasedCredentials, &erasedTombstone, &envelopeAbsent))
	require.Equal(t, "{}", string(erasedCredentials))
	require.True(t, erasedTombstone)
	require.True(t, envelopeAbsent)
	require.Zero(t, counter.entries.Load(), "same-operation Stage must return the reserved tombstone without transport")
}
