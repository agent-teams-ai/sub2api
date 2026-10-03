//go:build integration || gatewaycustody

package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	"github.com/gin-gonic/gin"
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
