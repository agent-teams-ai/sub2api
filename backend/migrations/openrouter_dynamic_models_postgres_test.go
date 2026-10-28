//go:build integration || gatewaycustody

package migrations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// The normal native fixture must first apply all embedded migrations to this
// disposable database. This regression tests actual SQL structural/lifecycle
// guards without compiling the service-unit test package. Authentic encrypted
// custody and live catalogue membership are exercised by the joined HTTP proof.
func TestGatewayOpenRouterDynamicModelsPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OPENROUTER_MODELS_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: disposable migrated OpenRouter PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") ||
		(u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") ||
		(!strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "native_openrouter_models_") && !strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "native_provider_joined_")) ||
		(u.RawQuery != "" && u.RawQuery != "sslmode=disable") {
		t.Fatal("only an explicitly supplied disposable local OpenRouter database is allowed")
	}
	if u.User != nil {
		if _, password := u.User.Password(); password {
			t.Fatal("disposable fixture must not require a password")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("open disposable PostgreSQL fixture")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	migration, err := FS.ReadFile("258_gateway_openrouter_dynamic_models.sql")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(string(migration))))
	var checksum, body string
	var enabled bool
	if db.QueryRowContext(ctx, `SELECT checksum FROM public.schema_migrations WHERE filename='258_gateway_openrouter_dynamic_models.sql'`).Scan(&checksum) != nil || checksum != hex.EncodeToString(digest[:]) {
		t.Fatal("the stock migration loader must apply the exact current embedded 258 migration first")
	}
	if db.QueryRowContext(ctx, `SELECT prosrc FROM pg_proc WHERE oid='public.gateway_native_account_guard()'::regprocedure`).Scan(&body) != nil || body != strings.Split(string(migration), "$$")[1] {
		t.Fatal("the database account guard must match the current embedded migration")
	}
	if db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.accounts'::regclass AND tgname='gateway_native_account_guard' AND tgfoid='public.gateway_native_account_guard()'::regprocedure AND tgtype=31 AND tgenabled IN ('O','A') AND NOT tgisinternal) AND current_setting('session_replication_role')='origin'`).Scan(&enabled) != nil || !enabled {
		t.Fatal("the real INSERT/UPDATE/DELETE guard must remain enabled")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin rollback-only guard regression")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='2s'`); err != nil {
		t.Fatal("bound fixture statements")
	}
	// SQL cannot authenticate AES-GCM: this is a canonical structural envelope.
	// The server-only key and exact AAD remain verified at credential entry.
	envelope := "gcn1.pg-fixture." + base64.RawURLEncoding.EncodeToString(make([]byte, 12)) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 17))
	fixture := func(t *testing.T, model any) (map[string]any, map[string]any) {
		var bytes [16]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			t.Fatal("generate unique fixture generation")
		}
		generation := fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
		return map[string]any{"api_key": envelope, "base_url": "https://openrouter.ai/api/v1"}, map[string]any{
			"gateway_generation_v1": generation, "gateway_profile_v1": "openrouter-openai-responses-apikey-v1", "gateway_model_v1": model,
			"gateway_credential_scope_v1": map[string]any{"consumer": "pg/consumer", "owner": "pg/owner", "account": "pg/" + generation, "generation": generation, "purpose": "provider-authorization-v1"},
			"openai_responses_mode":       "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true,
		}
	}
	encode := func(t *testing.T, value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal("encode fixture metadata")
		}
		return string(raw)
	}
	const insert = `INSERT INTO public.accounts(name,platform,type,status,schedulable,credentials,extra) VALUES ('dynamic-model-pg-fixture','openai','apikey',$1,false,$2::jsonb,$3::jsonb)`
	reject := func(t *testing.T, statement string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, "SAVEPOINT denied_guard_write"); err != nil {
			t.Fatal("create rejected-write savepoint")
		}
		_, denied := tx.ExecContext(ctx, statement, args...)
		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT denied_guard_write; RELEASE SAVEPOINT denied_guard_write"); err != nil {
			t.Fatal("recover rejected-write savepoint")
		}
		var pgError *pq.Error
		if !errors.As(denied, &pgError) || pgError.Code != "23514" {
			t.Fatal("protected write must fail with its check guard, not an unrelated constraint")
		}
	}
	var candidateID int64
	for _, model := range []string{"future-vendor/enrollment-anchor:free", "openrouter/auto", "a/" + strings.Repeat("x", 126)} {
		t.Run("accept/"+model, func(t *testing.T) {
			credentials, extra := fixture(t, model)
			var id int64
			if tx.QueryRowContext(ctx, insert+" RETURNING id", "disabled", encode(t, credentials), encode(t, extra)).Scan(&id) != nil || id <= 0 {
				t.Fatal("safe dynamic model must permit inert candidate creation")
			}
			if _, err := tx.ExecContext(ctx, `UPDATE public.accounts SET status='active' WHERE id=$1`, id); err != nil {
				t.Fatal("qualified candidate promotion must preserve its immutable dynamic birth")
			}
			candidateID = id
		})
	}
	for _, model := range []any{"vendor/model\n", "vendor/mødél", "vendor/模型", " model/x", "vendor/model ", "noslash", "https://vendor/model", "a/" + strings.Repeat("x", 127), "", nil, 42} {
		t.Run(fmt.Sprintf("reject/model/%q", model), func(t *testing.T) {
			credentials, extra := fixture(t, model)
			reject(t, insert, "disabled", encode(t, credentials), encode(t, extra))
		})
	}
	for _, mutation := range []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"wrong-origin", func(c, _ map[string]any) { c["base_url"] = "https://other.invalid/api/v1" }},
		{"plaintext", func(c, _ map[string]any) { c["api_key"] = "plaintext-fixture" }},
		{"wrong-generation", func(_, e map[string]any) {
			e["gateway_credential_scope_v1"].(map[string]any)["generation"] = "00000000-0000-0000-0000-000000000000"
		}},
		{"wrong-purpose", func(_, e map[string]any) {
			e["gateway_credential_scope_v1"].(map[string]any)["purpose"] = "provider-oauth-bundle-v1"
		}},
		{"extra-metadata", func(_, e map[string]any) { e["unqualified"] = true }},
	} {
		t.Run("reject/"+mutation.name, func(t *testing.T) {
			credentials, extra := fixture(t, "vendor/new-model")
			mutation.edit(credentials, extra)
			reject(t, insert, "disabled", encode(t, credentials), encode(t, extra))
		})
	}
	credentials, extra := fixture(t, "vendor/new-model")
	t.Run("reject/active-birth", func(t *testing.T) { reject(t, insert, "active", encode(t, credentials), encode(t, extra)) })
	for _, mutation := range []struct{ name, statement string }{
		{"immutable-birth-model", `UPDATE public.accounts SET extra=jsonb_set(extra,'{gateway_model_v1}','"vendor/another-safe-model"') WHERE id=$1`},
		{"immutable-owner", `UPDATE public.accounts SET extra=jsonb_set(extra,'{gateway_credential_scope_v1,owner}','"different-owner"') WHERE id=$1`},
		{"immutable-credential", `UPDATE public.accounts SET credentials=jsonb_set(credentials,'{api_key}','"plaintext-replacement"') WHERE id=$1`},
		{"immutable-birth-time", `UPDATE public.accounts SET created_at=created_at+interval '1 microsecond' WHERE id=$1`},
		{"unschedulable", `UPDATE public.accounts SET schedulable=true WHERE id=$1`},
		{"group-free", `INSERT INTO public.account_groups(account_id,group_id) VALUES ($1,-1)`},
		{"retain-tombstone", `DELETE FROM public.accounts WHERE id=$1`},
	} {
		t.Run("reject/lifecycle/"+mutation.name, func(t *testing.T) { reject(t, mutation.statement, candidateID) })
	}
	t.Run("reject/ordinary-row-adoption", func(t *testing.T) {
		var ordinaryID int64
		if tx.QueryRowContext(ctx, `INSERT INTO public.accounts(name,platform,type,status,schedulable,credentials,extra) VALUES ('ordinary-pg-fixture','openai','apikey','disabled',false,'{}','{}') RETURNING id`).Scan(&ordinaryID) != nil {
			t.Fatal("create ordinary account fixture")
		}
		reject(t, `UPDATE public.accounts SET credentials=$2::jsonb,extra=$3::jsonb WHERE id=$1`, ordinaryID, encode(t, credentials), encode(t, extra))
	})
	t.Run("erase-and-retain-tombstone", func(t *testing.T) {
		if _, err := tx.ExecContext(ctx, `UPDATE public.accounts SET status='disabled' WHERE id=$1`, candidateID); err != nil {
			t.Fatal("disable the protected candidate")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE public.accounts SET credentials=credentials-'api_key',deleted_at=clock_timestamp() WHERE id=$1`, candidateID); err != nil {
			t.Fatal("exact disabled credential erasure must remain supported")
		}
		reject(t, `UPDATE public.accounts SET status='active',deleted_at=NULL WHERE id=$1`, candidateID)
		reject(t, `DELETE FROM public.accounts WHERE id=$1`, candidateID)
	})
	if err := tx.Rollback(); err != nil {
		t.Fatal("rollback-only fixture must not persist any candidate")
	}
}
