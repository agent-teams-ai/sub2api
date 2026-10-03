//go:build integration

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	// Match stock server composition: initialize Ent defaults, hooks and interceptors.
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func nativeReviewGateway(repo service.AccountRepository, cache service.GatewayCache, transport service.HTTPUpstream) *service.OpenAIGatewayService {
	cfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false, AllowInsecureHTTP: true}}}
	return service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, cache, cfg, nil, nil, nil, nil, nil, transport, nil, nil, nil, nil, nil, nil, nil, nil)
}
func nativeReviewAdmin(repo service.AccountRepository, client *dbent.Client) service.AdminService {
	return service.NewAdminService(nil, nil, nil, repo.(service.AdminAccountRepository), nil, nil, nil, nil, nil, nil, nil, nil, nil, client, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}
func nativeReviewSyntheticBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	_, err := rand.Read(value)
	require.NoError(t, err)
	return value
}

func nativeReviewSyntheticKey(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(nativeReviewSyntheticBytes(t, 32))
}

func nativeReviewCustody(t *testing.T) *service.GatewayNativeCredentialCustody {
	t.Helper()
	custody, err := service.NewGatewayNativeCredentialCustody("fixture-k1", map[string][]byte{"fixture-k1": nativeReviewSyntheticBytes(t, 32)})
	require.NoError(t, err)
	return custody
}
func nativeReviewAuthorize(c *gin.Context) {
	ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), "fixture-consumer")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}
func nativeReviewHTTP(t *testing.T, client *http.Client, method, target string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, target, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	return resp.StatusCode, data
}

// Real Ent, the actual stock migration runner, ordinary HTTP handlers and the
// explicit private composition. Main must supply an empty disposable database.
func TestGatewayNativeReviewPrivateHTTPPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: dedicated PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "native_review_"), "only a new native_review_ database may be used")
	if u.User != nil {
		_, hasPassword := u.User.Password()
		require.False(t, hasPassword, "sandbox DSN must not contain credentials")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var existing int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&existing))
	require.Zero(t, existing, "sandbox must be new and empty")
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	repo := repository.NewAccountRepository(client, db, nil)
	adminSvc := nativeReviewAdmin(repo, client)
	gateway := nativeReviewGateway(repo, nil, nil)
	router := gin.New()
	handler := &AccountHandler{adminService: adminSvc}
	ordinary := router.Group("/api/v1/admin")
	ordinary.Use(handler.RejectGatewayNativeAdmin)
	ordinary.POST("/accounts/:id/clear-error", handler.ClearError)
	ordinary.POST("/accounts/batch-clear-error", handler.BatchClearError)
	profile := GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: "https://sandbox.invalid", Model: "mimo-test"}
	RegisterGatewayNativeRoutes(router.Group(""), adminSvc, gateway, profile, nativeReviewAuthorize, func(*gin.Context, service.GatewayNativeRoute) error { return nil }, func(*gin.Context, bool, error) {}, nativeReviewCustody(t))
	server := httptest.NewServer(router)
	defer server.Close()
	generation := "77777777-7777-4777-8777-777777777777"
	create := map[string]any{"generation": generation, "profile": profile.ID, "name": "candidate", "api_key": nativeReviewSyntheticKey(t), "owner_ref": "owner/fixture", "account_ref": "account/fixture"}
	status, raw := nativeReviewHTTP(t, server.Client(), http.MethodPost, server.URL+"/private/native/v1/candidates", create)
	require.Equal(t, http.StatusOK, status)
	var candidate GatewayNativeCandidate
	require.NoError(t, json.Unmarshal(raw, &candidate))
	require.Equal(t, "inactive", candidate.State)
	require.True(t, candidate.GroupFree)
	require.False(t, candidate.Schedulable)
	require.False(t, candidate.ProbesEnabled)
	t.Run("persisted creation is inert and has only the private allowlists", func(t *testing.T) {
		stored, err := repo.GetByID(ctx, candidate.Descriptor.AccountID)
		require.NoError(t, err)
		require.Equal(t, service.StatusDisabled, stored.Status)
		require.False(t, stored.Schedulable)
		require.Empty(t, stored.GroupIDs)
		require.Empty(t, stored.AccountGroups)
		require.Nil(t, stored.ProxyID)
		require.Nil(t, stored.ParentAccountID)
		require.Len(t, stored.Credentials, 2)
		require.Len(t, stored.Extra, 8)
		require.True(t, strings.HasPrefix(stored.GetCredential("api_key"), "gcn1.fixture-k1."))
		require.NotContains(t, stored.Extra, "openai_long_context_billing_enabled")
		require.NotContains(t, stored.Extra, service.UpstreamBillingProbeEnabledExtraKey)
		require.NotContains(t, stored.Extra, "openai_responses_supported")
		// Ordinary stock creation still applies its default, rather than adopting
		// the private policy or losing the ordinary active/schedulable behavior.
		ordinary, err := adminSvc.CreateAccount(ctx, &service.CreateAccountInput{Name: "normalizer baseline", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
			Credentials: map[string]any{"api_key": nativeReviewSyntheticKey(t), "base_url": profile.BaseURL}, SkipDefaultGroupBind: true, Concurrency: 1})
		require.NoError(t, err)
		require.Equal(t, false, ordinary.Extra["openai_long_context_billing_enabled"])
		require.Equal(t, service.StatusActive, ordinary.Status)
		require.True(t, ordinary.Schedulable)
		ordinary, err = repo.GetByID(ctx, ordinary.ID)
		require.NoError(t, err)
		require.Equal(t, false, ordinary.Extra["openai_long_context_billing_enabled"])
		// Reject forbidden ingress rather than silently stripping stock system extras.
		for _, key := range []string{"openai_long_context_billing_enabled", service.UpstreamBillingProbeEnabledExtraKey, "codex_auto_reset_credit_state"} {
			extra := map[string]any{}
			for k, v := range stored.Extra {
				extra[k] = v
			}
			extra[key] = false
			_, err := adminSvc.CreateAccount(service.WithGatewayNativeControl(ctx), &service.CreateAccountInput{Name: "forbidden", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": nativeReviewSyntheticKey(t), "base_url": profile.BaseURL}, Extra: extra, SkipDefaultGroupBind: true})
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		}
		var rows, groups int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE extra->>'gateway_generation_v1'=$1", generation).Scan(&rows))
		require.Equal(t, 1, rows)
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM account_groups WHERE account_id=$1", stored.ID).Scan(&groups))
		require.Zero(t, groups)
	})
	var birth time.Time
	require.NoError(t, db.QueryRowContext(ctx, "SELECT created_at FROM accounts WHERE id=$1", candidate.Descriptor.AccountID).Scan(&birth))
	t.Run("legacy bridge profile POST persists eight extras through the actual repository", func(t *testing.T) {
		bridge := GatewayNativeProfile{ID: service.GatewayLegacyBridgeProfile, BaseURL: "https://sandbox.invalid", Model: "mimo-test"}
		routes := gin.New()
		RegisterGatewayNativeRoutes(routes.Group(""), adminSvc, gateway, bridge, nativeReviewAuthorize, func(*gin.Context, service.GatewayNativeRoute) error { return nil }, func(*gin.Context, bool, error) {}, nativeReviewCustody(t))
		fixture := httptest.NewServer(routes)
		defer fixture.Close()
		status, data := nativeReviewHTTP(t, fixture.Client(), http.MethodPost, fixture.URL+"/private/native/v1/candidates", map[string]any{"generation": "99999999-9999-4999-8999-999999999999", "profile": bridge.ID, "name": "Bridge candidate", "api_key": nativeReviewSyntheticKey(t), "owner_ref": "owner/fixture", "account_ref": "account/bridge"})
		require.Equal(t, http.StatusOK, status)
		var got GatewayNativeCandidate
		require.NoError(t, json.Unmarshal(data, &got))
		stored, err := repo.GetByID(ctx, got.Descriptor.AccountID)
		require.NoError(t, err)
		require.Len(t, stored.Extra, 8)
		require.NotContains(t, stored.Extra, "openai_long_context_billing_enabled")
		require.Equal(t, bridge.ID, stored.Extra[service.GatewayProfileExtraKey])
		require.Equal(t, service.StatusDisabled, stored.Status)
		require.False(t, stored.Schedulable)
	})
	require.True(t, birth.Equal(candidate.Descriptor.CreatedAt), "POST birth must be the actually persisted instant")
	var count int
	countCandidates := func() int {
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE extra->>'gateway_generation_v1'=$1", generation).Scan(&count))
		return count
	}
	t.Run("lost acknowledgement readback never recreates", func(t *testing.T) {
		// Treat the already submitted POST acknowledgement as lost: use only GET.
		status, data := nativeReviewHTTP(t, server.Client(), http.MethodGet, server.URL+"/private/native/v1/candidates/"+generation, nil)
		require.Equal(t, http.StatusOK, status)
		var got GatewayNativeCandidate
		require.NoError(t, json.Unmarshal(data, &got))
		require.JSONEq(t, string(raw), string(data))
		require.Equal(t, 1, countCandidates())
		status, _ = nativeReviewHTTP(t, server.Client(), http.MethodPost, server.URL+"/private/native/v1/candidates", create)
		require.GreaterOrEqual(t, status, 400)
		require.Equal(t, 1, countCandidates())
	})
	ordinaryRow := &service.Account{Name: "ordinary", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusError, Schedulable: true, Concurrency: 1, Credentials: map[string]any{"api_key": nativeReviewSyntheticKey(t), "base_url": "https://sandbox.invalid"}, Extra: map[string]any{}}
	require.NoError(t, repo.Create(ctx, ordinaryRow))
	t.Run("ordinary SQL and current repository writers retain billing defaults", func(t *testing.T) {
		// Unlike CreateAccount, these writers never call the Go create normalizer.
		// Read persisted state: a correct Go result alone cannot qualify the SQL trigger.
		assertDefault := func(id int64, want map[string]any) {
			t.Helper()
			fresh, err := repo.GetByID(ctx, id)
			require.NoError(t, err)
			require.Equal(t, want, fresh.Extra)
		}
		assertDefault(ordinaryRow.ID, map[string]any{"openai_long_context_billing_enabled": false})
		var rawID int64
		require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,credentials,extra,status,schedulable,concurrency)
   VALUES ('raw billing fixture','openai','apikey',jsonb_build_object('api_key',$1::text,'base_url','https://sandbox.invalid'),'{}'::jsonb,'disabled',false,1) RETURNING id`, nativeReviewSyntheticKey(t)).Scan(&rawID))
		assertDefault(rawID, map[string]any{"openai_long_context_billing_enabled": false})
		_, err := db.ExecContext(ctx, "UPDATE accounts SET extra=$1::jsonb WHERE id=$2", `{"ordinary_fixture":true}`, rawID)
		require.NoError(t, err)
		assertDefault(rawID, map[string]any{"ordinary_fixture": true, "openai_long_context_billing_enabled": false})
		// SQL NULL must also stay on the ordinary trigger's path.
		_, err = db.ExecContext(ctx, "UPDATE accounts SET extra=NULL WHERE id=$1", rawID)
		require.NoError(t, err)
		assertDefault(rawID, map[string]any{"openai_long_context_billing_enabled": false})
		_, err = db.ExecContext(ctx, "UPDATE accounts SET extra=$1::jsonb WHERE id=$2", `{"openai_long_context_billing_enabled":true}`, rawID)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, "UPDATE accounts SET extra='{}'::jsonb WHERE id=$1", rawID)
		require.NoError(t, err)
		assertDefault(rawID, map[string]any{"openai_long_context_billing_enabled": true})
		_, err = db.ExecContext(ctx, "UPDATE accounts SET extra=$1::jsonb WHERE id=$2", `{"openai_long_context_billing_enabled":"false"}`, rawID)
		var pgErr *pq.Error
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, pq.ErrorCode("22023"), pgErr.Code)
		assertDefault(rawID, map[string]any{"openai_long_context_billing_enabled": true})
		ordinary, err := repo.GetByID(ctx, ordinaryRow.ID)
		require.NoError(t, err)
		ordinary.Extra = map[string]any{"ordinary_fixture": true}
		require.NoError(t, repo.Update(ctx, ordinary))
		assertDefault(ordinaryRow.ID, map[string]any{"ordinary_fixture": true, "openai_long_context_billing_enabled": false})
	})
	original, err := repo.GetByID(ctx, candidate.Descriptor.AccountID)
	require.NoError(t, err)
	t.Run("either reserved marker still rejects malformed insert and adoption", func(t *testing.T) {
		for _, extra := range []string{`{"gateway_generation_v1":null}`, `{"gateway_profile_v1":null}`} {
			_, err := db.ExecContext(ctx, `INSERT INTO accounts(name,platform,type,credentials,extra,status,schedulable,concurrency)
    SELECT 'malformed marker',platform,type,credentials,$1::jsonb,'disabled',false,1 FROM accounts WHERE id=$2`, extra, original.ID)
			var pgErr *pq.Error
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
			_, err = db.ExecContext(ctx, "UPDATE accounts SET extra=$1::jsonb WHERE id=$2", extra, ordinaryRow.ID)
			pgErr = nil
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
		}
		ordinary, err := repo.GetByID(ctx, ordinaryRow.ID)
		require.NoError(t, err)
		require.Equal(t, map[string]any{"ordinary_fixture": true, "openai_long_context_billing_enabled": false}, ordinary.Extra)
	})
	assertPrivateExtra := func() {
		t.Helper()
		fresh, err := repo.GetByID(ctx, original.ID)
		require.NoError(t, err)
		require.Equal(t, original.Extra, fresh.Extra)
		require.Len(t, fresh.Extra, 8)
		require.NotContains(t, fresh.Extra, "openai_long_context_billing_enabled")
	}
	t.Run("private SQL update preserves the exact eight extras", func(t *testing.T) {
		_, err := db.ExecContext(ctx, "UPDATE accounts SET extra=extra WHERE id=$1", original.ID)
		require.NoError(t, err)
		assertPrivateExtra()
	})
	snapshot := func() {
		fresh, err := repo.GetByID(ctx, original.ID)
		require.NoError(t, err)
		require.Equal(t, service.StatusDisabled, fresh.Status)
		require.Equal(t, original.Credentials, fresh.Credentials)
		require.True(t, original.CreatedAt.Equal(fresh.CreatedAt))
	}
	t.Run("clear error rejects before the first repository write", func(t *testing.T) {
		_, err := adminSvc.ClearAccountError(ctx, original.ID)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		snapshot()
	})
	t.Run("ordinary per-ID handler cannot activate managed", func(t *testing.T) {
		status, _ := nativeReviewHTTP(t, server.Client(), http.MethodPost, fmt.Sprintf("%s/api/v1/admin/accounts/%d/clear-error", server.URL, original.ID), nil)
		require.GreaterOrEqual(t, status, 400)
		snapshot()
	})
	t.Run("mixed batch preflights every target before any mutation", func(t *testing.T) {
		for _, ids := range [][]int64{{ordinaryRow.ID, original.ID}, {original.ID, ordinaryRow.ID}} {
			status, _ := nativeReviewHTTP(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/accounts/batch-clear-error", map[string]any{"account_ids": ids})
			require.GreaterOrEqual(t, status, 400)
			snapshot()
			ordinary, err := repo.GetByID(ctx, ordinaryRow.ID)
			require.NoError(t, err)
			require.Equal(t, service.StatusError, ordinary.Status)
		}
	})
	t.Run("other direct ordinary mutation helpers reject managed", func(t *testing.T) {
		require.ErrorIs(t, adminSvc.SetAccountError(ctx, original.ID, "fixture"), service.ErrGatewayNativeIdentity)
		_, err := adminSvc.SetAccountSchedulable(ctx, original.ID, true)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		require.ErrorIs(t, adminSvc.RevertAccountProxyFallback(ctx, original.ID), service.ErrGatewayNativeIdentity)
		require.ErrorIs(t, adminSvc.DeleteAccount(ctx, original.ID), service.ErrGatewayNativeIdentity)
		require.ErrorIs(t, adminSvc.UpdateAccountExtra(ctx, original.ID, map[string]any{"fixture": true}), service.ErrGatewayNativeIdentity)
		require.ErrorIs(t, adminSvc.ResetAccountQuota(ctx, original.ID), service.ErrGatewayNativeIdentity)
		snapshot()
	})
	t.Run("ordinary clear error still works", func(t *testing.T) {
		status, _ := nativeReviewHTTP(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/accounts/batch-clear-error", map[string]any{"account_ids": []int64{ordinaryRow.ID}})
		require.Equal(t, http.StatusOK, status)
		ordinary, err := repo.GetByID(ctx, ordinaryRow.ID)
		require.NoError(t, err)
		require.Equal(t, service.StatusActive, ordinary.Status)
		require.NoError(t, repo.SetError(ctx, ordinaryRow.ID, "fixture"))
		status, _ = nativeReviewHTTP(t, server.Client(), http.MethodPost, fmt.Sprintf("%s/api/v1/admin/accounts/%d/clear-error", server.URL, ordinaryRow.ID), nil)
		require.Equal(t, http.StatusOK, status)
		ordinary, err = repo.GetByID(ctx, ordinaryRow.ID)
		require.NoError(t, err)
		require.Equal(t, service.StatusActive, ordinary.Status)
	})
	t.Run("wire offset roundtrip and all identity fields", func(t *testing.T) {
		base := candidate.Descriptor
		base.CreatedAt = base.CreatedAt.In(time.FixedZone("wire offset", 3600))
		target := server.URL + "/private/native/v1/candidates/" + generation
		status, _ := nativeReviewHTTP(t, server.Client(), http.MethodPut, target, gatewayNativeMutation{Descriptor: base, Name: "renamed", State: "active"})
		require.Equal(t, http.StatusOK, status)
		assertPrivateExtra()
		for _, alter := range []func(*service.GatewayNativeRoute){
			func(d *service.GatewayNativeRoute) { d.AccountID++ }, func(d *service.GatewayNativeRoute) { d.Generation = "88888888-8888-4888-8888-888888888888" },
			func(d *service.GatewayNativeRoute) { d.CreatedAt = d.CreatedAt.Add(time.Nanosecond) }, func(d *service.GatewayNativeRoute) { d.Profile = service.GatewayLegacyBridgeProfile },
			func(d *service.GatewayNativeRoute) { d.BaseURL += "/foreign" }, func(d *service.GatewayNativeRoute) { d.Model = "foreign" },
		} {
			bad := base
			alter(&bad)
			status, _ := nativeReviewHTTP(t, server.Client(), http.MethodPut, target, gatewayNativeMutation{Descriptor: bad, Name: "must-not-apply", State: "inactive"})
			require.GreaterOrEqual(t, status, 400)
			fresh, err := repo.GetByID(ctx, base.AccountID)
			require.NoError(t, err)
			require.Equal(t, "renamed", fresh.Name)
			require.Equal(t, service.StatusActive, fresh.Status)
		}
		status, _ = nativeReviewHTTP(t, server.Client(), http.MethodPut, target, gatewayNativeMutation{Descriptor: base, Name: "renamed", State: "inactive"})
		require.Equal(t, http.StatusOK, status)
		fresh, err := repo.GetByID(ctx, base.AccountID)
		require.NoError(t, err)
		require.Equal(t, service.StatusDisabled, fresh.Status)
		assertPrivateExtra()
	})
}

type nativeReviewReasoningRepo struct {
	service.AccountRepository
	row *service.Account
}

func (r *nativeReviewReasoningRepo) GetByID(context.Context, int64) (*service.Account, error) {
	return r.row, nil
}
func (r *nativeReviewReasoningRepo) LockGatewayNativeAccount(context.Context, int64) (*service.Account, func(), error) {
	return r.row, func() {}, nil
}

type nativeReviewRealHTTP struct {
	service.HTTPUpstream
	client *http.Client
}

func (h *nativeReviewRealHTTP) Do(r *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return h.client.Do(r)
}

// Real Redis + actual ordinary recache/extractor and the private bridge. Observe
// outbound reasoning to catch service wiring that a cache-only test would miss.
func TestGatewayNativeReviewReasoningHTTPRedis(t *testing.T) {
	addr := os.Getenv("GATEWAY_NATIVE_TEST_HTTP_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOT_RUN: dedicated HTTP Redis address not supplied")
	}
	require.True(t, strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "[::1]:"))
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	n, err := client.DBSize(context.Background()).Result()
	require.NoError(t, err)
	require.Zero(t, n, "a separate empty disposable Redis is required")
	cache := repository.NewGatewayCache(client)
	managed := cache.(service.GatewayNativeReasoningCache)
	g1 := "11111111-1111-4111-8111-111111111111"
	g2 := "22222222-2222-4222-8222-222222222222"
	item := "http-item"
	require.NoError(t, managed.SetGatewayNativeReasoningContent(context.Background(), g1, item, "managed one", time.Minute))
	require.NoError(t, managed.SetGatewayNativeReasoningContent(context.Background(), g2, item, "managed two", time.Minute))
	var calls atomic.Int32
	observed := make(chan string, 8)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Messages []struct {
				Reasoning string `json:"reasoning_content"`
			} `json:"messages"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		reasoning := ""
		for _, m := range body.Messages {
			if m.Reasoning != "" {
				reasoning = m.Reasoning
				break
			}
		}
		observed <- reasoning
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"fixture","model":"mimo-test","choices":[{"index":0,"message":{"role":"assistant","content":"fixture"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	a := &service.Account{ID: 17, CreatedAt: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive,
		Credentials: map[string]any{"api_key": nativeReviewSyntheticKey(t), "base_url": upstream.URL}, Extra: map[string]any{service.GatewayGenerationExtraKey: g1, service.GatewayProfileExtraKey: service.GatewayLegacyBridgeProfile, service.GatewayModelExtraKey: "mimo-test", "openai_responses_mode": "force_chat_completions", "openai_passthrough": false, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	custody := nativeReviewCustody(t)
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "owner/fixture", Account: "account/reasoning", Generation: g1, Purpose: service.GatewayCredentialPurpose}
	envelope, err := custody.Seal(scope, nativeReviewSyntheticKey(t))
	require.NoError(t, err)
	a.Credentials["api_key"] = envelope
	a.Extra[service.GatewayCredentialScopeExtraKey] = scope.Metadata()
	repo := &nativeReviewReasoningRepo{row: a}
	gateway := nativeReviewGateway(repo, cache, &nativeReviewRealHTTP{client: upstream.Client()})
	ordinary := &service.Account{ID: 19, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Credentials: map[string]any{"api_key": nativeReviewSyntheticKey(t), "base_url": upstream.URL}, Extra: map[string]any{"openai_responses_mode": "force_chat_completions", "openai_preserve_compatible_reasoning": true}}
	router := gin.New()
	router.POST("/ordinary", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		_, err := gateway.Forward(c.Request.Context(), c, ordinary, body)
		if err != nil {
			c.Status(502)
		}
	})
	router.POST("/managed/:generation", func(c *gin.Context) {
		a.Extra[service.GatewayGenerationExtraKey] = c.Param("generation")
		scope.Generation = c.Param("generation")
		envelope, err := custody.Seal(scope, nativeReviewSyntheticKey(t))
		require.NoError(t, err)
		a.Credentials["api_key"] = envelope
		a.Extra[service.GatewayCredentialScopeExtraKey] = scope.Metadata()
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), scope.Consumer)
		require.NoError(t, err)
		c.Request = c.Request.WithContext(service.WithGatewayNativeCustody(ctx, custody))
		route, err := service.GatewayNativeDescriptor(a)
		if err != nil {
			c.Status(400)
			return
		}
		body, _ := io.ReadAll(c.Request.Body)
		_, entered, err := gateway.ForwardGatewayRoute(c.Request.Context(), c, route, body)
		if err != nil || !entered {
			c.Status(502)
		}
	})
	downstream := httptest.NewServer(router)
	defer downstream.Close()
	history := func(id, text string) map[string]any {
		summary := []map[string]string{}
		if text != "" {
			summary = append(summary, map[string]string{"type": "summary_text", "text": text})
		}
		return map[string]any{"model": "mimo-test", "store": false, "input": []any{map[string]any{"type": "reasoning", "id": id, "summary": summary, "encrypted_content": "opaque"}, map[string]any{"type": "function_call", "call_id": "call", "name": "fixture", "arguments": "{}"}, map[string]any{"type": "function_call_output", "call_id": "call", "output": "fixture"}}}
	}
	alias := "gateway-native-v1:" + g1 + ":" + item
	_, err = cache.GetReasoningContent(context.Background(), alias)
	require.ErrorIs(t, err, service.ErrReasoningContentNotFound)
	status, _ := nativeReviewHTTP(t, downstream.Client(), http.MethodPost, downstream.URL+"/ordinary", history(alias, "ordinary adversary"))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "ordinary adversary", <-observed)
	for _, p := range []struct{ g, want string }{{g1, "managed one"}, {g2, "managed two"}} {
		status, _ := nativeReviewHTTP(t, downstream.Client(), http.MethodPost, downstream.URL+"/managed/"+p.g, history(item, ""))
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, p.want, <-observed)
	}
	status, _ = nativeReviewHTTP(t, downstream.Client(), http.MethodPost, downstream.URL+"/ordinary", history(alias, ""))
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "ordinary adversary", <-observed)
	require.EqualValues(t, 4, calls.Load())
}
