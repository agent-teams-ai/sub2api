//go:build integration

package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Controlled persistence exercises the real management/service HTTP boundaries.
// Existing SQL triggers reject OpenRouter: migrated SQL remains NOT_QUALIFIED.
type finiteCatalogRows struct {
	service.AdminAccountRepository
	mu   sync.Mutex
	rows map[int64]*service.Account
}

func (r *finiteCatalogRows) Create(_ context.Context, a *service.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.ID = int64(len(r.rows) + 1)
	a.CreatedAt = time.Date(2026, 10, 6, 0, 0, 0, 123456000, time.UTC)
	r.rows[a.ID] = a
	return nil
}

func (r *finiteCatalogRows) GetByID(_ context.Context, id int64) (*service.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}

func (r *finiteCatalogRows) FindByExtraField(_ context.Context, key string, value any) ([]service.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found []service.Account
	for _, a := range r.rows {
		if a.Extra[key] == value {
			found = append(found, *a)
		}
	}
	return found, nil
}

func (r *finiteCatalogRows) UpdateWithAccountBillingSettings(_ context.Context, a *service.Account, _, _ *bool, _ *float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[a.ID] = a
	return nil
}

func (r *finiteCatalogRows) LockGatewayNativeAccount(_ context.Context, id int64) (*service.Account, func(), error) {
	r.mu.Lock()
	return r.rows[id], r.mu.Unlock, nil
}

func TestFiniteAPIKeyCatalogHTTPCreateReadMutation(t *testing.T) {
	var entries, admissions atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		if r.Host == "openrouter.ai" {
			require.Equal(t, "/api/v1/responses", r.URL.Path)
		} else {
			require.Equal(t, "mimo.fixture.invalid", r.Host)
			require.Equal(t, "/v1/responses", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer upstream.Close()
	local := upstream.Client().Transport.(*http.Transport).Clone()
	local.Proxy = nil
	local.TLSClientConfig.ServerName = "example.com"
	local.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "mimo.fixture.invalid:443" && address != "openrouter.ai:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	defer local.CloseIdleConnections()
	repo := &finiteCatalogRows{rows: map[int64]*service.Account{}}
	admin := nativeReviewAdmin(repo, nil)
	gateway := nativeReviewGateway(repo, nil, &nativeReviewRealHTTP{client: &http.Client{Transport: local}})
	primary := GatewayNativeProfile{service.GatewayMiMoResponsesProfile, "https://mimo.fixture.invalid/v1", "fixture-model"}
	secondary := GatewayNativeProfile{service.GatewayOpenRouterResponsesProfile, service.GatewayOpenRouterBaseURL, service.GatewayOpenRouterModel}
	token := "Bearer " + nativeReviewSyntheticKey(t)
	authorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != token {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), "fixture-consumer")
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	router := gin.New()
	RegisterGatewayNativeRoutes(router.Group(""), admin, gateway, primary, authorize,
		func(*gin.Context, service.GatewayNativeRoute) error { admissions.Add(1); return nil }, func(*gin.Context, bool, error) {}, nativeReviewCustody(t), secondary)
	server := httptest.NewServer(router)
	defer server.Close()
	base := server.URL + "/private/native/v1"
	status, _ := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/candidates", token,
		gatewayNativeCreate{"55555555-5555-4555-8555-555555555555", "caller-profile", "fixture", nativeReviewSyntheticKey(t), "fixture-owner", "fixture-account"})
	require.Equal(t, http.StatusBadRequest, status)
	require.Empty(t, repo.rows)
	var candidates []GatewayNativeCandidate
	for i, profile := range []GatewayNativeProfile{primary, secondary} {
		generation := []string{"33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"}[i]
		status, data := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/candidates", token,
			gatewayNativeCreate{generation, profile.ID, "fixture", nativeReviewSyntheticKey(t), "fixture-owner", profile.ID})
		require.Equal(t, http.StatusOK, status, string(data))
		var candidate GatewayNativeCandidate
		require.NoError(t, json.Unmarshal(data, &candidate))
		require.Equal(t, profile.ID, candidate.Descriptor.Profile)
		require.Equal(t, profile.BaseURL, candidate.Descriptor.BaseURL)
		require.Equal(t, profile.Model, candidate.Descriptor.Model)
		require.Equal(t, "inactive", candidate.State)
		status, _ = custodyAPIRequest(t, server.Client(), http.MethodGet, base+"/candidates/"+generation, token, nil)
		require.Equal(t, http.StatusOK, status)
		candidates = append(candidates, candidate)
	}
	require.Zero(t, entries.Load(), "create/read performs no provider probe")
	bad := candidates[1].Descriptor
	bad.Profile, bad.BaseURL, bad.Model = primary.ID, primary.BaseURL, primary.Model
	status, _ = custodyAPIRequest(t, server.Client(), http.MethodPut, base+"/candidates/"+bad.Generation, token, gatewayNativeMutation{Descriptor: bad, State: "active"})
	require.Equal(t, http.StatusConflict, status)
	bad = candidates[1].Descriptor
	bad.BaseURL = primary.BaseURL
	status, _ = custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/responses", token, gatewayNativeDispatchRequest{bad, json.RawMessage(`{}`)})
	require.Equal(t, http.StatusBadRequest, status)
	require.Zero(t, admissions.Load())
	require.Zero(t, entries.Load())
	for _, candidate := range candidates {
		status, data := custodyAPIRequest(t, server.Client(), http.MethodPut, base+"/candidates/"+candidate.Descriptor.Generation, token,
			gatewayNativeMutation{Descriptor: candidate.Descriptor, Name: "renamed", State: "active"})
		require.Equal(t, http.StatusOK, status, string(data))
		payload, err := json.Marshal(map[string]any{"model": candidate.Descriptor.Model, "input": "controlled", "store": false, "service_tier": "default"})
		require.NoError(t, err)
		status, data = custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/responses", token, gatewayNativeDispatchRequest{candidate.Descriptor, payload})
		require.Equal(t, http.StatusOK, status, string(data))
	}
	require.EqualValues(t, 2, admissions.Load())
	require.EqualValues(t, 2, entries.Load())
}

func custodyAPIRequest(t *testing.T, client *http.Client, method, target, token string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, target, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	bounded := *client
	bounded.Timeout = 10 * time.Second
	resp, err := bounded.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	return resp.StatusCode, data
}

// Regression: private create can still persist/read back a plaintext key, accept
// caller consumer authority, or dispatch an unauthenticated restored envelope.
// This uses the migrated PostgreSQL repository, real admin service/private API,
// and a real TLS provider. Admission here is a fixture, not a B registry receipt.
func TestGatewayNativeCustodyPrivateAPIPostgres(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_CUSTODY_API_PG_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: dedicated custody API PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid disposable PostgreSQL URL")
	}
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "native_custody_api_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&tables))
	require.Zero(t, tables, "only a new empty disposable database")
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	repo := repository.NewAccountRepository(client, db, nil)
	admin := nativeReviewAdmin(repo, client)
	key := nativeReviewSyntheticKey(t)
	var entries atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "Bearer "+key, r.Header.Get("Authorization"))
		require.Equal(t, "/v1/responses", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer upstream.Close()
	gateway := nativeReviewGateway(repo, nil, &nativeReviewRealHTTP{client: upstream.Client()})
	profile := GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: upstream.URL, Model: "synthetic-model"}
	custody := nativeReviewCustody(t)
	tokenA, tokenB := "Bearer "+nativeReviewSyntheticKey(t), "Bearer "+nativeReviewSyntheticKey(t)
	authorize := func(c *gin.Context) {
		consumer, ok := map[string]string{tokenA: "consumer/a", tokenB: "consumer/b"}[c.GetHeader("Authorization")]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), consumer)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	compose := func(adapter *service.GatewayNativeCredentialCustody) *httptest.Server {
		router := gin.New()
		RegisterGatewayNativeRoutes(router.Group(""), admin, gateway, profile, authorize,
			func(*gin.Context, service.GatewayNativeRoute) error { return nil }, func(*gin.Context, bool, error) {}, adapter)
		server := httptest.NewServer(router)
		t.Cleanup(server.Close)
		return server
	}
	server := compose(custody)
	base := server.URL + "/private/native/v1"
	generation := "c3333333-3333-4333-8333-333333333333"
	create := map[string]any{"generation": generation, "profile": profile.ID, "name": "世界 café 🚀", "api_key": key,
		"owner_ref": "workspace/世界", "account_ref": "account/é"}
	// Regression: optional custody silently re-enables the old plaintext API mode.
	t.Run("custody composition is required", func(t *testing.T) {
		require.Panics(t, func() { compose(nil) })
	})
	// Regression: permissive JSON/refs/header input reaches durable create. The
	// real API must reject it without creating even an inactive candidate.
	t.Run("write-only bounded canonical ingress", func(t *testing.T) {
		for _, change := range []string{"consumer", "owner", "account", "key", "generation"} {
			bad := make(map[string]any)
			for k, v := range create {
				bad[k] = v
			}
			bad["generation"] = "d4444444-4444-4444-8444-444444444444"
			switch change {
			case "consumer":
				bad["consumer"] = "consumer/b"
			case "owner":
				bad["owner_ref"] = strings.Repeat("o", 201)
			case "account":
				bad["account_ref"] = ""
			case "key":
				bad["api_key"] = key + "\r\n"
			case "generation":
				bad["generation"] = "invalid"
			}
			status, raw := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/candidates", tokenA, bad)
			require.Equal(t, http.StatusBadRequest, status)
			require.NotContains(t, string(raw), key)
		}
		canonical := make(map[string]any)
		for k, v := range create {
			canonical[k] = v
		}
		canonical["generation"] = "d4444444-4444-4444-8444-444444444444"
		validBody, err := json.Marshal(canonical)
		require.NoError(t, err)
		for _, raw := range []string{
			strings.Replace(string(validBody), `"generation":`, `"generation":"d4444444-4444-4444-8444-444444444444","generation":`, 1),
			strings.Replace(string(validBody), `"generation":`, `"Generation":`, 1),
			strings.Replace(string(validBody), `"owner_ref":`, `"owner_ref":"workspace/foreign","owner_ref":`, 1),
		} {
			status, _ := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/candidates", tokenA, json.RawMessage(raw))
			require.Equal(t, http.StatusBadRequest, status)
		}

		var rows int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM accounts").Scan(&rows))
		require.Zero(t, rows)
		require.Zero(t, entries.Load())
	})
	status, raw := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/candidates", tokenA, create)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, string(raw), key)
	require.NotContains(t, string(raw), "gcn1.")
	var candidate GatewayNativeCandidate
	require.NoError(t, json.Unmarshal(raw, &candidate))
	require.Equal(t, "inactive", candidate.State)
	require.Equal(t, create["name"], candidate.Name)
	row, err := repo.GetByID(ctx, candidate.Descriptor.AccountID)
	require.NoError(t, err)
	envelope := row.GetCredential("api_key")
	require.True(t, strings.HasPrefix(envelope, "gcn1.fixture-k1."))
	scope, err := service.GatewayNativeCredentialScopeForAccount(row)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeCredentialScope{Consumer: "consumer/a", Owner: "workspace/世界", Account: "account/é", Generation: generation, Purpose: service.GatewayCredentialPurpose}, scope)
	var stored string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", row.ID).Scan(&stored))
	require.NotContains(t, stored, key)
	require.Zero(t, entries.Load(), "create/readback must not perform an inference credential probe")
	payload := json.RawMessage(`{"model":"synthetic-model","input":"fixture","store":false,"service_tier":"default"}`)
	dispatch := gatewayNativeDispatchRequest{Descriptor: candidate.Descriptor, Payload: payload}
	// Regression: a staged candidate or foreign authenticated consumer dispatches.
	t.Run("staging and foreign consumer quarantine", func(t *testing.T) {
		status, _ := custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/responses", tokenA, dispatch)
		require.GreaterOrEqual(t, status, 400)
		status, data := custodyAPIRequest(t, server.Client(), http.MethodGet, base+"/candidates/"+generation, tokenB, nil)
		require.Equal(t, http.StatusConflict, status)
		require.NotContains(t, string(data), candidate.Name)
		require.NotContains(t, string(data), key)
		require.Zero(t, entries.Load())
	})
	// Regression: rename rewrites encrypted key/scope, or encrypted storage is
	// passed directly to Authorization. Actual HTTP must see the original key once.
	t.Run("Unicode rename and one explicit dispatch", func(t *testing.T) {
		status, data := custodyAPIRequest(t, server.Client(), http.MethodPut, base+"/candidates/"+generation, tokenA,
			gatewayNativeMutation{Descriptor: candidate.Descriptor, Name: "renamed 世界 é", State: "active"})
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, string(data), key)
		fresh, err := repo.GetByID(ctx, row.ID)
		require.NoError(t, err)
		require.Equal(t, envelope, fresh.GetCredential("api_key"))
		require.Equal(t, row.Extra, fresh.Extra)
		status, _ = custodyAPIRequest(t, server.Client(), http.MethodPost, base+"/responses", tokenA, dispatch)
		require.Equal(t, http.StatusOK, status)
		require.EqualValues(t, 1, entries.Load())
		_, err = admin.GetAccountsByIDs(ctx, []int64{row.ID})
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity, "ordinary export input rejects managed")
		schedulable, err := repo.ListSchedulableUngroupedByPlatform(ctx, service.PlatformOpenAI)
		require.NoError(t, err)
		require.Empty(t, schedulable)
	})
	// Regression: same-ID wrong key or retired key causes a retry/bridge/probe.
	t.Run("wrong and unavailable composition keys make zero entries", func(t *testing.T) {
		for _, id := range []string{"fixture-k1", "retired-read-key"} {
			adapter, err := service.NewGatewayNativeCredentialCustody(id, map[string][]byte{id: nativeReviewSyntheticBytes(t, 32)})
			require.NoError(t, err)
			other := compose(adapter)
			before := entries.Load()
			status, data := custodyAPIRequest(t, other.Client(), http.MethodPost, other.URL+"/private/native/v1/responses", tokenA, dispatch)
			require.GreaterOrEqual(t, status, 400)
			require.Contains(t, string(data), "native_candidate_quarantined")
			require.NotContains(t, string(data), key)
			require.Equal(t, before, entries.Load())
		}
	})
	// Regression: cleanup rounds birth precision, erases foreign scope, requires
	// decryption after key loss, or an erased descriptor is revived by SQL restore.
	t.Run("exact erase is key-independent and cannot revive", func(t *testing.T) {
		missing, err := service.NewGatewayNativeCredentialCustody("new-only", map[string][]byte{"new-only": nativeReviewSyntheticBytes(t, 32)})
		require.NoError(t, err)
		cleanup := compose(missing)
		candidateURL := cleanup.URL + "/private/native/v1/candidates/" + generation
		status, data := custodyAPIRequest(t, cleanup.Client(), http.MethodGet, candidateURL, tokenA, nil)
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, string(data), key)
		var metadata GatewayNativeCandidate
		require.NoError(t, json.Unmarshal(data, &metadata))
		require.Equal(t, "active", metadata.State, "key is retired before deactivation")
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodGet, candidateURL, tokenB, nil)
		require.Equal(t, http.StatusConflict, status)
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPut, candidateURL, tokenA,
			gatewayNativeMutation{Descriptor: candidate.Descriptor, State: "active"})
		require.Equal(t, http.StatusConflict, status, "metadata is not key availability proof")
		bad := candidate.Descriptor
		bad.CreatedAt = bad.CreatedAt.Add(time.Nanosecond)
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPut, candidateURL, tokenA,
			gatewayNativeMutation{Descriptor: bad, State: "inactive"})
		require.Equal(t, http.StatusConflict, status)
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPut, candidateURL, tokenB,
			gatewayNativeMutation{Descriptor: candidate.Descriptor, State: "inactive"})
		require.Equal(t, http.StatusConflict, status)
		fresh, err := repo.GetByID(ctx, row.ID)
		require.NoError(t, err)
		require.Equal(t, service.StatusActive, fresh.Status, "rejected mutations do not deactivate")
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPut, candidateURL, tokenA,
			gatewayNativeMutation{Descriptor: candidate.Descriptor, State: "inactive"})
		require.Equal(t, http.StatusOK, status)
		status, data = custodyAPIRequest(t, cleanup.Client(), http.MethodGet, candidateURL, tokenA, nil)
		require.Equal(t, http.StatusOK, status)
		require.NoError(t, json.Unmarshal(data, &metadata))
		require.Equal(t, "inactive", metadata.State)
		require.EqualValues(t, 1, entries.Load(), "cleanup makes no provider entry")
		target := candidateURL + "/erase"
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPost, target, tokenA, gatewayNativeMutation{Descriptor: bad})
		require.Equal(t, http.StatusConflict, status)
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPost, target, tokenB, gatewayNativeMutation{Descriptor: candidate.Descriptor})
		require.Equal(t, http.StatusConflict, status)
		for i := 0; i < 2; i++ {
			status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPost, target, tokenA, gatewayNativeMutation{Descriptor: candidate.Descriptor})
			require.Equal(t, http.StatusOK, status)
		}
		var keyPresent bool
		require.NoError(t, db.QueryRowContext(ctx, "SELECT credentials ? 'api_key' FROM accounts WHERE id=$1", row.ID).Scan(&keyPresent))
		require.False(t, keyPresent)
		_, err = db.ExecContext(ctx, "UPDATE accounts SET deleted_at=NULL,status='active',credentials=jsonb_set(credentials,'{api_key}',to_jsonb($1::text)) WHERE id=$2", envelope, row.ID)
		var pgErr *pq.Error
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, pq.ErrorCode("23514"), pgErr.Code)
		status, _ = custodyAPIRequest(t, cleanup.Client(), http.MethodPost, cleanup.URL+"/private/native/v1/responses", tokenA, dispatch)
		require.GreaterOrEqual(t, status, 400)
		require.EqualValues(t, 1, entries.Load())
	})
}
