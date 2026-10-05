package repository

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func oauthPGScope(t *testing.T, consumer, owner, account string) (context.Context, service.GatewayNativeCredentialScope) {
	t.Helper()
	scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: owner, Account: account, Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}
	ctx, err := service.WithGatewayNativeConsumer(context.Background(), consumer)
	require.NoError(t, err)
	ctx, err = service.WithGatewayNativeOAuthOwner(ctx, owner)
	require.NoError(t, err)
	return ctx, scope
}
func oauthPGFixture(t *testing.T) (*service.GatewayNativeOAuthVerifier, func(string) service.GatewayNativeOAuthBundle) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, "/.well-known/jwks.json", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "fixture", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	}))
	t.Cleanup(server.Close)
	baseTransport, ok := server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "auth.openai.com:443", address)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	verifier := service.NewGatewayNativeOAuthVerifier(transport)
	return verifier, func(subject string) service.GatewayNativeOAuthBundle {
		expiry := time.Now().Add(time.Hour)
		if subject == "subject-expiring" {
			expiry = time.Now().Add(3 * time.Second)
		}
		claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":"app_EMoamEEZ73f0CkXaXp7hrann","exp":%d}`, service.GatewayOAuthIssuer, subject, expiry.Unix())
		body := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)
		return service.GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixture1 + subject, RefreshToken: gatewayOAuthGuardFixture2 + subject, IDToken: body + "." + base64.RawURLEncoding.EncodeToString(signature), SensitiveMetadata: json.RawMessage(`{"private":"synthetic-f1-metadata","scope":"synthetic-scope"}`)}
	}
}

// Failure: service-wide duplicates could create two encrypted writers under
// different owners/consumers, retries could create another physical generation,
// or a conflict/foreign cleanup could erase the winner. Uses real migrated PG.
func TestGatewayNativeOAuthPostgresReservationAndCustody(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OAUTH_TEST_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: new disposable OAuth PostgreSQL database not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	require.True(t, strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "gateway_oauth_test_"))
	require.True(t, u.RawQuery == "" || u.RawQuery == "sslmode=disable")
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	db.SetMaxOpenConns(4)
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables))
	require.Zero(t, tables, "new isolated database required")
	require.NoError(t, ApplyMigrations(ctx, db))
	repo, ok := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	verifier, bundleFor := oauthPGFixture(t)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, repo, key)
	require.NoError(t, err)
	principal, birth := oauthPGScope(t, "consumer-a", "owner-a", "logical-a")
	bundle := bundleFor("subject-a")
	var wg sync.WaitGroup
	outcomes := make([]service.GatewayNativeOAuthOutcome, 4)
	errors := make([]error, 4)
	start := make(chan struct{})
	for i := range outcomes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			outcomes[i], errors[i] = enrollment.Stage(principal, birth, "stable-operation", bundle)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range outcomes {
		require.NoError(t, errors[i])
		require.Equal(t, outcomes[0], outcomes[i])
	}
	winner := outcomes[0]
	require.Positive(t, winner.AccountID)
	readback, err := repo.ReadGatewayNativeOAuth(principal, birth, "stable-operation")
	require.NoError(t, err)
	require.Equal(t, winner, readback)
	reordered := bundle
	reordered.SensitiveMetadata = json.RawMessage(`{ "scope":"synthetic-scope", "private":"synthetic-f1-metadata" }`)
	repeated, err := enrollment.Stage(principal, birth, "stable-operation", reordered)
	require.NoError(t, err)
	require.Equal(t, winner, repeated)
	changed := bundle
	changed.AccessToken += "-changed"
	_, err = enrollment.Stage(principal, birth, "stable-operation", changed)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	changedBirth := birth
	changedBirth.Generation = uuid.NewString()
	_, err = enrollment.Stage(principal, changedBirth, "stable-operation", bundle)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	foreign, foreignBirth := oauthPGScope(t, "consumer-b", "owner-b", "logical-b")
	_, err = enrollment.Stage(foreign, foreignBirth, "other-operation", bundle)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	require.ErrorIs(t, repo.EraseGatewayNativeOAuth(foreign, birth, "stable-operation"), service.ErrGatewayNativeIdentity)
	var credentials, extra []byte
	var status string
	var schedulable bool
	var grouped bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials,extra,status,schedulable,EXISTS(SELECT 1 FROM account_groups WHERE account_id=accounts.id) FROM accounts WHERE id=$1`, winner.AccountID).Scan(&credentials, &extra, &status, &schedulable, &grouped))
	row := &service.Account{ID: winner.AccountID, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: status, Schedulable: schedulable}
	require.NoError(t, json.Unmarshal(credentials, &row.Credentials))
	require.NoError(t, json.Unmarshal(extra, &row.Extra))
	require.False(t, grouped)
	require.Equal(t, service.StatusDisabled, status)
	require.False(t, schedulable)
	require.Len(t, row.Credentials, 1)
	require.True(t, service.HasGatewayNativeIdentity(row))
	_, err = service.GatewayNativeDescriptor(row)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	for _, query := range []string{`UPDATE accounts SET status='active' WHERE id=$1`, `UPDATE accounts SET schedulable=true WHERE id=$1`, `UPDATE accounts SET credentials='{"refresh_token":"synthetic-plaintext"}' WHERE id=$1`, `DELETE FROM accounts WHERE id=$1`} {
		_, err = db.ExecContext(ctx, query, winner.AccountID)
		require.Error(t, err)
	}
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_identity_reservations SET owner_ref='foreign' WHERE account_id=$1`, winner.AccountID)
	require.Error(t, err)
	// Cross-consumer AND cross-owner simultaneous enrollment of a new subject.
	contenders := make([]service.GatewayNativeOAuthOutcome, 2)
	failures := make([]error, 2)
	scopes := make([]service.GatewayNativeCredentialScope, 2)
	principals := make([]context.Context, 2)
	for i := range contenders {
		principals[i], scopes[i] = oauthPGScope(t, fmt.Sprintf("consumer-race-%d", i), fmt.Sprintf("owner-race-%d", i), fmt.Sprintf("logical-race-%d", i))
	}
	raceBundle := bundleFor("subject-race")
	start = make(chan struct{})
	for i := range contenders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			contenders[i], failures[i] = enrollment.Stage(principals[i], scopes[i], "race-operation", raceBundle)
		}(i)
	}
	close(start)
	wg.Wait()
	successes := 0
	for i := range contenders {
		if failures[i] == nil {
			successes++
			require.Positive(t, contenders[i].AccountID)
		} else {
			require.ErrorIs(t, failures[i], service.ErrGatewayOAuthConflict)
		}
	}
	require.Equal(t, 1, successes)
	// Distinct subjects remain distinct reservations; no email/workspace collapse.
	distinctCtx, distinctScope := oauthPGScope(t, "consumer-a", "owner-a", "logical-distinct")
	distinctBundle := bundleFor("subject-distinct")
	distinct, err := enrollment.Stage(distinctCtx, distinctScope, "distinct-operation", distinctBundle)
	require.NoError(t, err)
	require.NotEqual(t, winner.AccountID, distinct.AccountID)
	// Genuine expiry cannot change an already accepted stable operation result.
	expCtx, expScope := oauthPGScope(t, "consumer-expiry", "owner-expiry", "logical-expiry")
	expBundle := bundleFor("subject-expiring")
	original, err := enrollment.Stage(expCtx, expScope, "expiry-operation", expBundle)
	require.NoError(t, err)
	time.Sleep(3 * time.Second)
	_, err = verifier.Verify(expCtx, expBundle.IDToken)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	replayed, err := enrollment.Stage(expCtx, expScope, "expiry-operation", expBundle)
	require.NoError(t, err)
	require.Equal(t, original, replayed)
	// A new repository/service instance recovers the original birth without the
	// retired AES key. Safe operation readback is not credential qualification.
	restoredRepo, ok := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	retired, err := service.NewGatewayNativeCredentialCustody("new-key", map[string][]byte{"new-key": make([]byte, 32)})
	require.NoError(t, err)
	restored, err := service.NewGatewayNativeOAuthEnrollment(verifier, retired, restoredRepo, key)
	require.NoError(t, err)
	replayed, err = restored.Stage(principal, birth, "stable-operation", bundle)
	require.NoError(t, err)
	require.Equal(t, winner, replayed)
	var groupID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO groups(name) VALUES('f1-disposable-group') RETURNING id`).Scan(&groupID))
	_, err = db.ExecContext(ctx, `INSERT INTO account_groups(account_id,group_id) VALUES($1,$2)`, winner.AccountID, groupID)
	require.Error(t, err)
	// Invalid envelope insertion must roll back its reservation, without touching
	// the successful winner. No plaintext legacy row is adopted or re-encrypted.
	badCtx, badScope := oauthPGScope(t, "consumer-invalid", "owner-invalid", "logical-invalid")
	badBundle := bundleFor("subject-invalid")
	identity, err := verifier.Verify(badCtx, badBundle.IDToken)
	require.NoError(t, err)
	_, err = repo.StageGatewayNativeOAuth(badCtx, service.GatewayNativeOAuthReservation{Identity: identity, Scope: badScope, Operation: "invalid-operation", IntentMAC: strings.Repeat("a", 64), Envelope: "gco0.fixture." + strings.Repeat("A", 16) + "." + strings.Repeat("A", 32)})
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	var rows int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_identity_reservations`).Scan(&rows))
	require.Equal(t, 4, rows)
	// Dump actual persisted Account and reservation data, not a synthetic projection.
	var accountDump, reservationDump []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]'::jsonb) FROM accounts a`).Scan(&accountDump))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(r)) FROM gateway_oauth_identity_reservations r`).Scan(&reservationDump))
	for _, dump := range [][]byte{accountDump, reservationDump} {
		for _, fixture := range []service.GatewayNativeOAuthBundle{bundle, raceBundle, distinctBundle, expBundle} {
			for _, secret := range []string{fixture.AccessToken, fixture.RefreshToken, fixture.IDToken, "synthetic-f1-metadata"} {
				require.NotContains(t, string(dump), secret)
			}
		}
	}

	// Erasure requires exact owner but no active/read key; the reservation persists.
	require.NoError(t, repo.EraseGatewayNativeOAuth(principal, birth, "stable-operation"))
	require.NoError(t, repo.EraseGatewayNativeOAuth(principal, birth, "stable-operation"))
	readback, err = repo.ReadGatewayNativeOAuth(principal, birth, "stable-operation")
	require.NoError(t, err)
	require.Equal(t, "erased", readback.State)
	replayed, err = restored.Stage(principal, birth, "stable-operation", bundle)
	require.NoError(t, err)
	require.Equal(t, winner, replayed)
	_, err = enrollment.Stage(foreign, foreignBirth, "post-erase", bundle)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
}

// Failure: scheduler full/meta publication or ordinary token cache/refresh could
// expose managed tokens despite inert DB staging. Actual Redis + HTTP fixture.
func oauthPGRedisGuards(t *testing.T, row *service.Account, bundle service.GatewayNativeOAuthBundle) {
	t.Helper()
	addr := os.Getenv("GATEWAY_NATIVE_OAUTH_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("NOT_RUN: new disposable OAuth Redis address not supplied")
	}
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.True(t, host == "127.0.0.1" || host == "::1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	count, err := client.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Zero(t, count, "disposable Redis must start empty")
	scheduler := NewSchedulerCache(client)
	require.NoError(t, scheduler.SetAccount(ctx, row))
	require.Zero(t, client.Exists(ctx, schedulerAccountKey(fmt.Sprint(row.ID)), schedulerAccountMetaKey(fmt.Sprint(row.ID))).Val())
	// Prove both stale full and meta projections are erased, not just omitted.
	require.NoError(t, client.Set(ctx, schedulerAccountKey(fmt.Sprint(row.ID)), "stale-full", 0).Err())
	require.NoError(t, client.Set(ctx, schedulerAccountMetaKey(fmt.Sprint(row.ID)), "stale-meta", 0).Err())
	require.NoError(t, scheduler.SetAccount(ctx, row))
	require.Zero(t, client.Exists(ctx, schedulerAccountKey(fmt.Sprint(row.ID)), schedulerAccountMetaKey(fmt.Sprint(row.ID))).Val())
	hook := &oauthRedisCommandHook{}
	client.AddHook(hook)
	cache := NewGeminiTokenCache(client)
	defer func() {
		require.NoError(t, client.Del(ctx, oauthTokenKeyPrefix+service.OpenAITokenCacheKey(row)).Err())
	}()
	require.NoError(t, cache.SetAccessToken(ctx, service.OpenAITokenCacheKey(row), "ordinary-fixture-cache-hit", time.Hour))
	hook.calls.Store(0)
	var upstream atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	oauth := service.NewOpenAIOAuthService(nil, &openaiOAuthService{tokenURL: server.URL})
	defer oauth.Stop()
	refresher := service.NewOpenAITokenRefresher(oauth, nil)
	provider := service.NewOpenAITokenProvider(nil, cache, oauth)
	token, err := provider.GetAccessToken(ctx, row)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Empty(t, token)
	// Supply refreshable tokens only in this ephemeral fixture. They must never
	// reach the actual HTTP endpoint or real Redis even via direct Refresh.
	fixture := *row
	fixture.Credentials = map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "expires_at": "1"}
	_, err = refresher.Refresh(ctx, &fixture)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	_, err = service.NewOAuthRefreshAPI(nil, cache).RefreshIfNeeded(ctx, &fixture, refresher, time.Hour)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Zero(t, upstream.Load())
	require.Zero(t, hook.calls.Load(), "managed paths must make zero ordinary token-cache commands")
	keys, err := client.Keys(ctx, "*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	dump, err := client.Dump(ctx, keys[0]).Result()
	require.NoError(t, err)
	for _, secret := range []string{bundle.AccessToken, bundle.RefreshToken, bundle.IDToken, "synthetic-f1-metadata"} {
		require.NotContains(t, dump, secret)
	}
}

// Failure: OAuth staging could leak via the existing full/meta Redis scheduler
// projections or ordinary cache/refresh paths independently of DB availability.
func TestGatewayNativeOAuthRealRedisGuards(t *testing.T) {
	_, scope := oauthPGScope(t, "consumer-cache", "owner-cache", "logical-cache")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	bundle := service.GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixture3, RefreshToken: gatewayOAuthGuardFixture4, IDToken: gatewayOAuthGuardFixture5, SensitiveMetadata: json.RawMessage(`{"private":"synthetic-f1-metadata"}`)}
	envelope, err := custody.SealOAuthBundle(scope, bundle)
	require.NoError(t, err)
	row := &service.Account{ID: 123, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusDisabled, Credentials: map[string]any{"oauth_bundle": envelope}, Extra: map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: service.GatewayOAuthStagingProfile, service.GatewayCredentialScopeExtraKey: scope.Metadata()}}
	oauthPGRedisGuards(t, row, bundle)
}

type oauthRedisCommandHook struct{ calls atomic.Int32 }

func (h *oauthRedisCommandHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *oauthRedisCommandHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, command redis.Cmder) error { h.calls.Add(1); return next(ctx, command) }
}
func (h *oauthRedisCommandHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		h.calls.Add(int32(len(commands)))
		return next(ctx, commands)
	}
}

// Redis protocol endpoint records all token-cache operations. A seeded usable
// hit proves the guard runs before an ordinary access token can escape.
type oauthGuardCache struct {
	client *redis.Client
	calls  atomic.Int32
}

func (c *oauthGuardCache) GetAccessToken(ctx context.Context, key string) (string, error) {
	c.calls.Add(1)
	return c.client.Get(ctx, key).Result()
}
func (c *oauthGuardCache) SetAccessToken(ctx context.Context, key, value string, ttl time.Duration) error {
	c.calls.Add(1)
	return c.client.Set(ctx, key, value, ttl).Err()
}
func (c *oauthGuardCache) DeleteAccessToken(ctx context.Context, key string) error {
	c.calls.Add(1)
	return c.client.Del(ctx, key).Err()
}
func (c *oauthGuardCache) AcquireRefreshLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	c.calls.Add(1)
	return c.client.SetNX(ctx, key+":lock", "owned", ttl).Result()
}
func (c *oauthGuardCache) ReleaseRefreshLock(ctx context.Context, key string) error {
	c.calls.Add(1)
	return c.client.Del(ctx, key+":lock").Err()
}

// Failure: managed rows, even malformed markers, could use a Redis hit, publish
// plaintext tokens, acquire a refresh lock, or enter direct refresh.
func TestGatewayNativeOAuthOrdinaryGuardsBeforeTokenCacheAndRefresh(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	cache := &oauthGuardCache{client: client}
	ctx := context.Background()
	for _, marker := range []string{service.GatewayGenerationExtraKey, service.GatewayProfileExtraKey, service.GatewayCredentialScopeExtraKey} {
		t.Run(marker, func(t *testing.T) {
			row := &service.Account{ID: 41, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Extra: map[string]any{marker: nil}, Credentials: map[string]any{"access_token": "synthetic-plaintext-access", "refresh_token": "synthetic-plaintext-refresh", "expires_at": "1"}}
			cacheKey := service.OpenAITokenCacheKey(row)
			require.NoError(t, client.Set(ctx, cacheKey, "synthetic-cache-hit", time.Hour).Err())
			before := redisServer.Dump()
			provider := service.NewOpenAITokenProvider(nil, cache, nil)
			token, err := provider.GetAccessToken(ctx, row)
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
			require.Empty(t, token)
			// Nil provider/repository would panic if either path passed the guard.
			api := service.NewOAuthRefreshAPI(nil, cache)
			result, err := api.RefreshIfNeeded(ctx, row, &service.OpenAITokenRefresher{}, time.Hour)
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
			require.Nil(t, result)
			refresher := service.NewOpenAITokenRefresher(nil, nil)
			require.False(t, refresher.CanRefresh(row))
			require.False(t, refresher.NeedsRefresh(row, time.Hour))
			credentials, err := refresher.Refresh(ctx, row)
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
			require.Nil(t, credentials)
			require.Zero(t, cache.calls.Load())
			require.Equal(t, before, redisServer.Dump())
			require.NotContains(t, redisServer.Dump(), "synthetic-plaintext")
		})
	}
	ordinary := &service.Account{ID: 41, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth}
	token, err := service.NewOpenAITokenProvider(nil, cache, nil).GetAccessToken(ctx, ordinary)
	require.NoError(t, err)
	require.Equal(t, "synthetic-cache-hit", token)
	require.Equal(t, int32(1), cache.calls.Load())
}

type oauthFreshManagedRepo struct {
	service.AccountRepository
	row   *service.Account
	reads atomic.Int32
}

func (r *oauthFreshManagedRepo) GetByID(context.Context, int64) (*service.Account, error) {
	r.reads.Add(1)
	return r.row, nil
}

// Failure: an initially ordinary snapshot could fall back to cached plaintext
// after the repository returns a managed identity, or refresh a managed reread.
func TestGatewayNativeOAuthFreshManagedRowsDenyOrdinaryPublication(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	cache := &oauthGuardCache{client: client}
	managed := &service.Account{ID: 72, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Extra: map[string]any{service.GatewayCredentialScopeExtraKey: nil}}
	repo := &oauthFreshManagedRepo{row: managed}
	ordinary := &service.Account{ID: 72, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Credentials: map[string]any{"access_token": "synthetic-stale-access", "expires_at": time.Now().Add(time.Hour).Unix()}}
	token, err := service.NewOpenAITokenProvider(repo, cache, nil).GetAccessToken(context.Background(), ordinary)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Empty(t, token)
	require.Positive(t, repo.reads.Load())
	require.Empty(t, redisServer.Keys())
	// This refresh path does acquire/release the ordinary snapshot's lock. The
	// fresh managed row must deny before a provider/executor or token write.
	result, err := service.NewOAuthRefreshAPI(repo, cache).RefreshIfNeeded(context.Background(), ordinary, &service.OpenAITokenRefresher{}, time.Hour)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Nil(t, result)
	require.Empty(t, redisServer.Keys())
}

func gatewayOAuthGuardFixtureOpaque() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("synthetic fixture entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var gatewayOAuthGuardFixture1 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture2 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture3 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture4 = gatewayOAuthGuardFixtureOpaque()
var gatewayOAuthGuardFixture5 = gatewayOAuthGuardFixtureOpaque()
