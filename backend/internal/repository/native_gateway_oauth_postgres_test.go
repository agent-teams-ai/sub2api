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
	"errors"
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
	"github.com/lib/pq"
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

// F2 uses a separately supplied disposable database; this does not rerun F1's
// accepted PG qualification. No DSN, credential, container or DB is provisioned.
func TestGatewayNativeOAuthPostgresFencedRefresh(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_OAUTH_REFRESH_TEST_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: existing populated compatible F2/F4 purpose PostgreSQL DSN absent; ROOT runs after independent review")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, u.Scheme == "postgres" || u.Scheme == "postgresql")
	require.True(t, u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	database := strings.TrimPrefix(u.Path, "/")
	require.True(t, strings.HasPrefix(database, "gateway_oauth_refresh_test_") || database == "gateway_oauth_dispatch_test_f4_oct6_guardv5")
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
	// Source-only admission for ROOT's existing populated compatible purpose DB.
	// This boundary never migrates or provisions a database/server.
	require.Positive(t, tables, "ROOT must supply the populated compatible F2/F4 purpose database")
	var compatible bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('public.gateway_oauth_refresh_attempts') IS NOT NULL
 AND to_regclass('public.gateway_oauth_connect_intents') IS NOT NULL
 AND to_regclass('public.gateway_oauth_profile_qualifications') IS NOT NULL`).Scan(&compatible))
	require.True(t, compatible)
	repo, ok := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	refreshRepo, ok := repo.(service.GatewayNativeOAuthRefreshRepository)
	require.True(t, ok)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	var calls atomic.Int32
	var accountChecks atomic.Int32
	providerAccount := uuid.NewString()
	var originalBundle service.GatewayNativeOAuthBundle
	var expirySeconds atomic.Int64
	expirySeconds.Store(3600)
	runConsumer := "consumer-f2-" + uuid.NewString()
	var mismatch atomic.Bool
	var releaseMu sync.Mutex
	releases := []chan struct{}{}
	// Hold the winning provider request until every losing invocation has had a
	// chance to observe durable ENTERED. Tokens/signatures are generated at runtime.
	verifier, transport, bundleFor := oauthPGRefreshFixture(t, func(w http.ResponseWriter, r *http.Request, bundleFor func(string) service.GatewayNativeOAuthBundle) {
		calls.Add(1)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		require.Equal(t, "app_EMoamEEZ73f0CkXaXp7hrann", r.Form.Get("client_id"))
		require.Equal(t, "openid profile email", r.Form.Get("scope"))
		releaseMu.Lock()
		var hold chan struct{}
		if len(releases) > 0 {
			hold = releases[0]
			releases = releases[1:]
		}
		releaseMu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		subject := "subject-f2"
		if mismatch.Load() {
			subject = "foreign-subject"
		}
		b := bundleFor(subject)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": b.AccessToken, "refresh_token": b.RefreshToken, "id_token": b.IDToken, "token_type": "Bearer", "expires_in": expirySeconds.Load(), "protected_hint": "f2-sensitive-metadata"})
	}, func(w http.ResponseWriter, r *http.Request) {
		accountChecks.Add(1)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer "+originalBundle.AccessToken, r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		_, _ = fmt.Fprintf(w, `{"accounts":{"unrelated-workspace":{"account":{"account_id":%q}}}}`, providerAccount)
	})
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, repo, key)
	require.NoError(t, err)
	principal, scope := oauthPGScope(t, runConsumer, "owner-f2", "logical-f2")
	originalBundle = bundleFor("subject-f2")
	// Reuse the real F3 journal and F4 qualification on this exact F2 row.
	journal, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connector, err := service.NewGatewayNativeOAuthConnect(key, transport, journal, enrollment, repo)
	require.NoError(t, err)
	const connectOperation = "maintenance-original-connect"
	_, err = connector.BeginConnect(principal, scope, connectOperation)
	require.NoError(t, err)
	connectIntent, err := journal.ReadConnectIntent(principal, scope, connectOperation)
	require.NoError(t, err)
	won, err := journal.EnterConnect(principal, connectIntent)
	require.NoError(t, err)
	require.True(t, won)
	binding := &oauthRefreshConnectBinding{GatewayNativeOAuthRepository: repo, journal: journal, intent: connectIntent}
	boundEnrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, binding, key)
	require.NoError(t, err)
	staged, err := boundEnrollment.Stage(principal, scope, connectIntent.EnrollmentOperation, originalBundle)
	require.NoError(t, err)
	_, err = journal.FinishConnect(principal, binding.intent, "completed", staged)
	require.NoError(t, err)
	dispatchRepo, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok)
	_, physical, release, err := dispatchRepo.LockGatewayNativeOAuthDispatch(principal, scope, connectOperation, staged.AccountID)
	require.NoError(t, err)
	release()
	// A bare physical DTO has no private proof and cannot qualify this row.
	require.False(t, physical.QualificationValid(1))
	require.ErrorIs(t, dispatchRepo.QualifyGatewayNativeOAuthDispatch(principal, physical, 1), service.ErrGatewayNativeIdentity)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(dispatchRepo, custody, verifier, transport)
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
	require.EqualValues(t, 1, accountChecks.Load())
	require.Zero(t, calls.Load())
	var birth time.Time
	var original, extra []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at,credentials,extra FROM accounts WHERE id=$1`, staged.AccountID).Scan(&birth, &original, &extra))
	require.True(t, birth.Equal(descriptor.Native.CreatedAt))
	in := service.GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: staged.AccountID, CreatedAt: birth, ExpectedVersion: 1, Operation: "refresh-one", Intent: "rotate-whole-bundle"}
	lossy := &oauthRefreshLostACK{GatewayNativeOAuthRefreshRepository: refreshRepo}
	lossy.lose.Store(true)
	refresher, err := service.NewGatewayNativeOAuthRefresh(lossy, custody, verifier, transport)
	require.NoError(t, err)
	// Legacy bundle has no reserved trusted deadline: maintenance creates no
	// attempt and performs no token exchange, even on a qualified physical row.
	idle, err := refresher.Maintain(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, "idle", idle.State)
	require.Empty(t, idle.RefreshRef)
	require.Zero(t, calls.Load())
	require.EqualValues(t, 1, accountChecks.Load())
	resolver, ok := repo.(service.GatewayNativeOAuthRefreshResolver)
	require.True(t, ok)
	// Same numeric ID with one microsecond birth difference is not authority.
	wrong := in
	wrong.CreatedAt = wrong.CreatedAt.Add(time.Microsecond)
	_, err = refresher.Refresh(principal, wrong)
	require.Error(t, err)
	require.Zero(t, calls.Load())
	// Wrong scope/context and changed stable operation intent do not enter.
	foreign, _ := oauthPGScope(t, "consumer-foreign", "owner-foreign", "logical-foreign")
	_, err = refresher.Refresh(foreign, in)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Zero(t, calls.Load())
	hold := make(chan struct{})
	releaseMu.Lock()
	releases = append(releases, hold)
	releaseMu.Unlock()
	var wg sync.WaitGroup
	outcomes := make([]service.GatewayNativeOAuthRefreshOutcome, 4)
	failures := make([]error, 4)
	start := make(chan struct{})
	for i := range outcomes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); <-start; outcomes[i], failures[i] = refresher.Refresh(principal, in) }(i)
	}
	close(start)
	require.Eventually(t, func() bool { return calls.Load() == 1 }, 3*time.Second, 10*time.Millisecond)
	recovered, err := resolver.ResolveGatewayNativeOAuthRefresh(principal, scope, connectOperation)
	require.NoError(t, err)
	require.NotNil(t, recovered.Attempt)
	require.Equal(t, in, *recovered.Attempt, "must reconstruct original arbitrary F2 reference, not derive from current version")
	observed, err := refresher.Maintain(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, "entered", observed.State)
	require.Equal(t, in.Operation, observed.RefreshRef)
	require.Equal(t, int32(1), calls.Load())
	changed := in
	changed.Intent = "different-intent"
	_, err = refresher.Refresh(principal, changed)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	changed = in
	changed.ExpectedVersion = 2
	_, err = refresher.Refresh(principal, changed)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	changed = in
	changed.Scope.Account = "other-account"
	_, err = refresher.Refresh(principal, changed)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	close(hold)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
	// The sole completion ACK was discarded after actual durable publication.
	errors := 0
	for _, err := range failures {
		if err != nil {
			errors++
			require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		}
	}
	require.Zero(t, errors)
	require.False(t, lossy.lose.Load(), "completion ACK must actually have been discarded")
	done, err := refresher.Refresh(principal, in)
	require.NoError(t, err)
	require.Equal(t, service.GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "completed", Version: 2}, done)
	require.Equal(t, int32(1), calls.Load())
	// The caller lost its completion ACK and supplies only original F3 selectors.
	// Current version is already newer: reconstruct old version/ref before due.
	recovered, err = resolver.ResolveGatewayNativeOAuthRefresh(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, in, *recovered.Attempt)
	require.Equal(t, int64(2), recovered.Version)
	for j := 0; j < 4; j++ {
		maintained, err := refresher.Maintain(principal, scope, connectOperation)
		require.NoError(t, err)
		require.Equal(t, "completed", maintained.State)
		require.Equal(t, connectOperation, maintained.Operation)
		require.Equal(t, scope.Account, maintained.AccountRef)
		require.Equal(t, in.Operation, maintained.RefreshRef)
	}
	require.Equal(t, int32(1), calls.Load(), "future trusted expiry suppresses a second rotation after lost completion ACK")
	var attempts int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_oauth_refresh_attempts WHERE account_id=$1`, in.AccountID).Scan(&attempts))
	require.Equal(t, 1, attempts)
	checkRow := func(version int64) []byte {
		var afterBirth time.Time
		var credentials, afterExtra []byte
		var status string
		var schedulable, assigned bool
		var actual int64
		require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at,credentials,extra,status,schedulable,
   EXISTS(SELECT 1 FROM account_groups WHERE account_id=accounts.id),gateway_oauth_credential_version(credentials) FROM accounts WHERE id=$1`, in.AccountID).
			Scan(&afterBirth, &credentials, &afterExtra, &status, &schedulable, &assigned, &actual))
		require.True(t, birth.Equal(afterBirth))
		require.JSONEq(t, string(extra), string(afterExtra))
		require.Equal(t, service.StatusDisabled, status)
		require.False(t, schedulable)
		require.False(t, assigned)
		require.Equal(t, version, actual)
		return credentials
	}
	after := checkRow(2)
	require.NotEqual(t, string(original), string(after))
	// An old writer cannot directly replace, downgrade, or complete a different
	// version. A completed operation remains readback-stable after later rotations.
	_, err = db.ExecContext(ctx, `UPDATE accounts SET credentials=$1::jsonb WHERE id=$2`, string(original), in.AccountID)
	require.Error(t, err)
	stale := in
	stale.Operation = "new-op-stale-version"
	_, err = refresher.Refresh(principal, stale)
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load())
	next := in
	next.ExpectedVersion = 2
	next.Operation = "refresh-two"
	prepared, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(principal, next)
	require.NoError(t, err)
	require.True(t, prepared.Claimed)
	require.Equal(t, int64(2), prepared.Fence)
	duplicate, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(principal, next)
	require.NoError(t, err)
	require.False(t, duplicate.Claimed)
	maintained, err := refresher.Maintain(principal, scope, connectOperation)
	require.NoError(t, err)
	require.Equal(t, "prepared", maintained.State)
	require.Equal(t, next.Operation, maintained.RefreshRef)
	require.Equal(t, int32(1), calls.Load(), "prepared is not permission to bypass future trusted deadline")
	time.Sleep(time.Until(prepared.Deadline) + 100*time.Millisecond)
	expirySeconds.Store(1)
	second, err := refresher.Refresh(principal, next)
	require.NoError(t, err)
	require.Equal(t, int64(3), second.Version)
	var fence int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT fence FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, scope.Consumer, next.Operation).Scan(&fence))
	require.Equal(t, prepared.Fence+1, fence)
	entered, err := refreshRepo.EnterGatewayNativeOAuthRefresh(principal, next, prepared.Fence)
	require.Error(t, err)
	require.False(t, entered)
	_, err = refreshRepo.CompleteGatewayNativeOAuthRefresh(principal, next, prepared.Fence, prepared.Envelope)
	require.Error(t, err)
	require.Equal(t, int32(2), calls.Load())
	// Race original-selector maintenance against the same physical lock on an
	// actually due bundle. The provider publishes a future deadline afterwards.
	expirySeconds.Store(3600)
	lossy.lose.Store(true)
	maintenanceOut := make([]service.GatewayNativeOAuthMaintenanceOutcome, 4)
	maintenanceErr := make([]error, 4)
	maintenanceStart := make(chan struct{})
	for j := range maintenanceOut {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			<-maintenanceStart
			maintenanceOut[j], maintenanceErr[j] = refresher.Maintain(principal, scope, connectOperation)
		}(j)
	}
	close(maintenanceStart)
	wg.Wait()
	for _, err := range maintenanceErr {
		require.NoError(t, err)
	}
	require.Equal(t, int32(3), calls.Load(), "concurrent due maintenance has one fenced provider entry")
	require.False(t, lossy.lose.Load(), "maintenance completion ACK must have been discarded")
	recovered, err = resolver.ResolveGatewayNativeOAuthRefresh(principal, scope, connectOperation)
	require.NoError(t, err)
	require.NotNil(t, recovered.Attempt)
	require.Equal(t, int64(3), recovered.Attempt.ExpectedVersion)
	require.Equal(t, int64(4), recovered.Version)
	canonicalRef := recovered.Attempt.Operation
	require.NotEqual(t, next.Operation, canonicalRef)
	for j := 0; j < 3; j++ {
		maintained, err := refresher.Maintain(principal, scope, connectOperation)
		require.NoError(t, err)
		require.Equal(t, "completed", maintained.State)
		require.Equal(t, canonicalRef, maintained.RefreshRef)
	}
	require.Equal(t, int32(3), calls.Load(), "future bundle cannot rotate again")
	beforeUnknown := checkRow(4)
	doneAgain, err := refresher.Refresh(principal, in)
	require.NoError(t, err)
	require.Equal(t, done, doneAgain)
	// Crash after durable ENTERED (even before actual HTTP) is permanently unknown.
	ambiguous := in
	ambiguous.ExpectedVersion = 4
	ambiguous.Operation = "entered-crash"
	enteredAttempt, err := refreshRepo.PrepareGatewayNativeOAuthRefresh(principal, ambiguous)
	require.NoError(t, err)
	entered, err = refreshRepo.EnterGatewayNativeOAuthRefresh(principal, ambiguous, enteredAttempt.Fence)
	require.NoError(t, err)
	require.True(t, entered)
	time.Sleep(time.Until(enteredAttempt.Deadline) + 100*time.Millisecond)
	unknown, err := refresher.Refresh(principal, ambiguous)
	require.NoError(t, err)
	require.Equal(t, "unknown", unknown.State)
	_, err = refreshRepo.CompleteGatewayNativeOAuthRefresh(principal, ambiguous, enteredAttempt.Fence, enteredAttempt.Envelope)
	require.Error(t, err)
	for j := 0; j < 3; j++ {
		maintained, err := refresher.Maintain(principal, scope, connectOperation)
		require.NoError(t, err)
		require.Equal(t, "unknown", maintained.State)
		require.Equal(t, ambiguous.Operation, maintained.RefreshRef)
	}
	require.Equal(t, int32(3), calls.Load(), "unknown reconstructed through original connect cannot rearm")
	takeover := ambiguous
	takeover.Operation = "new-op-after-ambiguity"
	_, err = refresher.Refresh(principal, takeover)
	require.Error(t, err)
	require.Equal(t, int32(3), calls.Load())
	require.JSONEq(t, string(beforeUnknown), string(checkRow(4)))
	// A validly signed different principal is quarantined; no fallback publication.
	principal2, scope2 := oauthPGScope(t, runConsumer, "owner-f2", "mismatch-account")
	staged2, err := enrollment.Stage(principal2, scope2, "stage-mismatch", bundleFor("subject-other"))
	require.NoError(t, err)
	var birth2 time.Time
	var old2 []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at,credentials FROM accounts WHERE id=$1`, staged2.AccountID).Scan(&birth2, &old2))
	mismatch.Store(true)
	mismatchIntent := service.GatewayNativeOAuthRefreshIntent{Scope: scope2, AccountID: staged2.AccountID, CreatedAt: birth2, ExpectedVersion: 1, Operation: "refresh-mismatch", Intent: "rotate"}
	quarantine, err := refresher.Refresh(principal2, mismatchIntent)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Equal(t, "unknown", quarantine.State)
	quarantine, err = refresher.Refresh(principal2, mismatchIntent)
	require.NoError(t, err)
	require.Equal(t, "unknown", quarantine.State)
	var retained []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials FROM accounts WHERE id=$1`, staged2.AccountID).Scan(&retained))
	require.JSONEq(t, string(old2), string(retained))
	require.Equal(t, int32(4), calls.Load())
	// Cryptographically invalid initial custody is structurally accepted staging
	// but must make zero provider/JWKS calls at the refresh credential boundary.
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	require.NoError(t, err)
	wrongCustody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": wrongKey})
	require.NoError(t, err)
	wrongEnrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, wrongCustody, repo, key)
	require.NoError(t, err)
	principal3, scope3 := oauthPGScope(t, runConsumer, "owner-f2", "invalid-custody")
	staged3, err := wrongEnrollment.Stage(principal3, scope3, "stage-invalid-custody", bundleFor("invalid-custody-subject"))
	require.NoError(t, err)
	var birth3 time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at FROM accounts WHERE id=$1`, staged3.AccountID).Scan(&birth3))
	invalid := service.GatewayNativeOAuthRefreshIntent{Scope: scope3, AccountID: staged3.AccountID, CreatedAt: birth3, ExpectedVersion: 1, Operation: "refresh-invalid-custody", Intent: "rotate"}
	_, err = refresher.Refresh(principal3, invalid)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	require.Equal(t, int32(4), calls.Load())
	var dump []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object('accounts',(SELECT jsonb_agg(to_jsonb(a)) FROM accounts a),'attempts',(SELECT jsonb_agg(to_jsonb(f)) FROM gateway_oauth_refresh_attempts f))`).Scan(&dump))
	for _, secret := range []string{originalBundle.AccessToken, originalBundle.RefreshToken, originalBundle.IDToken, "f2-sensitive-metadata"} {
		require.NotContains(t, string(dump), secret)
	}
	t.Run("publication held past entered deadline rolls back at commit", func(t *testing.T) {
		lateVerifier, lateTransport, lateBundleFor := oauthPGRefreshFixture(t, func(w http.ResponseWriter, r *http.Request, bundleFor func(string) service.GatewayNativeOAuthBundle) {
			b := bundleFor("subject-late-commit")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": b.AccessToken, "refresh_token": b.RefreshToken, "id_token": b.IDToken, "token_type": "Bearer", "expires_in": 3600})
		}, nil)
		lateEnrollment, err := service.NewGatewayNativeOAuthEnrollment(lateVerifier, custody, repo, key)
		require.NoError(t, err)
		lateCtx, lateScope := oauthPGScope(t, runConsumer, "owner-f2", "late-commit-account")
		staged, err := lateEnrollment.Stage(lateCtx, lateScope, "stage-late-commit", lateBundleFor("subject-late-commit"))
		require.NoError(t, err)
		var created time.Time
		var oldCredentials []byte
		require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at,credentials FROM accounts WHERE id=$1`, staged.AccountID).Scan(&created, &oldCredentials))
		late := service.GatewayNativeOAuthRefreshIntent{Scope: lateScope, AccountID: staged.AccountID, CreatedAt: created, ExpectedVersion: 1, Operation: "refresh-late-commit", Intent: "rotate"}
		held := &oauthRefreshHeldCommit{GatewayNativeOAuthRefreshRepository: refreshRepo, db: db, t: t}
		lateRefresh, err := service.NewGatewayNativeOAuthRefresh(held, custody, lateVerifier, lateTransport)
		require.NoError(t, err)
		out, err := lateRefresh.Refresh(lateCtx, late)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
		require.Equal(t, "unknown", out.State)
		require.True(t, held.validPublicationBeforeDeadline)
		var commitErr *pq.Error
		require.ErrorAs(t, held.commitErr, &commitErr)
		require.Equal(t, pq.ErrorCode("23514"), commitErr.Code)
		require.Equal(t, "refresh publication deadline expired", commitErr.Message)
		var retained []byte
		var version int64
		require.NoError(t, db.QueryRowContext(ctx, `SELECT credentials,gateway_oauth_credential_version(credentials) FROM accounts WHERE id=$1`, staged.AccountID).Scan(&retained, &version))
		require.JSONEq(t, string(oldCredentials), string(retained))
		require.Equal(t, int64(1), version)
		// A safe returned status alone cannot prove the completion journal rolled
		// back. Read the durable attempt after service recovery independently.
		var state string
		var resultVersion sql.NullInt64
		var publicationXID sql.NullString
		require.NoError(t, db.QueryRowContext(ctx, `SELECT state,result_version,publication_xid::text
 FROM gateway_oauth_refresh_attempts WHERE consumer=$1 AND operation_ref=$2`, late.Scope.Consumer, late.Operation).Scan(&state, &resultVersion, &publicationXID))
		require.Equal(t, "unknown", state)
		require.False(t, resultVersion.Valid)
		require.False(t, publicationXID.Valid)
	})
}

// Deliberately defeat caller cancellation to exercise the SQL commit guard:
// both valid UPDATEs execute while authority is live, then the transaction holds.
// The envelope comes from the actual signed transport and versioned custody.
type oauthRefreshHeldCommit struct {
	service.GatewayNativeOAuthRefreshRepository
	db                             *sql.DB
	t                              *testing.T
	validPublicationBeforeDeadline bool
	commitErr                      error
}

func (r *oauthRefreshHeldCommit) CompleteGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent, fence int64, envelope string) (service.GatewayNativeOAuthRefreshOutcome, error) {
	r.t.Helper()
	holdCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(holdCtx, nil)
	require.NoError(r.t, err)
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			require.NoError(r.t, err)
		}
	}()
	var id int64
	require.NoError(r.t, tx.QueryRowContext(holdCtx, `SELECT id FROM accounts WHERE id=$1 AND created_at=$2 FOR UPDATE`, in.AccountID, in.CreatedAt).Scan(&id))
	var deadline time.Time
	require.NoError(r.t, tx.QueryRowContext(holdCtx, `UPDATE gateway_oauth_refresh_attempts SET state='completed',result_version=expected_version+1,publication_xid=pg_current_xact_id()
 WHERE consumer=$1 AND operation_ref=$2 AND fence=$3 AND state='entered' AND deadline>clock_timestamp() RETURNING deadline`, in.Scope.Consumer, in.Operation, fence).Scan(&deadline))
	credentials, err := json.Marshal(map[string]string{"oauth_bundle": envelope, "credential_version": fmt.Sprint(in.ExpectedVersion + 1)})
	require.NoError(r.t, err)
	result, err := tx.ExecContext(holdCtx, `UPDATE accounts SET credentials=$1::jsonb,updated_at=clock_timestamp()
 WHERE id=$2 AND created_at=$3 AND gateway_oauth_credential_version(credentials)=$4`, string(credentials), in.AccountID, in.CreatedAt, in.ExpectedVersion)
	require.NoError(r.t, err)
	rows, err := result.RowsAffected()
	require.NoError(r.t, err)
	require.Equal(r.t, int64(1), rows)
	require.NoError(r.t, tx.QueryRowContext(holdCtx, `SELECT clock_timestamp()<$1`, deadline).Scan(&r.validPublicationBeforeDeadline))
	require.True(r.t, r.validPublicationBeforeDeadline)
	_, err = tx.ExecContext(holdCtx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.1)`, deadline)
	require.NoError(r.t, err)
	var expired bool
	require.NoError(r.t, tx.QueryRowContext(holdCtx, `SELECT clock_timestamp()>=$1`, deadline).Scan(&expired))
	require.True(r.t, expired)
	r.commitErr = tx.Commit()
	return service.GatewayNativeOAuthRefreshOutcome{}, r.commitErr
}

type oauthRefreshLostACK struct {
	service.GatewayNativeOAuthRefreshRepository
	lose atomic.Bool
}

func (r *oauthRefreshLostACK) CompleteGatewayNativeOAuthRefresh(ctx context.Context, in service.GatewayNativeOAuthRefreshIntent, fence int64, envelope string) (service.GatewayNativeOAuthRefreshOutcome, error) {
	out, err := r.GatewayNativeOAuthRefreshRepository.CompleteGatewayNativeOAuthRefresh(ctx, in, fence, envelope)
	if err == nil && r.lose.CompareAndSwap(true, false) {
		return service.GatewayNativeOAuthRefreshOutcome{}, service.ErrGatewayNativeIdentity
	}
	return out, err
}
func oauthPGRefreshFixture(t *testing.T, handler func(http.ResponseWriter, *http.Request, func(string) service.GatewayNativeOAuthBundle), accountCheck func(http.ResponseWriter, *http.Request)) (*service.GatewayNativeOAuthVerifier, http.RoundTripper, func(string) service.GatewayNativeOAuthBundle) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	subjectSuffix := "-" + uuid.NewString()
	bundleFor := func(subject string) service.GatewayNativeOAuthBundle {
		subject += subjectSuffix
		claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":"app_EMoamEEZ73f0CkXaXp7hrann","exp":%d}`, service.GatewayOAuthIssuer, subject, time.Now().Add(time.Hour).Unix())
		body := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)
		return service.GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixtureOpaque(), RefreshToken: gatewayOAuthGuardFixtureOpaque(), IDToken: body + "." + base64.RawURLEncoding.EncodeToString(signature), SensitiveMetadata: json.RawMessage(`{"private":"f2-sensitive-metadata"}`)}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if accountCheck != nil && r.Host == "chatgpt.com" {
			require.Equal(t, "/backend-api/accounts/check/v4-2023-04-27", r.URL.Path)
			accountCheck(w, r)
			return
		}
		require.Equal(t, "auth.openai.com", r.Host)
		if r.URL.Path == "/.well-known/jwks.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "fixture", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
			return
		}
		require.Equal(t, "/oauth/token", r.URL.Path)
		handler(w, r, bundleFor)
	}))
	t.Cleanup(server.Close)
	baseTransport, ok := server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" && (accountCheck == nil || address != "chatgpt.com:443") {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return service.NewGatewayNativeOAuthVerifier(transport), transport, bundleFor
}

// Bind real F1 commitment into the existing entered F3 journal before staging.
type oauthRefreshConnectBinding struct {
	service.GatewayNativeOAuthRepository
	journal service.GatewayNativeOAuthConnectRepository
	intent  service.GatewayNativeOAuthConnectIntent
}

func (b *oauthRefreshConnectBinding) StageGatewayNativeOAuth(ctx context.Context, in service.GatewayNativeOAuthReservation) (service.GatewayNativeOAuthOutcome, error) {
	saved, err := b.journal.BindConnectEnrollment(ctx, b.intent, in.IntentMAC)
	if err != nil {
		return service.GatewayNativeOAuthOutcome{}, err
	}
	b.intent = saved
	return b.GatewayNativeOAuthRepository.StageGatewayNativeOAuth(ctx, in)
}
func (r *oauthRefreshLostACK) ResolveGatewayNativeOAuthRefresh(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthRefreshResolution, error) {
	resolver, ok := r.GatewayNativeOAuthRefreshRepository.(service.GatewayNativeOAuthRefreshResolver)
	if !ok {
		return service.GatewayNativeOAuthRefreshResolution{}, errors.New("refresh test repository does not implement resolver")
	}
	return resolver.ResolveGatewayNativeOAuthRefresh(ctx, scope, operation)
}
