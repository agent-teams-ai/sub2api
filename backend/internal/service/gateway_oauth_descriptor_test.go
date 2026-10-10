package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
)

// Everything named test* below is a TEST adapter. The deterministic signer is
// prospective TEST custody only and is NOT production issuer authority.

var testDescriptorProfile = OAuthDescriptorProfile{
	Profile: "openai-codex-oauth-responses-v1",
	BaseURL: "https://chatgpt.com/backend-api/codex",
	Model:   "gpt-6.1-sol",
}

var testDescriptorScope = OAuthDescriptorScope{
	ConsumerID: "consumer-1", OwnerRef: "owner-1", OperationID: "op-1",
	AccountRef: "11111111-1111-4111-8111-111111111111",
	Generation: "22222222-2222-4222-8222-222222222222",
}

const (
	testDescriptorToken = "test-token"
	testDescriptorOrg   = "org-test"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testCustodyEnvelope struct {
	Scope     OAuthDescriptorScope
	AccountID int64
	CreatedAt string
	Profile   string
	BaseURL   string
	Model     string
	Revision  string
	ExpiresAt time.Time
}

// canonical binds every scope and birth field with length-prefixed encoding.
func (e testCustodyEnvelope) canonical() []byte {
	var b bytes.Buffer
	b.WriteString("TEST-custody-v1")
	for _, f := range []string{e.Scope.ConsumerID, e.Scope.OwnerRef, e.Scope.OperationID, e.Scope.AccountRef,
		e.Scope.Generation, strconv.FormatInt(e.AccountID, 10), e.CreatedAt, e.Profile, e.BaseURL, e.Model,
		e.Revision, strconv.FormatInt(e.ExpiresAt.UnixNano(), 10)} {
		b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f))))
		b.WriteString(f)
	}
	return b.Bytes()
}

type testCustodyRecord struct {
	Envelope testCustodyEnvelope
	Sig      []byte
}

func testSigner(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	return priv, priv.Public().(ed25519.PublicKey)
}

type testCustodyVerifier struct {
	pub     ed25519.PublicKey
	clock   *testClock
	mu      sync.Mutex
	records map[[2]string]testCustodyRecord
	revoked map[string]bool
	calls   atomic.Int32
}

func (v *testCustodyVerifier) put(key ed25519.PrivateKey, e testCustodyEnvelope) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.records[[2]string{e.Scope.ConsumerID, e.Scope.OperationID}] = testCustodyRecord{e, ed25519.Sign(key, e.canonical())}
}

// tamper mutates the stored envelope without re-signing it.
func (v *testCustodyVerifier) tamper(scope OAuthDescriptorScope, mutate func(*testCustodyEnvelope)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	k := [2]string{scope.ConsumerID, scope.OperationID}
	r := v.records[k]
	mutate(&r.Envelope)
	v.records[k] = r
}

func (v *testCustodyVerifier) revoke(revision string, on bool) {
	v.mu.Lock()
	v.revoked[revision] = on
	v.mu.Unlock()
}

func (v *testCustodyVerifier) Verify(_ context.Context, scope OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
	v.calls.Add(1)
	v.mu.Lock()
	r, ok := v.records[[2]string{scope.ConsumerID, scope.OperationID}]
	revoked := ok && v.revoked[r.Envelope.Revision]
	v.mu.Unlock()
	e := r.Envelope
	if !ok || !ed25519.Verify(v.pub, e.canonical(), r.Sig) || e.Scope != scope {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorDenied
	}
	if revoked {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorRevoked
	}
	if !v.clock.Now().Before(e.ExpiresAt) {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorExpired
	}
	return OAuthVerifiedBirth{Scope: e.Scope, AccountID: e.AccountID, CreatedAt: e.CreatedAt, Profile: e.Profile,
		BaseURL: e.BaseURL, Model: e.Model, CustodyRevision: e.Revision, ExpiresAt: e.ExpiresAt}, nil
}

// testAccountQualifier executes the real fetchChatGPTAccountInfo parser against
// a local httptest account-check endpoint with a fake credential lookup.
type testAccountQualifier struct {
	factory PrivacyClientFactory
	before  func()
}

func (q *testAccountQualifier) Check(ctx context.Context, birth OAuthVerifiedBirth) error {
	if q.before != nil {
		q.before()
	}
	if birth.AccountID != 42 || birth.Scope.OwnerRef != "owner-1" { // fake credential lookup
		return ErrOAuthDescriptorUnqualified
	}
	info := fetchChatGPTAccountInfo(ctx, q.factory, testDescriptorToken, "", testDescriptorOrg)
	if info == nil || info.AccountID != testDescriptorOrg {
		return ErrOAuthDescriptorUnqualified
	}
	return nil
}

type descriptorHarness struct {
	svc       *OAuthDescriptorService
	cache     *OAuthDescriptorMemoryCache
	clock     *testClock
	verifier  *testCustodyVerifier
	qualifier *testAccountQualifier
	key       ed25519.PrivateKey
	hits      atomic.Int32
	failing   atomic.Bool
}

func testEnvelope(scope OAuthDescriptorScope, clock *testClock) testCustodyEnvelope {
	return testCustodyEnvelope{Scope: scope, AccountID: 42, CreatedAt: "2026-10-10T00:00:00Z",
		Profile: testDescriptorProfile.Profile, BaseURL: testDescriptorProfile.BaseURL, Model: testDescriptorProfile.Model,
		Revision: "rev-1", ExpiresAt: clock.Now().Add(time.Hour)}
}

func newDescriptorHarness(t *testing.T) *descriptorHarness {
	t.Helper()
	h := &descriptorHarness{clock: &testClock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}}
	var pub ed25519.PublicKey
	h.key, pub = testSigner(7)
	h.verifier = &testCustodyVerifier{pub: pub, clock: h.clock, records: map[[2]string]testCustodyRecord{}, revoked: map[string]bool{}}
	h.verifier.put(h.key, testEnvelope(testDescriptorScope, h.clock))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		if h.failing.Load() || r.Header.Get("Authorization") != "Bearer "+testDescriptorToken {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accounts":{"` + testDescriptorOrg + `":{"account":{"account_id":"` + testDescriptorOrg + `","plan_type":"plus"}}}}`))
	}))
	old := chatGPTAccountsCheckURL
	chatGPTAccountsCheckURL = srv.URL
	t.Cleanup(func() { chatGPTAccountsCheckURL = old; srv.Close() })

	h.qualifier = &testAccountQualifier{factory: func(string) (*req.Client, error) { return req.C(), nil }}
	var err error
	h.cache, err = NewOAuthDescriptorMemoryCache(8)
	require.NoError(t, err)
	h.svc, err = NewOAuthDescriptorService(h.verifier, h.qualifier, h.cache, h.clock, testDescriptorProfile, 10*time.Minute)
	require.NoError(t, err)
	return h
}

func TestOAuthDescriptorQualifiesOnceAndRevalidatesCustodyOnHit(t *testing.T) {
	h := newDescriptorHarness(t)
	first, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	require.Equal(t, int64(42), first.AccountID)
	require.Equal(t, int32(1), h.hits.Load())
	verifyCalls := h.verifier.calls.Load()

	second, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	require.True(t, first.same(second))
	require.Equal(t, int32(1), h.hits.Load(), "cache hit must not qualify again")
	require.Equal(t, verifyCalls+1, h.verifier.calls.Load(), "cache hit must consult live custody")
}

func TestOAuthDescriptorRevocationAfterCacheHitIsRejected(t *testing.T) {
	h := newDescriptorHarness(t)
	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	h.verifier.revoke("rev-1", true)
	_, err = h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorRevoked)
	require.Equal(t, int32(1), h.hits.Load())
}

func TestOAuthDescriptorExpiry(t *testing.T) {
	h := newDescriptorHarness(t)
	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)

	// Past the cache age but inside custody: qualification must be redone.
	h.clock.Advance(11 * time.Minute)
	_, err = h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	require.Equal(t, int32(2), h.hits.Load())

	// Past custody expiry: cached authority must not survive.
	h.clock.Advance(2 * time.Hour)
	_, err = h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorExpired)
	require.Equal(t, int32(2), h.hits.Load())
}

func TestOAuthDescriptorRejectsEveryTamperedField(t *testing.T) {
	mutations := map[string]func(*testCustodyEnvelope){
		"consumer":   func(e *testCustodyEnvelope) { e.Scope.ConsumerID = "consumer-2" },
		"owner":      func(e *testCustodyEnvelope) { e.Scope.OwnerRef = "owner-2" },
		"operation":  func(e *testCustodyEnvelope) { e.Scope.OperationID = "op-2" },
		"account":    func(e *testCustodyEnvelope) { e.Scope.AccountRef = "33333333-3333-4333-8333-333333333333" },
		"generation": func(e *testCustodyEnvelope) { e.Scope.Generation = "33333333-3333-4333-8333-333333333333" },
		"accountID":  func(e *testCustodyEnvelope) { e.AccountID = 43 },
		"createdAt":  func(e *testCustodyEnvelope) { e.CreatedAt = "2026-10-10T00:00:01Z" },
		"profile":    func(e *testCustodyEnvelope) { e.Profile = "other-profile" },
		"baseURL":    func(e *testCustodyEnvelope) { e.BaseURL = "https://example.com/codex" },
		"model":      func(e *testCustodyEnvelope) { e.Model = "other-model" },
		"revision":   func(e *testCustodyEnvelope) { e.Revision = "rev-2" },
		"expiresAt":  func(e *testCustodyEnvelope) { e.ExpiresAt = e.ExpiresAt.Add(time.Hour) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newDescriptorHarness(t)
			h.verifier.tamper(testDescriptorScope, mutate)
			_, err := h.svc.Describe(context.Background(), testDescriptorScope)
			require.ErrorIs(t, err, ErrOAuthDescriptorDenied)
			require.Zero(t, h.hits.Load())
			require.Empty(t, h.cache.entries)
		})
	}
}

func TestOAuthDescriptorRejectsForeignSignatureAndScopeSubstitution(t *testing.T) {
	h := newDescriptorHarness(t)
	other, _ := testSigner(9)
	h.verifier.put(other, testEnvelope(testDescriptorScope, h.clock))
	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorDenied)

	h.verifier.put(h.key, testEnvelope(testDescriptorScope, h.clock))
	for name, mutate := range map[string]func(*OAuthDescriptorScope){
		"consumer":   func(s *OAuthDescriptorScope) { s.ConsumerID = "consumer-2" },
		"owner":      func(s *OAuthDescriptorScope) { s.OwnerRef = "owner-2" },
		"operation":  func(s *OAuthDescriptorScope) { s.OperationID = "op-2" },
		"account":    func(s *OAuthDescriptorScope) { s.AccountRef = "33333333-3333-4333-8333-333333333333" },
		"generation": func(s *OAuthDescriptorScope) { s.Generation = "33333333-3333-4333-8333-333333333333" },
	} {
		scope := testDescriptorScope
		mutate(&scope)
		_, err := h.svc.Describe(context.Background(), scope)
		require.ErrorIs(t, err, ErrOAuthDescriptorDenied, name)
	}
	_, err = h.svc.Describe(context.Background(), OAuthDescriptorScope{})
	require.ErrorIs(t, err, ErrOAuthDescriptorInvalid)
	require.Zero(t, h.hits.Load())
	require.Empty(t, h.cache.entries)
}

type testVerifierFunc func(OAuthDescriptorScope) (OAuthVerifiedBirth, error)

func (f testVerifierFunc) Verify(_ context.Context, s OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
	return f(s)
}

func TestOAuthDescriptorRejectsVerifierBirthForOtherScope(t *testing.T) {
	h := newDescriptorHarness(t)
	svc, err := NewOAuthDescriptorService(testVerifierFunc(func(s OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
		b, err := h.verifier.Verify(context.Background(), s)
		b.Scope.Generation = "33333333-3333-4333-8333-333333333333"
		return b, err
	}), h.qualifier, h.cache, h.clock, testDescriptorProfile, time.Minute)
	require.NoError(t, err)
	_, err = svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorDenied)
	require.Zero(t, h.hits.Load())
}

func TestOAuthDescriptorFailureIsNotCached(t *testing.T) {
	h := newDescriptorHarness(t)
	h.failing.Store(true)
	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorUnqualified)
	require.Empty(t, h.cache.entries)

	h.failing.Store(false)
	_, err = h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	require.Equal(t, int32(2), h.hits.Load())
}

func TestOAuthDescriptorRevocationDuringQualificationIsNotStored(t *testing.T) {
	h := newDescriptorHarness(t)
	h.qualifier.before = func() { h.verifier.revoke("rev-1", true) }
	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorRevoked)
	require.Empty(t, h.cache.entries)
}

func TestOAuthDescriptorConcurrentIdenticalRequestsShareOneQualification(t *testing.T) {
	h := newDescriptorHarness(t)
	release := make(chan struct{})
	h.qualifier.before = func() { <-release }
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = h.svc.Describe(context.Background(), testDescriptorScope)
		}(i)
	}
	for deadline := time.Now().Add(5 * time.Second); h.verifier.calls.Load() < n && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), h.hits.Load())
}

// testMissCache never serves a hit, so a late caller cannot bypass the flight
// by reading the owner's stored entry; it counts Loads to observe joining.
type testMissCache struct {
	inner OAuthDescriptorCache
	loads atomic.Int32
}

func (c *testMissCache) Load(OAuthDescriptorScope, string, time.Time) (OAuthDescriptorCacheEntry, bool) {
	c.loads.Add(1)
	return OAuthDescriptorCacheEntry{}, false
}

func (c *testMissCache) Store(e OAuthDescriptorCacheEntry, now time.Time) { c.inner.Store(e, now) }

func TestOAuthDescriptorWaiterRejectsCustodyChangedWhileJoining(t *testing.T) {
	cases := map[string]struct {
		change func(h *descriptorHarness)
		want   error
	}{
		"revoked": {func(h *descriptorHarness) { h.verifier.revoke("rev-1", true) }, ErrOAuthDescriptorRevoked},
		"changed birth under same flight key": {func(h *descriptorHarness) {
			e := testEnvelope(testDescriptorScope, h.clock)
			e.ExpiresAt = e.ExpiresAt.Add(time.Hour) // same revision, account and createdAt
			h.verifier.put(h.key, e)
		}, ErrOAuthDescriptorDenied},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newDescriptorHarness(t)
			cache := &testMissCache{inner: h.cache}
			var calls atomic.Int32
			// Verify order: 1 owner, 2 waiter, 3 owner re-verify after qualification.
			// Authority changes right after the owner's re-verify succeeded, so only a
			// live re-verification by the joined waiter can observe it.
			verifier := testVerifierFunc(func(s OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
				b, err := h.verifier.Verify(context.Background(), s)
				if calls.Add(1) == 3 {
					tc.change(h)
				}
				return b, err
			})
			release := make(chan struct{})
			h.qualifier.before = func() { <-release }
			svc, err := NewOAuthDescriptorService(verifier, h.qualifier, cache, h.clock, testDescriptorProfile, 10*time.Minute)
			require.NoError(t, err)

			var wg sync.WaitGroup
			var ownerErr, waiterErr error
			wg.Add(1)
			go func() { defer wg.Done(); _, ownerErr = svc.Describe(context.Background(), testDescriptorScope) }()
			for deadline := time.Now().Add(5 * time.Second); calls.Load() < 1 && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
			wg.Add(1)
			go func() { defer wg.Done(); _, waiterErr = svc.Describe(context.Background(), testDescriptorScope) }()
			// owner: 2 Loads; a joined waiter: 1 Load.
			for deadline := time.Now().Add(5 * time.Second); cache.loads.Load() < 3 && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
			close(release)
			wg.Wait()

			require.NoError(t, ownerErr, "owner was verified before the change")
			require.ErrorIs(t, waiterErr, tc.want)
		})
	}
}

func waitDescriptorCond(cond func() bool) {
	for deadline := time.Now().Add(5 * time.Second); !cond() && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
}

// testCancelFirstQualifier blocks its first Check until that caller's context is
// cancelled, then delegates every later Check to the real parser-backed qualifier.
type testCancelFirstQualifier struct {
	next  OAuthAccountQualifier
	calls atomic.Int32
}

func (q *testCancelFirstQualifier) Check(ctx context.Context, b OAuthVerifiedBirth) error {
	if q.calls.Add(1) == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return q.next.Check(ctx, b)
}

func TestOAuthDescriptorCancelledLeaderDoesNotFailLiveWaiter(t *testing.T) {
	h := newDescriptorHarness(t)
	cache := &testMissCache{inner: h.cache}
	q := &testCancelFirstQualifier{next: h.qualifier}
	svc, err := NewOAuthDescriptorService(h.verifier, q, cache, h.clock, testDescriptorProfile, 10*time.Minute)
	require.NoError(t, err)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	var wg sync.WaitGroup
	var leaderErr, waiterErr error
	var waiterBirth OAuthVerifiedBirth
	wg.Add(1)
	go func() { defer wg.Done(); _, leaderErr = svc.Describe(leaderCtx, testDescriptorScope) }()
	waitDescriptorCond(func() bool { return q.calls.Load() == 1 })
	wg.Add(1)
	go func() {
		defer wg.Done()
		waiterBirth, waiterErr = svc.Describe(context.Background(), testDescriptorScope)
	}()
	waitDescriptorCond(func() bool { return cache.loads.Load() >= 3 }) // leader 2 + joined waiter 1
	cancelLeader()
	wg.Wait()

	require.ErrorIs(t, leaderErr, ErrOAuthDescriptorUnavailable)
	require.NoError(t, waiterErr, "a live waiter must re-lead, not inherit the leader's cancellation")
	require.Equal(t, int64(42), waiterBirth.AccountID)
	require.Equal(t, int32(2), q.calls.Load())
	require.Equal(t, int32(1), h.hits.Load())
	require.Empty(t, svc.flights)
}

func TestOAuthDescriptorCancelledWaiterReturnsPromptlyAndLeaderCompletes(t *testing.T) {
	h := newDescriptorHarness(t)
	cache := &testMissCache{inner: h.cache}
	release := make(chan struct{})
	h.qualifier.before = func() { <-release }
	svc, err := NewOAuthDescriptorService(h.verifier, h.qualifier, cache, h.clock, testDescriptorProfile, 10*time.Minute)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var leaderErr error
	wg.Add(1)
	go func() { defer wg.Done(); _, leaderErr = svc.Describe(context.Background(), testDescriptorScope) }()
	waitDescriptorCond(func() bool { return cache.loads.Load() >= 2 })

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() { _, err := svc.Describe(waiterCtx, testDescriptorScope); waiterDone <- err }()
	waitDescriptorCond(func() bool { return cache.loads.Load() >= 3 })
	cancelWaiter()
	select {
	case err := <-waiterDone:
		require.ErrorIs(t, err, ErrOAuthDescriptorUnavailable)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter stayed blocked on the leader")
	}

	close(release)
	wg.Wait()
	require.NoError(t, leaderErr)
	require.Equal(t, int32(1), h.hits.Load())
	require.Empty(t, svc.flights)
}

func TestOAuthDescriptorFlightCapRejectsWithoutQualifying(t *testing.T) {
	h := newDescriptorHarness(t)
	h.svc.mu.Lock()
	for i := 0; i < oauthDescriptorMaxInflight; i++ {
		h.svc.flights[oauthDescriptorFlightKey{accountID: int64(1000 + i)}] = &oauthDescriptorFlight{done: make(chan struct{})}
	}
	h.svc.mu.Unlock()

	_, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.ErrorIs(t, err, ErrOAuthDescriptorUnavailable)
	require.Zero(t, h.hits.Load())
	require.Empty(t, h.cache.entries)
	require.Len(t, h.svc.flights, oauthDescriptorMaxInflight, "a rejected caller must not add or remove flights")
}

type testPanicQualifier struct{}

func (testPanicQualifier) Check(context.Context, OAuthVerifiedBirth) error { panic("qualifier boom") }

func TestOAuthDescriptorPanickingQualifierCleansUpFlight(t *testing.T) {
	h := newDescriptorHarness(t)
	svc, err := NewOAuthDescriptorService(h.verifier, testPanicQualifier{}, h.cache, h.clock, testDescriptorProfile, time.Minute)
	require.NoError(t, err)
	require.PanicsWithValue(t, "qualifier boom", func() { _, _ = svc.Describe(context.Background(), testDescriptorScope) })
	require.Empty(t, svc.flights)
	require.Empty(t, h.cache.entries)

	svc.qualifier = h.qualifier
	_, err = svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err, "the key must be leadable again after a panic")
}

func TestOAuthDescriptorPanickingLeaderReleasesWaiterAsUnavailable(t *testing.T) {
	h := newDescriptorHarness(t)
	cache := &testMissCache{inner: h.cache}
	release := make(chan struct{})
	var armed atomic.Bool
	armed.Store(true)
	q := testQualifierFunc(func(ctx context.Context, b OAuthVerifiedBirth) error {
		if armed.CompareAndSwap(true, false) {
			<-release
			panic("leader boom")
		}
		return h.qualifier.Check(ctx, b)
	})
	svc, err := NewOAuthDescriptorService(h.verifier, q, cache, h.clock, testDescriptorProfile, time.Minute)
	require.NoError(t, err)

	leaderDone := make(chan any, 1)
	go func() {
		defer func() { leaderDone <- recover() }()
		_, _ = svc.Describe(context.Background(), testDescriptorScope)
	}()
	waitDescriptorCond(func() bool { return cache.loads.Load() >= 2 })
	var waiterErr error
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		_, waiterErr = svc.Describe(context.Background(), testDescriptorScope)
	}()
	waitDescriptorCond(func() bool { return cache.loads.Load() >= 3 })
	close(release)
	require.Equal(t, "leader boom", <-leaderDone)
	<-waiterDone
	require.ErrorIs(t, waiterErr, ErrOAuthDescriptorUnavailable)
	require.Empty(t, svc.flights)
}

type testQualifierFunc func(context.Context, OAuthVerifiedBirth) error

func (f testQualifierFunc) Check(ctx context.Context, b OAuthVerifiedBirth) error { return f(ctx, b) }

// testSeqCache misses on the first Load and then serves a fixed entry, which
// exercises the post-lock cache re-check.
type testSeqCache struct {
	entry OAuthDescriptorCacheEntry
	loads atomic.Int32
}

func (c *testSeqCache) Load(OAuthDescriptorScope, string, time.Time) (OAuthDescriptorCacheEntry, bool) {
	if c.loads.Add(1) == 1 {
		return OAuthDescriptorCacheEntry{}, false
	}
	return c.entry, true
}
func (c *testSeqCache) Store(OAuthDescriptorCacheEntry, time.Time) {}

func TestOAuthDescriptorCacheEntryWithDifferentBirthIsNotTrusted(t *testing.T) {
	base := func(h *descriptorHarness) OAuthVerifiedBirth {
		b, err := h.verifier.Verify(context.Background(), testDescriptorScope)
		require.NoError(t, err)
		return b
	}
	mutations := map[string]func(*OAuthVerifiedBirth){
		"accountID": func(b *OAuthVerifiedBirth) { b.AccountID = 41 },
		"createdAt": func(b *OAuthVerifiedBirth) { b.CreatedAt = "2026-10-10T00:00:01Z" },
		"expiresAt": func(b *OAuthVerifiedBirth) { b.ExpiresAt = b.ExpiresAt.Add(time.Minute) },
		"model":     func(b *OAuthVerifiedBirth) { b.Model = "other-model" },
	}
	for name, mutate := range mutations {
		t.Run("first lookup/"+name, func(t *testing.T) {
			h := newDescriptorHarness(t)
			b := base(h)
			mutate(&b)
			h.cache.Store(OAuthDescriptorCacheEntry{Birth: b, ExpiresAt: h.clock.Now().Add(time.Minute)}, h.clock.Now())
			_, err := h.svc.Describe(context.Background(), testDescriptorScope)
			require.NoError(t, err)
			require.Equal(t, int32(1), h.hits.Load(), "a mismatched cached birth must be requalified")
		})
		t.Run("post-lock lookup/"+name, func(t *testing.T) {
			h := newDescriptorHarness(t)
			b := base(h)
			mutate(&b)
			cache := &testSeqCache{entry: OAuthDescriptorCacheEntry{Birth: b, ExpiresAt: h.clock.Now().Add(time.Minute)}}
			svc, err := NewOAuthDescriptorService(h.verifier, h.qualifier, cache, h.clock, testDescriptorProfile, time.Minute)
			require.NoError(t, err)
			_, err = svc.Describe(context.Background(), testDescriptorScope)
			require.NoError(t, err)
			require.Equal(t, int32(1), h.hits.Load())
		})
	}
	t.Run("identical birth is served", func(t *testing.T) {
		h := newDescriptorHarness(t)
		cache := &testSeqCache{entry: OAuthDescriptorCacheEntry{Birth: base(h), ExpiresAt: h.clock.Now().Add(time.Minute)}}
		svc, err := NewOAuthDescriptorService(h.verifier, h.qualifier, cache, h.clock, testDescriptorProfile, time.Minute)
		require.NoError(t, err)
		_, err = svc.Describe(context.Background(), testDescriptorScope)
		require.NoError(t, err)
		require.Zero(t, h.hits.Load())
	})
}

func TestOAuthDescriptorBirthFieldParityWithGatewayReader(t *testing.T) {
	// The verifier returns a well-formed but out-of-domain birth; custody
	// signature checks are not what is under test here.
	describeWith := func(mutate func(*OAuthVerifiedBirth)) (*descriptorHarness, error) {
		h := newDescriptorHarness(t)
		svc, err := NewOAuthDescriptorService(testVerifierFunc(func(s OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
			b, err := h.verifier.Verify(context.Background(), s)
			mutate(&b)
			return b, err
		}), h.qualifier, h.cache, h.clock, testDescriptorProfile, time.Minute)
		require.NoError(t, err)
		_, err = svc.Describe(context.Background(), testDescriptorScope)
		return h, err
	}

	t.Run("account id above MAX_SAFE_INTEGER", func(t *testing.T) {
		for _, id := range []int64{0, -1, 1 << 53, 1<<63 - 1} {
			h, err := describeWith(func(b *OAuthVerifiedBirth) { b.AccountID = id })
			require.ErrorIs(t, err, ErrOAuthDescriptorDenied, id)
			require.Zero(t, h.hits.Load())
		}
		// MAX_SAFE_INTEGER itself passes verification and only fails qualification.
		_, err := describeWith(func(b *OAuthVerifiedBirth) { b.AccountID = 1<<53 - 1 })
		require.ErrorIs(t, err, ErrOAuthDescriptorUnqualified)
	})

	rejected := []string{
		"2026-10-10T00:00:00.1234567890Z", "2026-10-10T00:00:00.Z", "2026-10-10T00:00:00+24:00",
		"2026-10-10T00:00:00-23:60", "2026-10-10T00:00:00", "2026-10-10t00:00:00z", "2026-10-10T24:00:00Z",
		"2026-10-10T00:00:60Z", "2026-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2026-04-31T00:00:00Z",
		"2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z", "0000-01-01T00:00:00Z", " 2026-10-10T00:00:00Z",
		"2026-10-10T00:00:00Z ", "2026-10-10T00:00:00+0000", "", "２０２６-10-10T00:00:00Z",
	}
	for _, v := range rejected {
		h, err := describeWith(func(b *OAuthVerifiedBirth) { b.CreatedAt = v })
		require.ErrorIs(t, err, ErrOAuthDescriptorDenied, v)
		require.Zero(t, h.hits.Load(), v)
	}
	accepted := []string{
		"2026-10-10T00:00:00Z", "2024-02-29T23:59:59.123456789+23:59", "2000-02-29T00:00:00Z",
		"2026-10-10T00:00:00.1-23:59", "0001-01-01T00:00:00Z", "2026-12-31T23:59:59Z",
	}
	for _, v := range accepted {
		_, err := describeWith(func(b *OAuthVerifiedBirth) { b.CreatedAt = v })
		require.NoError(t, err, v)
	}
}

func TestOAuthDescriptorDifferentScopesDoNotShareResults(t *testing.T) {
	h := newDescriptorHarness(t)
	second := testDescriptorScope
	second.OperationID = "op-2"
	second.Generation = "44444444-4444-4444-8444-444444444444"
	h.verifier.put(h.key, testEnvelope(second, h.clock))
	a, err := h.svc.Describe(context.Background(), testDescriptorScope)
	require.NoError(t, err)
	b, err := h.svc.Describe(context.Background(), second)
	require.NoError(t, err)
	require.NotEqual(t, a.Scope, b.Scope)
	require.Equal(t, int32(2), h.hits.Load())
}

func TestOAuthDescriptorMemoryCacheIsBounded(t *testing.T) {
	_, err := NewOAuthDescriptorMemoryCache(0)
	require.Error(t, err)
	c, err := NewOAuthDescriptorMemoryCache(1)
	require.NoError(t, err)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, op := range []string{"op-a", "op-b"} {
		s := testDescriptorScope
		s.OperationID = op
		c.Store(OAuthDescriptorCacheEntry{Birth: OAuthVerifiedBirth{Scope: s, CustodyRevision: "r"}, ExpiresAt: now.Add(time.Minute)}, now)
	}
	require.Len(t, c.entries, 1)
	_, ok := c.Load(testDescriptorScope, "r", now.Add(time.Hour))
	require.False(t, ok)
}

func TestNewOAuthDescriptorServiceRejectsMissingPorts(t *testing.T) {
	h := newDescriptorHarness(t)
	_, err := NewOAuthDescriptorService(nil, h.qualifier, h.cache, h.clock, testDescriptorProfile, time.Minute)
	require.Error(t, err)
	_, err = NewOAuthDescriptorService(h.verifier, h.qualifier, h.cache, h.clock, OAuthDescriptorProfile{}, time.Minute)
	require.Error(t, err)
}
