package service

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// Finite descriptor failure categories. Port errors that are not one of these
// are reported as ErrOAuthDescriptorUnavailable; raw errors never leave the service.
var (
	ErrOAuthDescriptorInvalid     = errors.New("oauth descriptor: invalid scope")
	ErrOAuthDescriptorDenied      = errors.New("oauth descriptor: denied")
	ErrOAuthDescriptorExpired     = errors.New("oauth descriptor: custody expired")
	ErrOAuthDescriptorRevoked     = errors.New("oauth descriptor: custody revoked")
	ErrOAuthDescriptorUnqualified = errors.New("oauth descriptor: account not qualified")
	ErrOAuthDescriptorUnavailable = errors.New("oauth descriptor: unavailable")
)

const (
	oauthDescriptorMaxField    = 128
	oauthDescriptorMaxURL      = 2048
	oauthDescriptorMaxInflight = 256
	// Number.MAX_SAFE_INTEGER, the Gateway reader's account id ceiling.
	oauthDescriptorMaxSafeInteger = 1<<53 - 1
	// A waiter whose live context outlasts a cancelled leader may re-lead this many times.
	oauthDescriptorMaxRelead = 3
)

var (
	// Parity with the TS identifier()/uuid() domain contracts: leading punctuation
	// is allowed; UUIDs are lowercase, version 1-8, variant 89ab.
	oauthDescriptorIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)
	oauthDescriptorUUID       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	oauthDescriptorModel      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	// Exact parity with gateway-management-reference.ts physicalCandidate createdAt.
	oauthDescriptorCreatedAt = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)
)

func oauthDescriptorCreatedAtValid(v string) bool {
	if len(v) > 64 || !oauthDescriptorCreatedAt.MatchString(v) {
		return false
	}
	year, _ := strconv.Atoi(v[0:4])
	month, _ := strconv.Atoi(v[5:7])
	day, _ := strconv.Atoi(v[8:10])
	leap := year%4 == 0 && (year%100 != 0 || year%400 == 0)
	days := [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if leap {
		days[1] = 29
	}
	return year >= 1 && day <= days[month-1]
}

// OAuthDescriptorScope is the exact Gateway request identity.
type OAuthDescriptorScope struct {
	ConsumerID  string
	OwnerRef    string
	OperationID string
	AccountRef  string
	Generation  string
}

// OAuthDescriptorProfile is the single admitted profile/baseURL/model tuple.
type OAuthDescriptorProfile struct {
	Profile string
	BaseURL string
	Model   string
}

// OAuthVerifiedBirth is the value-only result of custody verification. It binds
// the exact scope to a native account and carries the custody authority expiry.
// CreatedAt is kept verbatim (RFC3339 text), as the Gateway consumer does.
type OAuthVerifiedBirth struct {
	Scope           OAuthDescriptorScope
	AccountID       int64
	CreatedAt       string
	Profile         string
	BaseURL         string
	Model           string
	CustodyRevision string
	ExpiresAt       time.Time
}

func (b OAuthVerifiedBirth) same(o OAuthVerifiedBirth) bool {
	return b.Scope == o.Scope && b.AccountID == o.AccountID && b.CreatedAt == o.CreatedAt &&
		b.Profile == o.Profile && b.BaseURL == o.BaseURL && b.Model == o.Model &&
		b.CustodyRevision == o.CustodyRevision && b.ExpiresAt.Equal(o.ExpiresAt)
}

// OAuthCustodyVerifier validates an authenticated custody record for exactly
// this scope and re-checks revocation on every call. Implementations return
// ErrOAuthDescriptorExpired/Revoked/Denied where applicable. No production
// implementation exists yet; it must never accept caller-supplied birth data.
type OAuthCustodyVerifier interface {
	Verify(ctx context.Context, scope OAuthDescriptorScope) (OAuthVerifiedBirth, error)
}

// OAuthAccountQualifier checks the owner-bound native account without
// returning token, email or raw upstream data. Nil means qualified.
type OAuthAccountQualifier interface {
	Check(ctx context.Context, birth OAuthVerifiedBirth) error
}

// OAuthAccountCredential is the private upstream credential of one native
// account. It never crosses the descriptor port or any HTTP response.
type OAuthAccountCredential struct {
	AccessToken string
	OrgID       string
	ProxyURL    string
}

// OAuthAccountCredentialLookup resolves the credential of the exact owner-bound
// account named by a verified birth (full scope, account id and revision). It
// returns ErrOAuthDescriptorDenied/Unqualified when the owner has no such
// account. No production implementation exists yet.
type OAuthAccountCredentialLookup interface {
	Lookup(ctx context.Context, birth OAuthVerifiedBirth) (OAuthAccountCredential, error)
}

// OAuthChatGPTAccountQualifier qualifies a birth by running the existing
// fetchChatGPTAccountInfo against the looked-up credential and requiring the
// returned account to be exactly the bound organisation.
type OAuthChatGPTAccountQualifier struct {
	lookup  OAuthAccountCredentialLookup
	factory PrivacyClientFactory
}

func NewOAuthChatGPTAccountQualifier(lookup OAuthAccountCredentialLookup, factory PrivacyClientFactory) (*OAuthChatGPTAccountQualifier, error) {
	if lookup == nil || factory == nil {
		return nil, ErrOAuthDescriptorInvalid
	}
	return &OAuthChatGPTAccountQualifier{lookup: lookup, factory: factory}, nil
}

// Check never returns token, email or raw upstream data or errors.
func (q *OAuthChatGPTAccountQualifier) Check(ctx context.Context, birth OAuthVerifiedBirth) error {
	if err := birth.Scope.Validate(); err != nil || birth.AccountID < 1 {
		return ErrOAuthDescriptorDenied
	}
	cred, err := q.lookup.Lookup(ctx, birth)
	if err != nil {
		if errors.Is(err, ErrOAuthDescriptorDenied) || errors.Is(err, ErrOAuthDescriptorUnqualified) {
			return ErrOAuthDescriptorUnqualified
		}
		return ErrOAuthDescriptorUnavailable
	}
	if cred.AccessToken == "" || cred.OrgID == "" {
		return ErrOAuthDescriptorUnqualified
	}
	info := fetchChatGPTAccountInfo(ctx, q.factory, cred.AccessToken, cred.ProxyURL, cred.OrgID)
	if ctx.Err() != nil {
		// A cancelled or expired context makes a nil info transient, not a refusal.
		return ErrOAuthDescriptorUnavailable
	}
	if info == nil || info.PlanType == "" || info.AccountID != cred.OrgID {
		return ErrOAuthDescriptorUnqualified
	}
	return nil
}

// OAuthDescriptorClock supplies time for expiry decisions.
type OAuthDescriptorClock interface {
	Now() time.Time
}

type oauthDescriptorCacheKey struct {
	scope    OAuthDescriptorScope
	revision string
}

// OAuthDescriptorCacheEntry is a finite qualification of one verified birth.
type OAuthDescriptorCacheEntry struct {
	Birth     OAuthVerifiedBirth
	ExpiresAt time.Time
}

// OAuthDescriptorCache is keyed by the exact full scope plus custody revision.
type OAuthDescriptorCache interface {
	Load(scope OAuthDescriptorScope, revision string, now time.Time) (OAuthDescriptorCacheEntry, bool)
	Store(entry OAuthDescriptorCacheEntry, now time.Time)
}

// OAuthDescriptorMemoryCache is a bounded in-memory cache. Cleanup is lazy and
// owned by Load/Store; there is no background goroutine.
type OAuthDescriptorMemoryCache struct {
	mu      sync.Mutex
	max     int
	entries map[oauthDescriptorCacheKey]OAuthDescriptorCacheEntry
}

func NewOAuthDescriptorMemoryCache(maxEntries int) (*OAuthDescriptorMemoryCache, error) {
	if maxEntries < 1 || maxEntries > 65536 {
		return nil, ErrOAuthDescriptorInvalid
	}
	return &OAuthDescriptorMemoryCache{max: maxEntries, entries: make(map[oauthDescriptorCacheKey]OAuthDescriptorCacheEntry)}, nil
}

func (c *OAuthDescriptorMemoryCache) Load(scope OAuthDescriptorScope, revision string, now time.Time) (OAuthDescriptorCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := oauthDescriptorCacheKey{scope, revision}
	entry, ok := c.entries[key]
	if ok && !now.Before(entry.ExpiresAt) {
		delete(c.entries, key)
		return OAuthDescriptorCacheEntry{}, false
	}
	return entry, ok
}

func (c *OAuthDescriptorMemoryCache) Store(entry OAuthDescriptorCacheEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := oauthDescriptorCacheKey{entry.Birth.Scope, entry.Birth.CustodyRevision}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.max {
		var oldest oauthDescriptorCacheKey
		var oldestAt time.Time
		found := false
		for k, e := range c.entries {
			if !now.Before(e.ExpiresAt) {
				delete(c.entries, k)
				continue
			}
			if !found || e.ExpiresAt.Before(oldestAt) {
				oldest, oldestAt, found = k, e.ExpiresAt, true
			}
		}
		if len(c.entries) >= c.max && found {
			delete(c.entries, oldest)
		}
	}
	c.entries[key] = entry
}

type oauthDescriptorFlightKey struct {
	scope     OAuthDescriptorScope
	revision  string
	accountID int64
	createdAt string
}

type oauthDescriptorFlight struct {
	done  chan struct{}
	birth OAuthVerifiedBirth
	err   error
	// leaderCancelled: the flight failed while its leader's own context was done,
	// so the failure says nothing about the waiters' custody or account.
	leaderCancelled bool
}

// OAuthDescriptorService orchestrates verify -> cache -> qualify -> reverify -> store.
type OAuthDescriptorService struct {
	verifier  OAuthCustodyVerifier
	qualifier OAuthAccountQualifier
	cache     OAuthDescriptorCache
	clock     OAuthDescriptorClock
	profile   OAuthDescriptorProfile
	maxAge    time.Duration

	mu      sync.Mutex
	flights map[oauthDescriptorFlightKey]*oauthDescriptorFlight
}

// NewOAuthDescriptorService wires the ports. maxAge caps how long a
// qualification may be reused; entries never outlive custody expiry.
func NewOAuthDescriptorService(verifier OAuthCustodyVerifier, qualifier OAuthAccountQualifier,
	cache OAuthDescriptorCache, clock OAuthDescriptorClock, profile OAuthDescriptorProfile, maxAge time.Duration) (*OAuthDescriptorService, error) {
	if verifier == nil || qualifier == nil || cache == nil || clock == nil || maxAge <= 0 || maxAge > 24*time.Hour ||
		!oauthDescriptorIdentifier.MatchString(profile.Profile) || len(profile.Profile) > 64 ||
		!oauthDescriptorModel.MatchString(profile.Model) || !oauthDescriptorHTTPS(profile.BaseURL) {
		return nil, ErrOAuthDescriptorInvalid
	}
	return &OAuthDescriptorService{verifier: verifier, qualifier: qualifier, cache: cache, clock: clock,
		profile: profile, maxAge: maxAge, flights: make(map[oauthDescriptorFlightKey]*oauthDescriptorFlight)}, nil
}

func oauthDescriptorHTTPS(raw string) bool {
	if raw == "" || len(raw) > oauthDescriptorMaxURL {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// Validate checks that every scope field is bounded and well formed.
func (s OAuthDescriptorScope) Validate() error {
	for _, v := range []string{s.ConsumerID, s.OwnerRef, s.OperationID} {
		if len(v) < 1 || len(v) > oauthDescriptorMaxField || !oauthDescriptorIdentifier.MatchString(v) {
			return ErrOAuthDescriptorInvalid
		}
	}
	if !oauthDescriptorUUID.MatchString(s.AccountRef) || !oauthDescriptorUUID.MatchString(s.Generation) {
		return ErrOAuthDescriptorInvalid
	}
	return nil
}

func (s *OAuthDescriptorService) verify(ctx context.Context, scope OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
	b, err := s.verifier.Verify(ctx, scope)
	if err != nil {
		switch {
		case errors.Is(err, ErrOAuthDescriptorExpired):
			return OAuthVerifiedBirth{}, ErrOAuthDescriptorExpired
		case errors.Is(err, ErrOAuthDescriptorRevoked):
			return OAuthVerifiedBirth{}, ErrOAuthDescriptorRevoked
		case errors.Is(err, ErrOAuthDescriptorDenied):
			return OAuthVerifiedBirth{}, ErrOAuthDescriptorDenied
		}
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorUnavailable
	}
	if b.Scope != scope || b.AccountID < 1 || b.AccountID > oauthDescriptorMaxSafeInteger ||
		b.CustodyRevision == "" || len(b.CustodyRevision) > oauthDescriptorMaxField ||
		b.Profile != s.profile.Profile || b.BaseURL != s.profile.BaseURL || b.Model != s.profile.Model ||
		!oauthDescriptorCreatedAtValid(b.CreatedAt) {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorDenied
	}
	if !s.clock.Now().Before(b.ExpiresAt) {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorExpired
	}
	return b, nil
}

// Describe returns the qualified birth for scope. Custody is verified live on
// every call, including cache hits; only the account qualification is cached.
func (s *OAuthDescriptorService) Describe(ctx context.Context, scope OAuthDescriptorScope) (OAuthVerifiedBirth, error) {
	if err := scope.Validate(); err != nil {
		return OAuthVerifiedBirth{}, err
	}
	// Each pass verifies custody live. A pass only repeats when the joined flight
	// died because its leader's context was cancelled while this caller's is live.
	for pass := 0; ; pass++ {
		birth, err := s.verify(ctx, scope)
		if err != nil {
			return OAuthVerifiedBirth{}, err
		}
		out, relead, err := s.describePass(ctx, scope, birth)
		if relead && pass < oauthDescriptorMaxRelead {
			continue
		}
		if relead {
			err = ErrOAuthDescriptorUnavailable
		}
		return out, err
	}
}

// describePass joins or leads one flight. relead reports that the joined flight
// failed only because its leader was cancelled, so the caller may lead afresh.
func (s *OAuthDescriptorService) describePass(ctx context.Context, scope OAuthDescriptorScope, birth OAuthVerifiedBirth) (OAuthVerifiedBirth, bool, error) {
	if entry, ok := s.cache.Load(scope, birth.CustodyRevision, s.clock.Now()); ok && entry.Birth.same(birth) {
		return birth, false, nil
	}
	key := oauthDescriptorFlightKey{birth.Scope, birth.CustodyRevision, birth.AccountID, birth.CreatedAt}
	s.mu.Lock()
	if f, ok := s.flights[key]; ok {
		s.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return OAuthVerifiedBirth{}, false, ErrOAuthDescriptorUnavailable
		}
		if f.err != nil {
			return OAuthVerifiedBirth{}, f.leaderCancelled, f.err
		}
		// The flight result is shared, not authority: the custody may have been
		// revoked, expired or replaced while this waiter was joining. Re-verify the
		// exact scope live and require the entire immutable birth to be unchanged.
		again, verr := s.verify(ctx, scope)
		if verr != nil {
			return OAuthVerifiedBirth{}, false, verr
		}
		if !again.same(f.birth) || !again.same(birth) {
			return OAuthVerifiedBirth{}, false, ErrOAuthDescriptorDenied
		}
		return again, false, nil
	}
	// A finished flight stores before it is removed, so this closes the window
	// between the first cache miss and taking the lock.
	if entry, ok := s.cache.Load(scope, birth.CustodyRevision, s.clock.Now()); ok && entry.Birth.same(birth) {
		s.mu.Unlock()
		return birth, false, nil
	}
	if len(s.flights) >= oauthDescriptorMaxInflight {
		s.mu.Unlock()
		return OAuthVerifiedBirth{}, false, ErrOAuthDescriptorUnavailable
	}
	f := &oauthDescriptorFlight{done: make(chan struct{})}
	s.flights[key] = f
	s.mu.Unlock()

	f.err = ErrOAuthDescriptorUnavailable // preserved if a port panics
	defer func() {
		s.mu.Lock()
		delete(s.flights, key)
		s.mu.Unlock()
		close(f.done)
	}()
	f.birth, f.err = s.qualify(ctx, birth)
	f.leaderCancelled = f.err != nil && ctx.Err() != nil
	return f.birth, false, f.err
}

func (s *OAuthDescriptorService) qualify(ctx context.Context, birth OAuthVerifiedBirth) (OAuthVerifiedBirth, error) {
	if err := s.qualifier.Check(ctx, birth); err != nil {
		if errors.Is(err, ErrOAuthDescriptorUnqualified) {
			return OAuthVerifiedBirth{}, ErrOAuthDescriptorUnqualified
		}
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorUnavailable
	}
	// Qualification is async: custody may have been revoked, expired or replaced.
	again, err := s.verify(ctx, birth.Scope)
	if err != nil {
		return OAuthVerifiedBirth{}, err
	}
	if !again.same(birth) {
		return OAuthVerifiedBirth{}, ErrOAuthDescriptorDenied
	}
	now := s.clock.Now()
	expires := now.Add(s.maxAge)
	if birth.ExpiresAt.Before(expires) {
		expires = birth.ExpiresAt
	}
	s.cache.Store(OAuthDescriptorCacheEntry{Birth: birth, ExpiresAt: expires}, now)
	return birth, nil
}
