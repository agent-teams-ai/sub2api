package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/stretchr/testify/require"
)

// Genuine signed responses over controlled TLS exercise the transport and
// verifier together. SQL ownership/races are tested once at the PG boundary.
func TestGatewayNativeOAuthRefreshSignedHTTPContainment(t *testing.T) {
	key := oauthFixtureKey(t)
	now := time.Now().Truncate(time.Second)
	var mode atomic.Int32
	var tokenCalls, jwksCalls, destinationCalls atomic.Int32
	var receivedHeaders atomic.Bool
	var verifyClockAdvance atomic.Bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	refresh := gatewayOAuthGuardFixtureOpaque()
	signed := func(subject string) string {
		return oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims(subject, now))
	}
	goodID, badID := signed("reserved-subject"), signed("foreign-subject")
	nextAccess, nextRefresh := gatewayOAuthGuardFixtureOpaque(), gatewayOAuthGuardFixtureOpaque()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		if r.URL.Path == "/.well-known/jwks.json" {
			jwksCalls.Add(1)
			if mode.Load() == 14 {
				verifyClockAdvance.Store(true)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
			return
		}
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, openai.ClientID, r.Form.Get("client_id"))
		require.Equal(t, "openid profile email", r.Form.Get("scope"))
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		require.Equal(t, refresh, r.Form.Get("refresh_token"))
		require.Empty(t, r.Header.Get("Authorization"))
		require.Len(t, r.Form, 4)
		tokenCalls.Add(1)
		response := map[string]any{"access_token": nextAccess, "refresh_token": nextRefresh, "id_token": goodID, "token_type": "Bearer", "expires_in": 3600, "private_account_hint": gatewayOAuthGuardFixtureOpaque()}
		switch mode.Load() {
		case 1:
			response["id_token"] = badID
		case 2:
			delete(response, "id_token")
		case 3:
			http.Redirect(w, r, destination.URL+"/stolen", http.StatusTemporaryRedirect)
			return
		case 4:
			_, _ = w.Write([]byte(strings.Repeat(" ", 65537)))
			return
		case 5:
			<-r.Context().Done()
			return
		case 6:
			delete(response, "refresh_token")
		case 8:
			response["expires_in"] = "malformed"
		case 9:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":`))
			flusher, ok := w.(http.Flusher)
			require.True(t, ok)
			flusher.Flush()
			<-r.Context().Done()
			return
		case 10:
			response[gatewayOAuthTimingMember] = map[string]any{"request_started": now.Format(time.RFC3339Nano)}
		case 11:
			response["expires_in"] = 0
		case 12:
			response["expires_in"] = int64(9223372036854775807)
		case 13:
			delete(response, "expires_in")
		case 7:
			_, _ = w.Write([]byte(`{"access_token":"a","Access_token":"b"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	baseTransport, ok := server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "auth.openai.com:443" {
			address = server.Listener.Addr().String()
		} else {
			require.Equal(t, destination.Listener.Addr().String(), address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	verifier := NewGatewayNativeOAuthVerifier(transport)
	verifier.now = func() time.Time {
		if verifyClockAdvance.Load() {
			return now.Add(2 * time.Hour)
		}
		return now
	}
	// exchange shares the exact production constructor's fixed client policy.
	custodyKey := make([]byte, 32)
	_, err := rand.Read(custodyKey)
	require.NoError(t, err)
	custody, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": custodyKey})
	require.NoError(t, err)
	// A repository is not used by the transport-only scenario. The separate PG
	// scenario uses the real adapter to prove entry/unknown/atomic publication.
	s, err := NewGatewayNativeOAuthRefresh(&httpOnlyRefreshRepository{}, custody, verifier, transport)
	require.NoError(t, err)
	bundle, err := s.exchange(context.Background(), refresh, GatewayOAuthIssuer, "reserved-subject")
	require.NoError(t, err)
	require.Equal(t, nextAccess, bundle.AccessToken)
	require.Equal(t, nextRefresh, bundle.RefreshToken)
	require.Equal(t, goodID, bundle.IDToken)
	require.Contains(t, string(bundle.SensitiveMetadata), "private_account_hint")
	require.NotContains(t, string(bundle.SensitiveMetadata), nextAccess)
	require.Equal(t, int32(1), jwksCalls.Load())
	// Signed ID expiry wins over access expiry, which is fixed at request start.
	metadata, err := gatewayOAuthJSON(bundle.SensitiveMetadata)
	require.NoError(t, err)
	var timing gatewayOAuthTiming
	require.NoError(t, json.Unmarshal(metadata[gatewayOAuthTimingMember], &timing))
	require.Equal(t, now.Add(time.Hour).Format(time.RFC3339Nano), timing.IDExpires)
	tokenStarted, err := time.Parse(time.RFC3339Nano, timing.RequestStarted)
	require.NoError(t, err)
	accessExpires, err := time.Parse(time.RFC3339Nano, timing.AccessExpires)
	require.NoError(t, err)
	require.True(t, accessExpires.Equal(tokenStarted.Add(time.Hour)))
	due, qualified := gatewayOAuthBundleDue(bundle, now.Add(time.Hour-61*time.Second), custody)
	require.True(t, qualified)
	require.False(t, due)
	due, qualified = gatewayOAuthBundleDue(bundle, now.Add(time.Hour-60*time.Second), custody)
	require.True(t, qualified)
	require.True(t, due)
	// Historical provider metadata, even when encrypted, cannot forge fresh timing.
	legacy := bundle
	legacyMetadata := map[string]any{"expires_in": 3600, gatewayOAuthTimingMember: map[string]any{
		"request_started": timing.RequestStarted, "access_expires": timing.AccessExpires, "id_expires": timing.IDExpires, "engine_proof": "provider-controlled"}}
	legacy.SensitiveMetadata, err = json.Marshal(legacyMetadata)
	require.NoError(t, err)
	due, qualified = gatewayOAuthBundleDue(legacy, time.Now().Add(24*time.Hour), custody)
	require.False(t, qualified)
	require.False(t, due)
	// Dates and whole-bundle bytes are bound by the engine proof; raw JWT text or
	// changing either the date or access token cannot become timing authority.
	changed := bundle
	changed.AccessToken = gatewayOAuthGuardFixtureOpaque()
	_, qualified = gatewayOAuthBundleDue(changed, time.Now(), custody)
	require.False(t, qualified)
	timing.IDExpires = now.Add(-time.Hour).Format(time.RFC3339Nano)
	metadata[gatewayOAuthTimingMember], err = json.Marshal(timing)
	require.NoError(t, err)
	changed = bundle
	changed.SensitiveMetadata, err = json.Marshal(metadata)
	require.NoError(t, err)
	_, qualified = gatewayOAuthBundleDue(changed, time.Now(), custody)
	require.False(t, qualified)
	for _, tc := range []struct {
		name string
		mode int32
	}{{"signed foreign principal", 1}, {"missing fresh ID token", 2}, {"redirect", 3}, {"body overflow", 4}, {"header deadline", 5}, {"missing refresh token", 6}, {"ambiguous JSON", 7}, {"malformed expiry", 8}, {"reserved provider metadata", 10}, {"zero expiry", 11}, {"overflow expiry", 12}, {"missing expiry", 13}} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			budget := 100 * time.Millisecond
			if tc.mode == 5 {
				budget = 8 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			start := time.Now()
			bundle, err := s.exchange(ctx, refresh, GatewayOAuthIssuer, "reserved-subject")
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Equal(t, GatewayNativeOAuthBundle{}, bundle)
			if tc.mode == 5 {
				require.GreaterOrEqual(t, time.Since(start), 4*time.Second)
				require.Less(t, time.Since(start), 6*time.Second, "production HTTP/body timeout must enforce 5s")
			} else {
				require.Less(t, time.Since(start), time.Second)
			}
			require.Zero(t, destinationCalls.Load(), "redirect denial must precede destination contact")
		})
	}
	require.Equal(t, int32(13), tokenCalls.Load())
	require.Equal(t, int32(2), jwksCalls.Load(), "only complete ID tokens require fixed trusted verification")
	// Exercise fresh enrollment enrichment at the same signed HTTP/custody
	// boundary. A later retry must match the original four-field commitment,
	// even with a different request-start clock and an expired original ID token.
	scope := GatewayNativeCredentialScope{Consumer: "timing-consumer", Owner: "timing-owner", Account: "timing-account", Generation: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Purpose: GatewayOAuthBundlePurpose}
	ownerCtx, err := WithGatewayNativeConsumer(context.Background(), scope.Consumer)
	require.NoError(t, err)
	ownerCtx, err = WithGatewayNativeOAuthOwner(ownerCtx, scope.Owner)
	require.NoError(t, err)
	intentKey := make([]byte, 32)
	_, err = rand.Read(intentKey)
	require.NoError(t, err)
	enrollmentObserver := &refreshEnrollmentCommitmentObserver{}
	enrollment, err := NewGatewayNativeOAuthEnrollment(verifier, custody, enrollmentObserver, intentKey)
	require.NoError(t, err)
	fresh := GatewayNativeOAuthBundle{
		AccessToken: nextAccess, RefreshToken: nextRefresh, IDToken: goodID,
		SensitiveMetadata: json.RawMessage(`{"expires_in":3600,"private_account_hint":"fresh-exchange"}`),
		requestStarted:    now.Add(-30 * time.Second),
	}
	jwksBeforeEnrollment := jwksCalls.Load()
	accepted, err := enrollment.Stage(ownerCtx, scope, "timed-original-enrollment", fresh)
	require.NoError(t, err)
	require.Equal(t, jwksBeforeEnrollment+1, jwksCalls.Load(), "fresh enrichment uses the original complete verification")
	sealedBeforeReplay := enrollmentObserver.reservation.Envelope
	stored, err := custody.openOAuthVersion(sealedBeforeReplay, scope, 1)
	require.NoError(t, err)
	storedMetadata, err := gatewayOAuthJSON(stored.SensitiveMetadata)
	require.NoError(t, err)
	var storedTiming gatewayOAuthTiming
	require.NoError(t, json.Unmarshal(storedMetadata[gatewayOAuthTimingMember], &storedTiming))
	require.Equal(t, fresh.requestStarted.Format(time.RFC3339Nano), storedTiming.RequestStarted)
	require.Equal(t, now.Add(time.Hour-30*time.Second).Format(time.RFC3339Nano), storedTiming.AccessExpires,
		"verification must not extend access expiry beyond fixed request start")
	require.Equal(t, now.Add(time.Hour).Format(time.RFC3339Nano), storedTiming.IDExpires)
	due, qualified = gatewayOAuthBundleDue(stored, now.Add(time.Hour-90*time.Second), custody)
	require.True(t, qualified)
	require.True(t, due, "access expiry is earlier than signed ID expiry in this enrollment")
	verifyClockAdvance.Store(true)
	fresh.requestStarted = now.Add(2 * time.Hour)
	replayed, err := enrollment.Stage(ownerCtx, scope, "timed-original-enrollment", fresh)
	require.NoError(t, err)
	require.Equal(t, accepted, replayed)
	require.Equal(t, sealedBeforeReplay, enrollmentObserver.reservation.Envelope)
	require.Equal(t, 1, enrollmentObserver.stages, "replay does not rewrite historical custody or timing")
	require.Equal(t, jwksBeforeEnrollment+1, jwksCalls.Load(), "exact original replay bypasses expired token verification")
	changedIntent := fresh
	changedIntent.AccessToken = gatewayOAuthGuardFixtureOpaque()
	_, err = enrollment.Stage(ownerCtx, scope, "timed-original-enrollment", changedIntent)
	require.ErrorIs(t, err, ErrGatewayOAuthConflict)
	verifyClockAdvance.Store(false)

	// A delayed JWKS crosses signed expiry: the verifier must fail, rather than
	// moving the absolute deadline forward to verification/response completion.
	mode.Store(14)
	_, err = s.exchange(context.Background(), refresh, GatewayOAuthIssuer, "reserved-subject")
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.True(t, verifyClockAdvance.Load())
	verifyClockAdvance.Store(false)
	// Failure: live policy may be revoked during preparation, after the HTTP
	// middleware authorized Maintain. Entry must make zero token HTTP calls.
	t.Run("live owner revoked at refresh entry", func(t *testing.T) {
		scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "account", Generation: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Purpose: GatewayOAuthBundlePurpose}
		ctx, err := WithGatewayNativeConsumer(context.Background(), scope.Consumer)
		require.NoError(t, err)
		ctx, err = WithGatewayNativeOAuthOwner(ctx, scope.Owner)
		require.NoError(t, err)
		old := GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixtureOpaque(), RefreshToken: refresh, IDToken: goodID, SensitiveMetadata: json.RawMessage(`{"private":"old-custody"}`)}
		envelope, err := custody.SealOAuthBundle(scope, old)
		require.NoError(t, err)
		in := GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: 1, CreatedAt: time.Now().Truncate(time.Microsecond), ExpectedVersion: 1, Operation: "rotation", Intent: "intent", ConnectOperation: "original-connect"}
		observer := &refreshContextObserver{prepared: GatewayNativeOAuthRefreshPrepared{Outcome: GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "prepared"}, Fence: 1, Deadline: time.Now().Add(time.Second), Claimed: true, Envelope: envelope}}
		service, err := NewGatewayNativeOAuthRefresh(observer, custody, verifier, transport)
		require.NoError(t, err)
		checks := 0
		require.NoError(t, service.SetEntryAuthorizer(func(_ context.Context, got GatewayNativeCredentialScope, operation string) error {
			checks++
			require.Equal(t, scope, got)
			require.Equal(t, "original-connect", operation)
			return ErrGatewayNativeIdentity
		}))
		before := tokenCalls.Load()
		out, err := service.Refresh(ctx, in)
		require.Error(t, err)
		require.Equal(t, "unknown", out.State)
		require.Equal(t, 1, checks)
		require.Equal(t, before, tokenCalls.Load())
		require.False(t, observer.completionCalled)
		require.Equal(t, "prepared", observer.prepared.Outcome.State)
	})

	// These scenarios observe service/repository context contracts using actual
	// signed HTTP and custody. Durable SQL publication is proved only by real PG.
	for _, tc := range []struct {
		name     string
		mode     int32
		deadline time.Duration
	}{{"completion context expires at prepared deadline", 0, 400 * time.Millisecond}, {"post-header body stall retains unknown old custody", 9, 8 * time.Second}} {
		t.Run(tc.name, func(t *testing.T) {
			mode.Store(tc.mode)
			receivedHeaders.Store(false)
			scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "account", Generation: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Purpose: GatewayOAuthBundlePurpose}
			ctx, err := WithGatewayNativeConsumer(context.Background(), scope.Consumer)
			require.NoError(t, err)
			ctx, err = WithGatewayNativeOAuthOwner(ctx, scope.Owner)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
			defer cancel()
			old := GatewayNativeOAuthBundle{AccessToken: gatewayOAuthGuardFixtureOpaque(), RefreshToken: refresh, IDToken: goodID, SensitiveMetadata: json.RawMessage(`{"private":"old-custody"}`)}
			envelope, err := custody.SealOAuthBundle(scope, old)
			require.NoError(t, err)
			in := GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: 1, CreatedAt: time.Now().Truncate(time.Microsecond), ExpectedVersion: 1, Operation: "bounded-refresh", Intent: "rotate"}
			observer := &refreshContextObserver{prepared: GatewayNativeOAuthRefreshPrepared{Outcome: GatewayNativeOAuthRefreshOutcome{Operation: in.Operation, State: "prepared"}, Fence: 1, Deadline: time.Now().Add(tc.deadline), Claimed: true, Envelope: envelope, Issuer: GatewayOAuthIssuer, Subject: "reserved-subject"}}
			refreshService, err := NewGatewayNativeOAuthRefresh(observer, custody, verifier, &refreshHeaderObserver{RoundTripper: transport, received: &receivedHeaders})
			require.NoError(t, err)
			beforeCalls := tokenCalls.Load()
			start := time.Now()
			out, err := refreshService.Refresh(ctx, in)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.Equal(t, "unknown", out.State)
			require.True(t, receivedHeaders.Load(), "actual HTTP response headers precede stalled work")
			require.True(t, observer.cleanupLive, "ambiguity recording has its own bounded live context")
			if tc.mode == 0 {
				require.True(t, observer.completionCalled, "signed response must reach completion")
				require.True(t, observer.completionDeadline.Equal(observer.prepared.Deadline))
				require.Less(t, time.Since(start), 2*time.Second)
			} else {
				require.False(t, observer.completionCalled, "partial body cannot publish")
				require.GreaterOrEqual(t, time.Since(start), 4*time.Second)
				require.Less(t, time.Since(start), 6*time.Second, "fixed production timeout bounds post-header body reads")
			}
			require.Equal(t, envelope, observer.prepared.Envelope)
			retained, err := custody.openOAuthVersion(observer.prepared.Envelope, scope, 1)
			require.NoError(t, err)
			require.Equal(t, old, retained)
			replayed, err := refreshService.Refresh(ctx, in)
			require.NoError(t, err)
			require.Equal(t, out, replayed)
			require.Equal(t, beforeCalls+1, tokenCalls.Load(), "unknown never re-enters provider")
			require.Zero(t, destinationCalls.Load())
		})
	}
	// Negative control: dropping the production redirect policy really contacts
	// the destination before the eventual fixed-origin check rejects its response.
	mode.Store(3)
	s.client.CheckRedirect = nil
	_, err = s.exchange(context.Background(), refresh, GatewayOAuthIssuer, "reserved-subject")
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	require.Equal(t, int32(1), destinationCalls.Load())
}

type refreshHeaderObserver struct {
	http.RoundTripper
	received *atomic.Bool
}

func (o *refreshHeaderObserver) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := o.RoundTripper.RoundTrip(r)
	if err == nil && r.URL.String() == openai.TokenURL {
		o.received.Store(true)
	}
	return response, err
}

// A context observer holds completion until cancellation; it does not emulate
// SQL publication, version validation or transaction expiry.
type refreshContextObserver struct {
	prepared           GatewayNativeOAuthRefreshPrepared
	completionCalled   bool
	completionDeadline time.Time
	cleanupLive        bool
}

func (o *refreshContextObserver) PrepareGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent) (GatewayNativeOAuthRefreshPrepared, error) {
	return o.prepared, nil
}
func (o *refreshContextObserver) EnterGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) (bool, error) {
	o.prepared.Claimed = false
	o.prepared.Outcome.State = "entered"
	return true, nil
}
func (o *refreshContextObserver) CompleteGatewayNativeOAuthRefresh(ctx context.Context, _ GatewayNativeOAuthRefreshIntent, _ int64, _ string) (GatewayNativeOAuthRefreshOutcome, error) {
	o.completionCalled = true
	o.completionDeadline, _ = ctx.Deadline()
	<-ctx.Done()
	return GatewayNativeOAuthRefreshOutcome{}, ctx.Err()
}
func (o *refreshContextObserver) UnknownGatewayNativeOAuthRefresh(ctx context.Context, _ GatewayNativeOAuthRefreshIntent, _ int64) error {
	_, bounded := ctx.Deadline()
	o.cleanupLive = ctx.Err() == nil && bounded
	if o.prepared.Outcome.State == "entered" {
		o.prepared.Outcome.State = "unknown"
	}
	return nil
}

// This sentinel has no successful behavior and prevents a transport-only test
// from silently acquiring repository authority. SQL is not mocked in this suite.
type httpOnlyRefreshRepository struct{}

func (*httpOnlyRefreshRepository) PrepareGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent) (GatewayNativeOAuthRefreshPrepared, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) EnterGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) (bool, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) CompleteGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64, string) (GatewayNativeOAuthRefreshOutcome, error) {
	panic("SQL scenario must use real PG")
}
func (*httpOnlyRefreshRepository) UnknownGatewayNativeOAuthRefresh(context.Context, GatewayNativeOAuthRefreshIntent, int64) error {
	panic("SQL scenario must use real PG")
}

// This observer checks the enrollment commitment/custody contract only; the
// closest PostgreSQL test remains authoritative for durable replay and fencing.
type refreshEnrollmentCommitmentObserver struct {
	GatewayNativeOAuthRepository
	reservation GatewayNativeOAuthReservation
	outcome     GatewayNativeOAuthOutcome
	stages      int
}

func (o *refreshEnrollmentCommitmentObserver) ReplayGatewayNativeOAuth(_ context.Context, scope GatewayNativeCredentialScope, operation, commitment string) (GatewayNativeOAuthOutcome, bool, error) {
	if o.stages == 0 {
		return GatewayNativeOAuthOutcome{}, false, nil
	}
	if scope != o.reservation.Scope || operation != o.reservation.Operation || commitment != o.reservation.IntentMAC {
		return GatewayNativeOAuthOutcome{}, false, ErrGatewayOAuthConflict
	}
	return o.outcome, true, nil
}

func (o *refreshEnrollmentCommitmentObserver) StageGatewayNativeOAuth(_ context.Context, in GatewayNativeOAuthReservation) (GatewayNativeOAuthOutcome, error) {
	o.stages++
	o.reservation = in
	o.outcome = GatewayNativeOAuthOutcome{Operation: in.Operation, AccountID: 1, Generation: in.Scope.Generation, State: "staged"}
	return o.outcome, nil
}
