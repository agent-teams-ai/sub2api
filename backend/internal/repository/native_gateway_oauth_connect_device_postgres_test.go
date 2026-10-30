package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Called after the existing empty-database guard and complete migration suite.
// Real SQL claims, fake HTTP endpoints and the real enrollment/verifier/custody
// boundary expose duplicate provider effects, scope confusion and lost-ACK replay.
func testGatewayNativeDeviceConnectPostgres(t *testing.T, db *sql.DB) {
	repo, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	f1, ok := NewAccountRepository(nil, db, nil).(service.GatewayNativeOAuthRepository)
	require.True(t, ok, "account repository must support native OAuth enrollment")
	verifier, bundleFor := oauthPGFixture(t)
	bundle := bundleFor("device-controlled-principal")
	var starts, polls, exchanges atomic.Int32
	var mode atomic.Int32
	var pollEntered chan struct{}
	var pollRelease chan struct{}
	codeVerifier := strings.Repeat("v", 64)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		require.Equal(t, http.MethodPost, r.Method)
		require.Empty(t, r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("Cookie"))
		switch r.URL.Path {
		case "/api/accounts/deviceauth/usercode":
			starts.Add(1)
			var req map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, map[string]string{"client_id": openai.ClientID}, req)
			if mode.Load() == 1 {
				w.WriteHeader(503)
				return
			}
			expires := 600
			if mode.Load() == 2 {
				expires = 1
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"device_auth_id": "native-only-device-id", "user_code": "ABCD-EFGH", "interval": "1", "expires_in": expires})
		case "/api/accounts/deviceauth/token":
			n := polls.Add(1)
			var req map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			require.Equal(t, map[string]string{"device_auth_id": "native-only-device-id", "user_code": "ABCD-EFGH"}, req)
			if n == 1 {
				close(pollEntered)
				<-pollRelease
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"authorization_code": "native-only-authorized-code", "code_verifier": codeVerifier, "code_challenge": openai.GenerateCodeChallenge(codeVerifier)})
		case "/oauth/token":
			exchanges.Add(1)
			require.NoError(t, r.ParseForm())
			require.Len(t, r.PostForm, 5)
			require.Equal(t, service.GatewayOAuthDeviceRedirect, r.PostForm.Get("redirect_uri"))
			require.Equal(t, "native-only-authorized-code", r.PostForm.Get("code"))
			require.Equal(t, codeVerifier, r.PostForm.Get("code_verifier"))
			scope := openai.DefaultScopes
			if mode.Load() == 3 {
				scope = "openid"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "id_token": bundle.IDToken, "token_type": "Bearer", "expires_in": 3600, "scope": scope})
		default:
			t.Errorf("unexpected provider path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer provider.Close()
	providerTransport, ok := provider.Client().Transport.(*http.Transport)
	require.True(t, ok, "TLS provider fixture must expose its HTTP transport")
	transport := providerTransport.Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, provider.Listener.Addr().String())
	}
	key := []byte(strings.Repeat("k", 32))
	custody, err := service.NewGatewayNativeCredentialCustody("device-fixture", map[string][]byte{"device-fixture": key})
	require.NoError(t, err)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, f1, key)
	require.NoError(t, err)
	connector, err := service.NewGatewayNativeOAuthConnect(key, transport, repo, enrollment, f1)
	require.NoError(t, err)
	owner, scope := oauthPGScope(t, "device-consumer", "device-owner", "device-account")
	operation := "device-operation"
	const concurrent = 4
	var wg sync.WaitGroup
	var handoffs atomic.Int32
	beginStart := make(chan struct{})
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-beginStart
			out, err := connector.BeginConnectMethod(owner, scope, operation, "device_code")
			require.NoError(t, err)
			if out.DeviceAuthorization != nil {
				handoffs.Add(1)
				require.Equal(t, "ABCD-EFGH", out.DeviceAuthorization.UserCode)
				require.Equal(t, "https://auth.openai.com/codex/device", out.DeviceAuthorization.VerificationURL)
				require.Equal(t, 1, out.DeviceAuthorization.IntervalSeconds)
			}
		}()
	}
	close(beginStart)
	wg.Wait()
	require.EqualValues(t, 1, starts.Load())
	require.EqualValues(t, 1, handoffs.Load())
	in, err := repo.ReadConnectIntent(owner, scope, operation)
	require.NoError(t, err)
	require.NotContains(t, in.Envelope, "native-only-device-id")
	require.NotContains(t, in.Envelope, "ABCD-EFGH")
	private, err := json.Marshal(in)
	require.NoError(t, err)
	require.Equal(t, "{}", string(private))
	repeat, err := connector.BeginConnectMethod(owner, scope, operation, "device_code")
	require.NoError(t, err)
	require.Nil(t, repeat.DeviceAuthorization)
	_, err = connector.BeginConnect(owner, scope, operation)
	require.ErrorIs(t, err, service.ErrGatewayOAuthConflict)
	for _, name := range []string{"owner", "account", "generation", "operation"} {
		foreign := scope
		op := operation
		switch name {
		case "owner":
			foreign.Owner = "foreign"
		case "account":
			foreign.Account = "foreign"
		case "generation":
			foreign.Generation = "11111111-1111-4111-8111-111111111111"
		case "operation":
			op = "foreign"
		}
		_, err = connector.PollDeviceConnect(owner, foreign, op)
		require.Error(t, err)
	}
	_, err = connector.PollDeviceConnect(owner, scope, operation)
	require.NoError(t, err)
	require.Zero(t, polls.Load())
	// Read must never poll, even when the scheduled interval is due.
	time.Sleep(time.Until(in.DevicePollAfter) + 20*time.Millisecond)
	_, err = connector.ReadConnect(owner, scope, operation)
	require.NoError(t, err)
	require.Zero(t, polls.Load())
	pollEntered, pollRelease = make(chan struct{}), make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := connector.PollDeviceConnect(owner, scope, operation)
		require.NoError(t, err)
	}()
	<-pollEntered
	for range concurrent {
		_, err = connector.PollDeviceConnect(owner, scope, operation)
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, polls.Load())
	close(pollRelease)
	wg.Wait()
	pending, err := repo.ReadConnectIntent(owner, scope, operation)
	require.NoError(t, err)
	require.Equal(t, "pending", pending.DevicePhase)
	time.Sleep(time.Until(pending.DevicePollAfter) + 20*time.Millisecond)
	pollStart := make(chan struct{})
	for range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-pollStart
			_, err := connector.PollDeviceConnect(owner, scope, operation)
			require.NoError(t, err)
		}()
	}
	close(pollStart)
	wg.Wait()
	require.EqualValues(t, 2, polls.Load())
	require.EqualValues(t, 1, exchanges.Load())
	restarted, err := service.NewGatewayNativeOAuthConnect(key, transport, repo, enrollment, f1)
	require.NoError(t, err)
	out, err := restarted.PollDeviceConnect(owner, scope, operation)
	require.NoError(t, err)
	require.Equal(t, "completed", out.State)
	require.Nil(t, out.DeviceAuthorization)
	done, err := repo.ReadConnectIntent(owner, scope, operation)
	require.NoError(t, err)
	require.Empty(t, done.Envelope)
	stage, err := f1.ReadGatewayNativeOAuth(owner, scope, done.EnrollmentOperation)
	require.NoError(t, err)
	require.Equal(t, done.Outcome, stage)
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	for _, secret := range []string{"native-only-device-id", "ABCD-EFGH", "native-only-authorized-code", codeVerifier, bundle.AccessToken, bundle.RefreshToken, bundle.IDToken} {
		require.NotContains(t, string(raw), secret)
	}
	// Provider uncertainty cannot replay Begin. The exact operation is spent.
	mode.Store(1)
	failedOwner, failedScope := oauthPGScope(t, "device-fail-consumer", "device-fail-owner", "device-fail-account")
	failed, err := restarted.BeginConnectMethod(failedOwner, failedScope, "device-fail", "device_code")
	require.NoError(t, err)
	require.Equal(t, "unknown", failed.State)
	_, err = restarted.BeginConnectMethod(failedOwner, failedScope, "device-fail", "device_code")
	require.NoError(t, err)
	require.EqualValues(t, 2, starts.Load())
	// Expiry clears encrypted device material without polling or exchanging.
	mode.Store(2)
	expiredOwner, expiredScope := oauthPGScope(t, "device-expire-consumer", "device-expire-owner", "device-expire-account")
	expired, err := restarted.BeginConnectMethod(expiredOwner, expiredScope, "device-expire", "device_code")
	require.NoError(t, err)
	require.NotNil(t, expired.DeviceAuthorization)
	time.Sleep(time.Until(expired.DeviceAuthorization.ExpiresAt) + 20*time.Millisecond)
	expired, err = restarted.PollDeviceConnect(expiredOwner, expiredScope, "device-expire")
	require.NoError(t, err)
	require.Equal(t, "expired", expired.State)
	require.EqualValues(t, 2, polls.Load())
	require.EqualValues(t, 1, exchanges.Load())
	// The shared token validator rejects missing OAuth scopes, and the consumed
	// authorization code is never exchanged a second time after restart/readback.
	mode.Store(3)
	badOwner, badScope := oauthPGScope(t, "device-bad-consumer", "device-bad-owner", "device-bad-account")
	_, err = restarted.BeginConnectMethod(badOwner, badScope, "device-bad", "device_code")
	require.NoError(t, err)
	bad, err := repo.ReadConnectIntent(badOwner, badScope, "device-bad")
	require.NoError(t, err)
	time.Sleep(time.Until(bad.DevicePollAfter) + 20*time.Millisecond)
	rejected, err := restarted.PollDeviceConnect(badOwner, badScope, "device-bad")
	require.NoError(t, err)
	require.Equal(t, "unknown", rejected.State)
	_, err = restarted.PollDeviceConnect(badOwner, badScope, "device-bad")
	require.NoError(t, err)
	require.EqualValues(t, 2, exchanges.Load())
	// A restart after either durable begin claim or durable handoff-save ACK loss
	// cannot replay the native HTTP effect or reissue a user capability.
	deviceRepo, ok := repo.(service.GatewayNativeOAuthDeviceRepository)
	require.True(t, ok, "connect repository must support durable device claims")
	for _, loss := range []string{"claim", "save"} {
		mode.Store(0)
		wrapped := &deviceLostACK{GatewayNativeOAuthConnectRepository: repo, device: deviceRepo}
		if loss == "claim" {
			wrapped.loseClaim.Store(true)
		} else {
			wrapped.loseSave.Store(true)
		}
		uncertain, err := service.NewGatewayNativeOAuthConnect(key, transport, wrapped, enrollment, f1)
		require.NoError(t, err)
		lossOwner, lossScope := oauthPGScope(t, "loss-"+loss+"-consumer", "loss-"+loss+"-owner", "loss-"+loss+"-account")
		before := starts.Load()
		_, err = uncertain.BeginConnectMethod(lossOwner, lossScope, "loss-"+loss, "device_code")
		require.Error(t, err)
		retry, err := restarted.BeginConnectMethod(lossOwner, lossScope, "loss-"+loss, "device_code")
		require.NoError(t, err)
		require.Nil(t, retry.DeviceAuthorization)
		expected := before
		if loss == "save" {
			expected++
		}
		require.Equal(t, expected, starts.Load())
	}

	// Losing a committed poll claim never causes a second HTTP request after
	// restart. A stale pending snapshot cannot acquire its successor's revision.
	mode.Store(0)
	pollLossOwner, pollLossScope := oauthPGScope(t, "poll-loss-consumer", "poll-loss-owner", "poll-loss-account")
	_, err = restarted.BeginConnectMethod(pollLossOwner, pollLossScope, "poll-loss", "device_code")
	require.NoError(t, err)
	pollLossIntent, err := repo.ReadConnectIntent(pollLossOwner, pollLossScope, "poll-loss")
	require.NoError(t, err)
	time.Sleep(time.Until(pollLossIntent.DevicePollAfter) + 20*time.Millisecond)
	pollLost := &deviceLostACK{GatewayNativeOAuthConnectRepository: repo, device: deviceRepo}
	pollLost.loseClaim.Store(true)
	uncertainPoll, err := service.NewGatewayNativeOAuthConnect(key, transport, pollLost, enrollment, f1)
	require.NoError(t, err)
	pollsBefore := polls.Load()
	_, err = uncertainPoll.PollDeviceConnect(pollLossOwner, pollLossScope, "poll-loss")
	require.Error(t, err)
	_, err = restarted.PollDeviceConnect(pollLossOwner, pollLossScope, "poll-loss")
	require.NoError(t, err)
	require.Equal(t, pollsBefore, polls.Load())
	staleWon, err := deviceRepo.ClaimConnectDevice(pollLossOwner, pollLossIntent, "polling")
	require.NoError(t, err)
	require.False(t, staleWon)

	// A live grant revoked while polling cannot enter the token exchange, even
	// when the provider has just issued a valid authorization code and verifier.
	revokedOwner, revokedScope := oauthPGScope(t, "revoked-device-consumer", "revoked-device-owner", "revoked-device-account")
	revocable, err := service.NewGatewayNativeOAuthConnect(key, transport, repo, enrollment, f1)
	require.NoError(t, err)
	var entryChecks atomic.Int32
	require.NoError(t, revocable.SetEntryAuthorizer(func(context.Context, service.GatewayNativeCredentialScope, string) error {
		if entryChecks.Add(1) >= 3 {
			return service.ErrGatewayNativeIdentity
		}
		return nil
	}))
	_, err = revocable.BeginConnectMethod(revokedOwner, revokedScope, "revoked-device", "device_code")
	require.NoError(t, err)
	revokedIntent, err := repo.ReadConnectIntent(revokedOwner, revokedScope, "revoked-device")
	require.NoError(t, err)
	time.Sleep(time.Until(revokedIntent.DevicePollAfter) + 20*time.Millisecond)
	exchangesBefore := exchanges.Load()
	revoked, err := revocable.PollDeviceConnect(revokedOwner, revokedScope, "revoked-device")
	require.NoError(t, err)
	require.Equal(t, "unknown", revoked.State)
	require.Equal(t, exchangesBefore, exchanges.Load())

	// Reconnect is a new generation of the same existing logical/principal claim,
	// using the same device lifecycle and custody enrollment rather than a new stack.
	mode.Store(0)
	nextScope := scope
	nextScope.Generation = uuid.NewString()
	_, err = restarted.BeginConnectMethod(owner, nextScope, "device-reconnect", "device_code")
	require.NoError(t, err)
	reconnectIntent, err := repo.ReadConnectIntent(owner, nextScope, "device-reconnect")
	require.NoError(t, err)
	time.Sleep(time.Until(reconnectIntent.DevicePollAfter) + 20*time.Millisecond)
	reconnected, err := restarted.PollDeviceConnect(owner, nextScope, "device-reconnect")
	require.NoError(t, err)
	require.Equal(t, "completed", reconnected.State)
	reconnectDone, err := repo.ReadConnectIntent(owner, nextScope, "device-reconnect")
	require.NoError(t, err)
	require.NotEqual(t, done.Outcome.AccountID, reconnectDone.Outcome.AccountID)
	var claims int
	require.NoError(t, db.QueryRowContext(owner, `SELECT count(*) FROM gateway_oauth_principal_claims WHERE consumer=$1`, scope.Consumer).Scan(&claims))
	require.Equal(t, 1, claims)

}

// Deliberately lose committed claim or save ACKs; the service must observe the
// persisted phase on retry, without recreating a device code or polling again.
type deviceLostACK struct {
	service.GatewayNativeOAuthConnectRepository
	device    service.GatewayNativeOAuthDeviceRepository
	loseClaim atomic.Bool
	loseSave  atomic.Bool
}

func (r *deviceLostACK) ClaimConnectDevice(ctx context.Context, in service.GatewayNativeOAuthConnectIntent, phase string) (bool, error) {
	won, err := r.device.ClaimConnectDevice(ctx, in, phase)
	if err == nil && won && r.loseClaim.CompareAndSwap(true, false) {
		return false, service.ErrGatewayNativeIdentity
	}
	return won, err
}
func (r *deviceLostACK) SaveConnectDevice(ctx context.Context, in service.GatewayNativeOAuthConnectIntent, envelope string, after time.Time) (bool, error) {
	won, err := r.device.SaveConnectDevice(ctx, in, envelope, after)
	if err == nil && won && r.loseSave.CompareAndSwap(true, false) {
		return false, service.ErrGatewayNativeIdentity
	}
	return won, err
}
