package repository

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const claudeStreamingRequest = `{"model":"claude-sonnet-4-6","input":"controlled SQL lifetime fixture","store":false,"stream":true,"service_tier":"default","max_output_tokens":100}`
const claudeStreamingNativeRequest = `{"model":"claude-sonnet-4-6","max_tokens":100,"stream":true,"system":[{"type":"text","text":"Native fixture priority","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"Native fixture"},{"role":"assistant","content":[{"type":"thinking","thinking":"Prior thought","signature":"opaque-fixture-history-signature"},{"type":"tool_use","id":"prior_tool","name":"read_fixture","input":{"path":"native"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"prior_tool","content":"Native result"}]}],"tools":[{"name":"read_fixture","input_schema":{"type":"object","properties":{"path":{"type":"string"}}}}],"thinking":{"type":"adaptive"}}`
const claudeStreamingStart = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_sql_lifetime\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n"
const claudeStreamingEnd = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"controlled answer\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

type claudeStreamingAccount struct {
	scope        service.GatewayNativeCredentialScope
	owner        context.Context
	operation    string
	route        service.GatewayNativeRoute
	principal    string
	organization string
	finish       chan struct{}
	closed       chan struct{}
	native       bool
}

// Only the scheduling point is controlled. Both sides of the interleaving use
// the actual repository, driver, row locks, revision CAS and migrated tables.
type claudeStreamingCaptureGate struct {
	service.GatewayNativeClaudeRepository
	account string
	arrived chan service.GatewayNativeOAuthPhysical
	resume  chan struct{}
	stored  chan error
	once    sync.Once
}

func (r *claudeStreamingCaptureGate) StoreGatewayClaudeLimits(ctx context.Context, p service.GatewayNativeOAuthPhysical, raw service.GatewayClaudeRawLimits, observed time.Time) error {
	gated := false
	if p.Scope.Account == r.account {
		r.once.Do(func() { gated = true })
	}
	if gated {
		r.arrived <- p
		select {
		case <-r.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	err := r.GatewayNativeClaudeRepository.StoreGatewayClaudeLimits(ctx, p, raw, observed)
	if gated {
		r.stored <- err
	}
	return err
}

type claudeStreamingHTTP struct {
	service.HTTPUpstream
	client *http.Client
	calls  atomic.Int32
	closed atomic.Int32
}

func (u *claudeStreamingHTTP) Do(r *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.calls.Add(1)
	response, err := u.client.Do(r)
	if response != nil && response.Body != nil {
		response.Body = &claudeStreamingBody{ReadCloser: response.Body, closed: &u.closed}
	}
	return response, err
}

type claudeStreamingBody struct {
	io.ReadCloser
	closed *atomic.Int32
}

func (b *claudeStreamingBody) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

type claudeStreamingResult struct {
	index      int
	entered    bool
	completed  bool
	usage      service.GatewayNativeUsage
	lifetime   service.GatewayNativeLifetimeSnapshot
	err        error
	nativeWire bool
}

// Five real, distinct Claude streams share the same four-connection SQL pool.
// Header publication, refresh and erasure must progress before any stream ends.
// A SQL transaction held for the SSE lifetime prevents the fifth HTTP entry.
func TestGatewayNativeClaudePostgresStreamsReleaseSQLAtHeaders(t *testing.T) {
	dsn := os.Getenv("GATEWAY_NATIVE_CLAUDE_STREAM_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_NOT_RUN: disposable Claude streaming PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	require.Equal(t, "127.0.0.1", u.Hostname())
	require.True(t, strings.HasPrefix(u.Path, "/gateway_claude_stream_test_"))
	require.Contains(t, []string{"", "sslmode=disable"}, u.RawQuery)
	require.Empty(t, u.Fragment)
	if u.User != nil {
		_, password := u.User.Password()
		require.False(t, password)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := openOAuthDispatchFixtureDB(dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(4)
	require.NoError(t, requireOAuthDispatchEmptyObjects(ctx, db))
	require.NoError(t, ApplyMigrations(ctx, db))
	rows, err := NewGatewayNativeClaudeRepository(db)
	require.NoError(t, err)

	consumer, owner := uuid.NewString(), uuid.NewString()
	ownerCtx, err := service.WithGatewayNativeConsumer(ctx, consumer)
	require.NoError(t, err)
	ownerCtx, err = service.WithGatewayNativeOAuthOwner(ownerCtx, owner)
	require.NoError(t, err)
	accounts := make([]claudeStreamingAccount, 5)
	byToken := make(map[string]int)
	for i := range accounts {
		accounts[i] = claudeStreamingAccount{scope: service.GatewayNativeCredentialScope{Consumer: consumer, Owner: owner, Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}, owner: ownerCtx, operation: uuid.NewString(), principal: uuid.NewString(), organization: uuid.NewString(), finish: make(chan struct{}), closed: make(chan struct{}), native: i < 2}
		byToken["fixture-access-"+accounts[i].scope.Account] = i
	}
	arrived := make(chan int, len(accounts))
	shutdown := make(chan struct{})
	var exchanges atomic.Int32
	var invalidWire atomic.Int32
	nativeEnd := claudeStreamingNativeEnd()
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "platform.claude.com" && r.URL.Path == "/v1/oauth/token" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			logical := body["code"]
			if body["grant_type"] == "refresh_token" {
				logical = strings.TrimPrefix(body["refresh_token"], "fixture-refresh-")
			}
			for i := range accounts {
				if logical == accounts[i].scope.Account {
					exchanges.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access-" + logical, "refresh_token": "fixture-refresh-" + logical, "token_type": "Bearer", "expires_in": 60, "scope": "user:inference", "account": map[string]string{"uuid": accounts[i].principal}, "organization": map[string]string{"uuid": accounts[i].organization}})
					return
				}
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		index, valid := byToken[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !valid || r.Host != "api.anthropic.com" || r.URL.Path != "/v1/messages" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		_ = r.Body.Close()
		if err != nil || accounts[index].native && !bytes.Equal(raw, []byte(claudeStreamingNativeRequest)) {
			invalidWire.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer close(accounts[index].closed)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Utilization", "0.25")
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", "1792700000")
		_, _ = io.WriteString(w, claudeStreamingStart)
		w.(http.Flusher).Flush()
		arrived <- index
		select {
		case <-r.Context().Done():
		case <-shutdown:
		case <-accounts[index].finish:
			if accounts[index].native {
				_, _ = io.WriteString(w, nativeEnd)
			} else {
				_, _ = io.WriteString(w, claudeStreamingEnd)
			}
		}
	}))
	defer provider.Close()
	defer close(shutdown)
	transport := provider.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
		if address != "platform.claude.com:443" && address != "api.anthropic.com:443" {
			return nil, service.ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(c, network, provider.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	gate := &claudeStreamingCaptureGate{GatewayNativeClaudeRepository: rows, account: accounts[0].scope.Account, arrived: make(chan service.GatewayNativeOAuthPhysical, 1), resume: make(chan struct{}), stored: make(chan error, 1)}
	var resumeOnce sync.Once
	resumeCapture := func() { resumeOnce.Do(func() { close(gate.resume) }) }
	defer resumeCapture()
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("stream-fixture", map[string][]byte{"stream-fixture": key})
	require.NoError(t, err)
	dispatch, err := service.NewGatewayNativeClaudeOAuth(gate, custody, transport)
	require.NoError(t, err)
	allow := func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }
	require.NoError(t, dispatch.SetEntryAuthorizers(allow, allow))
	for i := range accounts {
		a := &accounts[i]
		started, e := dispatch.BeginConnectMethod(a.owner, a.scope, a.operation, "browser")
		require.NoError(t, e)
		parsed, e := url.Parse(started.AuthorizeURL)
		require.NoError(t, e)
		_, e = dispatch.CompleteOwnerCallback(a.owner, a.scope, a.operation, parsed.Query().Get("state"), a.scope.Account)
		require.NoError(t, e)
		descriptor, e := dispatch.Descriptor(a.owner, a.scope, a.operation)
		require.NoError(t, e)
		require.NotNil(t, descriptor.Native)
		a.route = *descriptor.Native
	}
	physicalHTTP := &claudeStreamingHTTP{client: &http.Client{Transport: transport}}
	upstream, err := service.NewGatewayNativeLifetimeUpstream(physicalHTTP)
	require.NoError(t, err)
	gateway := service.NewOpenAIGatewayService(NewAccountRepository(nil, db, nil), nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	results := make(chan claudeStreamingResult, len(accounts))
	cancels := make([]context.CancelFunc, len(accounts))
	// These run before provider.Close even on an assertion failure, so a red
	// regression never leaves fixture handlers or physical streams waiting.
	defer func() {
		for _, stop := range cancels {
			if stop != nil {
				stop()
			}
		}
	}()
	for i := range accounts {
		requestCtx, stop := context.WithTimeout(accounts[i].owner, 30*time.Second)
		cancels[i] = stop
		go func(index int, requestCtx context.Context, stop context.CancelFunc) {
			result := claudeStreamingResult{index: index}
			body := []byte(claudeStreamingRequest)
			if accounts[index].native {
				body = []byte(claudeStreamingNativeRequest)
				requestCtx = service.WithGatewayNativeClaudeMessages(requestCtx)
			}
			life, e := service.NewGatewayNativeLifetime(requestCtx, stop, func() {}, 16384)
			if e == nil {
				life.BindAccount(consumer, accounts[index].scope.Account, accounts[index].scope.Generation)
				if !life.Admit(time.Now().Add(30 * time.Second)) {
					e = service.ErrGatewayNativeIdentity
				}
			}
			if e == nil {
				requestCtx = service.WithGatewayNativeLifetime(requestCtx, life)
				requestCtx, e = dispatch.BindApproved(requestCtx, accounts[index].route, accounts[index].scope.Account, 1, 8192, 100)
			}
			if e == nil {
				requestCtx = service.WithGatewayNativeUsageObserver(requestCtx, func(u service.GatewayNativeUsage) { result.usage = u })
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
				_, result.entered, e = gateway.ForwardGatewayRoute(requestCtx, c, accounts[index].route, body)
				if accounts[index].native {
					result.completed = strings.Contains(recorder.Body.String(), "event: message_stop")
					result.nativeWire = bytes.Equal(recorder.Body.Bytes(), []byte(claudeStreamingStart+nativeEnd))
				} else {
					result.completed = strings.Contains(recorder.Body.String(), "event: response.completed")
				}
			}
			result.err = e
			if life != nil {
				result.lifetime = life.Snapshot()
			}
			results <- result
		}(i, requestCtx, stop)
	}
	seen := make(map[int]bool)
	arrivalDeadline := time.NewTimer(3 * time.Second)
	defer arrivalDeadline.Stop()
	for len(seen) < len(accounts) {
		select {
		case index := <-arrived:
			require.False(t, seen[index], "a physical request must never replay")
			seen[index] = true
		case <-arrivalDeadline.C:
			t.Fatalf("only %d of 5 distinct streams reached provider headers with SQL maxOpen=4 (inUse=%d)", len(seen), db.Stats().InUse)
		}
	}
	require.EqualValues(t, 5, physicalHTTP.calls.Load())
	require.Equal(t, 4, db.Stats().MaxOpenConnections)
	require.LessOrEqual(t, db.Stats().OpenConnections, 4)
	select {
	case captured := <-gate.arrived:
		require.EqualValues(t, 1, captured.CredentialRevision)
	case <-time.After(time.Second):
		t.Fatal("header capture did not reach the post-lock publication boundary")
	}
	controlCtx, controlCancel := context.WithTimeout(ownerCtx, 3*time.Second)
	defer controlCancel()
	var control int
	require.NoError(t, db.QueryRowContext(controlCtx, "SELECT 1").Scan(&control), "control SQL must progress while all streams remain open")
	var snapshot service.GatewayAccountLimitsStored
	require.Eventually(t, func() bool {
		snapshot, err = rows.ReadGatewayClaudeLimits(controlCtx, accounts[2].scope, accounts[2].route)
		return err == nil && snapshot.Claude != nil
	}, time.Second, time.Millisecond, "response-header limits must be visible before SSE completion")
	require.EqualValues(t, 1, snapshot.Revision)
	require.Eventually(t, func() bool { return db.Stats().InUse == 0 }, time.Second, time.Millisecond, "SSE bodies must retain no SQL connections")
	select {
	case <-results:
		t.Fatal("a stream finished before the controlled terminal event or cancellation")
	default:
	}
	// A refresh wins the deliberately delayed publication race. The real writer
	// must reject revision 1 after revision 2 commits, without reviving old data.
	refreshRef := uuid.NewString()
	refreshed, err := dispatch.Refresh(controlCtx, accounts[0].scope, accounts[0].operation, refreshRef)
	require.NoError(t, err)
	require.Equal(t, "completed", refreshed.State)
	require.EqualValues(t, 2, refreshed.Version)
	resumeCapture()
	select {
	case e := <-gate.stored:
		require.ErrorIs(t, e, service.ErrGatewayNativeIdentity)
	case <-time.After(time.Second):
		t.Fatal("stale header publication did not finish")
	}
	refreshedAgain, err := dispatch.Refresh(controlCtx, accounts[0].scope, accounts[0].operation, refreshRef)
	require.NoError(t, err)
	require.Equal(t, refreshed, refreshedAgain)
	require.EqualValues(t, 6, exchanges.Load(), "completed refresh replay must not exchange again")
	current, err := dispatch.Enter(controlCtx, accounts[0].scope, accounts[0].operation, accounts[0].route)
	require.NoError(t, err)
	require.EqualValues(t, 2, current.Physical.CredentialRevision)
	current.Release()
	snapshot, err = rows.ReadGatewayClaudeLimits(controlCtx, accounts[0].scope, accounts[0].route)
	require.NoError(t, err)
	require.Nil(t, snapshot.Claude, "stale capture must not publish after refresh")

	cleanup := service.GatewayNativeOAuthCleanupRequest{Scope: accounts[1].scope, Operation: accounts[1].operation, Action: "erase", CleanupRef: uuid.NewString(), CleanupToken: uuid.NewString()}
	grant := func(context.Context, service.GatewayNativeOAuthCleanupRequest) (service.GatewayNativeOAuthCleanupAuthority, error) {
		return service.GatewayNativeOAuthCleanupAuthority{Owner: owner, LeaseExpiresAt: time.Now().Add(time.Second), Native: &accounts[1].route}, nil
	}
	erased, err := dispatch.Cleanup(controlCtx, cleanup, grant)
	require.NoError(t, err)
	require.True(t, erased.CredentialsErased)
	_, err = dispatch.Enter(controlCtx, accounts[1].scope, accounts[1].operation, accounts[1].route)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	_, err = dispatch.BindApproved(controlCtx, accounts[1].route, accounts[1].scope.Account, 1, 8192, 100)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	cancels[1]()
	for i := range accounts {
		if i != 1 {
			close(accounts[i].finish)
		}
	}
	for range accounts {
		select {
		case result := <-results:
			require.True(t, result.entered)
			require.True(t, result.usage.Finalized)
			require.True(t, result.lifetime.ContextDone)
			require.True(t, result.lifetime.ForwardingReturned)
			require.True(t, result.lifetime.BodyKnown)
			require.True(t, result.lifetime.BodyClosed)
			if result.index == 1 {
				require.ErrorIs(t, result.err, service.ErrGatewayNativeEffectUnknown)
				require.False(t, result.completed)
				require.Equal(t, "unknown", result.usage.State)
			} else {
				require.NoError(t, result.err)
				require.True(t, result.completed)
				require.Equal(t, "complete", result.usage.State)
				require.True(t, result.lifetime.Completed)
				if accounts[result.index].native {
					require.True(t, result.nativeWire, "real HTTP native thinking signatures, tool deltas and text must preserve exact frames")
					require.EqualValues(t, 7, *result.usage.InputTokens)
					require.EqualValues(t, 3, *result.usage.OutputTokens)
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatal("physical stream failed to close after completion or cancellation")
		}
	}
	for i := range accounts {
		select {
		case <-accounts[i].closed:
		case <-time.After(time.Second):
			t.Fatal("provider handler remained open after physical closure")
		}
	}
	require.EqualValues(t, 5, physicalHTTP.calls.Load())
	require.Zero(t, invalidWire.Load(), "native request bytes must reach real HTTP unchanged")
	require.EqualValues(t, 5, physicalHTTP.closed.Load(), "each physical body must close exactly once")
	require.Zero(t, db.Stats().InUse)
}

func claudeStreamingNativeEnd() string {
	thinking := "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Native fixture thought\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"opaque-native-output-signature\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
	tool := "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"native_tool\",\"name\":\"read_fixture\",\"input\":{}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\"native\\\"}\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":2}\n\n"
	tail := strings.ReplaceAll(claudeStreamingEnd, `"index":0`, `"index":1`)
	tail = strings.Replace(tail, "event: message_delta", tool+"event: message_delta", 1)
	tail = strings.Replace(tail, `"stop_reason":"end_turn"`, `"stop_reason":"tool_use"`, 1)
	return thinking + tail
}
