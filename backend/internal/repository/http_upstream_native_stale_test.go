//go:build unit

package repository

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type nativeStaleRequestObserver struct {
	service.HTTPUpstream
	requests             atomic.Int32
	bodyReplayPossible   atomic.Bool
	idempotencyForwarded atomic.Bool
}

func (o *nativeStaleRequestObserver) Do(request *http.Request, proxy string, account int64, concurrency int) (*http.Response, error) {
	o.requests.Add(1)
	if request.GetBody != nil {
		o.bodyReplayPossible.Store(true)
	}
	if request.Header.Get("Idempotency-Key") != "" || request.Header.Get("X-Idempotency-Key") != "" {
		o.idempotencyForwarded.Store(true)
	}
	return o.HTTPUpstream.Do(request, proxy, account, concurrency)
}

// Deterministically close the selected idle H1 socket after GotConn selects it
// and before the second POST is written. This proves a mechanism, not the cause
// of any historical load failure: native Entered can coexist with zero provider
// entries for that attempt, and the original POST must never be replayed.
func TestGatewayNativeStaleHTTP1ConnectionRetainsEnteredUnknownWithoutReplay(t *testing.T) {
	var entries atomic.Int32
	idle := make(chan net.Conn, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, 1, r.ProtoMajor)
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		entries.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateIdle {
			select {
			case idle <- conn:
			default:
			}
		}
	}
	server.StartTLS()
	defer server.Close()

	// Preserve the production pool builder and finite per-host bound. Only the
	// disposable TLS root is supplied by this fixture; H2 is explicitly off.
	cfg := &config.Config{Gateway: config.GatewayConfig{MaxConnsPerHost: 1}}
	upstream := NewHTTPUpstream(cfg).(*httpUpstreamService)
	defer func() {
		for _, entry := range upstream.clients {
			entry.client.CloseIdleConnections()
		}
	}()
	entry, err := upstream.getClientEntryWithHeaderLimit("", 71, 0, service.HTTPUpstreamProfileOpenAI, false, true, 16<<10)
	require.NoError(t, err)
	transport, ok := entry.client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, 1, transport.MaxConnsPerHost, "production per-host bound remains in force")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}

	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.Repeat("K", 32))})
	require.NoError(t, err)
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: service.GatewayCredentialPurpose}
	envelope, err := custody.Seal(scope, "synthetic-provider-key")
	require.NoError(t, err)
	row := &service.Account{ID: 71, CreatedAt: time.Now().UTC(), Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive,
		Credentials: map[string]any{"api_key": envelope, "base_url": server.URL},
		Extra: map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: service.GatewayMiMoResponsesProfile,
			service.GatewayModelExtraKey: "fixture-model", service.GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses",
			"openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	descriptor, err := service.GatewayNativeDescriptor(row)
	require.NoError(t, err)
	observed := &nativeStaleRequestObserver{HTTPUpstream: upstream}
	wrapped, err := service.NewGatewayNativeLifetimeUpstream(observed)
	require.NoError(t, err)
	gateway := service.NewOpenAIGatewayService(&nativeHeaderFixtureRepo{row: row}, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, wrapped, nil, nil, nil, nil, nil, nil, nil, nil)
	forward := func(trace *httptrace.ClientTrace) (*httptest.ResponseRecorder, bool, error, service.GatewayNativeLifetimeSnapshot) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		life, err := service.NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
		require.NoError(t, err)
		life.BindAccount(scope.Consumer, scope.Account, scope.Generation)
		require.True(t, life.Admit(time.Now().Add(5*time.Second)))
		if trace != nil {
			ctx = httptrace.WithClientTrace(ctx, trace)
		}
		ctx = service.WithGatewayNativeLifetime(ctx, life)
		ctx, err = service.WithGatewayNativeConsumer(ctx, scope.Consumer)
		require.NoError(t, err)
		ctx = service.WithGatewayNativeCustody(ctx, custody)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", nil)
		c.Request.Header.Set("Idempotency-Key", "synthetic-caller-key")
		c.Request.Header.Set("X-Idempotency-Key", "synthetic-caller-key")
		_, entered, err := gateway.ForwardGatewayRoute(ctx, c, descriptor, []byte(`{"model":"fixture-model","input":"synthetic","store":false,"stream":true,"service_tier":"default"}`))
		return recorder, entered, err, life.Snapshot()
	}
	_, entered, err, complete := forward(nil)
	require.NoError(t, err)
	require.True(t, entered)
	require.True(t, complete.Completed)
	require.EqualValues(t, 1, entries.Load())
	var previous net.Conn
	select {
	case previous = <-idle:
	case <-time.After(time.Second):
		t.Fatal("first provider connection did not become idle")
	}
	var gotConnections atomic.Int32
	var reused atomic.Bool
	closed := make(chan error, 1)
	recorder, entered, err, failed := forward(&httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		gotConnections.Add(1)
		if info.Reused {
			reused.Store(true)
			closed <- previous.Close()
		}
	}})
	require.True(t, reused.Load(), "fixture must select the actual warmed H1 connection")
	select {
	case closeErr := <-closed:
		require.NoError(t, closeErr)
	case <-time.After(time.Second):
		t.Fatal("fixture did not close the selected idle connection")
	}
	require.ErrorIs(t, err, service.ErrGatewayNativeEffectUnknown)
	require.True(t, entered)
	require.True(t, failed.Entered)
	require.True(t, failed.ContextDone)
	require.True(t, failed.ForwardingReturned)
	require.True(t, failed.BodyKnown)
	require.True(t, failed.BodyClosed)
	require.False(t, failed.CloseFailed)
	require.False(t, failed.Completed)
	require.Empty(t, recorder.Body.String())
	require.EqualValues(t, 1, entries.Load(), "second attempt never reached the provider handler")
	require.EqualValues(t, 1, gotConnections.Load(), "a spent native POST must not obtain a retry connection")
	require.EqualValues(t, 2, observed.requests.Load(), "one production upstream invocation per original request")
	require.False(t, observed.bodyReplayPossible.Load(), "the native boundary must remove GetBody before RoundTrip")
	require.False(t, observed.idempotencyForwarded.Load(), "caller retry hints must not make the native POST replayable")
}
