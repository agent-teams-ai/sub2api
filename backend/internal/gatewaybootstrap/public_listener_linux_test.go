//go:build linux

package gatewaybootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Exercise the production bounded listener and PublicHandler together over TCP.
// Metadata-authorized body reads hold admission without claim/provider entry.
func TestPublicListenerSaturatedRequestsReturnSafeAdmissionRefusal(t *testing.T) {
	const active, burst = 16, 32
	c := fixtureConfig()
	custody, err := c.validate()
	require.NoError(t, err)
	var metadata atomic.Int32
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/private/native/v1/execution-authority", r.URL.Path)
		metadata.Add(1)
		var input struct {
			RequestRef string `json:"requestRef"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		p := c.Profile.qualified()
		admission := gatewaytransport.Admission{ExecutionRef: "11111111-1111-4111-8111-111111111111", IssuerEpoch: "22222222-2222-4222-8222-222222222222", InvocationRef: "fixture-invocation", AttemptRef: "fixture-attempt", AccountRef: "33333333-3333-4333-8333-333333333333", AuthorizationEpoch: 1, SubjectRef: "fixture-subject", PolicyRevision: 1, BindingRevision: 1, ProfileID: p.Profile, Limits: gatewaytransport.Limits{Requests: 2, Concurrency: 1, RequestBytes: p.RequestBytes, OutputBytes: p.OutputBytes, Tokens: p.Tokens}, ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"consumerId": "fixture-consumer", "requestRef": input.RequestRef, "worker": "44444444-4444-4444-8444-444444444444", "admission": admission, "descriptor": service.GatewayNativeRoute{AccountID: 7, Generation: "55555555-5555-4555-8555-555555555555", CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Profile: p.Profile, BaseURL: p.BaseURL, Model: p.Model}})
	}))
	defer authority.Close()
	db, err := sql.Open("postgres", c.PostgresDSN)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	repo := repository.NewAccountRepository(client, db, nil)
	svcCfg := privateGatewayServiceConfig()
	upstream, err := service.NewGatewayNativeLifetimeUpstream(repository.NewHTTPUpstream(svcCfg))
	require.NoError(t, err)
	gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, svcCfg, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	auth := authorize(c.Peers)
	transport, err := gatewaytransport.New(context.Background(), gatewaytransport.Config{Gateway: gateway, Custody: custody, Authorize: auth, Enrollment: gatewaytransport.Enrollment{OriginRef: "fixture-origin", EngineIncarnation: "66666666-6666-4666-8666-666666666666", QualificationRef: c.Profile.QualificationRef}, VerifyEnrollment: func(context.Context, gatewaytransport.Enrollment) error { return nil }, Profile: c.Profile.qualified(), CallbackOrigin: authority.URL, CallbackCredential: c.Authority.Credential, VerifyDispatch: func(context.Context, string, gatewaytransport.Proof, time.Time) error { return ErrDenied }, AuthorizeCleanup: func(context.Context, string, gatewaytransport.Proof, gatewaytransport.CleanupLease) error {
		return ErrDenied
	}, AcknowledgeClosure: func(context.Context, string, gatewaytransport.Proof, gatewaytransport.CleanupLease, gatewaytransport.Receipt) error {
		return ErrDenied
	}, MaxEntries: active, CallbackTimeout: time.Second, IOTimeout: 10 * time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 8192, CallbackBytes: 65536})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	slots := make(chan struct{}, publicSocketBudget(active))
	server := newPublicHTTPServer(context.Background(), transport.PublicHandler(active))
	served := make(chan error, 1)
	go func() { served <- server.Serve(&boundedListener{Listener: listener, slots: slots}) }()
	defer func() {
		_ = server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = transport.Stop(ctx)
	}()
	var sockets []net.Conn
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	for i := 0; i < active; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		require.NoError(t, err)
		sockets = append(sockets, conn)
		// Partial headers own a socket without reaching public admission.
		_, err = io.WriteString(conn, "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\n")
		require.NoError(t, err)
	}
	for i := 0; i < active; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		require.NoError(t, err)
		sockets = append(sockets, conn)
		_, err = fmt.Fprintf(conn, "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-public-capability\r\nContent-Type: application/json\r\nX-Gateway-Request-Id: held-%d\r\nContent-Length: 100\r\n\r\n", i)
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return metadata.Load() == active }, 2*time.Second, time.Millisecond)
	require.Equal(t, 2*active, len(slots), "held requests and incomplete headers own separate sockets")
	httpTransport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: burst}
	defer httpTransport.CloseIdleConnections()
	httpClient := &http.Client{Transport: httpTransport, Timeout: 2 * time.Second}
	results := make(chan error, burst)
	for i := 0; i < burst; i++ {
		go func(index int) {
			ref := fmt.Sprintf("overflow-%d", index)
			req, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/v1/responses", strings.NewReader("{}"))
			if err != nil {
				results <- err
				return
			}
			req.Header.Set("Authorization", "Bearer synthetic-public-capability")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Gateway-Request-Id", ref)
			response, err := httpClient.Do(req)
			if err != nil {
				results <- err
				return
			}
			defer response.Body.Close()
			var body struct{ Code, Effect, RequestRef string }
			if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
				results <- err
				return
			}
			if response.StatusCode != 503 || body.Code != "admission_limited" || body.Effect != "not_dispatched" || body.RequestRef != ref {
				results <- fmt.Errorf("overflow lacked exact positive admission refusal")
				return
			}
			results <- nil
		}(i)
	}
	for i := 0; i < burst; i++ {
		require.NoError(t, <-results)
	}
	require.Equal(t, int32(active), metadata.Load(), "overflow never reaches metadata, claim, or provider work")
	adminRepo, ok := repo.(service.AdminAccountRepository)
	require.True(t, ok)
	adminSvc := service.NewAdminService(nil, nil, nil, adminRepo, nil, nil, nil, nil, nil, nil, nil, nil, nil, client, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	private := httptest.NewServer(privateHandler(c.Profile, adminSvc, gateway, custody, transport, auth))
	defer private.Close()
	request, err := http.NewRequest(http.MethodGet, private.URL+"/private/native/v1/runtime", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+c.Peers[0].Credential)
	response, err := httpClient.Do(request)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode, "public occupancy cannot starve private runtime control")
	require.NoError(t, server.Close())
	select {
	case err = <-served:
		require.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(time.Second):
		t.Fatal("public shutdown exceeded its bound")
	}
	require.Eventually(t, func() bool { return len(slots) == 0 }, time.Second, time.Millisecond, "shutdown releases incomplete and held socket ownership")
}
