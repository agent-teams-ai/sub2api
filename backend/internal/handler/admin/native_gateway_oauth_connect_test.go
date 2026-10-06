package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Sequential controlled HTTP fixture; PG owns concurrent CAS qualification.
type connectHTTPStore struct {
	row           service.GatewayNativeOAuthConnectIntent
	rejectPrepare bool
	lostFinalACK  bool
	losses        int
}

func (r *connectHTTPStore) PrepareConnect(_ context.Context, in service.GatewayNativeOAuthConnectIntent) (service.GatewayNativeOAuthConnectIntent, error) {
	if r.rejectPrepare {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	if r.row.Operation == "" {
		r.row = in
	}
	if !service.SameGatewayNativeOAuthConnectIntent(in, r.row) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayOAuthConflict
	}
	return r.row, nil
}
func (r *connectHTTPStore) ReadConnectIntent(_ context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthConnectIntent, error) {
	if r.row.Scope != s || r.row.Operation != op {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.row, nil
}
func (r *connectHTTPStore) FindConnectState(_ context.Context, hash string) (service.GatewayNativeOAuthConnectIntent, error) {
	if r.row.StateHash != hash {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	return r.row, nil
}
func (r *connectHTTPStore) EnterConnect(_ context.Context, _ service.GatewayNativeOAuthConnectIntent) (bool, error) {
	if r.row.State != "prepared" || !time.Now().Before(r.row.Deadline) {
		return false, nil
	}
	r.row.State = "entered"
	return true, nil
}
func (r *connectHTTPStore) BindConnectEnrollment(_ context.Context, in service.GatewayNativeOAuthConnectIntent, mac string) (service.GatewayNativeOAuthConnectIntent, error) {
	if r.row.RecoveryDenied || r.row.StateHash != in.StateHash || (r.row.EnrollmentMAC != "" && r.row.EnrollmentMAC != mac) {
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayOAuthConflict
	}
	r.row.EnrollmentMAC = mac
	return r.row, nil
}
func (r *connectHTTPStore) FinishConnect(_ context.Context, _ service.GatewayNativeOAuthConnectIntent, state string, out service.GatewayNativeOAuthOutcome) (service.GatewayNativeOAuthConnectIntent, error) {
	if state == "completed" && r.lostFinalACK {
		r.lostFinalACK = false
		r.losses++
		return service.GatewayNativeOAuthConnectIntent{}, service.ErrGatewayNativeIdentity
	}
	if state == "quarantined" {
		state = "unknown"
		r.row.RecoveryDenied = true
	}
	if r.row.State != "completed" {
		r.row.State = state
		r.row.Envelope = ""
		r.row.Outcome = out
	}
	return r.row, nil
}

type connectHTTPEnrollmentStore struct {
	service.GatewayNativeOAuthRepository
	reservation  service.GatewayNativeOAuthReservation
	outcome      service.GatewayNativeOAuthOutcome
	calls        int
	conflicts    int
	lostStageACK bool
}

func (r *connectHTTPEnrollmentStore) ReplayGatewayNativeOAuth(ctx context.Context, scope service.GatewayNativeCredentialScope, op, mac string) (service.GatewayNativeOAuthOutcome, bool, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) {
		return service.GatewayNativeOAuthOutcome{}, false, service.ErrGatewayNativeIdentity
	}
	if r.reservation.Operation == op {
		if r.reservation.Scope != scope || r.reservation.IntentMAC != mac {
			r.conflicts++
			return service.GatewayNativeOAuthOutcome{}, false, service.ErrGatewayOAuthConflict
		}
		return r.outcome, true, nil
	}
	return service.GatewayNativeOAuthOutcome{}, false, nil
}
func (r *connectHTTPEnrollmentStore) StageGatewayNativeOAuth(ctx context.Context, in service.GatewayNativeOAuthReservation) (service.GatewayNativeOAuthOutcome, error) {
	if !in.Identity.Verified() || !service.GatewayNativeOAuthScopeAuthorized(ctx, in.Scope) || !strings.HasPrefix(in.Envelope, "gco1.") {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	r.calls++
	if r.reservation.Operation != "" {
		r.conflicts++
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayOAuthConflict
	}
	r.reservation = in
	r.outcome = service.GatewayNativeOAuthOutcome{Operation: in.Operation, AccountID: 42, Generation: in.Scope.Generation, State: "staged"}
	if r.lostStageACK {
		r.lostStageACK = false
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return r.outcome, nil
}
func (r *connectHTTPEnrollmentStore) ReadGatewayNativeOAuth(ctx context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthOutcome, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s) || r.reservation.Scope != s || r.outcome.Operation != op {
		return service.GatewayNativeOAuthOutcome{}, service.ErrGatewayNativeIdentity
	}
	return r.outcome, nil
}

type connectHTTPFixture struct {
	router         *gin.Engine
	store          *connectHTTPStore
	enrolled       *connectHTTPEnrollmentStore
	connect        *service.GatewayNativeOAuthConnect
	enrollment     *service.GatewayNativeOAuthEnrollment
	tokens         atomic.Int32
	destination    atomic.Int32
	response       string
	redirect       bool
	stallBody      bool
	headersFlushed chan struct{}
	bodyCancelled  chan struct{}
	challenge      string
	scope          service.GatewayNativeCredentialScope
	secrets        []string
	logs           bytes.Buffer
}

func connectHTTPRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}
func newConnectHTTPFixture(t *testing.T) *connectHTTPFixture {
	t.Helper()
	f := &connectHTTPFixture{store: &connectHTTPStore{}, enrolled: &connectHTTPEnrollmentStore{}}
	f.scope = service.GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "logical", Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": service.GatewayOAuthIssuer, "sub": "fixture-principal", "aud": openai.ClientID, "exp": time.Now().Add(time.Hour).Unix()})
	token.Header["kid"] = "fixture"
	id, err := token.SignedString(key)
	require.NoError(t, err)
	access := base64.RawURLEncoding.EncodeToString(connectHTTPRandom(t, 32))
	refresh := base64.RawURLEncoding.EncodeToString(connectHTTPRandom(t, 32))
	f.secrets = []string{access, refresh, id, "fixture-sensitive-metadata"}
	good, err := json.Marshal(map[string]any{"access_token": access, "refresh_token": refresh, "id_token": id, "token_type": "Bearer", "expires_in": 3600, "scope": openai.DefaultScopes, "private": "fixture-sensitive-metadata"})
	require.NoError(t, err)
	f.response = string(good)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.destination.Add(1); w.WriteHeader(200) }))
	t.Cleanup(destination.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "auth.openai.com", r.Host)
		if r.URL.Path == "/.well-known/jwks.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "fixture", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
			return
		}
		f.tokens.Add(1)
		require.Equal(t, "/oauth/token", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-Host", "X-Proxy-URL"} {
			require.Empty(t, r.Header.Get(h))
		}
		require.NoError(t, r.ParseForm())
		require.Len(t, r.PostForm, 5)
		require.Equal(t, openai.ClientID, r.PostForm.Get("client_id"))
		require.Equal(t, service.GatewayOAuthConnectRedirect, r.PostForm.Get("redirect_uri"))
		require.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
		require.True(t, r.PostForm.Get("code") == "fixture-code")
		require.Len(t, r.PostForm.Get("code_verifier"), 128)
		require.True(t, openai.GenerateCodeChallenge(r.PostForm.Get("code_verifier")) == f.challenge)
		if f.redirect {
			http.Redirect(w, r, destination.URL+"/stolen", http.StatusFound)
			return
		}
		if f.stallBody {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			require.True(t, ok)
			flusher.Flush()
			close(f.headersFlushed)
			select {
			case <-r.Context().Done():
				close(f.bodyCancelled)
				return
			case <-time.After(6 * time.Second):
			}
		}
		_, _ = io.WriteString(w, f.response)
	}))
	t.Cleanup(source.Close)
	baseTransport, ok := source.Client().Transport.(*http.Transport)
	require.True(t, ok)
	transport := baseTransport.Clone()
	transport.DisableKeepAlives = true
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "auth.openai.com:443" {
			address = source.Listener.Addr().String()
		} else if address != destination.Listener.Addr().String() {
			return nil, fmt.Errorf("unexpected fixture destination")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	t.Cleanup(transport.CloseIdleConnections)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": connectHTTPRandom(t, 32)})
	require.NoError(t, err)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(service.NewGatewayNativeOAuthVerifier(transport), custody, f.enrolled, connectHTTPRandom(t, 32))
	require.NoError(t, err)
	f.enrollment = enrollment
	f.connect, err = service.NewGatewayNativeOAuthConnect(connectHTTPRandom(t, 32), transport, f.store, enrollment, f.enrolled)
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	f.router = gin.New()
	// Sanitized composition records only fixed route/status after the callback.
	group := f.router.Group("", func(c *gin.Context) {
		c.Next()
		fmt.Fprintf(&f.logs, "%s %d\n", c.Request.RequestURI, c.Writer.Status())
	})
	authorize := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer fixture-owner" {
			c.AbortWithStatus(404)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), "consumer")
		require.NoError(t, err)
		ctx, err = service.WithGatewayNativeOAuthOwner(ctx, "owner")
		require.NoError(t, err)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	require.NoError(t, RegisterGatewayNativeOAuthConnectRoutes(group, f.connect, authorize))
	return f
}
func (f *connectHTTPFixture) request(t *testing.T, path, body string, owner bool) *httptest.ResponseRecorder {
	t.Helper()
	method := http.MethodPost
	if strings.HasPrefix(path, "/auth/") {
		method = http.MethodGet
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if owner {
		r.Header.Set("Authorization", "Bearer fixture-owner")
	}
	r.Header.Set("Cookie", "ingress-cookie")
	r.Header.Set("X-Forwarded-Host", "evil.invalid")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}
func (f *connectHTTPFixture) input() string {
	b, _ := json.Marshal(gatewayConnectInput{Operation: "operation", Owner: f.scope.Owner, Account: f.scope.Account, Generation: f.scope.Generation})
	return string(b)
}
func (f *connectHTTPFixture) begin(t *testing.T) string {
	t.Helper()
	w := f.request(t, "/private/native/v1/oauth/connect", f.input(), true)
	require.Equal(t, 200, w.Code)
	var out service.GatewayNativeOAuthConnectResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	u, err := url.Parse(out.AuthorizeURL)
	require.NoError(t, err)
	require.Equal(t, service.GatewayOAuthConnectRedirect, u.Query().Get("redirect_uri"))
	require.Equal(t, openai.DefaultScopes, u.Query().Get("scope"))
	f.challenge = u.Query().Get("code_challenge")
	return u.Query().Get("state")
}

// Failure: malformed/duplicate callback queries or stock/wrong-owner authority
// could spend another owner's intent or leak the token response into DTO/logs.
func TestGatewayNativeOAuthConnectHTTPGinSignedStageAndContainment(t *testing.T) {
	f := newConnectHTTPFixture(t)
	f.store.lostFinalACK = true
	denied := f.request(t, "/private/native/v1/oauth/connect", f.input(), false)
	require.Equal(t, 404, denied.Code)
	wrong := strings.Replace(f.input(), `"owner"`, `"foreign-owner"`, 1)
	require.Equal(t, 404, f.request(t, "/private/native/v1/oauth/connect", wrong, true).Code)
	require.Empty(t, f.store.row.Operation)
	state := f.begin(t)
	path := "/auth/callback?state=" + state + "&code=fixture-code"
	for _, bad := range []string{path + "&state=" + state, path + "&%63ode=other", path + "&error=raw-upstream-error", strings.Replace(path, state, strings.Repeat("0", 64), 1), path + "&junk=" + strings.Repeat("x", 8193)} {
		w := f.request(t, bad, "", false)
		require.Equal(t, 200, w.Code)
		require.NotContains(t, w.Body.String(), state)
		require.Zero(t, f.tokens.Load())
	}
	wrongBody := f.request(t, path, "secret-body", false)
	require.Equal(t, 200, wrongBody.Code)
	require.Zero(t, f.tokens.Load())
	w := f.request(t, path, "", false)
	require.Equal(t, 200, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, int32(1), f.tokens.Load())
	require.Equal(t, 1, f.enrolled.calls)
	require.Equal(t, 1, f.store.losses)
	require.True(t, f.enrolled.reservation.Scope == f.scope)
	require.True(t, f.enrolled.reservation.Identity.Verified())
	duplicate := f.request(t, strings.Replace(path, "fixture-code", "different-code", 1), "", false)
	require.Equal(t, w.Body.String(), duplicate.Body.String())
	require.Equal(t, int32(1), f.tokens.Load())
	read := f.request(t, "/private/native/v1/oauth/connect/read", f.input(), true)
	require.Equal(t, 200, read.Code)
	require.Contains(t, read.Body.String(), `"outcome":"staged"`)
	require.NotContains(t, read.Body.String(), "account_id")
	require.NotContains(t, read.Body.String(), "authorize_url")
	for _, secret := range append(f.secrets, state, "fixture-code", "different-code", "raw-upstream-error", "secret-body") {
		require.False(t, strings.Contains(w.Body.String()+read.Body.String()+f.logs.String()+f.store.row.Envelope+f.enrolled.reservation.Envelope, secret), "sensitive fixture data escaped custody")
	}
	for _, body := range []string{f.input() + "{}", strings.Replace(f.input(), `"operation":`, `"Operation":`, 1), strings.TrimSuffix(f.input(), "}") + `,"\u006fperation":"other"}`, strings.Repeat("x", 4097), strings.TrimSuffix(f.input(), "}") + `,"deadline":"2099-01-01"}`} {
		require.Equal(t, 404, f.request(t, "/private/native/v1/oauth/connect", body, true).Code)
	}
	require.Equal(t, 404, f.request(t, "/private/native/v1/oauth/connect/read", wrong, true).Code)
	require.Error(t, RegisterGatewayNativeOAuthConnectRoutes(f.router.Group("/wrong-prefix"), f.connect, func(*gin.Context) {}))
}

// Failure: redirects can send the code/verifier elsewhere even if a later URL
// check denies; malformed/oversized/token-mismatched responses must never Stage.
func TestGatewayNativeOAuthConnectHTTPTokenFailureIsSpent(t *testing.T) {
	for _, kind := range []string{"redirect", "body-cap", "missing-refresh", "missing-access", "missing-id", "duplicate", "case-alias", "bad-type", "wrong-scope", "invalid-id", "vendor-error"} {
		t.Run(kind, func(t *testing.T) {
			f := newConnectHTTPFixture(t)
			state := f.begin(t)
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(f.response), &m))
			switch kind {
			case "redirect":
				f.redirect = true
			case "body-cap":
				f.response += strings.Repeat(" ", 65537)
			case "missing-refresh":
				delete(m, "refresh_token")
			case "missing-access":
				delete(m, "access_token")
			case "missing-id":
				delete(m, "id_token")
			case "duplicate":
				f.response = strings.TrimSuffix(f.response, "}") + `,"\u0061ccess_token":"other"}`
			case "case-alias":
				m["ID_TOKEN"] = m["id_token"]
				delete(m, "id_token")
			case "bad-type":
				m["token_type"] = "MAC"
			case "wrong-scope":
				m["scope"] = openai.DefaultScopes + " connectors"
			case "invalid-id":
				m["id_token"] = "unsigned.invalid.token"
			case "vendor-error":
				f.response = `{"error":"fixture-upstream-secret"}`
			}
			if kind != "redirect" && kind != "body-cap" && kind != "duplicate" && kind != "vendor-error" {
				raw, err := json.Marshal(m)
				require.NoError(t, err)
				f.response = string(raw)
			}
			path := "/auth/callback?state=" + state + "&code=fixture-code"
			w := f.request(t, path, "", false)
			require.Equal(t, 200, w.Code)
			require.Equal(t, "unknown", f.store.row.State)
			require.Empty(t, f.store.row.Envelope)
			f.request(t, path, "", false)
			require.Equal(t, int32(1), f.tokens.Load())
			require.Zero(t, f.destination.Load())
			require.Zero(t, f.enrolled.calls)
			require.NotContains(t, w.Body.String()+f.logs.String(), "fixture-upstream-secret")
		})
	}
}

// A is a real signed, verified, sealed F1 Stage under the caller's operation.
// B exchanges a different bundle for that same operation. A's old result must
// never become B's success after either a definite conflict or failed exchange.
func TestGatewayNativeOAuthConnectHTTPPriorStageCannotCompleteNewAttempt(t *testing.T) {
	for _, failedExchange := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-exchange-%t", failedExchange), func(t *testing.T) {
			f := newConnectHTTPFixture(t)
			ctx, err := service.WithGatewayNativeConsumer(context.Background(), f.scope.Consumer)
			require.NoError(t, err)
			ctx, err = service.WithGatewayNativeOAuthOwner(ctx, f.scope.Owner)
			require.NoError(t, err)
			var m map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(f.response), &m))
			var bundle service.GatewayNativeOAuthBundle
			require.NoError(t, json.Unmarshal(m["id_token"], &bundle.IDToken))
			bundle.AccessToken = gatewayConnectStageFixtureOpaque()
			bundle.RefreshToken = gatewayConnectStageFixtureOpaque()
			bundle.SensitiveMetadata = json.RawMessage(`{"private":"controlled-stage-A"}`)
			out, err := f.enrollment.Stage(ctx, f.scope, "operation", bundle)
			require.NoError(t, err)
			require.Equal(t, "staged", out.State)
			original := f.enrolled.reservation
			state := f.begin(t)
			if failedExchange {
				f.response = `{"error":"controlled-exchange-failure"}`
			}
			path := "/auth/callback?state=" + state + "&code=fixture-code"
			require.Equal(t, 200, f.request(t, path, "", false).Code)
			read := f.request(t, "/private/native/v1/oauth/connect/read", f.input(), true)
			require.Contains(t, read.Body.String(), `"state":"unknown"`)
			require.NotContains(t, read.Body.String(), `"outcome":"staged"`)
			require.Equal(t, original, f.enrolled.reservation)
			if !failedExchange {
				require.Equal(t, 1, f.enrolled.conflicts)
			}
			f.request(t, path, "", false)
			require.Equal(t, int32(1), f.tokens.Load())
		})
	}
}

// Immediate headers do not end the exchange budget: a withheld body must be
// cancelled at five seconds, and the spent callback must not exchange again.
func TestGatewayNativeOAuthConnectHTTPFlushedHeadersStalledBodyDeadline(t *testing.T) {
	f := newConnectHTTPFixture(t)
	f.stallBody = true
	f.headersFlushed = make(chan struct{})
	f.bodyCancelled = make(chan struct{})
	state := f.begin(t)
	path := "/auth/callback?state=" + state + "&code=fixture-code"
	started := time.Now()
	require.Equal(t, 200, f.request(t, path, "", false).Code)
	elapsed := time.Since(started)
	select {
	case <-f.headersFlushed:
	default:
		t.Fatal("controlled TLS server did not flush headers")
	}
	require.GreaterOrEqual(t, elapsed, 4500*time.Millisecond)
	require.Less(t, elapsed, 5750*time.Millisecond)
	require.Equal(t, "unknown", f.store.row.State)
	require.Empty(t, f.store.row.Envelope)
	require.Zero(t, f.enrolled.calls)
	select {
	case <-f.bodyCancelled:
	case <-time.After(time.Second):
		t.Fatal("body read did not cancel the controlled server request")
	}
	f.request(t, path, "", false)
	require.Equal(t, int32(1), f.tokens.Load())
}

func TestGatewayNativeOAuthConnectHTTPExactCommitmentLostStageACK(t *testing.T) {
	f := newConnectHTTPFixture(t)
	f.enrolled.lostStageACK = true
	state := f.begin(t)
	path := "/auth/callback?state=" + state + "&code=fixture-code"
	require.Equal(t, 200, f.request(t, path, "", false).Code)
	require.Equal(t, "completed", f.store.row.State)
	require.NotEqual(t, "operation", f.enrolled.reservation.Operation)
	require.Equal(t, f.store.row.EnrollmentOperation, f.enrolled.reservation.Operation)
	require.Equal(t, f.store.row.EnrollmentMAC, f.enrolled.reservation.IntentMAC)
	require.NotEmpty(t, f.store.row.EnrollmentMAC)
	require.Equal(t, f.enrolled.outcome, f.store.row.Outcome)
	read := f.request(t, "/private/native/v1/oauth/connect/read", f.input(), true)
	for _, private := range []string{f.store.row.EnrollmentOperation, f.store.row.EnrollmentMAC} {
		require.NotContains(t, read.Body.String()+f.logs.String(), private)
	}
	f.request(t, path, "", false)
	require.Equal(t, int32(1), f.tokens.Load())
	require.Equal(t, 1, f.enrolled.calls)
}

func gatewayConnectStageFixtureOpaque() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("fixture entropy unavailable")
	}
	return hex.EncodeToString(b)
}
