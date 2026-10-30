//go:build linux && integration

package gatewaybootstrap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// A regression in the real private mount, OAuth purpose authority, retained AEAD
// proof or Gateway suspend/resume fences fails this cross-language test. Both
// databases are new disposable fixtures; no provider inference is performed.
func TestNativeGatewayJoinedLifecyclePostgres(t *testing.T) {
	dsn, runner := os.Getenv("GATEWAY_NATIVE_JOINED_PG_DSN"), os.Getenv("GATEWAY_NATIVE_JOINED_RUNNER")
	if dsn == "" || runner == "" {
		t.Skip("NOT_RUN: explicit disposable joined fixture not configured")
	}
	require.Equal(t, "disposable_pg17_10", os.Getenv("AG_NATIVE_RETAINED_JOINED_ALLOW"))
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	require.Equal(t, "127.0.0.1", u.Hostname())
	require.Equal(t, "fixture_owner", u.User.Username())
	_, password := u.User.Password()
	require.False(t, password)
	require.True(t, strings.HasPrefix(u.Path, "/native_custody_api_"))
	require.Contains(t, []string{"", "sslmode=disable"}, u.RawQuery)
	require.Empty(t, u.Fragment)
	require.True(t, filepath.IsAbs(runner))
	runnerBytes, err := os.ReadFile(runner)
	require.NoError(t, err)
	runnerDigest := sha256.Sum256(runnerBytes)
	runnerSHA := hex.EncodeToString(runnerDigest[:])
	require.Equal(t, os.Getenv("GATEWAY_NATIVE_JOINED_RUNNER_SHA256"), runnerSHA, "only frozen qualified Gateway runner bytes")
	node := os.Getenv("GATEWAY_NATIVE_JOINED_NODE")
	require.True(t, filepath.IsAbs(node))
	artifactDir := os.Getenv("GATEWAY_NATIVE_JOINED_ARTIFACTS")
	require.True(t, filepath.IsAbs(artifactDir))
	require.NoError(t, os.MkdirAll(artifactDir, 0700))
	var observationsMu sync.Mutex
	observations := []joinedObservation{}
	record := func(boundary, method, path string, status int) {
		observationsMu.Lock()
		defer observationsMu.Unlock()
		observations = append(observations, joinedObservation{boundary, method, path, status})
	}
	defer func() {
		observationsMu.Lock()
		defer observationsMu.Unlock()
		data, e := json.Marshal(observations)
		if e == nil {
			_ = os.WriteFile(filepath.Join(artifactDir, "http-observations.json"), data, 0600)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	var version string
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT current_setting('server_version')").Scan(&version))
	require.Regexp(t, `^17\.10(?:$| )`, version)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&tables))
	require.Zero(t, tables, "never reset or reuse a populated native fixture")
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	repo := repository.NewAccountRepository(client, db, nil)
	adminRepo, ok := repo.(service.AdminAccountRepository)
	require.True(t, ok)
	adminSvc := service.NewAdminService(nil, nil, nil, adminRepo, nil, nil, nil, nil, nil, nil, nil, nil, nil, client, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	cfg := fixtureOAuthConfig()
	control, callback := "joined-test-control-"+uuid.NewString(), "joined-test-callback-"+uuid.NewString()
	consumer := "joined-consumer"
	cfg.Peers[0] = ControlPeer{ConsumerID: consumer, Role: "management", Credential: control}
	cfg.Peers[1] = ControlPeer{ConsumerID: consumer, Role: "execution", Credential: "joined-test-execution-" + uuid.NewString()}
	cfg.Peers[2] = ControlPeer{ConsumerID: consumer, Role: "cleanup", Credential: "joined-test-cleanup-" + uuid.NewString()}
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("joined", map[string][]byte{"joined": key})
	require.NoError(t, err)
	var inference atomic.Int32
	upstream, err := service.NewGatewayNativeLifetimeUpstream(&joinedDenyInference{entries: &inference})
	require.NoError(t, err)
	gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	auth := authorize(cfg.Peers)
	// Create the API-key fixture through the real management handler. The trusted
	// test token establishes only this synthetic consumer, exactly as bootstrap.
	router := gin.New()
	authorizeCandidate := func(c *gin.Context) {
		p, e := auth(c.Request)
		if e != nil || p.Role != "management" {
			c.AbortWithStatus(403)
			return
		}
		x, e := service.WithGatewayNativeConsumer(c.Request.Context(), p.ConsumerID)
		if e != nil {
			c.AbortWithStatus(403)
			return
		}
		c.Request = c.Request.WithContext(x)
		c.Next()
	}
	admin.RegisterGatewayNativeRoutes(router.Group(""), adminSvc, gateway, admin.GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: cfg.Profile.BaseURL, Model: cfg.Profile.Model}, authorizeCandidate, func(*gin.Context, service.GatewayNativeRoute) error { return ErrDenied }, func(*gin.Context, bool, error) {}, custody)
	staging := httptest.NewServer(router)
	defer staging.Close()
	request := func(method, target, credential string, body any) (int, []byte) {
		raw, e := json.Marshal(body)
		require.NoError(t, e)
		r, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(raw))
		require.NoError(t, e)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential)
		resp, e := staging.Client().Do(r)
		require.NoError(t, e)
		defer resp.Body.Close()
		data, e := io.ReadAll(io.LimitReader(resp.Body, 16385))
		require.NoError(t, e)
		require.LessOrEqual(t, len(data), 16384)
		return resp.StatusCode, data
	}
	apiGeneration, apiRef := uuid.NewString(), uuid.NewString()
	apiSecret := "joined-synthetic-key-" + uuid.NewString()
	status, raw := request("POST", staging.URL+"/private/native/v1/candidates", control, map[string]any{"generation": apiGeneration, "profile": service.GatewayMiMoResponsesProfile, "name": "Joined synthetic API key", "api_key": apiSecret, "owner_ref": "joined-owner", "account_ref": apiRef})
	require.Equal(t, 200, status)
	var candidate admin.GatewayNativeCandidate
	require.NoError(t, json.Unmarshal(raw, &candidate))
	status, _ = request("PUT", staging.URL+"/private/native/v1/candidates/"+apiGeneration, control, map[string]any{"descriptor": candidate.Descriptor, "state": "active"})
	require.Equal(t, 200, status)

	// Real OAuth code exchange, signature verification, enrollment journal and
	// controlled-source qualification. The TLS fixture has no internet fallback.
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": service.GatewayOAuthIssuer, "sub": "joined-synthetic-principal", "aud": openai.ClientID, "exp": time.Now().Add(time.Hour).Unix()})
	signed.Header["kid"] = "joined"
	idToken, err := signed.SignedString(signing)
	require.NoError(t, err)
	access, refresh := "joined-access-"+uuid.NewString(), "joined-refresh-"+uuid.NewString()
	var exchanges, checks, jwks atomic.Int32
	var challenge string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Host == "auth.openai.com" && r.URL.Path == "/.well-known/jwks.json":
			jwks.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "joined", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(signing.N.Bytes()), "e": "AQAB"}}})
		case r.Host == "auth.openai.com" && r.URL.Path == "/oauth/token":
			exchanges.Add(1)
			require.NoError(t, r.ParseForm())
			require.Equal(t, challenge, openai.GenerateCodeChallenge(r.PostForm.Get("code_verifier")))
			require.Equal(t, "joined-code", r.PostForm.Get("code"))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "refresh_token": refresh, "id_token": idToken, "token_type": "Bearer", "expires_in": 3600, "scope": openai.DefaultScopes})
		case r.Host == "chatgpt.com" && r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27":
			checks.Add(1)
			require.Equal(t, "Bearer "+access, r.Header.Get("Authorization"))
			_ = json.NewEncoder(w).Encode(map[string]any{"accounts": map[string]any{"joined": map[string]any{"account": map[string]any{"account_id": "11111111-1111-4111-8111-111111111111", "is_default": true}, "entitlement": map[string]any{"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339Nano)}}}})
		default:
			inference.Add(1)
			w.WriteHeader(403)
		}
	}))
	defer provider.Close()
	providerTransport := provider.Client().Transport.(*http.Transport).Clone()
	providerTransport.Proxy = nil
	providerTransport.TLSClientConfig.ServerName = "example.com"
	providerTransport.DialContext = func(c context.Context, n, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" && address != "chatgpt.com:443" {
			inference.Add(1)
			return nil, ErrDenied
		}
		return (&net.Dialer{}).DialContext(c, n, provider.Listener.Addr().String())
	}
	defer providerTransport.CloseIdleConnections()
	oauthRows, ok := repo.(service.GatewayNativeOAuthRepository)
	require.True(t, ok)
	dispatchRows, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	require.True(t, ok)
	intentKey := make([]byte, 32)
	_, err = rand.Read(intentKey)
	require.NoError(t, err)
	verifier := service.NewGatewayNativeOAuthVerifier(providerTransport)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, oauthRows, intentKey)
	require.NoError(t, err)
	journal, err := repository.NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connect, err := service.NewGatewayNativeOAuthConnect(intentKey, providerTransport, journal, enrollment, oauthRows)
	require.NoError(t, err)
	scope := service.GatewayNativeCredentialScope{Consumer: consumer, Owner: "joined-owner", Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}
	owner, err := service.WithGatewayNativeConsumer(ctx, consumer)
	require.NoError(t, err)
	owner, err = service.WithGatewayNativeOAuthOwner(owner, scope.Owner)
	require.NoError(t, err)
	operation := "joined-oauth-enrollment"
	begun, err := connect.BeginConnect(owner, scope, operation)
	require.NoError(t, err)
	authorizeURL, err := url.Parse(begun.AuthorizeURL)
	require.NoError(t, err)
	challenge = authorizeURL.Query().Get("code_challenge")
	completed, err := connect.CompleteOwnerCallback(owner, scope, operation, authorizeURL.Query().Get("state"), "joined-code")
	require.NoError(t, err)
	require.Equal(t, "staged", completed.Outcome)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(dispatchRows, custody, verifier, providerTransport)
	require.NoError(t, err)
	qualified, err := dispatch.Descriptor(owner, scope, operation)
	require.NoError(t, err)
	require.NotNil(t, qualified.Native)
	require.EqualValues(t, 1, exchanges.Load())
	require.EqualValues(t, 1, checks.Load())
	require.Positive(t, jwks.Load())
	frozenExchanges, frozenChecks, frozenJWKS := exchanges.Load(), checks.Load(), jwks.Load()
	beforeAPI, err := repo.GetByID(ctx, candidate.Descriptor.AccountID)
	require.NoError(t, err)
	beforeOAuth, err := repo.GetByID(ctx, qualified.Native.AccountID)
	require.NoError(t, err)
	apiEnvelope, oauthEnvelope := beforeAPI.GetCredential("api_key"), beforeOAuth.GetCredential("oauth_bundle")
	var nativeBefore string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM accounts a").Scan(&nativeBefore))
	require.True(t, strings.HasPrefix(apiEnvelope, "gcn1."))
	require.True(t, strings.HasPrefix(oauthEnvelope, "gco1."))

	// The listener exists before Gateway seeds its mapping. No request can reach
	// the production mount until its actual callback authority is ready.
	var mounted atomic.Value
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := mounted.Load()
		if h == nil {
			w.WriteHeader(503)
			return
		}
		audit := &joinedStatusWriter{ResponseWriter: w, status: 200}
		h.(http.Handler).ServeHTTP(audit, r)
		record("native", r.Method, r.URL.Path, audit.status)
	}))
	defer native.Close()
	descriptor := func(d service.GatewayNativeRoute) map[string]any {
		return map[string]any{"generation": d.Generation, "nativePhysicalIdentity": d.Generation, "nativeId": d.AccountID, "createdAt": d.CreatedAt.Format(time.RFC3339Nano), "profile": d.Profile, "baseURL": d.BaseURL, "model": d.Model}
	}
	fixture := map[string]any{"consumerId": consumer, "nativeOrigin": native.URL, "accounts": []any{
		map[string]any{"authKind": "api_key", "operationId": "joined-apikey-enrollment", "ownerRef": "joined-owner", "accountRef": apiRef, "qualificationRef": cfg.Profile.QualificationRef, "descriptor": descriptor(candidate.Descriptor)},
		map[string]any{"authKind": "oauth", "operationId": operation, "ownerRef": scope.Owner, "accountRef": scope.Account, "qualificationRef": cfg.OAuth.Profile.QualificationRef, "descriptor": descriptor(*qualified.Native)}}}
	safe, err := json.Marshal(fixture)
	require.NoError(t, err)
	fixturePath := filepath.Join(artifactDir, "fixture.json")
	require.NoError(t, os.WriteFile(fixturePath, safe, 0600))
	cmd := exec.CommandContext(ctx, node, runner)
	cmd.Env = append(os.Environ(), "AG_NATIVE_RETAINED_JOINED_FIXTURE="+fixturePath, "AG_NATIVE_RETAINED_JOINED_CONTROL="+control, "AG_NATIVE_RETAINED_JOINED_CALLBACK="+callback)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr := &bytes.Buffer{}
	stdoutLog, err := os.OpenFile(filepath.Join(artifactDir, "gateway-stdout.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err)
	defer stdoutLog.Close()
	stderrLog, err := os.OpenFile(filepath.Join(artifactDir, "gateway-stderr.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err)
	defer stderrLog.Close()
	cmd.Stderr = io.MultiWriter(stderr, stderrLog)
	require.NoError(t, cmd.Start())
	// One child launch only. Preserve its actual terminal status; never rerun on
	// an unknown result against either populated database.
	childWaited := false
	defer func() {
		if !childWaited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(io.TeeReader(stdout, stdoutLog))
	scanner.Buffer(make([]byte, 4096), 16384)
	require.True(t, scanner.Scan(), "child ready response missing")
	var ready struct {
		Phase             string `json:"phase"`
		CallbackOrigin    string `json:"callbackOrigin"`
		EngineIncarnation string `json:"engineIncarnation"`
	}
	readyLine := append([]byte(nil), scanner.Bytes()...)
	require.NoError(t, json.Unmarshal(readyLine, &ready))
	require.Equal(t, "ready", ready.Phase)
	require.Regexp(t, incarnation, ready.EngineIncarnation)
	authority, err := newAuthority(AuthorityConfig{Origin: ready.CallbackOrigin, Credential: callback}, nil)
	require.NoError(t, err)
	defer authority.client.CloseIdleConnections()
	authority.client.Transport = joinedAuditTransport{authority.client.Transport, record}
	transportCfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, OAuth: dispatch, Authorize: auth, Enrollment: gatewaytransport.Enrollment{OriginRef: "joined-test-origin", EngineIncarnation: ready.EngineIncarnation, QualificationRef: cfg.Profile.QualificationRef}, Profile: cfg.qualifiedProfile(), Codex: cfg.codexProfile(), MaxEntries: 4, CallbackTimeout: time.Second, IOTimeout: time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 16384, CallbackBytes: 65536}
	authority.compose(&transportCfg)
	transport, err := gatewaytransport.New(ctx, transportCfg)
	require.NoError(t, err)
	defer transport.Stop(context.Background())
	refreshRows, ok := repo.(service.GatewayNativeOAuthRefreshRepository)
	require.True(t, ok)
	refreshService, err := service.NewGatewayNativeOAuthRefresh(refreshRows, custody, verifier, providerTransport)
	require.NoError(t, err)
	oauth := &privateOAuth{connect: connect, dispatch: dispatch, owners: authority, refresh: refreshService, cleanup: authority.AuthorizeNativeOAuthCleanup}
	mounted.Store(privateHandler(cfg.Profile, adminSvc, gateway, custody, transport, auth, oauth))
	_, err = io.WriteString(stdin, "{\"phase\":\"continue\"}\n")
	require.NoError(t, err)
	var transcript bytes.Buffer
	transcript.Write(readyLine)
	transcript.WriteByte('\n')
	var terminal map[string]json.RawMessage
	for scanner.Scan() {
		line := scanner.Bytes()
		transcript.Write(line)
		transcript.WriteByte('\n')
		require.NoError(t, json.Unmarshal(line, &terminal))
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	childWaited = true
	receipt, _ := json.Marshal(map[string]any{"childExitCode": cmd.ProcessState.ExitCode(), "nativeVersion": version, "runnerSHA256": runnerSHA, "inferenceRequests": inference.Load(), "exchangeRequests": exchanges.Load(), "accountChecks": checks.Load()})
	require.NoError(t, os.WriteFile(filepath.Join(artifactDir, "receipt.json"), receipt, 0600))
	require.NoError(t, scanErr)
	require.NoError(t, waitErr, "joined runner failed; sanitized transcript: %s", transcript.String())
	require.JSONEq(t, `"completed"`, string(terminal["phase"]))
	require.JSONEq(t, `"gateway-native-retained-custody-joined/v1"`, string(terminal["contract"]))
	var results []struct {
		AuthKind             string `json:"authKind"`
		RetainedIdentity     bool   `json:"retainedIdentity"`
		OldAuthorityDenied   bool   `json:"oldAuthorityDenied"`
		NewAuthorityAllowed  bool   `json:"newAuthorityAllowed"`
		MissingCustodyDenied bool   `json:"missingCustodyDenied"`
	}
	require.NoError(t, json.Unmarshal(terminal["results"], &results))
	require.Len(t, results, 2)
	for i, r := range results {
		require.Equal(t, []string{"api_key", "oauth"}[i], r.AuthKind)
		require.True(t, r.RetainedIdentity && r.OldAuthorityDenied && r.NewAuthorityAllowed && r.MissingCustodyDenied)
	}
	for _, check := range []struct {
		id                           int64
		status, envelope, credential string
	}{{beforeAPI.ID, service.StatusActive, apiEnvelope, "api_key"}, {beforeOAuth.ID, service.StatusDisabled, oauthEnvelope, "oauth_bundle"}} {
		row, e := repo.GetByID(ctx, check.id)
		require.NoError(t, e)
		require.Equal(t, check.status, row.Status)
		require.Equal(t, check.envelope, row.GetCredential(check.credential))
		require.False(t, row.Schedulable)
	}
	var nativeAfter string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM accounts a").Scan(&nativeAfter))
	require.True(t, nativeBefore == nativeAfter, "retained custody must perform zero native account writes")
	var refreshAttempts int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM gateway_oauth_refresh_attempts").Scan(&refreshAttempts))
	require.Zero(t, refreshAttempts, "retained custody cannot prepare a refresh")
	require.Equal(t, frozenExchanges, exchanges.Load(), "custody cannot exchange or refresh")
	require.Equal(t, frozenChecks, checks.Load(), "custody cannot probe provider")
	require.Equal(t, frozenJWKS, jwks.Load(), "custody cannot reverify with provider")
	require.Zero(t, inference.Load())
	for _, secret := range []string{apiSecret, access, refresh, idToken, apiEnvelope, oauthEnvelope, control, callback} {
		require.NotContains(t, transcript.String()+stderr.String()+string(safe), secret)
	}
}

// Inference must have no network escape even if the child regresses.
type joinedDenyInference struct{ entries *atomic.Int32 }

func (d *joinedDenyInference) Do(*http.Request, string, int64, int) (*http.Response, error) {
	d.entries.Add(1)
	return nil, ErrDenied
}
func (d *joinedDenyInference) DoWithTLS(*http.Request, string, int64, int, *tlsfingerprint.Profile) (*http.Response, error) {
	d.entries.Add(1)
	return nil, ErrDenied
}

type joinedObservation struct {
	Boundary string `json:"boundary"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
}
type joinedStatusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *joinedStatusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *joinedStatusWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (w *joinedStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type joinedAuditTransport struct {
	base   http.RoundTripper
	record func(string, string, string, int)
}

func (a joinedAuditTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := a.base.RoundTrip(r)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	a.record("gateway-authority", r.Method, r.URL.Path, status)
	return resp, err
}
func (a joinedAuditTransport) CloseIdleConnections() {
	if closer, ok := a.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
