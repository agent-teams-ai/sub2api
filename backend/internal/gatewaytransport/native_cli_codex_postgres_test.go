//go:build unit && nativecli

package gatewaytransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Official npm @openai/codex@0.164.0-linux-x64, matched to release rust-v0.164.0.
const qualifiedCodexCLISHA256 = "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"

// Actual CLI -> actual public Go handler -> actual protected native service ->
// loopback TLS provider. Native identity/custody and terminal usage use migrated
// PostgreSQL. The metadata authority is an explicit fixture, not the TS kernel;
// this test does not claim full composition or live-provider acceptance.
func TestPinnedCodexCLIThroughPublicResponsesPostgres(t *testing.T) {
	binary, dsn := os.Getenv("GATEWAY_NATIVE_CLIENT_CODEX_BINARY"), os.Getenv("GATEWAY_NATIVE_CLIENT_CODEX_DSN")
	if binary == "" || dsn == "" {
		t.Skip("CLI_NOT_RUN: explicit pinned Codex binary and disposable PostgreSQL DSN not supplied")
	}
	requireNativeCLINetwork(t)
	require.True(t, filepath.IsAbs(binary))
	data, err := os.ReadFile(binary)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	require.Equal(t, qualifiedCodexCLISHA256, hex.EncodeToString(digest[:]))
	data = nil
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "postgresql", u.Scheme)
	require.Equal(t, "127.0.0.1", u.Hostname())
	require.True(t, strings.HasPrefix(u.Path, "/gateway_cli_test_"))
	require.Equal(t, "sslmode=disable", u.RawQuery)
	require.Empty(t, u.Fragment)
	require.NotNil(t, u.User)
	_, password := u.User.Password()
	require.False(t, password)
	ctx, stop := context.WithTimeout(context.Background(), 70*time.Second)
	defer stop()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(4)
	var tables int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables))
	require.Zero(t, tables, "never migrate or reset a preexisting client fixture database")
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	_, err = db.ExecContext(ctx, `CREATE TABLE cli_fixture_settlements(request_ref text PRIMARY KEY, native_usage jsonb NOT NULL)`)
	require.NoError(t, err)
	accountRepo := repository.NewAccountRepository(nil, db, nil)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.Repeat("K", 32))})
	require.NoError(t, err)
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}
	principal, organization := uuid.NewString(), uuid.NewString()
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": service.GatewayOAuthIssuer, "sub": principal, "aud": openai.ClientID, "exp": time.Now().Add(time.Hour).Unix()})
	token.Header["kid"] = "cli-fixture"
	idToken, err := token.SignedString(signing)
	require.NoError(t, err)
	var providerEntries, tokenEntries, authorityEntries, settlements atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Host == "auth.openai.com" && r.URL.Path == "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "cli-fixture", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(signing.N.Bytes()), "e": "AQAB"}}})
		case r.Host == "auth.openai.com" && r.URL.Path == "/oauth/token":
			tokenEntries.Add(1)
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 8192))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-cli-native-access", "refresh_token": "synthetic-cli-native-refresh", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600})
		case r.Host == "chatgpt.com" && r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27":
			_ = json.NewEncoder(w).Encode(map[string]any{"accounts": map[string]any{"cli-fixture": map[string]any{"account": map[string]string{"account_id": organization}}}})
		case r.Host == "chatgpt.com" && r.URL.Path == "/backend-api/codex/responses":
			providerEntries.Add(1)
			require.True(t, r.Header.Get("Authorization") == "Bearer synthetic-cli-native-access")
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, qualifiedCodexCLISSE())
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer provider.Close()
	transport := provider.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" && address != "chatgpt.com:443" {
			return nil, errDenied
		}
		return (&net.Dialer{}).DialContext(c, network, provider.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()

	owner, err := service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	owner, err = service.WithGatewayNativeOAuthOwner(owner, scope.Owner)
	require.NoError(t, err)
	operation := uuid.NewString()
	verifier := service.NewGatewayNativeOAuthVerifier(transport)
	stageRepo := accountRepo.(service.GatewayNativeOAuthRepository)
	intentKey := []byte(strings.Repeat("I", 32))
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, stageRepo, intentKey)
	require.NoError(t, err)
	connectRepo, err := repository.NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connector, err := service.NewGatewayNativeOAuthConnect(intentKey, transport, connectRepo, enrollment, stageRepo)
	require.NoError(t, err)
	require.NoError(t, connector.SetEntryAuthorizer(func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }))
	connect, err := connector.BeginConnect(owner, scope, operation)
	require.NoError(t, err)
	authorizeURL, err := url.Parse(connect.AuthorizeURL)
	require.NoError(t, err)
	_, err = connector.CompleteOwnerCallback(owner, scope, operation, authorizeURL.Query().Get("state"), "synthetic-cli-code")
	require.NoError(t, err)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(accountRepo.(service.GatewayNativeOAuthDispatchRepository), custody, verifier, transport)
	require.NoError(t, err)
	descriptor, err := dispatch.Descriptor(owner, scope, operation)
	require.NoError(t, err)
	require.NotNil(t, descriptor.Native)
	original := ownerRequest()
	original.Admission.AccountRef, original.Admission.ProfileID = scope.Account, service.GatewayCodexOAuthResponsesProfile
	original.Admission.Limits = Limits{Requests: 1, Concurrency: 1, RequestBytes: 1 << 20, OutputBytes: 1 << 20, Tokens: 65536}
	original.Admission.ExpiresAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	original.Descriptor = *descriptor.Native
	capability := "synthetic-controlled-execution-capability"
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fixtureCallbackToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			authorityEntries.Add(1)
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.True(t, input.ExecutionBearer == capability)
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{scope.Consumer, input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			var input admitRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(ownerReply(input))
		case "/private/native/v1/execution-settle":
			var input struct {
				Receipt Receipt `json:"receipt"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.True(t, closed(input.Receipt.Lifetime))
			require.True(t, input.Receipt.Lifetime.Completed)
			require.NotNil(t, input.Receipt.NativeUsage)
			require.Equal(t, "complete", input.Receipt.NativeUsage.State)
			require.EqualValues(t, 7, *input.Receipt.NativeUsage.InputTokens)
			require.EqualValues(t, 3, *input.Receipt.NativeUsage.OutputTokens)
			raw, e := json.Marshal(input.Receipt.NativeUsage)
			require.NoError(t, e)
			_, e = db.ExecContext(ctx, `INSERT INTO cli_fixture_settlements(request_ref,native_usage) VALUES($1,$2::jsonb)`, input.Receipt.RequestRef, string(raw))
			if e != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			settlements.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer authority.Close()
	upstream, err := service.NewGatewayNativeLifetimeUpstream(&ownerFixtureHTTP{client: &http.Client{Transport: transport}})
	require.NoError(t, err)
	gateway := service.NewOpenAIGatewayService(repository.NewAccountRepository(nil, db, nil), nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	h, err := New(ctx, Config{Gateway: gateway, Custody: custody, OAuth: dispatch, Enrollment: Enrollment{"fixture-origin", ownerIncarnation, "fixture-qualification"},
		Profile:    QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: "fixture-model", BaseURL: provider.URL, QualificationRef: "fixture-qualification", RequestBytes: 1 << 20, OutputBytes: 1 << 20, Tokens: 65536, ProviderTokenUpperBound: 65536},
		Codex:      &QualifiedProfile{Profile: service.GatewayCodexOAuthResponsesProfile, Model: service.GatewayCodexOAuthModel, BaseURL: service.GatewayCodexOAuthBaseURL, QualificationRef: "controlled-cli-native", RequestBytes: 1 << 20, OutputBytes: 1 << 20, Tokens: 65536, ProviderTokenUpperBound: 65536},
		MaxEntries: 4, EnvelopeBytes: 2 << 20, CallbackBytes: 65536, CallbackOrigin: authority.URL, CallbackCredential: fixtureCallbackToken, CallbackTimeout: time.Second, IOTimeout: 15 * time.Second, CleanupTimeout: 3 * time.Second,
		Authorize: func(*http.Request) (Peer, error) { return Peer{}, errDenied }, VerifyEnrollment: func(context.Context, Enrollment) error { return nil }, VerifyDispatch: func(context.Context, string, Proof, time.Time) error { return nil },
		AuthorizeCleanup: func(context.Context, string, Proof, CleanupLease) error { return errDenied }, AcknowledgeClosure: func(context.Context, string, Proof, CleanupLease, Receipt) error { return errDenied }})
	require.NoError(t, err)
	public := httptest.NewServer(h.PublicHandler(2))
	defer public.Close()
	work := t.TempDir()
	providerConfig := fmt.Sprintf(`{name="ControlledLocalGateway",base_url="%s/v1",env_key="AG_CLI_EXECUTION_CAPABILITY",wire_api="responses",request_max_retries=0,stream_max_retries=0,supports_websockets=false,requires_openai_auth=false}`, public.URL)
	command := exec.CommandContext(ctx, binary, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "-m", service.GatewayCodexOAuthModel, "-c", `model_provider="fixture"`, "-c", "model_providers.fixture="+providerConfig, "Return the local fixture answer.")
	command.Dir = work
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "AG_CLI_EXECUTION_CAPABILITY=" + capability}
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err = command.Run()
	require.True(t, err == nil, "pinned CLI failed; stdout bytes=%d, stderr bytes=%d, authorities=%d, provider entries=%d", output.Len(), diagnostic.Len(), authorityEntries.Load(), providerEntries.Load())
	success, answered := false, false
	for _, line := range bytes.Split(output.Bytes(), []byte{'\n'}) {
		var event struct {
			Type, Subtype, Result string
			Item                  struct{ Type, Text string } `json:"item"`
			IsError               bool                        `json:"is_error"`
		}
		if json.Unmarshal(line, &event) == nil {
			if event.Type == "turn.completed" {
				success = true
			}
			if event.Type == "item.completed" && event.Item.Type == "agent_message" && event.Item.Text == qualifiedClaudeCLIReply {
				answered = true
			}
		}
	}
	require.True(t, success && answered, "pinned CLI must parse native SSE and return the controlled terminal result")
	require.EqualValues(t, 1, tokenEntries.Load())
	require.EqualValues(t, 1, providerEntries.Load(), "actual client must perform exactly one controlled inference")
	require.EqualValues(t, 1, settlements.Load())
	var persisted int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM cli_fixture_settlements WHERE native_usage->>'state'='complete' AND (native_usage->>'outputTokens')::int=3`).Scan(&persisted))
	require.Equal(t, 1, persisted)
	require.Zero(t, db.Stats().InUse)
}

func qualifiedCodexCLISSE() string {
	item := map[string]any{"id": "msg_codex_fixture", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": qualifiedClaudeCLIReply, "annotations": []any{}}}}
	response := map[string]any{"id": "resp_codex_fixture", "object": "response", "created_at": 1792782000, "status": "completed", "model": service.GatewayCodexOAuthModel, "output": []any{item}, "usage": map[string]any{"input_tokens": 7, "output_tokens": 3, "total_tokens": 10, "input_tokens_details": map[string]int{"cached_tokens": 0}, "output_tokens_details": map[string]int{"reasoning_tokens": 0}}}
	events := []map[string]any{{"type": "response.created", "response": map[string]any{"id": "resp_codex_fixture", "status": "in_progress", "output": []any{}}}, {"type": "response.output_item.added", "output_index": 0, "item": map[string]any{"id": "msg_codex_fixture", "type": "message", "role": "assistant", "status": "in_progress", "content": []any{}}}, {"type": "response.output_text.delta", "output_index": 0, "item_id": "msg_codex_fixture", "content_index": 0, "delta": qualifiedClaudeCLIReply}, {"type": "response.output_item.done", "output_index": 0, "item": item}, {"type": "response.completed", "response": response}}
	var out strings.Builder
	for _, event := range events {
		raw, _ := json.Marshal(event)
		out.WriteString("event: " + event["type"].(string) + "\ndata: " + string(raw) + "\n\n")
	}
	return out.String()
}
