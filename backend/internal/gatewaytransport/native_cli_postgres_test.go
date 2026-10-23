//go:build unit && nativecli

package gatewaytransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"syscall"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Official npm @anthropic-ai/claude-code-linux-x64@2.1.309, independently
// matched to anthropics/claude-code release v2.1.309 on 2026-10-23. Install only
// in the operator's task scratch; this test never installs or updates software.
const qualifiedClaudeCLISHA256 = "4d704a8aecbe038affa3000f498ae17c1b4f753add8facb8764120affc99b658"
const qualifiedClaudeCLIReply = "Controlled local fixture reply."
const qualifiedClaudeCLISSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cli_fixture\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Controlled local fixture reply.\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// Actual CLI -> actual public Go handler -> actual protected native service ->
// loopback TLS provider. Native identity/custody and terminal usage use migrated
// PostgreSQL. The metadata authority is an explicit fixture, not the TS kernel;
// this test does not claim full composition or live-provider acceptance.
func TestPinnedClaudeCodeCLIThroughPublicMessagesPostgres(t *testing.T) {
	binary, dsn := os.Getenv("GATEWAY_NATIVE_CLIENT_CLAUDE_BINARY"), os.Getenv("GATEWAY_NATIVE_CLIENT_CLAUDE_DSN")
	if binary == "" || dsn == "" {
		t.Skip("CLI_NOT_RUN: explicit pinned Claude Code binary and disposable PostgreSQL DSN not supplied")
	}
	requireNativeCLINetwork(t)
	require.True(t, filepath.IsAbs(binary))
	data, err := os.ReadFile(binary)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	require.Equal(t, qualifiedClaudeCLISHA256, hex.EncodeToString(digest[:]))
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
	rows, err := repository.NewGatewayNativeClaudeRepository(db)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.Repeat("K", 32))})
	require.NoError(t, err)
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: service.GatewayOAuthBundlePurpose}
	principal, organization := uuid.NewString(), uuid.NewString()
	var providerEntries, tokenEntries, authorityEntries, settlements atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "platform.claude.com" && r.URL.Path == "/v1/oauth/token":
			tokenEntries.Add(1)
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 8192))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-cli-native-access", "refresh_token": "synthetic-cli-native-refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "user:inference", "account": map[string]string{"uuid": principal}, "organization": map[string]string{"uuid": organization}})
		case r.Host == "api.anthropic.com" && r.URL.Path == "/v1/messages" && r.URL.RawQuery == "beta=true":
			providerEntries.Add(1)
			require.True(t, r.Header.Get("Authorization") == "Bearer synthetic-cli-native-access")
			require.Empty(t, r.Header.Get("X-Api-Key"))
			raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			require.NoError(t, e)
			require.NoError(t, service.ValidateGatewayNativeClaudeMessagesBounded(raw, 1<<20, 65536), "actual pinned CLI payload must qualify without reserialization")
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, qualifiedClaudeCLISSE)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer provider.Close()
	transport := provider.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
		if address != "platform.claude.com:443" && address != "api.anthropic.com:443" {
			return nil, errDenied
		}
		return (&net.Dialer{}).DialContext(c, network, provider.Listener.Addr().String())
	}
	defer transport.CloseIdleConnections()
	dispatch, err := service.NewGatewayNativeClaudeOAuth(rows, custody, transport)
	require.NoError(t, err)
	allow := func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }
	require.NoError(t, dispatch.SetEntryAuthorizers(allow, allow))
	owner, err := service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	owner, err = service.WithGatewayNativeOAuthOwner(owner, scope.Owner)
	require.NoError(t, err)
	operation := uuid.NewString()
	connect, err := dispatch.BeginConnectMethod(owner, scope, operation, "browser")
	require.NoError(t, err)
	authorizeURL, err := url.Parse(connect.AuthorizeURL)
	require.NoError(t, err)
	_, err = dispatch.CompleteOwnerCallback(owner, scope, operation, authorizeURL.Query().Get("state"), "synthetic-cli-code")
	require.NoError(t, err)
	descriptor, err := dispatch.Descriptor(owner, scope, operation)
	require.NoError(t, err)
	require.NotNil(t, descriptor.Native)
	original := ownerRequest()
	original.Admission.AccountRef, original.Admission.ProfileID = scope.Account, service.GatewayClaudeOAuthMessagesProfile
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
	h, err := New(ctx, Config{Gateway: gateway, Custody: custody, ClaudeOAuth: dispatch, Enrollment: Enrollment{"fixture-origin", ownerIncarnation, "fixture-qualification"},
		Profile:    QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: "fixture-model", BaseURL: provider.URL, QualificationRef: "fixture-qualification", RequestBytes: 1 << 20, OutputBytes: 1 << 20, Tokens: 65536, ProviderTokenUpperBound: 65536},
		Claude:     &QualifiedProfile{Profile: service.GatewayClaudeOAuthMessagesProfile, Model: service.GatewayClaudeOAuthModel, BaseURL: service.GatewayClaudeOAuthBaseURL, QualificationRef: "controlled-cli-native", RequestBytes: 1 << 20, OutputBytes: 1 << 20, Tokens: 65536, ProviderTokenUpperBound: 65536},
		MaxEntries: 4, EnvelopeBytes: 2 << 20, CallbackBytes: 65536, CallbackOrigin: authority.URL, CallbackCredential: fixtureCallbackToken, CallbackTimeout: time.Second, IOTimeout: 15 * time.Second, CleanupTimeout: 3 * time.Second,
		Authorize: func(*http.Request) (Peer, error) { return Peer{}, errDenied }, VerifyEnrollment: func(context.Context, Enrollment) error { return nil }, VerifyDispatch: func(context.Context, string, Proof, time.Time) error { return nil },
		AuthorizeCleanup: func(context.Context, string, Proof, CleanupLease) error { return errDenied }, AcknowledgeClosure: func(context.Context, string, Proof, CleanupLease, Receipt) error { return errDenied }})
	require.NoError(t, err)
	public := httptest.NewServer(h.PublicHandler(2))
	defer public.Close()
	work := t.TempDir()
	command := exec.CommandContext(ctx, binary, "--bare", "-p", "--model", service.GatewayClaudeOAuthModel, "--output-format", "stream-json", "--verbose", "--max-turns", "1", "--tools", "", "--no-session-persistence", "--system-prompt", "Controlled local protocol fixture.", "Return the local fixture answer.")
	command.Dir = work
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "ANTHROPIC_BASE_URL=" + public.URL, "ANTHROPIC_API_KEY=" + capability, "CLAUDE_CONFIG_DIR=" + filepath.Join(work, "config"), "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_SKIP_PROMPT_HISTORY=1"}
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err = command.Run()
	require.True(t, err == nil, "pinned CLI failed; stdout bytes=%d, stderr bytes=%d, authorities=%d, provider entries=%d", output.Len(), diagnostic.Len(), authorityEntries.Load(), providerEntries.Load())
	success := false
	for _, line := range bytes.Split(output.Bytes(), []byte{'\n'}) {
		var event struct {
			Type, Subtype, Result string
			IsError               bool `json:"is_error"`
		}
		if json.Unmarshal(line, &event) == nil && event.Type == "result" {
			success = event.Subtype == "success" && !event.IsError && event.Result == qualifiedClaudeCLIReply
		}
	}
	require.True(t, success, "pinned CLI must parse native SSE and return the controlled terminal result")
	require.EqualValues(t, 1, tokenEntries.Load())
	require.EqualValues(t, 1, providerEntries.Load(), "actual client must perform exactly one controlled inference")
	require.EqualValues(t, 1, settlements.Load())
	var persisted int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM cli_fixture_settlements WHERE native_usage->>'state'='complete' AND (native_usage->>'outputTokens')::int=3`).Scan(&persisted))
	require.Equal(t, 1, persisted)
	require.Zero(t, db.Stats().InUse)
}

func requireNativeCLINetwork(t *testing.T) {
	t.Helper()
	evidence, err := os.ReadFile(os.Getenv("AG_LOAD_NETWORK_EVIDENCE"))
	require.NoError(t, err, "operator must supply private network evidence")
	var facts map[string]any
	require.NoError(t, json.Unmarshal(evidence, &facts))
	namespace, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	require.Equal(t, namespace, facts["networkNamespace"])
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	require.Len(t, interfaces, 1)
	require.Equal(t, "lo", interfaces[0].Name)
	routes, err := os.ReadFile("/proc/net/route")
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(routes)), "\n"), 1)
	connection, err := net.DialTimeout("tcp4", "192.0.2.1:443", 250*time.Millisecond)
	if connection != nil {
		connection.Close()
	}
	require.True(t, errors.Is(err, syscall.ENETUNREACH), "external probe must positively fail with no route")
}
