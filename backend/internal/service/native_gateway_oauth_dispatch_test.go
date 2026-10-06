//go:build unit

package service

import (
	"bytes"
	"context"
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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This store supplies controlled row postimages. The distinct PG test is the
// authoritative SQL promotion/fence/refresh boundary, never this fixture.
type oauthDispatchStore struct {
	AccountRepository
	row            *Account
	physical       GatewayNativeOAuthPhysical
	locks          int
	beforeLock     func(int)
	qualifications int
	reject         bool
	connectState   string
	fenceDeadline  time.Time
	fenceUnknown   bool
	fenceEntered   bool
	fenceChecks    int
}

func (r *oauthDispatchStore) ReadGatewayNativeOAuthDispatch(ctx context.Context, s GatewayNativeCredentialScope, op string) (GatewayNativeOAuthOutcome, error) {
	if r.reject || !GatewayNativeOAuthScopeAuthorized(ctx, s) || r.physical.Scope != s || r.physical.Operation != op {
		return GatewayNativeOAuthOutcome{}, ErrGatewayNativeIdentity
	}
	return GatewayNativeOAuthOutcome{Operation: op, AccountID: r.row.ID, Generation: s.Generation, State: r.connectState}, nil
}
func (r *oauthDispatchStore) LockGatewayNativeOAuthDispatch(ctx context.Context, s GatewayNativeCredentialScope, op string, id int64) (*Account, GatewayNativeOAuthPhysical, func(), error) {
	r.locks++
	if r.beforeLock != nil {
		r.beforeLock(r.locks)
	}
	if r.reject || !GatewayNativeOAuthScopeAuthorized(ctx, s) || s != r.physical.Scope || op != r.physical.Operation || id != r.row.ID {
		return nil, GatewayNativeOAuthPhysical{}, nil, ErrGatewayNativeIdentity
	}
	p := r.physical
	p.RefreshFence = r
	return r.row, p, func() {}, nil
}
func (r *oauthDispatchStore) Check(ctx context.Context) error {
	r.fenceChecks++
	if ctx.Err() != nil || r.fenceUnknown || r.fenceEntered || (!r.fenceDeadline.IsZero() && !time.Now().Before(r.fenceDeadline)) {
		return ErrGatewayNativeIdentity
	}
	return nil
}

func (r *oauthDispatchStore) QualifyGatewayNativeOAuthDispatch(ctx context.Context, p GatewayNativeOAuthPhysical, v int64) error {
	current, err := gatewayOAuthCredentialVersion(r.row)
	if err != nil || current != v || !p.QualificationValid(v) || !GatewayNativeOAuthScopeAuthorized(ctx, p.Scope) || !SameGatewayNativeDescriptor(p.Route, r.physical.Route) {
		return ErrGatewayNativeIdentity
	}
	r.qualifications++
	r.physical = p
	return nil
}

type oauthDispatchFixture struct {
	ctx               context.Context
	scope             GatewayNativeCredentialScope
	store             *oauthDispatchStore
	dispatch          *GatewayNativeOAuthDispatch
	svc               *OpenAIGatewayService
	bundle            GatewayNativeOAuthBundle
	accountCheck      string
	accountStatus     int
	mode              string
	checks            atomic.Int32
	entries           atomic.Int32
	jwks              atomic.Int32
	jwksDelay         time.Duration
	lastAuthorization atomic.Value
	lastPayload       atomic.Value
	lastContext       context.Context
}

func newOAuthDispatchFixture(t *testing.T) *oauthDispatchFixture {
	t.Helper()
	f := &oauthDispatchFixture{accountStatus: http.StatusOK}
	f.scope = GatewayNativeCredentialScope{Consumer: uuid.NewString(), Owner: uuid.NewString(), Account: uuid.NewString(), Generation: uuid.NewString(), Purpose: GatewayOAuthBundlePurpose}
	ctx, err := WithGatewayNativeConsumer(context.Background(), f.scope.Consumer)
	require.NoError(t, err)
	f.ctx, err = WithGatewayNativeOAuthOwner(ctx, f.scope.Owner)
	require.NoError(t, err)
	key := oauthFixtureKey(t)
	subject := uuid.NewString()
	f.bundle = GatewayNativeOAuthBundle{AccessToken: uuid.NewString(), RefreshToken: uuid.NewString(), IDToken: oauthFixtureSign(t, key, `{"alg":"RS256","kid":"fixture"}`, oauthFixtureClaims(subject, time.Now())), SensitiveMetadata: json.RawMessage(`{"expires_in":3600}`)}
	provider := uuid.NewString()
	f.accountCheck = fmt.Sprintf(`{"accounts":{"unrelated-workspace-key":{"account":{"account_id":%q,"is_default":false},"entitlement":{"expires_at":%q}}}}`, provider, time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			f.jwks.Add(1)
			if f.jwksDelay > 0 {
				time.Sleep(f.jwksDelay)
			}
			require.Equal(t, "auth.openai.com", r.Host)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{oauthFixtureJWK(key)}})
		case "/backend-api/accounts/check/v4-2023-04-27":
			f.checks.Add(1)
			require.Equal(t, "chatgpt.com", r.Host)
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer "+f.bundle.AccessToken, r.Header.Get("Authorization"))
			require.Empty(t, r.Header.Get("ChatGPT-Account-Id"))
			if f.accountStatus == http.StatusFound {
				w.Header().Set("Location", "https://chatgpt.com/redirect-must-not-enter")
			}
			w.WriteHeader(f.accountStatus)
			_, _ = io.WriteString(w, f.accountCheck)
		case "/backend-api/codex/responses":
			f.entries.Add(1)
			require.Equal(t, "chatgpt.com", r.Host)
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, provider, r.Header.Get("ChatGPT-Account-Id"))
			require.Equal(t, "text/event-stream", r.Header.Get("Accept"))
			for _, header := range []string{"X-Codex-Turn-State", "Cookie", "X-Api-Key", "Origin", "Idempotency-Key", "X-Idempotency-Key", "X-Caller-Only"} {
				require.Empty(t, r.Header.Get(header))
			}
			f.lastAuthorization.Store(r.Header.Get("Authorization"))
			raw, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			f.lastPayload.Store(string(raw))
			if f.mode == "error" {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, uuid.NewString())
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if f.mode == "hold" {
				_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				return
			}
			if f.mode == "partial" {
				_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
				return
			}
			_, _ = io.WriteString(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"custom_tool_call\",\"call_id\":\"call_fixture\",\"name\":\"exec\",\"input\":\"printf fixture\"}}\n\n")
			_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"controlled final\"}]}]}}\n\n")
		default:
			t.Errorf("unexpected provider path %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" && address != "chatgpt.com:443" {
			return nil, ErrGatewayNativeIdentity
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	custody, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": []byte(strings.ReplaceAll(uuid.NewString(), "-", ""))})
	require.NoError(t, err)
	envelope, err := custody.SealOAuthBundle(f.scope, f.bundle)
	require.NoError(t, err)
	created := time.Now().UTC().Truncate(time.Microsecond)
	a := &Account{ID: 41, CreatedAt: created, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusDisabled, Credentials: map[string]any{"oauth_bundle": envelope}, Extra: map[string]any{GatewayGenerationExtraKey: f.scope.Generation, GatewayProfileExtraKey: GatewayOAuthStagingProfile, GatewayCredentialScopeExtraKey: f.scope.Metadata()}}
	p := GatewayNativeOAuthPhysical{Scope: f.scope, Operation: uuid.NewString(), Route: GatewayNativeRoute{AccountID: a.ID, Generation: f.scope.Generation, CreatedAt: created, Profile: GatewayCodexOAuthResponsesProfile, BaseURL: GatewayCodexOAuthBaseURL, Model: GatewayCodexOAuthModel}, Issuer: GatewayOAuthIssuer, Subject: subject}
	f.store = &oauthDispatchStore{row: a, physical: p, connectState: "completed"}
	f.dispatch, err = NewGatewayNativeOAuthDispatch(f.store, custody, NewGatewayNativeOAuthVerifier(transport), transport)
	require.NoError(t, err)
	upstream, err := NewGatewayNativeLifetimeUpstream(&gatewayIdentityRealHTTP{client: &http.Client{Transport: transport}})
	require.NoError(t, err)
	f.svc = &OpenAIGatewayService{accountRepo: f.store, httpUpstream: upstream, cfg: rawChatCompletionsTestConfig()}
	return f
}

func (f *oauthDispatchFixture) qualify(t *testing.T) GatewayNativeRoute {
	t.Helper()
	out, err := f.dispatch.Descriptor(f.ctx, f.scope, f.store.physical.Operation)
	require.NoError(t, err)
	require.NotNil(t, out.Native)
	require.Equal(t, GatewayCodexOAuthQualification, out.Qualification)
	require.False(t, f.store.row.IsSchedulable())
	require.Equal(t, StatusDisabled, f.store.row.Status)
	return *out.Native
}
func oauthDispatchPayload() []byte {
	return []byte(`{"model":"gpt-6.1-sol","stream":true,"store":false,"service_tier":"default","max_output_tokens":128,"input":"controlled fixture","tools":[{"type":"custom","name":"exec","format":{"type":"text"}}]}`)
}
func (f *oauthDispatchFixture) call(t *testing.T, route GatewayNativeRoute, body []byte) (*httptest.ResponseRecorder, bool, error, *GatewayNativeLifetime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	t.Cleanup(cancel)
	life, err := NewGatewayNativeLifetime(ctx, cancel, func() {}, 4096)
	require.NoError(t, err)
	life.BindAccount(f.scope.Consumer, f.scope.Account, f.scope.Generation)
	require.True(t, life.Admit(time.Now().Add(time.Second)))
	ctx = WithGatewayNativeLifetime(ctx, life)
	ctx = WithGatewayNativeProviderReadIdle(ctx, 50*time.Millisecond)
	ctx, err = WithGatewayNativeOAuthDispatch(ctx, f.dispatch, f.scope, f.store.physical.Operation, 4096, 128)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
	for _, header := range []string{"Authorization", "ChatGPT-Account-Id", "X-Codex-Turn-State", "Cookie", "X-Api-Key", "Origin", "Idempotency-Key", "X-Idempotency-Key", "X-Caller-Only"} {
		c.Request.Header.Set(header, uuid.NewString())
	}
	_, entered, err := f.svc.ForwardGatewayRoute(ctx, c, route, body)
	f.lastContext = c.Request.Context()
	return rec, entered, err, life
}

func TestGatewayOAuthDescriptorControlledTLSSelection(t *testing.T) {
	for _, state := range []string{"prepared", "entered", "unknown", "expired"} {
		t.Run("connect-"+state+"-cannot-qualify-custody", func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			f.store.connectState = state
			out, err := f.dispatch.Descriptor(f.ctx, f.scope, f.store.physical.Operation)
			require.NoError(t, err)
			require.Equal(t, "pending", out.Qualification)
			require.Nil(t, out.Native)
			require.Zero(t, f.store.locks)
			require.Zero(t, f.checks.Load())
			require.Zero(t, f.entries.Load())
			require.Equal(t, state, f.store.connectState)
		})
	}
	for _, scenario := range []string{"ambiguous", "expired", "bad-expiry", "disabled", "disabled-alias", "invalid-utf8", "map-key-only", "duplicate-account", "case-alias", "escaped-duplicate", "redirect", "over-limit", "wrong-principal", "tampered-custody"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			switch scenario {
			case "ambiguous":
				f.accountCheck = fmt.Sprintf(`{"accounts":{"first":{"account":{"account_id":%q,"is_default":true},"entitlement":{"subscription_plan":"paid"}},"second":{"account":{"account_id":%q}}}}`, uuid.NewString(), uuid.NewString())
			case "expired":
				f.accountCheck = fmt.Sprintf(`{"accounts":{"one":{"account":{"account_id":%q},"entitlement":{"expires_at":%q}}}}`, uuid.NewString(), time.Now().Add(-time.Second).Format(time.RFC3339))
			case "bad-expiry":
				f.accountCheck = fmt.Sprintf(`{"accounts":{"one":{"account":{"account_id":%q},"entitlement":{"expires_at":"bad"}}}}`, uuid.NewString())
			case "disabled":
				f.accountCheck = fmt.Sprintf(`{"accounts":{"one":{"account":{"account_id":%q,"disabled":true}}}}`, uuid.NewString())
			case "disabled-alias":
				f.accountCheck = fmt.Sprintf(`{"accounts":{"one":{"account":{"account_id":%q,"DISABLED":true}}}}`, uuid.NewString())
			case "invalid-utf8":
				f.accountCheck = "{\"accounts\":{\"\xff\":{}}}"
			case "map-key-only":
				f.accountCheck = fmt.Sprintf(`{"accounts":{%q:{"account":{"is_default":true}}}}`, uuid.NewString())
			case "duplicate-account":
				id := uuid.NewString()
				f.accountCheck = fmt.Sprintf(`{"accounts":{"one":{"account":{"account_id":%q}},"two":{"account":{"account_id":%q}}}}`, id, id)
			case "case-alias":
				f.accountCheck = strings.ReplaceAll(f.accountCheck, "account_id", "ACCOUNT_ID")
			case "escaped-duplicate":
				f.accountCheck = `{"accounts":{},"\u0061ccounts":{}}`
			case "redirect":
				f.accountStatus = http.StatusFound
			case "over-limit":
				f.accountCheck = strings.Repeat(" ", 65537)
			case "wrong-principal":
				f.store.physical.Subject = uuid.NewString()
			case "tampered-custody":
				parts := strings.Split(f.store.row.GetCredential("oauth_bundle"), ".")
				parts[3] = strings.Repeat("A", len(parts[3]))
				f.store.row.Credentials["oauth_bundle"] = strings.Join(parts, ".")
			}
			out, err := f.dispatch.Descriptor(f.ctx, f.scope, f.store.physical.Operation)
			if scenario == "wrong-principal" || scenario == "tampered-custody" {
				require.Error(t, err)
				require.Zero(t, f.checks.Load())
			} else {
				require.NoError(t, err)
				require.EqualValues(t, 1, f.checks.Load())
			}
			require.Nil(t, out.Native)
			require.Equal(t, "pending", out.Qualification)
			require.Zero(t, f.store.qualifications)
			require.Zero(t, f.entries.Load())
			raw, err := json.Marshal(out)
			require.NoError(t, err)
			for _, secret := range []string{f.bundle.AccessToken, f.bundle.RefreshToken, f.bundle.IDToken, f.store.physical.Subject, "credential_version", "account_id", "base_url"} {
				require.NotContains(t, string(raw), secret)
			}
		})
	}
	t.Run("canonical returned ID differs from workspace key and signed subject", func(t *testing.T) {
		f := newOAuthDispatchFixture(t)
		route := f.qualify(t)
		require.Equal(t, GatewayCodexOAuthBaseURL, route.BaseURL)
		require.NotEqual(t, f.store.physical.Subject, f.store.physical.ProviderAccount)
		out, err := f.dispatch.Descriptor(f.ctx, f.scope, f.store.physical.Operation)
		require.NoError(t, err)
		require.NotNil(t, out.Native)
		require.EqualValues(t, 1, f.checks.Load())
		require.Equal(t, 1, f.store.qualifications)
	})
}

func TestGatewayOAuthNativeResponsesRefreshBeforeEntryAndCancellation(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	route := f.qualify(t)
	newAccess := uuid.NewString()
	next := f.bundle
	next.AccessToken = newAccess
	envelope, err := f.dispatch.custody.sealOAuthVersion(f.scope, 2, next)
	require.NoError(t, err)
	// Descriptor read is lock1. Forward snapshot is lock2, actual entry is lock3.
	f.store.beforeLock = func(n int) {
		if n == 3 {
			f.store.row.Credentials = map[string]any{"oauth_bundle": envelope, "credential_version": "2"}
		}
	}
	body := oauthDispatchPayload()
	rec, entered, err, life := f.call(t, route, body)
	require.NoError(t, err)
	require.True(t, entered)
	require.EqualValues(t, 1, f.entries.Load())
	require.Equal(t, "Bearer "+newAccess, f.lastAuthorization.Load())
	require.Equal(t, string(body), f.lastPayload.Load())
	require.Contains(t, rec.Body.String(), "custom_tool_call")
	require.Contains(t, rec.Body.String(), "controlled final")
	snapshot := life.Snapshot()
	require.True(t, snapshot.Completed)
	require.True(t, snapshot.ForwardingReturned)
	require.True(t, snapshot.ContextDone)
	require.True(t, snapshot.BodyClosed)
	require.False(t, snapshot.CloseFailed)
	state := f.lastContext.Value(gatewayNativeContextKey{}).(*gatewayNativeDispatch)
	request, err := http.NewRequestWithContext(f.lastContext, http.MethodPost, GatewayCodexOAuthBaseURL+"/responses", bytes.NewReader(body))
	require.NoError(t, err)
	_, err = f.svc.doOpenAIUpstream(request, "", state.account)
	require.Error(t, err)
	require.EqualValues(t, 1, f.entries.Load())
	for _, mode := range []string{"partial", "error", "hold"} {
		t.Run(mode, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			f.mode = mode
			rec, entered, err, life := f.call(t, route, oauthDispatchPayload())
			require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
			require.True(t, entered)
			require.EqualValues(t, 1, f.entries.Load())
			require.False(t, life.Snapshot().Completed)
			require.NotContains(t, rec.Body.String(), f.bundle.AccessToken)
			require.Eventually(t, func() bool { s := life.Snapshot(); return s.ForwardingReturned && s.ContextDone && s.BodyClosed }, time.Second, time.Millisecond)
		})
	}
}

func TestGatewayOAuthInvalidEntryHasNoProviderEffect(t *testing.T) {
	for _, scenario := range []string{"unowned-transport", "wrong-birth", "wrong-created", "wrong-row", "wrong-profile", "wrong-owner", "wrong-principal", "wrong-operation-at-entry", "erased", "grouped", "proxy", "model-alias", "store", "previous", "cap-alias", "cap-type", "bytes", "unqualified", "unsigned", "expired-current"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			body := oauthDispatchPayload()
			switch scenario {
			case "unowned-transport":
				f.svc.httpUpstream = f.svc.httpUpstream.(*gatewayNativeLifetimeUpstream).HTTPUpstream
			case "wrong-birth":
				route.Generation = uuid.NewString()
			case "wrong-created":
				route.CreatedAt = route.CreatedAt.Add(time.Microsecond)
			case "wrong-row":
				route.AccountID++
			case "wrong-profile":
				route.BaseURL = "https://chatgpt.com/backend-api/codex/"
			case "wrong-owner":
				f.store.row.Extra[GatewayCredentialScopeExtraKey] = GatewayNativeCredentialScope{Consumer: f.scope.Consumer, Owner: uuid.NewString(), Account: f.scope.Account, Generation: f.scope.Generation, Purpose: GatewayOAuthBundlePurpose}.Metadata()
			case "wrong-principal":
				f.store.physical.Subject = uuid.NewString()
			case "wrong-operation-at-entry":
				f.store.beforeLock = func(n int) {
					if n == 3 {
						f.store.physical.Operation = uuid.NewString()
					}
				}
			case "erased":
				f.store.reject = true
			case "grouped":
				f.store.row.GroupIDs = []int64{1}
			case "proxy":
				id := int64(1)
				f.store.row.ProxyID = &id
			case "model-alias":
				body = bytes.ReplaceAll(body, []byte("gpt-6.1-sol"), []byte("gpt-6.1"))
			case "store":
				body = bytes.ReplaceAll(body, []byte(`"store":false`), []byte(`"store":true`))
			case "previous":
				body = bytes.ReplaceAll(body, []byte(`"store":false`), []byte(`"store":false,"previous_response_id":null`))
			case "cap-alias":
				body = bytes.ReplaceAll(body, []byte(`"max_output_tokens":128`), []byte(`"max_output_tokens":128,"MAX_OUTPUT_TOKENS":1`))
			case "cap-type":
				body = bytes.ReplaceAll(body, []byte(`"max_output_tokens":128`), []byte(`"max_output_tokens":"128"`))
			case "bytes":
				body = append(body, bytes.Repeat([]byte(" "), 4096)...)
			case "unqualified":
				f.store.physical.QualifiedAt = time.Time{}
			case "unsigned", "expired-current":
				bundle := f.bundle
				if scenario == "unsigned" {
					parts := strings.Split(bundle.IDToken, ".")
					bundle.IDToken = parts[0] + "." + parts[1] + "."
				} else {
					f.dispatch.verifier.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
				}
				envelope, err := f.dispatch.custody.sealOAuthVersion(f.scope, 2, bundle)
				require.NoError(t, err)
				f.store.row.Credentials = map[string]any{"oauth_bundle": envelope, "credential_version": "2"}
			}
			_, entered, err, _ := f.call(t, route, body)
			require.Error(t, err)
			require.False(t, entered)
			require.Zero(t, f.entries.Load())
		})
	}
}

// Removing the retained post-JWKS fence permits provider entry after ambiguity
// publication or a prepared deadline crossing during signed JWKS verification.
func TestGatewayOAuthRetainedFenceAfterSignedJWKS(t *testing.T) {
	for _, mode := range []string{"unknown", "entered", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newOAuthDispatchFixture(t)
			route := f.qualify(t)
			f.store.beforeLock = func(n int) {
				if n == 3 {
					switch mode {
					case "unknown":
						f.store.fenceUnknown = true
					case "entered":
						f.store.fenceEntered = true
					case "deadline":
						f.store.fenceDeadline = time.Now().Add(20 * time.Millisecond)
						f.jwksDelay = 60 * time.Millisecond
					}
				}
			}
			_, entered, err, life := f.call(t, route, oauthDispatchPayload())
			require.Error(t, err)
			require.False(t, entered)
			require.Zero(t, f.entries.Load())
			require.Equal(t, 1, f.store.fenceChecks)
			require.False(t, life.Snapshot().Entered)
		})
	}
}
