//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Metadata is a fixture; the upstream is a REAL local HTTP server, not a mock
// dispatch return. SQL constraint and locking proof is in the separate DB suite.
type gatewayIdentityRepoFixture struct {
	AccountRepository
	row   *Account
	fresh *Account
}

func (r *gatewayIdentityRepoFixture) GetByID(context.Context, int64) (*Account, error) {
	return r.row, nil
}
func (r *gatewayIdentityRepoFixture) LockGatewayNativeAccount(context.Context, int64) (*Account, func(), error) {
	a := r.fresh
	if a == nil {
		a = r.row
	}
	return a, func() {}, nil
}

type gatewayIdentityRealHTTP struct {
	HTTPUpstream
	client *http.Client
}

func (h *gatewayIdentityRealHTTP) Do(r *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return h.client.Do(r)
}

func TestGatewayNativeIdentity_ActualForwardBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var dispatches atomic.Int32
	var authorization atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatches.Add(1)
		authorization.Store(r.Header.Get("Authorization"))
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "mimo-test", body["model"])
		require.Contains(t, body, "messages", "Responses must enter the native CC bridge")
		require.Contains(t, body, "tools")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"test-cc","model":"mimo-test","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_a","type":"function","function":{"name":"exec","arguments":"{\"input\":\"echo test\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer upstream.Close()
	a := &Account{ID: 17, CreatedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
		Credentials: map[string]any{"api_key": "fixture-key", "base_url": upstream.URL},
		Extra: map[string]any{GatewayGenerationExtraKey: "11111111-1111-4111-8111-111111111111", GatewayProfileExtraKey: GatewayLegacyBridgeProfile, GatewayModelExtraKey: "mimo-test",
			"openai_responses_mode": "force_chat_completions", "openai_passthrough": false, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	nativeFixtureSealAccount(t, a)
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	repo := &gatewayIdentityRepoFixture{row: a}
	svc := &OpenAIGatewayService{accountRepo: repo, httpUpstream: &gatewayIdentityRealHTTP{client: upstream.Client()}, cfg: rawChatCompletionsTestConfig()}
	body := []byte(`{"model":"mimo-test","input":"test","store":false,"tools":[{"type":"custom","name":"exec","description":"sandbox shell"}]}`)
	call := func(r GatewayNativeRoute, payload []byte) (*httptest.ResponseRecorder, bool, error) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
		_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, r, payload)
		return recorder, entered, err
	}
	t.Run("same integer foreign generation denies before forwarding", func(t *testing.T) {
		foreign := *a
		foreign.Extra = map[string]any{}
		for k, v := range a.Extra {
			foreign.Extra[k] = v
		}
		foreign.Extra[GatewayGenerationExtraKey] = "22222222-2222-4222-8222-222222222222"
		repo.row = &foreign
		_, entered, err := call(route, body)
		require.Error(t, err)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.row = a
	})
	t.Run("fresh row changed between read and transport denies", func(t *testing.T) {
		fresh := *a
		fresh.Credentials = map[string]any{"api_key": "different-sandbox-key", "base_url": upstream.URL}
		repo.fresh = &fresh
		_, entered, err := call(route, body)
		require.Error(t, err)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
		repo.fresh = nil
	})
	t.Run("previous response cannot choose native affinity", func(t *testing.T) {
		_, entered, err := call(route, []byte(`{"model":"mimo-test","previous_response_id":"foreign"}`))
		require.Error(t, err)
		require.False(t, entered)
		require.EqualValues(t, 0, dispatches.Load())
	})
	t.Run("matching owned Responses custom tool enters exactly once", func(t *testing.T) {
		rec, entered, err := call(route, body)
		require.NoError(t, err)
		require.True(t, entered)
		require.EqualValues(t, 1, dispatches.Load())
		require.Equal(t, "Bearer fixture-key", authorization.Load())
		require.Contains(t, rec.Body.String(), `"type":"custom_tool_call"`)
	})
	t.Run("same native context refuses a second transport", func(t *testing.T) {
		state := &gatewayNativeDispatch{route: route, account: a, scope: nativeFixtureScope(a), custody: nativeFixtureCustody(t)}
		state.entered.Store(true)
		request, _ := http.NewRequestWithContext(context.WithValue(nativeFixtureContext(t, context.Background()), gatewayNativeContextKey{}, state), http.MethodPost, upstream.URL+"/v1/chat/completions", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+a.GetCredential("api_key"))
		_, err := svc.doOpenAIUpstream(request, "", a)
		require.ErrorIs(t, err, ErrGatewayNativeReplay)
		require.EqualValues(t, 1, dispatches.Load())
	})
	t.Run("ordinary callers cannot forward managed credential", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat/completions", bytes.NewReader(body))
		_, err := svc.doOpenAIUpstream(request, "", a)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		require.False(t, a.IsSchedulable())
		require.EqualValues(t, 1, dispatches.Load())
	})
}

func (r *gatewayIdentityRepoFixture) GetByIDs(context.Context, []int64) ([]*Account, error) {
	return []*Account{r.row}, nil
}

func TestGatewayNativeIdentity_ControlAndInertCreation(t *testing.T) {
	input := &CreateAccountInput{Name: "fixture", Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Credentials: map[string]any{"api_key": "fixture-key", "base_url": "https://example.invalid/v1"}}
	extra := map[string]any{GatewayGenerationExtraKey: "55555555-5555-4555-8555-555555555555",
		GatewayProfileExtraKey: GatewayMiMoResponsesProfile, GatewayModelExtraKey: "fixture-model",
		"openai_responses_mode": "force_responses", "openai_passthrough": true,
		"native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}
	fixture := nativeFixtureSealAccount(t, &Account{Credentials: input.Credentials, Extra: extra})
	input.Credentials, input.Extra = fixture.Credentials, fixture.Extra
	a, err := buildAccountForCreate(input, extra)
	require.NoError(t, err)
	require.Equal(t, "disabled", a.Status)
	require.False(t, a.IsActive())
	require.False(t, a.Schedulable)
	require.Empty(t, a.GroupIDs)
	require.Empty(t, a.AccountGroups)
	require.False(t, isUpstreamBillingProbeAccount(a))
	admin := &adminServiceImpl{accountRepo: &gatewayIdentityRepoFixture{row: a}}
	_, err = admin.CreateAccount(context.Background(), input)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = admin.GetAccount(context.Background(), 17)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = admin.GetAccountsByIDs(context.Background(), []int64{17})
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = admin.UpdateAccount(context.Background(), 17, &UpdateAccountInput{Status: StatusActive})
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = admin.BulkUpdateAccounts(context.Background(), &BulkUpdateAccountsInput{AccountIDs: []int64{17}})
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
}
