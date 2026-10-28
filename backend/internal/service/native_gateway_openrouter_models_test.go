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
	"github.com/stretchr/testify/require"
)

type openRouterModelsRoundTrip func(*http.Request) (*http.Response, error)

func (f openRouterModelsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func openRouterModelRow(id string, tools bool) string {
	parameters := `[]`
	if tools {
		parameters = `["tools","reasoning"]`
	}
	return fmt.Sprintf(`{"id":%q,"architecture":{"input_modalities":["text"],"output_modalities":["text"]},"supported_parameters":%s,"description":"PRIVATE-DESCRIPTION"}`, id, parameters)
}

func openRouterModelsFixture(t *testing.T, raw *string) *GatewayOpenRouterModels {
	t.Helper()
	return NewGatewayOpenRouterModels(openRouterModelsRoundTrip(func(request *http.Request) (*http.Response, error) {
		require.Equal(t, gatewayOpenRouterModelsURL, request.URL.String())
		require.Equal(t, http.MethodGet, request.Method)
		require.Empty(t, request.Header.Get("Authorization"))
		require.Empty(t, request.Header.Get("Cookie"))
		return &http.Response{StatusCode: http.StatusOK, Request: request, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(*raw))}, nil
	}))
}

func TestGatewayOpenRouterModelsFullDynamicProjection(t *testing.T) {
	rows := []string{}
	for i := range 180 {
		rows = append(rows, openRouterModelRow(fmt.Sprintf("unseen-vendor/model-%d:free", i), i%2 == 0))
	}
	models, err := parseGatewayOpenRouterModels([]byte(`{"data":[` + strings.Join(rows, ",") + `]}`))
	require.NoError(t, err)
	require.Len(t, models, 180, "a full catalogue must not silently truncate at the Codex bound")
	require.Equal(t, "unseen-vendor/model-179:free", models[179].ModelID)
	require.Nil(t, models[0].Fast)
	require.Nil(t, models[0].Reasoning, "a parameter name does not advertise accepted effort values")
	require.Equal(t, []string{"none", "function"}, models[0].Tools.Allowed)
	require.Equal(t, []string{"none"}, models[1].Tools.Allowed)
	wire, err := json.Marshal(models)
	require.NoError(t, err)
	require.NotContains(t, string(wire), "PRIVATE-DESCRIPTION")
	for _, id := range []string{"openrouter/auto", "openrouter/free", "openrouter/owl"} {
		models, err := parseGatewayOpenRouterModels([]byte(`{"data":[` + openRouterModelRow(id, true) + `]}`))
		require.NoError(t, err)
		require.Equal(t, id, models[0].ModelID, "router aliases are admitted only by the same live membership")
	}
}

func TestGatewayOpenRouterModelsMalformedAndUnsupported(t *testing.T) {
	row := openRouterModelRow("vendor/model", true)
	for _, raw := range []string{
		`{}`, `{"data":null}`, `{"data":[],"Data":[]}`,
		`{"data":[` + row + `,` + row + `]}`,
		`{"data":[` + strings.Replace(row, `"vendor/model"`, `"https://forbidden.invalid/model"`, 1) + `]}`,
		`{"data":[` + strings.Replace(row, `"id":`, `"id":"vendor/other","id":`, 1) + `]}`,
		`{"data":[` + strings.Replace(row, `"supported_parameters":["tools","reasoning"]`, `"supported_parameters":"tools"`, 1) + `]}`,
	} {
		_, err := parseGatewayOpenRouterModels([]byte(raw))
		require.Error(t, err, raw)
	}
	rows := strings.Repeat(row+",", gatewayOpenRouterModelsMaximum) + openRouterModelRow("last/model", true)
	_, err := parseGatewayOpenRouterModels([]byte(`{"data":[` + rows + `]}`))
	require.Error(t, err)
	models, err := parseGatewayOpenRouterModels([]byte(`{"data":[` + strings.Replace(row, `"output_modalities":["text"]`, `"output_modalities":["image"]`, 1) + `]}`))
	require.NoError(t, err)
	require.Empty(t, models)
}

func TestGatewayOpenRouterModelsSourcePolicyAndCache(t *testing.T) {
	var calls atomic.Int32
	redirect := false
	source := NewGatewayOpenRouterModels(openRouterModelsRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		require.Equal(t, gatewayOpenRouterModelsURL, request.URL.String())
		require.Empty(t, request.Header.Get("Authorization"))
		if redirect {
			return &http.Response{StatusCode: 302, Request: request, Header: http.Header{"Location": []string{"https://other.invalid/models"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Request: request, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"data":[` + openRouterModelRow("fresh/model", true) + `]}`))}, nil
	}))
	first := source.read(context.Background(), "principal-a", false)
	require.Equal(t, "snapshot", first.Status)
	require.Equal(t, "snapshot", source.read(context.Background(), "principal-a", false).Status)
	require.EqualValues(t, 1, calls.Load())
	require.Equal(t, "snapshot", source.read(context.Background(), "principal-b", false).Status)
	require.EqualValues(t, 2, calls.Load(), "another credential principal has its own observation")
	redirect = true
	require.Equal(t, GatewayAccountModelsResult{Status: "unavailable"}, source.read(context.Background(), "principal-a", true))
	require.EqualValues(t, 3, calls.Load(), "redirect is not followed")
	require.False(t, gatewayOpenRouterModelsAllow(first, "birth/model", "missing/model", []byte(`{}`)))
	first.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	require.False(t, gatewayOpenRouterModelsAllow(first, "birth/model", "fresh/model", []byte(`{}`)), "expired observations never admit a model")
}

func TestGatewayOpenRouterModelsAccountFences(t *testing.T) {
	for _, change := range []string{"none", "owner", "epoch", "generation", "credential", "scope"} {
		t.Run(change, func(t *testing.T) {
			account := nativeReviewStreamAccount(t, GatewayOpenRouterBaseURL, GatewayOpenRouterResponsesProfile)
			account.Extra[GatewayModelExtraKey] = "birth/model"
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			scope, err := GatewayNativeCredentialScopeForAccount(account)
			require.NoError(t, err)
			repo := &gatewayIdentityRepoFixture{row: account}
			gateway := &OpenAIGatewayService{accountRepo: repo}
			raw := `{"data":[` + openRouterModelRow("future/model:free", true) + `]}`
			require.NoError(t, gateway.SetGatewayOpenRouterModels(openRouterModelsFixture(t, &raw)))
			calls := 0
			reader, err := NewGatewayAccountModelsReader(nil, gateway, func(_ context.Context, input GatewayAccountLimitsInput) (GatewayNativeRoute, error) {
				calls++
				if input.OwnerRef != scope.Owner || input.ExpectedAuthorizationEpoch != 7 {
					return GatewayNativeRoute{}, ErrGatewayNativeIdentity
				}
				if calls == 2 {
					switch change {
					case "generation":
						changed := route
						changed.Generation = "changed"
						return changed, nil
					case "credential":
						account.Credentials["api_key"] = "changed"
					case "scope":
						changed := scope
						changed.Owner = "foreign"
						account.Extra[GatewayCredentialScopeExtraKey] = changed.Metadata()
					}
				}
				return route, nil
			})
			require.NoError(t, err)
			input := GatewayAccountModelsInput{GatewayAccountLimitsInput: GatewayAccountLimitsInput{scope.Owner, scope.Account, route.Profile, 7}}
			if change == "owner" {
				input.OwnerRef = "foreign"
			}
			if change == "epoch" {
				input.ExpectedAuthorizationEpoch = 8
			}
			out := reader.Read(nativeFixtureContext(t, context.Background()), input)
			if change != "none" {
				require.Equal(t, GatewayAccountModelsResult{Status: "unavailable"}, out)
				return
			}
			require.Equal(t, "snapshot", out.Status)
			require.Equal(t, "openrouter", out.Source)
			require.Equal(t, route.Generation, out.PhysicalGeneration)
			require.NotEmpty(t, out.PrincipalVersion)
			wire, err := json.Marshal(out)
			require.NoError(t, err)
			require.NotContains(t, string(wire), account.GetCredential("api_key"))
			require.NotContains(t, string(wire), "PRIVATE-DESCRIPTION")
		})
	}
}

func TestGatewayOpenRouterModelsDynamicRealHTTPDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var entries, reads atomic.Int32
	model := "unseen-vendor/new-model:free"
	raw := `{"data":[` + openRouterModelRow(model, true) + `]}`
	var sent atomic.Value
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/models" {
			reads.Add(1)
			require.Empty(t, request.Header.Get("Authorization"))
			_, _ = io.WriteString(w, raw)
			return
		}
		entries.Add(1)
		require.Equal(t, "/api/v1/responses", request.URL.Path)
		require.Equal(t, "Bearer sandbox-fixture", request.Header.Get("Authorization"))
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		sent.Store(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer provider.Close()
	local := provider.Client().Transport.(*http.Transport).Clone()
	local.Proxy = nil
	local.TLSClientConfig.ServerName = "example.com"
	local.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "openrouter.ai:443", address)
		return (&net.Dialer{}).DialContext(ctx, network, provider.Listener.Addr().String())
	}
	defer local.CloseIdleConnections()
	account := nativeReviewStreamAccount(t, GatewayOpenRouterBaseURL, GatewayOpenRouterResponsesProfile)
	account.Extra[GatewayModelExtraKey] = "birth/anchor"
	route, err := GatewayNativeDescriptor(account)
	require.NoError(t, err)
	repo := &gatewayIdentityRepoFixture{row: account}
	gateway := &OpenAIGatewayService{accountRepo: repo, httpUpstream: &gatewayIdentityRealHTTP{client: &http.Client{Transport: local}}, cfg: rawChatCompletionsTestConfig()}
	require.NoError(t, gateway.SetGatewayOpenRouterModels(NewGatewayOpenRouterModels(local)))
	call := func(payload []byte) (bool, error) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
		_, entered, err := gateway.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
		return entered, err
	}
	payload := []byte(fmt.Sprintf(`{"model":%q,"input":"text","store":false,"tools":[{"type":"custom","name":"exec","format":{"type":"text"}}]}`, model))
	entered, err := call(payload)
	require.NoError(t, err)
	require.True(t, entered)
	require.EqualValues(t, 1, entries.Load())
	require.EqualValues(t, 1, reads.Load())
	require.Contains(t, sent.Load().(string), `"model":"unseen-vendor/new-model:free"`)
	require.Contains(t, sent.Load().(string), `"type":"function"`, "existing custom tools use the function codec")
	require.Equal(t, "birth/anchor", route.Model)
	fresh := snapshotGatewayNativeAccount(account)
	scope, err := GatewayNativeCredentialScopeForAccount(account)
	require.NoError(t, err)
	fresh.Credentials["api_key"], err = nativeFixtureCustody(t).Seal(scope, "rotated-fixture-key")
	require.NoError(t, err)
	repo.fresh = fresh
	entered, err = call(payload)
	require.Error(t, err)
	require.False(t, entered, "credential rotation after catalogue admission fences provider entry")
	repo.fresh = nil
	for _, invalid := range []string{
		strings.Replace(string(payload), model, "not-discovered/model", 1),
		strings.TrimSuffix(string(payload), "}") + `,"reasoning":{"effort":"high"}}`,
		strings.TrimSuffix(string(payload), "}") + `,"models":["not-discovered/model"]}`,
		strings.TrimSuffix(string(payload), "}") + `,"route":"fallback"}`,
		strings.TrimSuffix(string(payload), "}") + `,"plugins":[{"id":"web"}]}`,
		strings.TrimSuffix(string(payload), "}") + `,"background":true}`,
	} {
		entered, err = call([]byte(invalid))
		require.Error(t, err)
		require.False(t, entered)
	}
	raw = `{"data":[]}`
	result := gateway.gatewayOpenRouterModels.read(context.Background(), gatewayOpenRouterModelsPrincipal(scope, account.GetCredential("api_key")), true)
	require.Equal(t, "snapshot", result.Status)
	require.Empty(t, *result.Models)
	entered, err = call(payload)
	require.Error(t, err)
	require.False(t, entered)
	require.EqualValues(t, 1, entries.Load(), "removed models stop before provider entry")
}
