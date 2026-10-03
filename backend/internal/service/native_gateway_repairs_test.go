//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const nativeRepairText = `{"choices":[{"index":0,"message":{"role":"assistant","content":"fixture"},"finish_reason":"stop"}]}`
const nativeRepairTools = `{"choices":[{"index":0,"message":{"role":"assistant","content":"fixture","tool_calls":[{"id":"call_fixture","type":"function","function":{"name":"exec","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
const nativeRepairRequest = `{"model":"mimo-test","input":"sandbox","stream":false}`

const nativeRepairToolDelta = "data: " + `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fixture","type":"function","function":{"name":"exec","arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n"

type nativeRepairOutcome struct {
	result            *OpenAIForwardResult
	entered           bool
	err               error
	body              string
	entries, requests int32
	outbound          []byte
}

type nativeRepairPrivateCache struct{ GatewayCache }

func (nativeRepairPrivateCache) GetGatewayNativeReasoningContent(context.Context, string, string) (string, error) {
	return "", ErrReasoningContentNotFound
}
func (nativeRepairPrivateCache) SetGatewayNativeReasoningContent(context.Context, string, string, string, time.Duration) error {
	return errors.New("account_id=17 generation=99999999-9999-4999-8999-999999999999 origin=http://127.0.0.1 key=sandbox-fixture")
}

// The actual transport and both protocol paths run against a local HTTP peer.
func nativeRepairForward(t *testing.T, profile, request, response string, stream bool, decorate func(*gin.Context)) nativeRepairOutcome {
	t.Helper()
	var requests atomic.Int32
	var outbound []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var err error
		outbound, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
		}
		_, _ = io.WriteString(w, response)
	}))
	defer upstream.Close()
	a := nativeReviewStreamAccount(t, upstream.URL, profile)
	if profile == "" {
		a = &Account{ID: 23, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: a.Credentials}
	}
	transport := &gatewayBoundaryReviewHTTP{gatewayIdentityRealHTTP: gatewayIdentityRealHTTP{client: upstream.Client()}}
	svc := &OpenAIGatewayService{cache: nativeRepairPrivateCache{}, accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewBufferString(request))
	if decorate != nil {
		decorate(c)
	}
	var got nativeRepairOutcome
	if profile == "" {
		got.result, got.err = svc.forwardResponsesViaRawChatCompletions(context.Background(), c, a, []byte(request))
	} else {
		route, err := GatewayNativeDescriptor(a)
		require.NoError(t, err)
		got.result, got.entered, got.err = svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, []byte(request))
	}
	got.body, got.entries, got.requests, got.outbound = rec.Body.String(), transport.entries.Load(), requests.Load(), outbound
	return got
}

func TestGatewayNativeRepairPolicyCaseAliases(t *testing.T) {
	for _, profile := range []string{GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile} {
		for _, field := range []struct {
			canonical, value string
			aliases          []string
		}{
			{"model", `"foreign-model"`, []string{"MODEL", "Model", `\u004dodel`}},
			{"store", `true`, []string{"STORE", "Store", `\u0053tore`, "ſtore"}},
			{"previous_response_id", `"foreign-response"`, []string{"PREVIOUS_RESPONSE_ID", "Previous_Response_Id", `\u0050revious_response_id`, "previouſ_response_id"}},
			{"service_tier", `"priority"`, []string{"SERVICE_TIER", "Service_Tier", `\u0053ervice_tier`, "ſervice_tier"}},
		} {
			for _, alias := range field.aliases {
				for _, alongside := range []bool{false, true} {
					t.Run(profile+"/"+alias+"/"+map[bool]string{false: "alone", true: "alongside"}[alongside], func(t *testing.T) {
						prefix := `{"input":"sandbox",`
						if field.canonical != "model" || alongside {
							prefix += `"model":"mimo-test",`
						}
						if alongside && field.canonical != "model" {
							prefix += `"store":false,"previous_response_id":"","service_tier":"default",`
						}
						got := nativeRepairForward(t, profile, prefix+`"`+alias+`":`+field.value+`}`, nativeRepairText, false, nil)
						require.ErrorIs(t, got.err, ErrGatewayNativeIdentity)
						require.False(t, got.entered)
						require.Nil(t, got.result)
						require.Zero(t, got.entries)
						require.Zero(t, got.requests)
					})
				}
			}
		}
		request := ` {"mo\u0064el":"mimo-test","s\u0074ore":false,"previous_response_\u0069d":"","service_\u0074ier":"default","input":"sandbox","tools":[{"type":"function","name":"MODEL","parameters":{"type":"object"}}],"metadata":{"MODEL":"nested"}} `
		response := nativeRepairText
		if profile == GatewayMiMoResponsesProfile {
			response = `{"status":"completed","output":[]}`
		}
		got := nativeRepairForward(t, profile, request, response, false, nil)
		require.NoError(t, got.err)
		require.EqualValues(t, 1, got.entries)
		require.Equal(t, "mimo-test", gjson.GetBytes(got.outbound, "model").String())
		if profile == GatewayMiMoResponsesProfile {
			require.Equal(t, request, string(got.outbound))
		}
	}
}

func TestGatewayNativeRepairLegacyBufferedQualification(t *testing.T) {
	cases := []struct {
		name, wire string
		success    bool
	}{
		{"text", nativeRepairText, true}, {"text and tools", nativeRepairTools, true},
		{"text parts", strings.Replace(nativeRepairText, `"content":"fixture"`, `"content":[{"type":"text","text":"fixture"}]`, 1), true},
		{"malformed JSON", `{invalid`, false},
		{"empty object", `{}`, false}, {"null", `null`, false}, {"empty choices", `{"choices":[]}`, false},
		{"error only", `{"error":{"message":"fixture"}}`, false},
		{"missing finish", strings.Replace(nativeRepairText, `,"finish_reason":"stop"`, "", 1), false},
		{"null finish", strings.Replace(nativeRepairText, `"stop"`, `null`, 1), false},
		{"length", strings.Replace(nativeRepairText, `"stop"`, `"length"`, 1), false},
		{"filter", strings.Replace(nativeRepairText, `"stop"`, `"content_filter"`, 1), false},
		{"unknown finish", strings.Replace(nativeRepairText, `"stop"`, `"other"`, 1), false},
		{"missing message", `{"choices":[{"index":0,"finish_reason":"stop"}]}`, false},
		{"missing content", strings.Replace(nativeRepairText, `,"content":"fixture"`, "", 1), false},
		{"null content", strings.Replace(nativeRepairText, `"content":"fixture"`, `"content":null`, 1), false},
		{"wrong role", strings.Replace(nativeRepairText, `"assistant"`, `"user"`, 1), false},
		{"missing index", strings.Replace(nativeRepairText, `"index":0,`, "", 1), false},
		{"null index", strings.Replace(nativeRepairText, `"index":0`, `"index":null`, 1), false},
		{"unsupported index", strings.Replace(nativeRepairText, `"index":0`, `"index":1`, 1), false},
		{"multiple choices", strings.Replace(nativeRepairText, `}]}`, `},{"index":1}]}`, 1), false},
		{"tools missing", strings.Replace(nativeRepairText, `"stop"`, `"tool_calls"`, 1), false},
		{"tool ID missing", strings.Replace(nativeRepairTools, `"id":"call_fixture",`, "", 1), false},
		{"tool name missing", strings.Replace(nativeRepairTools, `"name":"exec",`, "", 1), false},
		{"tool type missing", strings.Replace(nativeRepairTools, `"type":"function",`, "", 1), false},
		{"tool arguments missing", strings.Replace(nativeRepairTools, `,"arguments":"{}"`, "", 1), false},
		{"tool type invalid", strings.Replace(nativeRepairTools, `"type":"function"`, `"type":"other"`, 1), false},
		{"tool arguments truncated", strings.Replace(nativeRepairTools, `"arguments":"{}"`, `"arguments":"{"`, 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "malformed JSON" {
				require.True(t, json.Valid([]byte(tc.wire)))
			}
			got := nativeRepairForward(t, GatewayLegacyBridgeProfile, nativeRepairRequest, tc.wire, false, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			if tc.success {
				require.NoError(t, got.err)
				require.NotNil(t, got.result)
				require.Equal(t, "completed", gjson.Get(got.body, "status").String())
				require.Equal(t, "fixture", gjson.Get(got.body, "output.0.content.0.text").String())
				if tc.wire == nativeRepairTools {
					require.Equal(t, "call_fixture", gjson.Get(got.body, "output.1.call_id").String())
				}
			} else {
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.Nil(t, got.result)
				if tc.name != "malformed JSON" {
					require.Empty(t, got.body)
				}
				require.NotContains(t, got.body, `"status":"completed"`)
			}
		})
	}
}

func TestGatewayNativeRepairOrdinaryBufferedCompatibility(t *testing.T) {
	for _, wire := range []string{`{}`, `null`, `{"choices":[]}`, `{"error":{"message":"fixture"}}`, strings.Replace(nativeRepairText, `,"finish_reason":"stop"`, "", 1), strings.Replace(nativeRepairText, `"stop"`, `"length"`, 1)} {
		got := nativeRepairForward(t, "", nativeRepairRequest, wire, false, nil)
		require.NoError(t, got.err)
		require.NotNil(t, got.result)
		require.EqualValues(t, 1, got.entries)
	}
}

type nativeRepairShortWrite struct{ gin.ResponseWriter }

func (w nativeRepairShortWrite) Write(b []byte) (int, error) {
	return w.ResponseWriter.Write(b[:len(b)-1])
}

func TestGatewayNativeRepairBufferedDeliveryFailures(t *testing.T) {
	for _, profile := range []string{GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile} {
		for _, failure := range []string{"write", "short write", "flush"} {
			t.Run(profile+"/"+failure, func(t *testing.T) {
				response := nativeRepairText
				if profile == GatewayMiMoResponsesProfile {
					response = `{"status":"completed","output":[]}`
				}
				got := nativeRepairForward(t, profile, nativeRepairRequest, response, false, func(c *gin.Context) {
					switch failure {
					case "write":
						rec := httptest.NewRecorder()
						wrapped, _ := gin.CreateTestContext(&nativeReviewWriteFailure{ResponseRecorder: rec, failOn: "all"})
						c.Writer = wrapped.Writer
					case "short write":
						c.Writer = nativeRepairShortWrite{c.Writer}
					case "flush":
						c.Writer = nativeReviewFlushFailure{c.Writer}
					}
				})
				require.True(t, got.entered)
				require.EqualValues(t, 1, got.entries)
				require.EqualValues(t, 1, got.requests)
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.Nil(t, got.result, "bytes may already be delivered; settlement must remain unknown")
			})
		}
	}
}

func TestGatewayNativeRepairLegacyStreamAmbiguousTerminal(t *testing.T) {
	finish := strings.TrimSuffix(strings.TrimPrefix(nativeReviewCCFinish, "data: "), "\n\n")
	for _, mutation := range []struct{ name, wire string }{
		{"finish last length", strings.Replace(finish, `"finish_reason":"stop"`, `"finish_reason":"stop","finish_reason":"length"`, 1)},
		{"finish last null", strings.Replace(finish, `"finish_reason":"stop"`, `"finish_reason":"stop","finish_reason":null`, 1)},
		{"finish identical", strings.Replace(finish, `"finish_reason":"stop"`, `"finish_reason":"stop","finish_reason":"stop"`, 1)},
		{"finish alias", strings.Replace(finish, `"finish_reason":"stop"`, `"finish_reason":"stop","FINISH_REASON":"length"`, 1)},
		{"finish alias alone", strings.Replace(finish, `finish_reason`, `FINISH_REASON`, 1)},
		{"finish escaped alias", strings.Replace(finish, `"finish_reason":"stop"`, `"finish_reason":"stop","\u0046inish_reason":null`, 1)},
		{"index last one", strings.Replace(finish, `"index":0`, `"index":0,"index":1`, 1)},
		{"index last null", strings.Replace(finish, `"index":0`, `"index":0,"index":null`, 1)},
		{"index identical", strings.Replace(finish, `"index":0`, `"index":0,"index":0`, 1)},
		{"index alias", strings.Replace(finish, `"index":0`, `"index":0,"INDEX":1`, 1)},
		{"index alias alone", strings.Replace(finish, `index`, `INDEX`, 1)},
		{"escaped duplicate index", strings.Replace(finish, `"index":0`, `"index":0,"ind\u0065x":1`, 1)},
		{"choices duplicate", strings.TrimSuffix(finish, "}") + `,"choices":[]}`},
		{"choices alias", strings.TrimSuffix(finish, "}") + `,"CHOICES":[]}`},
		{"choices alias alone", strings.Replace(finish, `choices`, `CHOICES`, 1)},
		{"escaped choices alias", strings.TrimSuffix(finish, "}") + `,"\u0043hoices":[]}`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			require.True(t, json.Valid([]byte(mutation.wire)))
			got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), nativeReviewCCDelta+"data: "+mutation.wire+"\n\n"+nativeReviewDone, true, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
			require.NotContains(t, got.body, "response.completed")
			require.NotContains(t, got.body, "[DONE]")
		})
	}
	for _, wire := range []string{nativeReviewCCFinish + nativeReviewDone, strings.Replace(nativeReviewCCFinish, "stop", "tool_calls", 1) + nativeReviewDone} {
		got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), wire, true, nil)
		require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
		require.NotContains(t, got.body, "response.completed")
		require.NotContains(t, got.body, "[DONE]")
	}
}

func TestGatewayNativeRepairLegacyStreamQualifiedTools(t *testing.T) {
	wire := nativeRepairToolDelta + strings.Replace(nativeReviewCCFinish, "stop", "tool_calls", 1) + nativeReviewDone
	got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), wire, true, nil)
	require.NoError(t, got.err)
	require.True(t, got.entered)
	require.EqualValues(t, 1, got.entries)
	require.Contains(t, got.body, "response.completed")
	require.Contains(t, got.body, `"call_id":"call_fixture"`)
	require.Contains(t, got.body, "[DONE]")
	for _, delta := range []string{
		strings.Replace(nativeRepairToolDelta, `"id":"call_fixture",`, "", 1),
		strings.Replace(nativeRepairToolDelta, `"type":"function"`, `"type":"other"`, 1),
		strings.Replace(nativeRepairToolDelta, `"name":"exec"`, `"name":""`, 1),
	} {
		got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), delta+strings.Replace(nativeReviewCCFinish, "stop", "tool_calls", 1)+nativeReviewDone, true, nil)
		require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
		require.NotContains(t, got.body, "response.completed")
		require.NotContains(t, got.body, "[DONE]")
	}
}

func TestGatewayNativeRepairPrivateDiagnosticPrivacy(t *testing.T) {
	sink, restore := captureStructuredLog(t)
	defer restore()
	for _, profile := range []string{GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile} {
		response := strings.Replace(nativeRepairText, `"content":"fixture"`, `"content":"fixture","reasoning_content":"fixture reasoning"`, 1)
		if profile == GatewayMiMoResponsesProfile {
			response = `{"status":"completed","output":[]}`
		}
		got := nativeRepairForward(t, profile, nativeRepairRequest, response, false, nil)
		require.NoError(t, got.err)
		sink.mu.Lock()
		logs, err := json.Marshal(sink.events)
		sink.mu.Unlock()
		require.NoError(t, err)
		for _, sensitive := range []string{"account_id", "99999999-9999-4999-8999-999999999999", "sandbox-fixture", "http://127.0.0.1"} {
			require.NotContains(t, string(logs), sensitive)
		}
	}
	got := nativeRepairForward(t, "", nativeRepairRequest, nativeRepairText, false, nil)
	require.NoError(t, got.err)
	require.True(t, sink.ContainsFieldValue("account_id", "23"), "ordinary diagnostics stay available")
}
