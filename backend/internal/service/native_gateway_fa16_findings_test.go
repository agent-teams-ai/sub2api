//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// F1: admission allowed a default-tier private request, then the ordinary global
// Fast rule upgraded its actual CC transport body. The same ordinary dispatch
// must still honor that rule. This uses the real SettingService and HTTP peer.
func TestGatewayNativeFA16LegacyDefaultTier(t *testing.T) {
	for _, rule := range []string{OpenAIFastTierMissing, OpenAIFastTierAny} {
		for _, tier := range []string{"", "default", "priority", "flex"} {
			for _, private := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/private=%t", rule, tier, private), func(t *testing.T) {
					var requests atomic.Int32
					outbound := make(chan []byte, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						outbound <- body
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, nativeRepairText)
					}))
					defer upstream.Close()
					a := nativeReviewStreamAccount(upstream.URL, GatewayLegacyBridgeProfile)
					if !private {
						a = &Account{ID: 23, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: a.Credentials}
					}
					transport := &gatewayBoundaryReviewHTTP{gatewayIdentityRealHTTP: gatewayIdentityRealHTTP{client: upstream.Client()}}
					svc := newOpenAIGatewayServiceWithSettings(t, nil)
					require.NoError(t, svc.settingService.SetOpenAIFastPolicySettings(context.Background(), &OpenAIFastPolicySettings{
						Rules: []OpenAIFastPolicyRule{{
							ServiceTier: rule, Action: OpenAIFastPolicyActionForcePriority, Scope: BetaPolicyScopeAll,
						}},
					}))
					svc.accountRepo = &gatewayIdentityRepoFixture{row: a}
					svc.httpUpstream, svc.cfg = transport, rawChatCompletionsTestConfig()
					request := nativeRepairRequest
					if tier != "" {
						request = strings.TrimSuffix(request, "}") + `,"service_tier":"` + tier + `"}`
					}
					rec := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(rec)
					c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewBufferString(request))
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					var entered bool
					var err error
					if private {
						route, descriptorErr := GatewayNativeDescriptor(a)
						require.NoError(t, descriptorErr)
						_, entered, err = svc.ForwardGatewayRoute(ctx, c, route, []byte(request))
					} else {
						_, err = svc.forwardResponsesViaRawChatCompletions(ctx, c, a, []byte(request))
					}
					if private && tier != "" && tier != "default" {
						require.ErrorIs(t, err, ErrGatewayNativeIdentity)
						require.False(t, entered)
						require.Zero(t, requests.Load())
						require.Zero(t, transport.entries.Load())
						require.Empty(t, rec.Body.String())
						return
					}
					require.NoError(t, err)
					if private {
						require.True(t, entered)
					}
					require.EqualValues(t, 1, requests.Load())
					require.EqualValues(t, 1, transport.entries.Load())
					sent := <-outbound
					expected := tier
					if !private && ((tier == "" && rule == OpenAIFastTierMissing) ||
						(tier != "" && rule == OpenAIFastTierAny)) {
						expected = OpenAIFastTierPriority
					}
					require.Equal(t, expected, gjson.GetBytes(sent, "service_tier").String())
					if private {
						require.NotEqual(t, OpenAIFastTierPriority, gjson.GetBytes(sent, "service_tier").String())
					}
					require.Equal(t, "completed", gjson.Get(rec.Body.String(), "status").String())
				})
			}
		}
	}
}

type nativeFA16Fields struct{ name, fields string }

// Each case is valid JSON. Both orders, escaped decoded duplicates, case aliases
// and identical duplicates must be rejected at the named protocol object only.
func nativeFA16AmbiguousFields(field, good, bad string) []nativeFA16Fields {
	aliases := []string{
		field, strings.ToUpper(field),
		fmt.Sprintf(`\u%04x%s`, field[0], field[1:]),
		fmt.Sprintf(`\u%04x%s`, strings.ToUpper(field)[0], field[1:]),
	}
	if strings.Contains(field, "s") {
		aliases = append(aliases, strings.Replace(field, "s", "ſ", 1))
	}
	var cases []nativeFA16Fields
	for _, alias := range aliases {
		for _, reverse := range []bool{false, true} {
			left, right := `"`+field+`":`+good, `"`+alias+`":`+bad
			if reverse {
				left, right = right, left
			}
			cases = append(cases, nativeFA16Fields{fmt.Sprintf("%s/reverse=%t", alias, reverse), left + "," + right})
		}
	}
	cases = append(cases, nativeFA16Fields{"identical", `"` + field + `":` + good + `,"` + field + `":` + good})
	return cases
}

// F2: first-match lookup could settle and deliver bytes that a last-value JSON
// decoder considers incomplete. Check the actual buffered transport output.
func TestGatewayNativeFA16ResponsesBufferedMembers(t *testing.T) {
	for _, tc := range nativeFA16AmbiguousFields("status", `"completed"`, `"incomplete"`) {
		t.Run(tc.name, func(t *testing.T) {
			wire := "{" + tc.fields + `,"output":[]}`
			require.True(t, json.Valid([]byte(wire)))
			got := nativeRepairForward(t, GatewayMiMoResponsesProfile, nativeRepairRequest, wire, false, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
			require.Nil(t, got.result)
			require.Empty(t, got.body, "ambiguous completed bytes must never be delivered")
		})
	}
}

// F2: ambiguity in the SSE event type/response or nested response status could
// qualify the wrong terminal. Prior valid tool bytes may pass; this terminal may
// not. The nested user payload deliberately contains unrelated duplicate names.
func TestGatewayNativeFA16ResponsesStreamMembers(t *testing.T) {
	prefix := "data: " + `{"type":"response.output_item.done","item":{"type":"custom_tool_call","name":"STATUS","input":"fixture","payload":{"status":1,"status":2,"TYPE":"user","response":1}}}` + "\n\n"
	for _, field := range []string{"status", "type", "response"} {
		good, bad := `"completed"`, `"incomplete"`
		if field == "type" {
			good, bad = `"response.completed"`, `"response.incomplete"`
		} else if field == "response" {
			good, bad = `{"status":"completed"}`, `{"status":"incomplete"}`
		}
		for _, tc := range nativeFA16AmbiguousFields(field, good, bad) {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				var event string
				switch field {
				case "status":
					event = `{"type":"response.completed","response":{` + tc.fields + "}}"
				case "type":
					event = "{" + tc.fields + `,"response":{"status":"completed"}}`
				case "response":
					event = `{"type":"response.completed",` + tc.fields + "}"
				}
				require.True(t, json.Valid([]byte(event)))
				got := nativeRepairForward(t, GatewayMiMoResponsesProfile, strings.Replace(nativeRepairRequest, "false", "true", 1),
					prefix+"data: "+event+"\n\n", true, nil)
				require.True(t, got.entered)
				require.EqualValues(t, 1, got.entries)
				require.EqualValues(t, 1, got.requests)
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.Equal(t, prefix, got.body, "only the prior unambiguous event may be delivered")
				require.NotContains(t, got.body, "response.completed")
				require.NotContains(t, got.body, "[DONE]")
			})
		}
	}
}

func TestGatewayNativeFA16ResponsesPayloadBytes(t *testing.T) {
	buffered := ` { "sta\u0074us":"completed", "output":[{"type":"custom_tool_call","name":"TYPE","input":"fixture","payload":{"status":1,"status":2,"response":3,"TYPE":4}}] } `
	stream := ": fixture\r\ndata: " + `{"t\u0079pe":"response.completed","re\u0073ponse":{"sta\u0074us":"completed","output":[{"type":"custom_tool_call","name":"TYPE","input":"fixture","payload":{"status":1,"status":2,"response":3,"TYPE":4}}]}}` + "\r\n\r\n"
	for _, tc := range []struct {
		name, wire string
		stream     bool
	}{{"buffered", buffered, false}, {"stream", stream, true}} {
		t.Run(tc.name, func(t *testing.T) {
			request := nativeRepairRequest
			if tc.stream {
				request = strings.Replace(request, "false", "true", 1)
			}
			got := nativeRepairForward(t, GatewayMiMoResponsesProfile, request, tc.wire, tc.stream, nil)
			require.NoError(t, got.err)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			require.NotNil(t, got.result)
			require.Equal(t, tc.wire, got.body, "protocol checking must preserve unrelated tool/user bytes")
		})
	}
}

// F3: the old strict branch decoded two data lines of one malformed SSE event
// separately, and accepted DONE at EOF without a dispatched blank-line boundary.
// Positive multiline JSON must qualify as one event, with bounded frame memory.
func TestGatewayNativeFA16LegacyCompleteEvents(t *testing.T) {
	multi := strings.Replace(nativeReviewCCDelta, `,"choices"`, ",\ndata: "+`"choices"`, 1)
	sized := func(n int) string {
		comment := ": fixture\n"
		padding := n - len(nativeReviewCCDelta) - 2
		return strings.Repeat(comment, padding/len(comment)) + ":" + strings.Repeat("x", padding%len(comment)) + "\n" + nativeReviewCCDelta
	}
	// Use many small comment lines, so this exercises the frame cap independently
	// of the preexisting configured per-line scanner cap.
	exact := sized(gatewayNativeSSEFrameLimit)
	cases := []struct {
		name, wire string
		success    bool
	}{
		{"two JSON data lines in one event", strings.TrimSuffix(nativeReviewCCDelta, "\n") + nativeReviewCCFinish + nativeReviewDone, false},
		{"unfinished DONE no newline", nativeReviewCCDelta + nativeReviewCCFinish + strings.TrimSuffix(nativeReviewDone, "\n\n"), false},
		{"unfinished DONE one newline", nativeReviewCCDelta + nativeReviewCCFinish + strings.TrimSuffix(nativeReviewDone, "\n"), false},
		{"multiline single JSON", multi + nativeReviewCCFinish + nativeReviewDone, true},
		{"multiline CRLF single JSON", strings.ReplaceAll(multi+nativeReviewCCFinish+nativeReviewDone, "\n", "\r\n"), true},
		{"exact frame cap", exact + nativeReviewCCFinish + nativeReviewDone, true},
		{"over frame cap", ":" + "\n" + exact + nativeReviewCCFinish + nativeReviewDone, false},
		{"invalid UTF8 JSON string", strings.Replace(nativeReviewCCDelta, "fixture", string([]byte{0xff}), 1) + nativeReviewCCFinish + nativeReviewDone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), tc.wire, true, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			if tc.success {
				require.NoError(t, got.err)
				require.Contains(t, got.body, "response.completed")
				require.Contains(t, got.body, "[DONE]")
				require.Contains(t, got.body, `"text":"fixture"`)
			} else {
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.NotContains(t, got.body, "response.completed")
				require.NotContains(t, got.body, "[DONE]")
			}
		})
	}
	// Retain the ordinary line-wise compatibility for these historical frames.
	for _, wire := range []string{
		strings.TrimSuffix(nativeReviewCCDelta, "\n") + nativeReviewCCFinish + nativeReviewDone,
		nativeReviewCCDelta + nativeReviewCCFinish + strings.TrimSuffix(nativeReviewDone, "\n\n"),
	} {
		got := nativeRepairForward(t, "", strings.Replace(nativeRepairRequest, "false", "true", 1), wire, true, nil)
		require.NoError(t, got.err)
		require.EqualValues(t, 1, got.entries)
		require.EqualValues(t, 1, got.requests)
		require.Contains(t, got.body, "response.completed")
		require.Contains(t, got.body, "[DONE]")
	}
}

// F4: the converter iterates 0..len-1 and dropped a gapped index from its final
// response. Reject gaps at final validation, while preserving out-of-order calls
// and argument fragments that eventually fill the complete dense index set.
func TestGatewayNativeFA16LegacyDenseTools(t *testing.T) {
	tool := func(index int) string {
		return strings.Replace(strings.Replace(nativeRepairToolDelta, `"index":0,"id"`, fmt.Sprintf(`"index":%d,"id"`, index), 1),
			"call_fixture", fmt.Sprintf("call_fixture_%d", index), 1)
	}
	finish := strings.Replace(nativeReviewCCFinish, "stop", "tool_calls", 1)
	cases := []struct {
		name, wire string
		success    bool
	}{
		{"index 1 only", tool(1) + finish + nativeReviewDone, false},
		{"indices 0 and 2", tool(0) + tool(2) + finish + nativeReviewDone, false},
		{"out of order 1 then 0", tool(1) + tool(0) + finish + nativeReviewDone, true},
		{"out of order with argument fragments", strings.Replace(tool(1), `"arguments":"{}"`, `"arguments":"{"`, 1) +
			tool(0) + "data: " + `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"}"}}]},"finish_reason":null}]}` + "\n\n" + finish + nativeReviewDone, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), tc.wire, true, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			if !tc.success {
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.NotContains(t, got.body, "response.completed")
				require.NotContains(t, got.body, "[DONE]")
				return
			}
			require.NoError(t, got.err)
			require.Contains(t, got.body, "[DONE]")
			var completed gjson.Result
			closed := make(map[string]bool)
			for _, line := range strings.Split(got.body, "\n") {
				if !strings.HasPrefix(line, "data: {") {
					continue
				}
				event := gjson.Parse(strings.TrimPrefix(line, "data: "))
				switch event.Get("type").String() {
				case "response.completed":
					require.False(t, completed.Exists(), "one successful terminal only")
					completed = event.Get("response")
				case "response.output_item.done":
					closed[event.Get("item.call_id").String()] = true
				}
			}
			require.True(t, completed.Exists())
			require.Equal(t, "completed", completed.Get("status").String())
			calls := completed.Get("output").Array()
			require.Len(t, calls, 2, "both calls must survive the actual converter's final output")
			for i, call := range calls {
				id := fmt.Sprintf("call_fixture_%d", i)
				require.Equal(t, id, call.Get("call_id").String())
				require.Equal(t, "exec", call.Get("name").String())
				require.Equal(t, "{}", call.Get("arguments").String())
				require.True(t, closed[id], "each call must have a closed output item")
			}
		})
	}
}
