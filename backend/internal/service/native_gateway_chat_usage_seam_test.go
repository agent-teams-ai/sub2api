//go:build unit

package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeNVIDIAChatUsage(t *testing.T) {
	for _, tc := range []struct {
		name, usage, finish, done, state string
		input, output, cached, reasoning *int64
		failure                          bool
	}{
		{"complete", `{"total_tokens":12,"prompt_tokens":9,"completion_tokens":3,"prompt_tokens_details":{"cached_tokens":2},"completion_tokens_details":{"reasoning_tokens":1}}`, "stop", nativeReviewDone, "complete", usageTestCount(9), usageTestCount(3), usageTestCount(2), usageTestCount(1), false},
		{"input only", `{"prompt_tokens":9}`, "stop", nativeReviewDone, "partial", usageTestCount(9), nil, nil, nil, false},
		{"output only", `{"completion_tokens":3}`, "stop", nativeReviewDone, "partial", nil, usageTestCount(3), nil, nil, false},
		{"absent", ``, "stop", nativeReviewDone, "unknown", nil, nil, nil, nil, false},
		{"explicit zero", `{"prompt_tokens":0,"completion_tokens":0}`, "stop", nativeReviewDone, "complete", usageTestCount(0), usageTestCount(0), nil, nil, false},
		{"missing DONE", `{"prompt_tokens":9,"completion_tokens":3}`, "stop", "", "partial", usageTestCount(9), usageTestCount(3), nil, nil, true},
		{"failed stream", `{"prompt_tokens":9,"completion_tokens":3}`, "stop", "data: {invalid\n\n", "partial", usageTestCount(9), usageTestCount(3), nil, nil, true},
		{"downstream failure", `{"prompt_tokens":9,"completion_tokens":3}`, "stop", nativeReviewDone, "partial", usageTestCount(9), usageTestCount(3), nil, nil, true},
		{"early usage only", `{"prompt_tokens":9,"completion_tokens":3}`, "stop", nativeReviewDone, "partial", usageTestCount(9), usageTestCount(3), nil, nil, false},
		{"usage on finish", `{"prompt_tokens":9,"completion_tokens":3}`, "stop", nativeReviewDone, "complete", usageTestCount(9), usageTestCount(3), nil, nil, false},
		{"known length", `{"prompt_tokens":9,"completion_tokens":3}`, "length", nativeReviewDone, "complete", usageTestCount(9), usageTestCount(3), nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := nativeReviewStreamAccount(t, GatewayNVIDIABuildBaseURL, GatewayLegacyBridgeProfile)
			account.Extra[GatewayProfileExtraKey] = GatewayNVIDIABuildChatProfile
			account.Extra[GatewayModelExtraKey] = GatewayNVIDIABuildAnchorModel
			nativeFixtureSealAccount(t, account)
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			frames := strings.ReplaceAll(nativeReviewCCDelta+strings.Replace(nativeReviewCCFinish, `"stop"`, `"`+tc.finish+`"`, 1), "mimo-test", GatewayNVIDIABuildAnchorModel)
			if tc.name == "early usage only" {
				frames = "data: {\"choices\":[],\"usage\":" + tc.usage + "}\n\n" + frames
			} else if tc.name == "usage on finish" {
				frames = strings.Replace(frames, `"finish_reason":"stop"}]}`, `"finish_reason":"stop"}],"usage":`+tc.usage+`}`, 1)
			} else if tc.usage != "" {
				frames += "data: {\"choices\":[],\"usage\":" + tc.usage + "}\n\n"
			}
			frames += tc.done
			upstream := &nativeDiagnosticHTTP{}
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: upstream, cfg: rawChatCompletionsTestConfig()}
			payload := []byte(`{"model":"` + GatewayNVIDIABuildAnchorModel + `","input":"synthetic","store":false,"stream":true,"max_output_tokens":128}`)
			var got []GatewayNativeUsage
			var wires []string
			for _, observing := range []bool{false, true} {
				upstream.response = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(frames))}
				var writer http.ResponseWriter = httptest.NewRecorder()
				if tc.name == "downstream failure" {
					writer = &nativeReviewWriteFailure{ResponseRecorder: httptest.NewRecorder(), failOn: "response.completed"}
				}
				c, _ := gin.CreateTestContext(writer)
				c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
				ctx := nativeFixtureContext(t, context.Background())
				if observing {
					ctx = WithGatewayNativeUsageObserver(ctx, func(u GatewayNativeUsage) { got = append(got, u) })
				}
				_, entered, err := svc.ForwardGatewayRoute(ctx, c, route, payload)
				require.True(t, entered)
				if tc.failure {
					require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
				} else {
					require.NoError(t, err)
				}
				wire, err := io.ReadAll(upstream.lastRequest.Body)
				require.NoError(t, err)
				wires = append(wires, string(wire))
			}
			require.Equal(t, wires[0], wires[1], "observation must not alter the provider request")
			require.Len(t, got, 1)
			require.True(t, got[0].Finalized)
			require.Equal(t, "native_provider_response", got[0].Source)
			require.Equal(t, tc.state, got[0].State)
			require.Equal(t, tc.input, got[0].InputTokens)
			require.Equal(t, tc.output, got[0].OutputTokens)
			require.Equal(t, tc.cached, got[0].CachedInputTokens)
			require.Equal(t, tc.reasoning, got[0].ReasoningOutputTokens)
			require.Equal(t, "unknown", got[0].CostState)
		})
	}
}

func usageTestCount(n int64) *int64 { return &n }
