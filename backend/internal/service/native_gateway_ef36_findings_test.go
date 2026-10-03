//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeEF36ChunkToolIdentity(t *testing.T) {
	for _, secondID := range []string{"call_B", "call_A", ""} {
		t.Run(secondID, func(t *testing.T) {
			wire := "data: " + `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_A","type":"function","function":{"name":"exec","arguments":"{"}},{"index":0,"id":"` + secondID + `","type":"function","function":{"arguments":"}"}}]},"finish_reason":null}]}` + "\n\n" +
				strings.Replace(nativeReviewCCFinish, "stop", "tool_calls", 1) + nativeReviewDone
			got := nativeRepairForward(t, GatewayLegacyBridgeProfile, strings.Replace(nativeRepairRequest, "false", "true", 1), wire, true, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			if secondID == "call_B" {
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.NotContains(t, got.body, "response.output_item.added")
				require.NotContains(t, got.body, "response.completed")
				require.NotContains(t, got.body, "[DONE]")
			} else {
				require.NoError(t, got.err)
				require.Contains(t, got.body, "response.completed")
				require.Contains(t, got.body, "[DONE]")
				require.Contains(t, got.body, "call_A")
			}
		})
	}
}

func TestGatewayNativeEF36UTF8(t *testing.T) {
	buffered := `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"fixture"}]}]}`
	bad := string([]byte{0xff})
	cases := []struct {
		name, profile, wire string
		stream, success     bool
	}{
		{"native buffered invalid", GatewayMiMoResponsesProfile, strings.Replace(buffered, "fixture", bad, 1), false, false},
		{"native terminal invalid", GatewayMiMoResponsesProfile, "data: {\"type\":\"response.completed\",\"response\":" + strings.Replace(buffered, "fixture", bad, 1) + "}\n\n", true, false},
		{"native comment invalid", GatewayMiMoResponsesProfile, ": " + bad + "\n\n" + nativeReviewCompleted, true, false},
		{"legacy buffered invalid", GatewayLegacyBridgeProfile, strings.Replace(nativeRepairText, "fixture", bad, 1), false, false},
		{"native unicode", GatewayMiMoResponsesProfile, strings.Replace(buffered, "fixture", "Привіт 🌍", 1), false, true},
		{"native stream unicode", GatewayMiMoResponsesProfile, ": Привіт 🌍\n\n" + nativeReviewCompleted, true, true},
		{"legacy unicode", GatewayLegacyBridgeProfile, strings.Replace(nativeRepairText, "fixture", "Привіт 🌍", 1), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := nativeRepairRequest
			if tc.stream {
				request = strings.Replace(request, "false", "true", 1)
			}
			got := nativeRepairForward(t, tc.profile, request, tc.wire, tc.stream, nil)
			require.True(t, got.entered)
			require.EqualValues(t, 1, got.entries)
			require.EqualValues(t, 1, got.requests)
			if tc.success {
				require.NoError(t, got.err)
				require.Contains(t, got.body, "Привіт 🌍")
				if tc.profile == GatewayMiMoResponsesProfile {
					require.Equal(t, tc.wire, got.body)
				}
			} else {
				require.ErrorIs(t, got.err, ErrGatewayNativeEffectUnknown)
				require.NotContains(t, got.body, "response.completed")
				require.NotContains(t, got.body, "[DONE]")
				require.Empty(t, got.body)
			}
		})
	}
}

func TestGatewayNativeEF36LegacyRedirect(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "stream"}[stream], func(t *testing.T) {
			var requests, redirects atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1) }))
			defer target.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", target.URL)
				body := nativeRepairText
				w.Header().Set("Content-Type", "application/json")
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					body = nativeReviewCCDelta + nativeReviewCCFinish + nativeReviewDone
				}
				w.WriteHeader(http.StatusFound)
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			client := upstream.Client()
			// The real repository's private transport returns redirects unchanged.
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			a := nativeReviewStreamAccount(t, upstream.URL, GatewayLegacyBridgeProfile)
			transport := &gatewayBoundaryReviewHTTP{gatewayIdentityRealHTTP: gatewayIdentityRealHTTP{client: client}}
			svc := &OpenAIGatewayService{cache: nativeRepairPrivateCache{}, accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: transport, cfg: rawChatCompletionsTestConfig()}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			request := nativeRepairRequest
			if stream {
				request = strings.Replace(request, "false", "true", 1)
			}
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewBufferString(request))
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, []byte(request))
			require.True(t, entered)
			require.ErrorIs(t, err, ErrGatewayNativeEffectUnknown)
			require.EqualValues(t, 1, requests.Load())
			require.EqualValues(t, 1, transport.entries.Load())
			require.Zero(t, redirects.Load())
			require.NotContains(t, rec.Body.String(), "response.completed")
			require.NotContains(t, rec.Body.String(), "[DONE]")
		})
	}
}
