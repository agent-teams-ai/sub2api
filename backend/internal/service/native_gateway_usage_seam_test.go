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

func TestGatewayNativeUsageActualSeam(t *testing.T) {
	for _, tc := range []struct {
		name, frames, state string
		failure             bool
	}{
		{"complete", "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":9,\"output_tokens\":3}}}\n\n", "complete", false},
		{"unknown", "data: {\"type\":\"response.created\"}\n\n", "unknown", true},
		{"downstream", nativeReviewCompleted, "complete", true},
		{"failed", "data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"usage\":{\"input_tokens\":9,\"output_tokens\":3}}}\n\n", "partial", true},
		{"aborted", "data: {\"type\":\"response.in_progress\",\"response\":{\"status\":\"in_progress\",\"usage\":{\"input_tokens\":9,\"output_tokens\":3}}}\n\n", "partial", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tc.frames)
			}))
			defer peer.Close()
			account := nativeReviewStreamAccount(t, peer.URL, GatewayMiMoResponsesProfile)
			route, err := GatewayNativeDescriptor(account)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: account}, httpUpstream: &gatewayIdentityRealHTTP{client: peer.Client()}, cfg: rawChatCompletionsTestConfig()}
			payload := `{"model":"mimo-test","input":"sandbox","store":false,"stream":true,"service_tier":"default"}`
			var writer http.ResponseWriter = httptest.NewRecorder()
			if tc.name == "downstream" {
				writer = &nativeReviewWriteFailure{ResponseRecorder: httptest.NewRecorder(), failOn: "all"}
			}
			c, _ := gin.CreateTestContext(writer)
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(payload))
			var got []GatewayNativeUsage
			ctx := WithGatewayNativeUsageObserver(nativeFixtureContext(t, context.Background()), func(u GatewayNativeUsage) { got = append(got, u) })
			_, entered, err := svc.ForwardGatewayRoute(ctx, c, route, []byte(payload))
			require.True(t, entered)
			if tc.failure {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, got, 1)
			require.True(t, got[0].Finalized)
			require.Equal(t, tc.state, got[0].State)
			if tc.name == "unknown" {
				require.Nil(t, got[0].InputTokens)
				require.Nil(t, got[0].OutputTokens)
				return
			}
			input, output := int64(9), int64(3)
			if tc.name == "downstream" {
				input, output = 3, 2
			}
			require.EqualValues(t, input, *got[0].InputTokens)
			require.EqualValues(t, output, *got[0].OutputTokens)
			require.Equal(t, "unknown", got[0].CostState)
		})
	}
}
