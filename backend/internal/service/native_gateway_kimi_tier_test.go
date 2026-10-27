//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type kimiTierPeerTransport struct{ peer *url.URL }

func (r kimiTierPeerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Routing/custody have already checked the real fixed provider origin. Only
	// this test's network leaf redirects those bytes to a local HTTP peer.
	copy := request.Clone(request.Context())
	target := *request.URL
	target.Scheme, target.Host = r.peer.Scheme, r.peer.Host
	copy.URL, copy.Host = &target, r.peer.Host
	return http.DefaultTransport.RoundTrip(copy)
}

func TestGatewayNativeKimiWireDefaultTier(t *testing.T) {
	const history = `"input":[{"type":"reasoning","id":"reasoning_1","summary":[],"encrypted_content":"opaque-history"},{"type":"function_call","call_id":"call_1","name":"add_integers","arguments":"{\"a\":2,\"b\":3}"},{"type":"function_call_output","call_id":"call_1","output":"5"}],"tools":[{"type":"function","name":"add_integers","parameters":{"type":"object","properties":{"service_tier":{"const":"nested-preserved"},"n":{"const":9007199254740993}}},"strict":true}],"tool_choice":"auto","stream":true,"store":false,"max_output_tokens":4096`
	for _, tier := range []string{`"default"`, `"\u0064efault"`, `"priority"`} {
		t.Run(tier, func(t *testing.T) {
			payload := []byte(`{"model":"k3-256k","service_tier":` + tier + `,` + history + `}`)
			want := []byte(`{"model":"k3-256k",` + history + `}`)
			var calls atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, "/coding/v1/responses", r.URL.Path)
				require.Equal(t, "ReviewRouter/native-account-gateway", r.Header.Get("User-Agent"))
				wire, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, want, wire, "only the top-level validated tier may be removed")
				if bytes.Contains(wire, []byte(`"service_tier":"default"`)) {
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			defer peer.Close()
			target, err := url.Parse(peer.URL)
			require.NoError(t, err)
			a := nativeReviewStreamAccount(t, GatewayKimiCodeResponsesBaseURL, GatewayKimiCodeResponsesProfile)
			a.Extra[GatewayModelExtraKey] = GatewayKimiCodeResponsesModel
			route, err := GatewayNativeDescriptor(a)
			require.NoError(t, err)
			svc := &OpenAIGatewayService{accountRepo: &gatewayIdentityRepoFixture{row: a}, httpUpstream: &gatewayIdentityRealHTTP{client: &http.Client{Transport: kimiTierPeerTransport{peer: target}}}, cfg: rawChatCompletionsTestConfig()}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", strings.NewReader(string(payload)))
			original := append([]byte(nil), payload...)
			_, entered, err := svc.ForwardGatewayRoute(nativeFixtureContext(t, context.Background()), c, route, payload)
			require.Equal(t, original, payload, "the admitted request must remain unchanged")
			if tier == `"priority"` {
				require.ErrorIs(t, err, ErrGatewayNativeIdentity)
				require.False(t, entered)
				require.Zero(t, calls.Load())
			} else {
				require.NoError(t, err)
				require.True(t, entered)
				require.EqualValues(t, 1, calls.Load())
			}
		})
	}
}
