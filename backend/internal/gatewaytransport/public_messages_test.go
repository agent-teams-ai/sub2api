//go:build unit

package gatewaytransport

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type publicClaudeRepository struct {
	service.GatewayNativeClaudeRepository
	physical service.GatewayNativeOAuthPhysical
	envelope string
	releases atomic.Int32
}

func (r *publicClaudeRepository) ResolveGatewayClaudeCanonical(_ context.Context, route service.GatewayNativeRoute, account string) (service.GatewayNativeCredentialScope, string, error) {
	if !service.SameGatewayNativeDescriptor(route, r.physical.Route) || account != r.physical.Scope.Account {
		return service.GatewayNativeCredentialScope{}, "", errDenied
	}
	return r.physical.Scope, r.physical.Operation, nil
}
func (r *publicClaudeRepository) LockGatewayClaudePhysical(_ context.Context, scope service.GatewayNativeCredentialScope, operation string, route *service.GatewayNativeRoute) (service.GatewayNativeOAuthPhysical, string, func(), error) {
	if scope != r.physical.Scope || operation != r.physical.Operation || route == nil || !service.SameGatewayNativeDescriptor(*route, r.physical.Route) {
		return service.GatewayNativeOAuthPhysical{}, "", nil, errDenied
	}
	return r.physical, r.envelope, func() { r.releases.Add(1) }, nil
}
func (*publicClaudeRepository) StoreGatewayClaudeLimits(context.Context, service.GatewayNativeOAuthPhysical, service.GatewayClaudeRawLimits, time.Time) error {
	return nil
}

// Encrypt a synthetic Claude bundle using the custody wire contract. No real
// enrollment/provider credential, HTTP destination or SQL authority is inferred.
func publicClaudeEnvelope(t *testing.T, p service.GatewayNativeOAuthPhysical) string {
	t.Helper()
	block, err := aes.NewCipher([]byte(strings.Repeat("K", 32)))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{"kind": "claude-oauth/v1", "revision": 1, "access_token": "synthetic-native-claude-access", "refresh_token": "synthetic-native-claude-refresh", "account": p.Subject, "organization": p.ProviderAccount, "expires_at": time.Now().Add(time.Hour)})
	require.NoError(t, err)
	scope, err := json.Marshal(p.Scope)
	require.NoError(t, err)
	aad := append([]byte("account-gateway/native/oauth-bundle/gco1/fixture\x00"), scope...)
	return "gco1.fixture." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, raw, aad))
}

func TestPublicNativeMessagesPreserveProtocolAndExecutionAuthority(t *testing.T) {
	const payload = `{"model":"claude-sonnet-4-6","stream":true,"max_tokens":100,"system":[{"type":"text","text":"Native system","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"prior","signature":"history-signature"}]},{"role":"user","content":"Continue native tool work"}],"tools":[{"name":"read_fixture","input_schema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`
	const output = ": keepalive\r\n\r\nevent: ping\ndata: {\"type\":\"ping\"}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_public\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Native reply\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	var original Request
	var entries, admits, settlements atomic.Int32
	repo := &publicClaudeRepository{}
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+fixtureCallbackToken, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, "synthetic-messages-capability", input.ExecutionBearer)
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			admits.Add(1)
			var input struct {
				admitRequest
				RequestedModel string `json:"requestedModel"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, service.GatewayClaudeOAuthModel, input.RequestedModel)
			_ = json.NewEncoder(w).Encode(ownerReply(input.admitRequest))
		case "/private/native/v1/execution-settle":
			var input struct {
				Receipt        Receipt `json:"receipt"`
				RequestedModel string  `json:"requestedModel"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.Equal(t, service.GatewayClaudeOAuthModel, input.RequestedModel)
			require.True(t, closed(input.Receipt.Lifetime))
			require.True(t, input.Receipt.Lifetime.Completed)
			require.NotNil(t, input.Receipt.NativeUsage)
			require.Equal(t, "complete", input.Receipt.NativeUsage.State)
			settlements.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Errorf("unexpected Messages callback %s", r.URL.Path)
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "/v1/messages", r.URL.Path)
		require.Equal(t, "api.anthropic.com", r.Host)
		require.Equal(t, "Bearer synthetic-native-claude-access", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("X-Api-Key"))
		require.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, payload, string(raw))
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, output)
	}), func(cfg *Config, rows *ownerFixtureRepo) {
		original = ownerRequest()
		original.Admission.ProfileID = service.GatewayClaudeOAuthMessagesProfile
		original.Descriptor.Profile = service.GatewayClaudeOAuthMessagesProfile
		original.Descriptor.Model = service.GatewayClaudeOAuthModel
		original.Descriptor.BaseURL = service.GatewayClaudeOAuthBaseURL
		repo.physical = service.GatewayNativeOAuthPhysical{Scope: service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-owner", Account: ownerAccount, Generation: ownerGeneration, Purpose: service.GatewayOAuthBundlePurpose}, Operation: "fixture-claude-connect", Route: original.Descriptor, Issuer: service.GatewayClaudeOAuthIssuer, Subject: uuid.NewString(), ProviderAccount: uuid.NewString(), CredentialRevision: 1}
		repo.envelope = publicClaudeEnvelope(t, repo.physical)
		dispatch, err := service.NewGatewayNativeClaudeOAuth(repo, cfg.Custody, nil)
		require.NoError(t, err)
		cfg.ClaudeOAuth = dispatch
		cfg.Claude = &QualifiedProfile{Profile: service.GatewayClaudeOAuthMessagesProfile, Model: service.GatewayClaudeOAuthModel, BaseURL: service.GatewayClaudeOAuthBaseURL, QualificationRef: "public-native-messages", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 100}
		cfg.CallbackOrigin = authority.URL
		localURL, err := url.Parse(cfg.Profile.BaseURL)
		require.NoError(t, err)
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "api.anthropic.com:443" {
				return nil, errDenied
			}
			return (&net.Dialer{}).DialContext(ctx, network, localURL.Host)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		upstream, err := service.NewGatewayNativeLifetimeUpstream(&ownerFixtureHTTP{client: &http.Client{Transport: transport}})
		require.NoError(t, err)
		cfg.Gateway = service.NewOpenAIGatewayService(rows, nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	})
	public := httptest.NewServer(h.PublicHandler(4))
	defer public.Close()
	query := "?beta=true"
	call := func(id, body string, key, both bool) (int, []byte) {
		req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/messages"+query, bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Gateway-Request-Id", id)
		if key {
			req.Header.Set("X-Api-Key", "synthetic-messages-capability")
		}
		if !key || both {
			req.Header.Set("Authorization", "Bearer synthetic-messages-capability")
		}
		response, err := public.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response.StatusCode, raw
	}
	for i, key := range []bool{false, true} {
		status, raw := call([]string{"messages-bearer", "messages-key"}[i], payload, key, false)
		require.Equal(t, 200, status)
		require.Equal(t, output, string(raw))
		require.NotContains(t, string(raw), "response.completed")
	}
	require.Equal(t, int32(2), entries.Load())
	require.Equal(t, int32(2), admits.Load())
	require.Equal(t, int32(2), settlements.Load())
	require.Equal(t, int32(2), repo.releases.Load())
	status, _ := call("ambiguous-auth", payload, true, true)
	require.Equal(t, 401, status)
	for _, bad := range []string{strings.Replace(payload, `"max_tokens":100`, `"max_tokens":101`, 1), strings.Replace(payload, `"claude-sonnet-4-6"`, `"unqualified"`, 1)} {
		status, _ = call(uuid.NewString(), bad, false, false)
		require.Equal(t, 400, status)
	}
	for _, invalidQuery := range []string{"?beta=true&beta=true", "?beta=%74rue", "?%62eta=true", "?beta=false", "?unknown=true", "?"} {
		query = invalidQuery
		status, _ = call(uuid.NewString(), payload, false, false)
		require.Equal(t, 404, status)
	}
	require.Equal(t, int32(2), entries.Load())
	require.Equal(t, int32(2), admits.Load())
}
