//go:build unit

package gatewaytransport

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type claudeIngressRepository struct {
	service.GatewayNativeClaudeRepository
	resolutions atomic.Int32
}

func (r *claudeIngressRepository) ResolveGatewayClaudeCanonical(context.Context, service.GatewayNativeRoute, string) (service.GatewayNativeCredentialScope, string, error) {
	r.resolutions.Add(1)
	return service.GatewayNativeCredentialScope{}, "", service.ErrGatewayNativeIdentity
}

// Losing unsupported Responses fields in the converter would let a materially
// different request consume a kernel claim and provider credential. The real
// private HTTP boundary must reject them before reserve/admit/credential lookup.
func TestClaudePrivateHTTPRejectsLossyPayloadBeforeAdmission(t *testing.T) {
	repo := &claudeIngressRepository{}
	h, server, admits, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unsupported Claude input reached a provider")
	}), func(cfg *Config, _ *ownerFixtureRepo) {
		claude, err := service.NewGatewayNativeClaudeOAuth(repo, cfg.Custody, nil)
		require.NoError(t, err)
		cfg.ClaudeOAuth = claude
		cfg.Claude = &QualifiedProfile{Profile: service.GatewayClaudeOAuthMessagesProfile, Model: service.GatewayClaudeOAuthModel, BaseURL: service.GatewayClaudeOAuthBaseURL,
			QualificationRef: "controlled-source-v1", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 100}
	})
	for _, input := range []string{
		`"` + strings.Repeat("x", 3000) + `"`, // canonical fits; expanded OAuth wire must still fit
		`[{"role":"user","content":[{"type":"input_image","image_url":"https://fixture.invalid/image"}]}]`,
		`[{"role":"user","content":"text","output":"would be discarded"}]`,
		`[{"type":"function_call_output","call_id":"orphan","output":"unbound"}]`,
	} {
		r := ownerRequest()
		r.Admission.ProfileID = service.GatewayClaudeOAuthMessagesProfile
		r.Descriptor.Profile, r.Descriptor.Model, r.Descriptor.BaseURL = r.Admission.ProfileID, service.GatewayClaudeOAuthModel, service.GatewayClaudeOAuthBaseURL
		r.Payload = json.RawMessage(`{"model":"claude-sonnet-4-6","input":` + input + `,"store":false,"stream":true,"service_tier":"default"}`)
		result := ownerPOST(server.Client(), server.URL, "", fixtureExecutionToken, r)
		require.NoError(t, result.err)
		require.Equal(t, http.StatusBadRequest, result.code)
		require.NotContains(t, string(result.body), strings.TrimSpace(input))
	}
	require.Zero(t, admits.Load())
	require.Zero(t, repo.resolutions.Load())
	h.mu.Lock()
	retained := len(h.entries)
	h.mu.Unlock()
	require.Zero(t, retained)
}
