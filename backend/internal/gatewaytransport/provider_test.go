//go:build unit

package gatewaytransport

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Modalities and tool types outside the qualified slice must not consume the
// durable claim or even look up the credential-bearing row.
func TestCodingPlanPrivateHTTPRejectsUnsupportedBeforeAdmission(t *testing.T) {
	plans := []QualifiedProfile{
		{Profile: service.GatewayKimiCodeResponsesProfile, BaseURL: service.GatewayKimiCodeResponsesBaseURL, Model: service.GatewayKimiCodeResponsesModel},
		{Profile: service.GatewayGLMCodingResponsesProfile, BaseURL: service.GatewayGLMCodingResponsesBaseURL, Model: service.GatewayGLMCodingResponsesModel},
		{Profile: service.GatewayMiniMaxMPlanResponsesProfile, BaseURL: service.GatewayMiniMaxMPlanResponsesBaseURL, Model: service.GatewayMiniMaxMPlanResponsesModel},
	}
	for i := range plans {
		plans[i].QualificationRef = "controlled-source-v1"
		plans[i].RequestBytes = 4096
		plans[i].OutputBytes = 4096
		plans[i].Tokens = 100
		plans[i].ProviderTokenUpperBound = 100
	}
	h, server, admits, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsupported provider entry") }), func(cfg *Config, _ *ownerFixtureRepo) { cfg.CodingPlans = plans })
	for _, plan := range plans {
		for _, input := range []string{
			`"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://forbidden.invalid"}]}]`,
			`"input":"text","tools":[{"type":"web_search"}]`,
			`"input":"text","previous_response_id":"stateful"`,
			`"input":"text","reasoning":{"effort":"xhigh"}`,
			`"input":"text","reasoning":{"effort":"high"}`,
			`"input":"text","prompt_cache_key":"not-a-uuid"`,
			`"input":"text","client_metadata":{"x-codex-installation-id":"44444444-4444-4444-8444-444444444444","authorization":"forbidden"}`,
		} {
			r := ownerRequest()
			r.Admission.ProfileID = plan.Profile
			r.Descriptor.Profile, r.Descriptor.BaseURL, r.Descriptor.Model = plan.Profile, plan.BaseURL, plan.Model
			r.Payload = json.RawMessage(`{"model":"` + plan.Model + `","store":false,"stream":true,"service_tier":"default",` + input + `}`)
			result := ownerPOST(server.Client(), server.URL, "", fixtureExecutionToken, r)
			require.NoError(t, result.err)
			require.Equal(t, http.StatusBadRequest, result.code)
		}
	}
	require.Zero(t, admits.Load())
	require.Empty(t, h.entries)
}

func TestCodingPlanRegistryRejectsEndpointModelAndDuplicateDefinitions(t *testing.T) {
	// The actual constructor rejects a bad optional leaf before enrollment I/O.
	// Reuse the real host fixture so a valid primary/custody cannot hide the risk.
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg := h.cfg
	good := QualifiedProfile{Profile: service.GatewayKimiCodeResponsesProfile, BaseURL: service.GatewayKimiCodeResponsesBaseURL, Model: service.GatewayKimiCodeResponsesModel, QualificationRef: "controlled-source-v1", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 100}
	for _, mutate := range []func(*QualifiedProfile){
		func(p *QualifiedProfile) { p.BaseURL = "https://api.kimi.ai/v1" },
		func(p *QualifiedProfile) { p.Model = "latest" },
		func(p *QualifiedProfile) { p.BaseURL += "/" },
		func(p *QualifiedProfile) { p.Profile = "runtime-plugin" },
		func(p *QualifiedProfile) { p.QualificationRef = strings.Repeat("x", 129) },
	} {
		bad := good
		mutate(&bad)
		cfg.CodingPlans = []QualifiedProfile{bad}
		_, err := New(context.Background(), cfg)
		require.Error(t, err)
	}
	cfg.CodingPlans = []QualifiedProfile{good, good}
	_, err := New(context.Background(), cfg)
	require.Error(t, err)
}
