package gatewaybootstrap

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"testing"
)

// A deployment preset cannot turn a closed tuple into arbitrary upstream
// routing; adding a profile does not silently enable Grok's public CLI client.
func TestCodingPlanConfigClosedAndExplicit(t *testing.T) {
	c := fixtureConfig()
	p := c.Profile
	p.BaseURL = service.GatewayKimiCodeResponsesBaseURL
	p.Model = service.GatewayKimiCodeResponsesModel
	c.CodingPlans = []CodingPlanConfig{{ProfileID: service.GatewayKimiCodeResponsesProfile, Profile: p}}
	if _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.CodingPlans[0].Profile.BaseURL = "https://arbitrary.invalid"
	if _, err := c.validate(); err == nil {
		t.Fatal("arbitrary coding plan URL accepted")
	}
	c.CodingPlans[0].Profile = p
	c.CodingPlans = append(c.CodingPlans, c.CodingPlans[0])
	if _, err := c.validate(); err == nil {
		t.Fatal("duplicate coding plan accepted")
	}
	c.CodingPlans = nil
	p.BaseURL = service.GatewayGrokOAuthBaseURL
	p.Model = service.GatewayGrokOAuthModel
	c.Grok = &GrokConfig{Profile: p, ClientID: "qualified-fixture-client", RedirectURI: "https://review.example/callback"}
	if _, err := c.validate(); err == nil {
		t.Fatal("unqualified public client accepted")
	}
	c.Grok.DeploymentQualified = true
	if _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
}
