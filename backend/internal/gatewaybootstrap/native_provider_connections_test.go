package gatewaybootstrap

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestCodingPlanGrokCleanupAuthorityExactTuple(t *testing.T) {
	generation := "11111111-1111-4111-8111-111111111111"
	route := service.GatewayNativeRoute{AccountID: 42, Generation: generation, CreatedAt: time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC), Profile: service.GatewayGrokOAuthResponsesProfile, BaseURL: service.GatewayGrokOAuthBaseURL, Model: service.GatewayGrokOAuthModel}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ownerRef": "owner", "leaseExpiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "native": route})
	}))
	defer server.Close()
	authority, err := newAuthority(AuthorityConfig{Origin: server.URL, Credential: fixtureConfig().Authority.Credential}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := service.GatewayNativeOAuthCleanupRequest{Scope: service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "owner", Account: "account", Generation: generation, Purpose: service.GatewayOAuthBundlePurpose}, Operation: "op", Action: "erase", CleanupRef: "cleanup", CleanupToken: "token"}
	if _, err = authority.AuthorizeNativeOAuthCleanup(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	route.Model = "unqualified-model"
	if _, err = authority.AuthorizeNativeOAuthCleanup(context.Background(), in); err == nil {
		t.Fatal("unqualified Grok cleanup tuple accepted")
	}
}
