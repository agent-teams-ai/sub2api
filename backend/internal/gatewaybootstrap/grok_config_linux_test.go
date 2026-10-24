//go:build linux

package gatewaybootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// The real FD6 loader must accept a qualified Grok object, rather than only
// configurations assembled directly in memory by the joined fixture.
func TestGrokConfigCapturedJSON(t *testing.T) {
	c := fixtureConfig()
	p := c.Profile
	p.BaseURL, p.Model = service.GatewayGrokOAuthBaseURL, service.GatewayGrokOAuthModel
	c.Grok = &GrokConfig{Profile: p, ClientID: "qualified-fixture-client", RedirectURI: "https://review.example/callback", DeploymentQualified: true}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	load := func(raw []byte) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bootstrap.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return readConfig(f)
	}
	decoded, err := load(raw)
	if err != nil || decoded.Grok == nil {
		t.Fatal("qualified Grok captured JSON rejected")
	}
	if *decoded.Grok != *c.Grok || decoded.grokProfile() == nil || decoded.grokProfile().Profile != service.GatewayGrokOAuthResponsesProfile {
		t.Fatal("Grok config changed during captured read")
	}
	if _, err := decoded.validate(); err != nil {
		t.Fatal("qualified decoded Grok rejected")
	}
	grokJSON, err := json.Marshal(c.Grok)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"null":             strings.Replace(string(raw), `"grok":`+string(grokJSON), `"grok":null`, 1),
		"alias":            strings.Replace(string(raw), `"grok":{`, `"Grok":{`, 1),
		"duplicate":        strings.Replace(string(raw), `"grok":{`, `"grok":null,"grok":{`, 1),
		"unknown":          strings.Replace(string(raw), `"grok":{`, `"grok":{"unknown":true,`, 1),
		"missing_client":   strings.Replace(string(raw), `"clientId":"qualified-fixture-client",`, "", 1),
		"null_qualified":   strings.Replace(string(raw), `"deploymentQualified":true`, `"deploymentQualified":null`, 1),
		"string_qualified": strings.Replace(string(raw), `"deploymentQualified":true`, `"deploymentQualified":"true"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load([]byte(bad)); err != ErrDenied {
				t.Fatal("malformed Grok captured JSON accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*GrokConfig){
		"unqualified":      func(g *GrokConfig) { g.DeploymentQualified = false },
		"foreign_origin":   func(g *GrokConfig) { g.Profile.BaseURL = "https://foreign.invalid/v1" },
		"foreign_model":    func(g *GrokConfig) { g.Profile.Model = "foreign-model" },
		"invalid_redirect": func(g *GrokConfig) { g.RedirectURI = "http://foreign.invalid/callback" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			g := *c.Grok
			mutate(&g)
			bad.Grok = &g
			b, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			got, err := load(b)
			if err != nil {
				t.Fatal("structural Grok config rejected before qualification")
			}
			if _, err := got.validate(); err != ErrDenied {
				t.Fatal("unqualified Grok deployment accepted")
			}
		})
	}
}
