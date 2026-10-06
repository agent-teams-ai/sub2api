package gatewaybootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func fixtureConfig() Config {
	return Config{ListenAddress: "127.0.0.1:18081", PostgresDSN: "postgres://fixture@127.0.0.1:1/fixture?sslmode=disable",
		Authority: AuthorityConfig{Origin: "http://127.0.0.1:18082", Credential: "fixture-authority-credential"},
		Custody:   CustodyConfig{ActiveKeyID: "fixture", Keys: []CustodyKey{{ID: "fixture", Key: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 32)))}}},
		Peers: []ControlPeer{{ConsumerID: "fixture-consumer", Role: "management", Credential: "fixture-management-credential"},
			{ConsumerID: "fixture-consumer", Role: "execution", Credential: "fixture-execution-credential"},
			{ConsumerID: "fixture-consumer", Role: "cleanup", Credential: "fixture-cleanup-credential"}},
		Profile: ProfileConfig{Model: "fixture-model", BaseURL: "https://fixture.invalid", QualificationRef: "fixture-qualification", RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 200}, MaxEntries: 4}
}

func TestAuthorityFixedPathsAndDistinctAckBodies(t *testing.T) {
	type observed struct {
		path string
		body map[string]json.RawMessage
	}
	seen := make(chan observed, 6)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+fixtureConfig().Authority.Credential || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong trusted authority request")
		}
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid authority body")
		}
		seen <- observed{r.URL.Path, body}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	a, err := newAuthority(AuthorityConfig{server.URL, "fixture-authority-credential"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.client.CloseIdleConnections()
	var cfg gatewaytransport.Config
	a.compose(&cfg)
	ctx := context.Background()
	proof := gatewaytransport.Proof{ExecutionRef: "fixture-execution", RequestRef: "fixture-request", Worker: "11111111-1111-4111-8111-111111111111", Token: "fixture-proof"}
	lease := gatewaytransport.CleanupLease{CleanupRef: "fixture-cleanup", Worker: proof.Worker, Token: "fixture-lease", LeaseExpiresAt: "2026-10-04T01:02:03.123456789Z"}
	stamp, _ := time.Parse(time.RFC3339Nano, lease.LeaseExpiresAt)
	checks := []struct {
		path string
		call func() error
		keys []string
	}{
		{"enrollment", func() error {
			return cfg.VerifyEnrollment(ctx, gatewaytransport.Enrollment{OriginRef: "fixture-origin", EngineIncarnation: proof.Worker, QualificationRef: "fixture-qualification"})
		}, []string{"originRef", "engineIncarnation", "qualificationRef"}},
		{"dispatch-proof", func() error { return cfg.VerifyDispatch(ctx, "fixture-consumer", proof, stamp) }, []string{"consumerId", "proof", "leaseExpiresAt"}},
		{"cleanup-authority", func() error { return cfg.AuthorizeCleanup(ctx, "fixture-consumer", proof, lease) }, []string{"consumerId", "proof", "cleanup"}},
		{"owner-closure-authority", func() error { return cfg.AuthorizeOwnerClosure(ctx, "fixture-consumer", proof) }, []string{"consumerId", "proof"}},
		{"closure-ack", func() error {
			return cfg.AcknowledgeClosure(ctx, "fixture-consumer", proof, lease, gatewaytransport.Receipt{})
		}, []string{"consumerId", "proof", "cleanup", "receipt"}},
		{"closure-ack", func() error {
			return cfg.AcknowledgeOwnerClosure(ctx, "fixture-consumer", proof, gatewaytransport.Receipt{})
		}, []string{"consumerId", "proof", "receipt"}},
	}
	for _, check := range checks {
		if check.call() != nil {
			t.Fatal("trusted ACK rejected", check.path)
		}
		got := <-seen
		if got.path != "/private/native/v1/"+check.path || len(got.body) != len(check.keys) {
			t.Fatal("authority wire changed", got.path)
		}
		for _, key := range check.keys {
			if _, ok := got.body[key]; !ok {
				t.Fatal("missing trusted wire field", key)
			}
		}
		if raw := got.body["leaseExpiresAt"]; raw != nil && string(raw) != `"2026-10-04T01:02:03.123456789Z"` {
			t.Fatal("lease precision lost")
		}
		if raw := got.body["proof"]; raw != nil {
			var gotProof gatewaytransport.Proof
			if json.Unmarshal(raw, &gotProof) != nil || gotProof != proof {
				t.Fatal("proof type was mapped incorrectly")
			}
		}
	}
}

func TestAuthorityAmbiguousAckNeverRetriesOrRedirects(t *testing.T) {
	for _, kind := range []string{"redirect", "status", "false", "unknown", "duplicate", "alias", "numeric", "utf8", "overcap", "headers", "timeout", "disconnected"} {
		t.Run(kind, func(t *testing.T) {
			var calls, redirected atomic.Int32
			releaseTimeout := make(chan struct{})
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				redirected.Add(1)
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				body := `{"ok":true}`
				switch kind {
				case "redirect":
					w.Header().Set("Location", target.URL)
					w.WriteHeader(307)
				case "status":
					w.WriteHeader(201)
				case "false":
					body = `{"ok":false}`
				case "unknown":
					body = `{"ok":true,"permission":true}`
				case "duplicate":
					body = `{"ok":false,"o\u006b":true}`
				case "alias":
					body = `{"OK":true}`
				case "numeric":
					body = `{"ok":1}`
				case "utf8":
					body += string([]byte{255})
				case "overcap":
					body = strings.Repeat(" ", 1025) + body
				case "headers":
					w.Header().Set("X-Fixture", strings.Repeat("H", 20000))
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-releaseTimeout:
					}
					return
				case "disconnected":
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Error("fixture response cannot hijack")
						return
					}
					conn, _, err := hijacker.Hijack()
					if err == nil {
						_ = conn.Close()
					}
					return
				}
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			// Unblock the fixture before Close even when an assertion aborts.
			defer close(releaseTimeout)
			a, err := newAuthority(AuthorityConfig{server.URL, "fixture-authority-credential"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer a.client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if a.post(ctx, "/private/native/v1/enrollment", enrollmentBody{}) == nil {
				t.Fatal("ambiguous ACK allowed authority")
			}
			if calls.Load() != 1 || redirected.Load() != 0 {
				t.Fatal("authority retried or followed redirect")
			}
		})
	}
}

func TestAuthorityTLSNeedsExplicitFixtureTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	c := AuthorityConfig{server.URL, "fixture-authority-credential"}
	a, err := newAuthority(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.post(context.Background(), "/private/native/v1/enrollment", enrollmentBody{}) == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	fixtureTransport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture TLS transport unavailable")
	}
	trusted, err := newAuthority(c, fixtureTransport)
	if err != nil || trusted.post(context.Background(), "/private/native/v1/enrollment", enrollmentBody{}) != nil {
		t.Fatal("explicit fixture certificate trust failed")
	}
}

func TestConfigStrictBytesAndNumericTokens(t *testing.T) {
	c := fixtureConfig()
	raw, _ := json.Marshal(c)
	var decoded Config
	if decodeStrict(raw, &decoded) != nil {
		t.Fatal("valid config rejected")
	}
	if _, err := decoded.validate(); err != nil {
		t.Fatal("valid fixed config rejected")
	}
	for _, bad := range [][]byte{
		append([]byte(`{"maxEntries":2,`), raw[1:]...),
		[]byte(strings.Replace(string(raw), `"maxEntries":4`, `"MaxEntries":4`, 1)),
		[]byte(strings.Replace(string(raw), `"maxEntries":4`, `"maxEntries":4.0`, 1)),
		[]byte(strings.Replace(string(raw), `"maxEntries":4`, `"maxEntries":4e0`, 1)),
		[]byte(strings.Replace(string(raw), `"maxEntries":4`, `"maxEntries":9007199254740992`, 1)),
		append(raw, 255), []byte(strings.Repeat(" ", configBytes) + string(raw)),
		[]byte(strings.Replace(string(raw), `"fixture-model"`, `"\ud800"`, 1)),
		[]byte(`{"listenAddress":"fixture-secret-marker","unknown":true}`),
		[]byte(strings.Replace(string(raw), `"peers":[`, `"peers":[[[[[[[[[[[[`, 1)),
	} {
		if err := decodeStrict(bad, &decoded); err == nil || err.Error() != "private native bootstrap denied" {
			t.Fatal("config failure leaked or accepted malformed authority")
		}
	}
}

// The byte bound is independent of the regexp quantifier supported by RE2.
func TestControlCredentialByteBounds(t *testing.T) {
	for _, check := range []struct {
		size  int
		valid bool
	}{{15, false}, {16, true}, {2048, true}, {2049, false}} {
		t.Run(fmt.Sprint(check.size), func(t *testing.T) {
			c := fixtureConfig()
			c.Peers[0].Credential = strings.Repeat("A", check.size)
			_, err := c.validate()
			if (err == nil) != check.valid {
				t.Fatal("control credential configuration byte bound changed")
			}
			req := httptest.NewRequest("POST", "http://127.0.0.1/private", nil)
			req.Header.Set("Authorization", "Bearer "+c.Peers[0].Credential)
			peer, err := authorize(c.Peers)(req)
			if (err == nil) != check.valid || (check.valid && peer.Role != "management") {
				t.Fatal("control header byte bound changed")
			}
		})
	}
}

func fixtureOAuthConfig() Config {
	c := fixtureConfig()
	c.ListenAddress = "127.0.0.1:1455"
	c.OAuth = &OAuthConfig{IntentKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("I", 32))),
		Profile: ProfileConfig{Model: service.GatewayCodexOAuthModel, BaseURL: service.GatewayCodexOAuthBaseURL,
			QualificationRef: "codex-fixture-qualification", RequestBytes: 2048, OutputBytes: 3072, Tokens: 50, ProviderTokenUpperBound: 80}}
	return c
}

// Nearest FD6 regression: introducing an optional member must not make any
// accepted MiMo required key, duplicate-name or exact-number check optional.
func TestOAuthConfigExplicitStrictVariant(t *testing.T) {
	legacy := fixtureConfig()
	raw, _ := json.Marshal(legacy)
	if bytesContain := strings.Contains(string(raw), `"oauth"`); bytesContain {
		t.Fatal("legacy MiMo wire changed")
	}
	var decoded Config
	if decodeStrict(raw, &decoded) != nil || decoded.OAuth != nil {
		t.Fatal("legacy strict config failed")
	}
	c := fixtureOAuthConfig()
	raw, _ = json.Marshal(c)
	if decodeStrict(raw, &decoded) != nil {
		t.Fatal("explicit OAuth config failed")
	}
	if _, err := decoded.validate(); err != nil || decoded.qualifiedProfile() != c.Profile.qualified() ||
		decoded.codexProfile().Profile != service.GatewayCodexOAuthResponsesProfile || decoded.codexProfile().QualificationRef != c.OAuth.Profile.QualificationRef {
		t.Fatal("canonical protected profile failed")
	}
	profileJSON, err := json.Marshal(c.OAuth.Profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.OAuth.Profile.Model = "caller-model" },
		func(c *Config) { c.OAuth.Profile.BaseURL = "https://chatgpt.com/backend-api/codex/" },
		func(c *Config) { c.OAuth.Profile = ProfileConfig{} },
		func(c *Config) { c.OAuth.Profile.QualificationRef = "" },
		func(c *Config) { c.OAuth.Profile.RequestBytes = 0 },
		func(c *Config) { c.OAuth.Profile.OutputBytes = 0 },
		func(c *Config) { c.OAuth.Profile.Tokens = 0 },
		func(c *Config) { c.OAuth.Profile.ProviderTokenUpperBound = c.OAuth.Profile.Tokens - 1 },
		func(c *Config) { c.ListenAddress = "127.0.0.1:18081" },
		func(c *Config) { c.OAuth.IntentKey = c.Custody.Keys[0].Key },
		func(c *Config) { c.OAuth.IntentKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		func(c *Config) { c.Peers[0].Role = "native-callback" },
	} {
		bad := fixtureOAuthConfig()
		mutate(&bad)
		if _, err := bad.validate(); err == nil {
			t.Fatal("unsafe OAuth config accepted")
		}
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"oauth":{`, `"oauth":null,"oauth":{`, 1),
		strings.Replace(string(raw), `"oauth":{`, `"OAuth":{`, 1),
		strings.Replace(string(raw), `"oauth":{`, `"oauth":{"unknown":true,`, 1),
		strings.Replace(string(raw), `"oauth":{`, `"oauth":null,"extra":{`, 1),
		strings.Replace(string(raw), `"maxEntries":4,`, "", 1),
		strings.Replace(string(raw), `"maxEntries":4`, `"maxEntries":4.0`, 1),
		strings.Replace(string(raw), `"intentKey":`, `"IntentKey":`, 1),
		strings.Replace(string(raw), `,"profile":`+string(profileJSON), "", 1),
	} {
		if decodeStrict([]byte(bad), &decoded) == nil {
			t.Fatal("OAuth variant loosened strict parsing")
		}
	}
}

func TestOAuthOwnerReplyAndFiniteConfig(t *testing.T) {
	gatewayOwnerFixtureCredentialRaw := make([]byte, 24)
	if _, err := rand.Read(gatewayOwnerFixtureCredentialRaw); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	gatewayOwnerFixtureCredential := base64.RawURLEncoding.EncodeToString(gatewayOwnerFixtureCredentialRaw)
	var calls atomic.Int32
 var refreshCall atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var got oauthOwnerBody
 expectedPath:="/private/native/v1/oauth-owner-authority"
 if refreshCall.Load(){expectedPath="/private/native/v1/oauth-refresh-authority"}
 body,readErr:=io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path!=expectedPath ||
			r.Header.Get("Authorization") != "Bearer "+gatewayOwnerFixtureCredential || (readErr!=nil || decodeStrict(body,&got)!=nil) ||
			got.ConsumerID != "fixture-consumer" || got.AccountRef != "fixture-account" || got.Generation != "33333333-3333-4333-8333-333333333333" {
			t.Error("owner lookup changed authenticated selectors")
		}
		w.Header().Set("Content-Type", "application/json")
		switch got.OperationID {
		case "valid":
			_, _ = io.WriteString(w, `{"ok":true,"ownerRef":"workspace/owned"}`)
		case "ack-only":
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "owner-alias":
			_, _ = io.WriteString(w, `{"ok":true,"OwnerRef":"workspace/owned"}`)
		case "private-field":
			_, _ = io.WriteString(w, `{"ok":true,"ownerRef":"workspace/owned","operation":"private"}`)
		case "oversize":
			_, _ = io.WriteString(w, strings.Repeat(" ", 1025)+`{"ok":true,"ownerRef":"workspace/owned"}`)
		}
	}))
	defer server.Close()
	a, err := newAuthority(AuthorityConfig{server.URL, gatewayOwnerFixtureCredential}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.client.CloseIdleConnections()
	for index,authorize:=range []func(context.Context,string,string,string,string)(string,error){a.AuthorizeNativeOAuthOwner,a.AuthorizeNativeOAuthRefreshOwner} {
 refreshCall.Store(index==1)
 for _, op := range []string{"valid", "ack-only", "owner-alias", "private-field", "oversize"} {
		owner, err := authorize(context.Background(), "fixture-consumer", op, "fixture-account", "33333333-3333-4333-8333-333333333333")
		if op == "valid" && (err != nil || owner != "workspace/owned") || op != "valid" && (err == nil || owner != "") {
			t.Fatal("owner-specific reply shape was not enforced", op)
		}
	}
	}
 if calls.Load() != 10 {
		t.Fatal("owner lookup retried")
	}

	c := fixtureConfig()
	c.OpenRouter = &ProfileConfig{BaseURL: service.GatewayOpenRouterBaseURL, Model: service.GatewayOpenRouterModel,
		QualificationRef: "openrouter-fixture-qualification", RequestBytes: 2048, OutputBytes: 3072, Tokens: 50, ProviderTokenUpperBound: 80}
	raw, _ := json.Marshal(c)
	var decoded Config
	if decodeStrict(raw, &decoded) != nil {
		t.Fatal("optional finite config failed")
	}
	if _, err := decoded.validate(); err != nil || decoded.qualifiedProfile() != c.Profile.qualified() ||
		decoded.openRouterProfile().Profile != service.GatewayOpenRouterResponsesProfile || decoded.openRouterProfile().Tokens != 50 {
		t.Fatal("second profile replaced the MiMo tuple or its own limits")
	}
	for i, bad := range []string{
		strings.Replace(string(raw), `"openRouter":{`, `"openRouter":null,"openRouter":{`, 1),
		strings.Replace(string(raw), `"openRouter":{`, `"OpenRouter":{`, 1),
		strings.Replace(string(raw), `"openRouter":{`, `"openRouter":{"id":"caller-profile",`, 1),
		strings.Replace(string(raw), `"openrouter-fixture-qualification"`, `null`, 1),
	} {
		if decodeStrict([]byte(bad), &decoded) == nil {
			t.Fatal("second profile loosened strict config", i)
		}
	}
	for _, mutate := range []func(*ProfileConfig){
		func(p *ProfileConfig) { p.BaseURL += "/" },
		func(p *ProfileConfig) { p.Model = c.Profile.Model },
		func(p *ProfileConfig) { p.QualificationRef = "" },
		func(p *ProfileConfig) { p.ProviderTokenUpperBound = p.Tokens - 1 },
	} {
		bad := c
		second := *c.OpenRouter
		bad.OpenRouter = &second
		mutate(bad.OpenRouter)
		if _, err := bad.validate(); err == nil {
			t.Fatal("cross-tuple or unqualified optional profile accepted")
		}
	}
}
