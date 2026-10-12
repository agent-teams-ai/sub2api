//go:build unit

package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func custodyTestBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	_, err := rand.Read(value)
	require.NoError(t, err)
	return value
}

func custodyTestScope() GatewayNativeCredentialScope {
	return GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "workspace/世界", Account: "account/é",
		Generation: "a1111111-1111-4111-8111-111111111111", Purpose: GatewayCredentialPurpose}
}

func custodyTestKeyring(t *testing.T, id string) *GatewayNativeCredentialCustody {
	t.Helper()
	c, err := NewGatewayNativeCredentialCustody(id, map[string][]byte{id: custodyTestBytes(t, 32)})
	require.NoError(t, err)
	return c
}

func custodyTestContext(t *testing.T, c *GatewayNativeCredentialCustody, consumer string) context.Context {
	t.Helper()
	ctx, err := WithGatewayNativeConsumer(context.Background(), consumer)
	require.NoError(t, err)
	return WithGatewayNativeCustody(ctx, c)
}

// Regression: a reversible encoding or unauthenticated encryption can pass
// readback while accepting tamper or a credential copied to another authority.
func TestGatewayNativeCustodyAEAD(t *testing.T) {
	c := custodyTestKeyring(t, "synthetic-k1")
	scope := custodyTestScope()
	key := base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32))
	envelope, err := c.Seal(scope, key)
	require.NoError(t, err)
	require.NotContains(t, envelope, key)
	require.NoError(t, c.ValidateEnvelope(envelope))
	authorization, err := c.authorization(envelope, scope)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+key, authorization)
	id, nonce, sealed, err := gatewayNativeParseEnvelope(envelope)
	require.NoError(t, err)
	// Regression: omitting any one scope member from AAD permits cross-scope use.
	for _, change := range []struct {
		name  string
		apply func(*GatewayNativeCredentialScope)
	}{
		{"consumer", func(s *GatewayNativeCredentialScope) { s.Consumer = "foreign-consumer" }},
		{"owner", func(s *GatewayNativeCredentialScope) { s.Owner = "workspace/foreign" }},
		{"account", func(s *GatewayNativeCredentialScope) { s.Account = "account/foreign" }},
		{"generation", func(s *GatewayNativeCredentialScope) { s.Generation = "b2222222-2222-4222-8222-222222222222" }},
		{"purpose", func(s *GatewayNativeCredentialScope) { s.Purpose = "export" }},
	} {
		t.Run("AAD "+change.name, func(t *testing.T) {
			changed := scope
			change.apply(&changed)
			// Actual AES-GCM authentication failure, even for wrong purpose (which
			// the public shape validator also rejects before decryption).
			_, err := c.keys[id].Open(nil, nonce, sealed, gatewayCredentialAAD(changed, id))
			require.Error(t, err)
			_, err = c.authorization(envelope, changed)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
	// Regression: ciphertext/nonce changes that preserve envelope shape evade a
	// parser-only check. Mutations below retain canonical base64 and byte lengths.
	for _, component := range []string{"ciphertext", "nonce"} {
		t.Run("tamper "+component, func(t *testing.T) {
			n, ciphertext := append([]byte(nil), nonce...), append([]byte(nil), sealed...)
			if component == "nonce" {
				n[0] ^= 1
			} else {
				ciphertext[0] ^= 1
			}
			bad := "gcn1." + id + "." + base64.RawURLEncoding.EncodeToString(n) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
			require.NoError(t, c.ValidateEnvelope(bad), "shape remains valid")
			_, err := c.authorization(bad, scope)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
	// Regression: a guessed/default key can turn key loss into silent adoption.
	t.Run("wrong and unavailable key", func(t *testing.T) {
		wrong := custodyTestKeyring(t, id)
		_, err := wrong.authorization(envelope, scope)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		missing := custodyTestKeyring(t, "different-id")
		require.ErrorIs(t, missing.ValidateEnvelope(envelope), ErrGatewayNativeIdentity)
		_, err = missing.authorization(envelope, scope)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	})
	// Regression: deterministic nonces disclose repeated plaintext and violate GCM.
	t.Run("independent nonce and encrypted JSON", func(t *testing.T) {
		other, err := c.Seal(scope, key)
		require.NoError(t, err)
		_, otherNonce, _, err := gatewayNativeParseEnvelope(other)
		require.NoError(t, err)
		require.NotEqual(t, nonce, otherNonce)
		encoded, err := json.Marshal(map[string]any{"api_key": envelope, "scope": scope.Metadata()})
		require.NoError(t, err)
		require.NotContains(t, string(encoded), key)
	})
}

// Regression: mutation of composition's key slice/map changes an active domain;
// implicit rotation also silently changes existing credential identity/readback.
func TestGatewayNativeCustodyExplicitRotation(t *testing.T) {
	scope := custodyTestScope()
	old := custodyTestBytes(t, 32)
	retained := append([]byte(nil), old...)
	key := base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32))
	keys := map[string][]byte{"old": old}
	c, err := NewGatewayNativeCredentialCustody("old", keys)
	require.NoError(t, err)
	envelope, err := c.Seal(scope, key)
	require.NoError(t, err)
	old[0] ^= 1
	delete(keys, "old")
	_, err = c.authorization(envelope, scope)
	require.NoError(t, err, "constructor owns a copied key")
	rotated, err := NewGatewayNativeCredentialCustody("new", map[string][]byte{
		"old": retained, "new": custodyTestBytes(t, 32)})
	require.NoError(t, err)
	require.NoError(t, rotated.ValidateEnvelope(envelope))
	_, err = rotated.authorization(envelope, scope)
	require.NoError(t, err)
	newEnvelope, err := rotated.Seal(scope, key)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(newEnvelope, "gcn1.new."))
	require.True(t, strings.HasPrefix(envelope, "gcn1.old."), "readback remains the original envelope")
	retired := custodyTestKeyring(t, "new")
	require.ErrorIs(t, retired.ValidateEnvelope(envelope), ErrGatewayNativeIdentity)
}

// Regression: oversized/control-bearing ingress or permissive envelope decoding
// enters HTTP headers, allocates unbounded data or accepts a plaintext marked row.
func TestGatewayNativeCustodyBounds(t *testing.T) {
	c := custodyTestKeyring(t, "k")
	for _, key := range []string{"", " leading", "trailing ", "line\nbreak", "nul\x00byte", strings.Repeat("a", 4097)} {
		_, err := c.Seal(custodyTestScope(), key)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	for _, bad := range []string{base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32)), "gcn1.k.bad.bad", strings.Repeat("a", 5601), "gcn2.k.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAA", "gcn1.k.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAA="} {
		require.ErrorIs(t, c.ValidateEnvelope(bad), ErrGatewayNativeIdentity)
	}
	_, err := NewGatewayNativeCredentialCustody("absent", map[string][]byte{"k": custodyTestBytes(t, 32)})
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = NewGatewayNativeCredentialCustody("k", map[string][]byte{"k": custodyTestBytes(t, 16)})
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	_, err = GatewayNativeConsumer(context.Background())
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
}

// Regression: decrypting an Account clone before fresh comparison can hide a
// row/key/scope change, or cause ciphertext itself to be sent as Authorization.
// The provider below is a real HTTP server; repository timing is controlled.
func TestGatewayNativeCustodyAuthorizationHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var entries atomic.Int32
	key := base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries.Add(1)
		require.Equal(t, "/v1/responses", r.URL.Path)
		require.Equal(t, "Bearer "+key, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","output":[]}`)
	}))
	defer upstream.Close()
	custody := custodyTestKeyring(t, "http-k1")
	scope := custodyTestScope()
	envelope, err := custody.Seal(scope, key)
	require.NoError(t, err)
	a := &Account{ID: 17, CreatedAt: time.Date(2026, 10, 3, 0, 0, 0, 123456000, time.UTC),
		Name: "世界 café", Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive, Concurrency: 1,
		Credentials: map[string]any{"api_key": envelope, "base_url": upstream.URL},
		Extra: map[string]any{GatewayGenerationExtraKey: scope.Generation, GatewayProfileExtraKey: GatewayMiMoResponsesProfile,
			GatewayModelExtraKey: "synthetic-model", GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses",
			"openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}}
	route, err := GatewayNativeDescriptor(a)
	require.NoError(t, err)
	repo := &gatewayIdentityRepoFixture{row: a}
	svc := &OpenAIGatewayService{accountRepo: repo, httpUpstream: &gatewayIdentityRealHTTP{client: upstream.Client()}, cfg: rawChatCompletionsTestConfig()}
	ctx := custodyTestContext(t, custody, scope.Consumer)
	body := []byte(`{"model":"synthetic-model","input":"fixture","store":false,"service_tier":"default"}`)
	invoke := func(ctx context.Context, d GatewayNativeRoute) (bool, error) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(body))
		_, entered, err := svc.ForwardGatewayRoute(ctx, c, d, body)
		require.NotContains(t, recorder.Body.String(), key)
		return entered, err
	}
	// Regression: a valid-shaped envelope with a wrong key/nonce/tag/AAD must not
	// reach the provider. Purpose and malformed shape also deny before transport.
	for _, field := range []string{"consumer", "owner", "account", "generation", "purpose", "tamper", "wrong-key", "missing-key", "missing-context", "plaintext"} {
		t.Run("zero entry "+field, func(t *testing.T) {
			row := snapshotGatewayNativeAccount(a)
			changed := scope
			callCtx, d := ctx, route
			switch field {
			case "consumer":
				changed.Consumer = "other-consumer"
				callCtx = custodyTestContext(t, custody, changed.Consumer)
			case "owner":
				changed.Owner = "workspace/other"
			case "account":
				changed.Account = "account/other"
			case "generation":
				changed.Generation = "b2222222-2222-4222-8222-222222222222"
				row.Extra[GatewayGenerationExtraKey], d.Generation = changed.Generation, changed.Generation
			case "purpose":
				otherPurpose := scope
				otherPurpose.Purpose = "export"
				id, nonce, _, err := gatewayNativeParseEnvelope(envelope)
				require.NoError(t, err)
				ciphertext := custody.keys[id].Seal(nil, nonce, []byte(key), gatewayCredentialAAD(otherPurpose, id))
				row.Credentials["api_key"] = "gcn1." + id + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
			case "tamper":
				id, nonce, ciphertext, err := gatewayNativeParseEnvelope(envelope)
				require.NoError(t, err)
				ciphertext[0] ^= 1
				row.Credentials["api_key"] = "gcn1." + id + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
			case "wrong-key":
				callCtx = custodyTestContext(t, custodyTestKeyring(t, "http-k1"), scope.Consumer)
			case "missing-key":
				callCtx = custodyTestContext(t, custodyTestKeyring(t, "other-id"), scope.Consumer)
			case "missing-context":
				callCtx = context.Background()
			case "plaintext":
				row.Credentials["api_key"] = key
			}
			row.Extra[GatewayCredentialScopeExtraKey] = changed.Metadata()
			repo.row, repo.fresh = row, nil
			entered, err := invoke(callCtx, d)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.False(t, entered)
			require.Zero(t, entries.Load())
		})
	}
	repo.row = a
	// Regression: fresh comparisons must use the encrypted original, even when
	// resealing produces the same plaintext or a transient clone contains it.
	for _, change := range []string{"resealed", "plaintext-clone", "scope"} {
		t.Run("fresh snapshot "+change, func(t *testing.T) {
			fresh := snapshotGatewayNativeAccount(a)
			switch change {
			case "resealed":
				value, err := custody.Seal(scope, key)
				require.NoError(t, err)
				fresh.Credentials["api_key"] = value
			case "plaintext-clone":
				fresh.Credentials["api_key"] = key
			case "scope":
				changed := scope
				changed.Owner = "workspace/other"
				fresh.Extra[GatewayCredentialScopeExtraKey] = changed.Metadata()
			}
			repo.fresh = fresh
			entered, err := invoke(ctx, route)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
			require.False(t, entered)
			require.Zero(t, entries.Load())
		})
	}
	// Regression: changing Unicode display names must not change credential AAD.
	t.Run("Unicode rename enters exactly once", func(t *testing.T) {
		fresh := snapshotGatewayNativeAccount(a)
		fresh.Name = "renamed 世界 café 🚀"
		repo.fresh = fresh
		entered, err := invoke(ctx, route)
		require.NoError(t, err)
		require.True(t, entered)
		require.EqualValues(t, 1, entries.Load())
		require.Equal(t, envelope, a.GetCredential("api_key"))
		require.Equal(t, envelope, fresh.GetCredential("api_key"))
	})
	repo.fresh = nil
	// Regression: a second common-seam transport call can bypass the entered CAS.
	t.Run("one-entry CAS", func(t *testing.T) {
		state := &gatewayNativeDispatch{route: route, account: a, scope: scope, custody: custody}
		state.entered.Store(true)
		request, err := http.NewRequestWithContext(context.WithValue(ctx, gatewayNativeContextKey{}, state), http.MethodPost, upstream.URL+"/v1/responses", bytes.NewReader(body))
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+envelope)
		_, err = svc.doOpenAIUpstream(request, "", a)
		require.ErrorIs(t, err, ErrGatewayNativeReplay)
		require.EqualValues(t, 1, entries.Load())
	})
	// Regression: custody context must not let ordinary export/forward/probe paths
	// authorize a managed row. These are the real existing service methods.
	t.Run("ordinary paths stay excluded", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		_, err := svc.Forward(ctx, c, a, body)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		admin := &adminServiceImpl{accountRepo: repo}
		_, err = admin.GetAccountsByIDs(ctx, []int64{a.ID})
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		probe := &AccountTestService{}
		request, err := http.NewRequest(http.MethodPost, upstream.URL+"/v1/responses", bytes.NewReader(body))
		require.NoError(t, err)
		_, err = probe.doOpenAIAccountTestUpstream(request, "", a, false)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		require.False(t, a.IsSchedulable())
		require.EqualValues(t, 1, entries.Load())
	})
}

// Failure: a rotated whole bundle could authenticate under another engine
// version, downgrade to initial gco1, or lose its exact custody scope.
func TestGatewayNativeOAuthVersionCustody(t *testing.T) {
	key := custodyTestBytes(t, 32)
	custody, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": key})
	require.NoError(t, err)
	scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "account", Generation: "11111111-1111-4111-8111-111111111111", Purpose: GatewayOAuthBundlePurpose}
	bundle := GatewayNativeOAuthBundle{AccessToken: base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32)), RefreshToken: base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32)), IDToken: base64.RawURLEncoding.EncodeToString(custodyTestBytes(t, 32)), SensitiveMetadata: json.RawMessage(`{"protected":"fixture"}`)}
	initial, err := custody.SealOAuthBundle(scope, bundle)
	require.NoError(t, err)
	_, err = custody.openOAuthVersion(initial, scope, 1)
	require.NoError(t, err)
	rotated, err := custody.sealOAuthVersion(scope, 2, bundle)
	require.NoError(t, err)
	again, err := custody.sealOAuthVersion(scope, 2, bundle)
	require.NoError(t, err)
	require.NotEqual(t, rotated, again, "fresh GCM nonce per publication")
	opened, err := custody.openOAuthVersion(rotated, scope, 2)
	require.NoError(t, err)
	require.Equal(t, bundle, opened)
	for _, version := range []int64{0, 1, 3} {
		_, err = custody.openOAuthVersion(rotated, scope, version)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	_, err = custody.openOAuthVersion(initial, scope, 2)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	for _, field := range []string{"consumer", "owner", "account", "generation", "purpose"} {
		foreign := scope
		switch field {
		case "consumer":
			foreign.Consumer = "other"
		case "owner":
			foreign.Owner = "other"
		case "account":
			foreign.Account = "other"
		case "generation":
			foreign.Generation = "22222222-2222-4222-8222-222222222222"
		case "purpose":
			foreign.Purpose = GatewayCredentialPurpose
		}
		_, err = custody.openOAuthVersion(rotated, foreign, 2)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	for _, bad := range []string{strings.Replace(rotated, ".2.", ".02.", 1), strings.Replace(rotated, ".2.", ".3.", 1), strings.Replace(rotated, "gco2.", "gco1.", 1)} {
		_, err = custody.openOAuthVersion(bad, scope, 2)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	parts := strings.Split(rotated, ".")
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[4])
	require.NoError(t, err)
	ciphertext[0] ^= 1
	parts[4] = base64.RawURLEncoding.EncodeToString(ciphertext)
	_, err = custody.openOAuthVersion(strings.Join(parts, "."), scope, 2)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	wrong, err := NewGatewayNativeCredentialCustody("fixture", map[string][]byte{"fixture": custodyTestBytes(t, 32)})
	require.NoError(t, err)
	_, err = wrong.openOAuthVersion(rotated, scope, 2)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	for _, token := range []string{bundle.AccessToken, bundle.RefreshToken, bundle.IDToken} {
		require.NotContains(t, rotated, token)
	}
}
