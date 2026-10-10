package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// All test* types are TEST adapters around the REAL service, cache and handler.
// The deterministic signer is prospective TEST custody, not production authority.

const (
	testDescProfile    = "openai-codex-oauth-responses-v1"
	testDescBaseURL    = "https://chatgpt.com/backend-api/codex"
	testDescModel      = "gpt-6.1-sol"
	testDescAccountRef = "11111111-1111-4111-8111-111111111111"
	testDescGeneration = "22222222-2222-4222-8222-222222222222"
)

type testDescClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testDescClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

type testDescVerifier struct {
	pub     ed25519.PublicKey
	mu      sync.Mutex
	scope   service.OAuthDescriptorScope
	birth   service.OAuthVerifiedBirth
	sig     []byte
	revoked bool
}

func testDescCanonical(b service.OAuthVerifiedBirth) []byte {
	var buf bytes.Buffer
	buf.WriteString("TEST-custody-v1")
	for _, f := range []string{b.Scope.ConsumerID, b.Scope.OwnerRef, b.Scope.OperationID, b.Scope.AccountRef,
		b.Scope.Generation, strconv.FormatInt(b.AccountID, 10), b.CreatedAt, b.Profile, b.BaseURL, b.Model,
		b.CustodyRevision, strconv.FormatInt(b.ExpiresAt.UnixNano(), 10)} {
		buf.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f))))
		buf.WriteString(f)
	}
	return buf.Bytes()
}

func (v *testDescVerifier) Verify(_ context.Context, scope service.OAuthDescriptorScope) (service.OAuthVerifiedBirth, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.birth.Scope != scope || !ed25519.Verify(v.pub, testDescCanonical(v.birth), v.sig) {
		return service.OAuthVerifiedBirth{}, service.ErrOAuthDescriptorDenied
	}
	if v.revoked {
		return service.OAuthVerifiedBirth{}, service.ErrOAuthDescriptorRevoked
	}
	return v.birth, nil
}

type testDescQualifier struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (q *testDescQualifier) Check(context.Context, service.OAuthVerifiedBirth) error {
	q.calls.Add(1)
	if q.fail.Load() {
		return service.ErrOAuthDescriptorUnqualified
	}
	return nil
}

type descHandlerHarness struct {
	router    *gin.Engine
	verifier  *testDescVerifier
	qualifier *testDescQualifier
}

func newDescHandlerHarness(t *testing.T) *descHandlerHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	clock := &testDescClock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	scope := service.OAuthDescriptorScope{ConsumerID: "consumer-1", OwnerRef: "owner-1", OperationID: "op-1",
		AccountRef: testDescAccountRef, Generation: testDescGeneration}
	birth := service.OAuthVerifiedBirth{Scope: scope, AccountID: 42, CreatedAt: "2026-10-10T00:00:00Z",
		Profile: testDescProfile, BaseURL: testDescBaseURL, Model: testDescModel, CustodyRevision: "rev-1",
		ExpiresAt: clock.Now().Add(time.Hour)}
	h := &descHandlerHarness{
		verifier:  &testDescVerifier{pub: priv.Public().(ed25519.PublicKey), birth: birth, sig: ed25519.Sign(priv, testDescCanonical(birth))},
		qualifier: &testDescQualifier{},
	}
	cache, err := service.NewOAuthDescriptorMemoryCache(4)
	require.NoError(t, err)
	svc, err := service.NewOAuthDescriptorService(h.verifier, h.qualifier, cache, clock,
		service.OAuthDescriptorProfile{Profile: testDescProfile, BaseURL: testDescBaseURL, Model: testDescModel}, 10*time.Minute)
	require.NoError(t, err)
	// Test authenticator: bearer token maps to consumer and owner.
	principal := func(c *gin.Context) (string, string, bool) {
		if c.GetHeader("Authorization") == "Bearer test-owner-1" {
			return "consumer-1", "owner-1", true
		}
		if c.GetHeader("Authorization") == "Bearer test-owner-2" {
			return "consumer-1", "owner-2", true
		}
		return "", "", false
	}
	h.router = gin.New()
	h.router.Any(OAuthDescriptorPath, NewOAuthDescriptorHandler(svc, principal).Describe)
	return h
}

const testDescBody = `{"operation":"op-1","owner_ref":"owner-1","account_ref":"` + testDescAccountRef + `","generation":"` + testDescGeneration + `"}`

func (h *descHandlerHarness) do(method, auth, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, OAuthDescriptorPath, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, r)
	return w
}

func (h *descHandlerHarness) post(body string) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, "Bearer test-owner-1", "application/json", body)
}

func TestOAuthDescriptorHandlerExactWireAndCacheHit(t *testing.T) {
	h := newDescHandlerHarness(t)
	want := `{"operation":"op-1","account_ref":"` + testDescAccountRef + `","state":"staged","qualification":"controlled-source-v1",` +
		`"native":{"account_id":42,"generation":"` + testDescGeneration + `","created_at":"2026-10-10T00:00:00Z",` +
		`"profile":"` + testDescProfile + `","base_url":"` + testDescBaseURL + `","model":"` + testDescModel + `"}}`
	for i := 0; i < 2; i++ {
		w := h.post(testDescBody)
		require.Equal(t, http.StatusOK, w.Code)
		require.JSONEq(t, want, w.Body.String())
		var generic map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &generic))
		require.Len(t, generic, 5)
	}
	require.Equal(t, int32(1), h.qualifier.calls.Load(), "second request must not qualify again")
}

func TestOAuthDescriptorHandlerRevokedAfterCacheIsDenied(t *testing.T) {
	h := newDescHandlerHarness(t)
	require.Equal(t, http.StatusOK, h.post(testDescBody).Code)
	h.verifier.mu.Lock()
	h.verifier.revoked = true
	h.verifier.mu.Unlock()
	w := h.post(testDescBody)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.JSONEq(t, `{"error":"denied"}`, w.Body.String())
	require.Equal(t, int32(1), h.qualifier.calls.Load())
}

func TestOAuthDescriptorHandlerRejectsMalformedRequests(t *testing.T) {
	h := newDescHandlerHarness(t)
	valid := testDescBody
	// Built at runtime so no literal unicode escape appears in the source:
	// the key decodes to "operation" only inside the JSON decoder.
	escapedOperationKey := `"operat` + string(rune(92)) + `u0069on"`
	cases := map[string]string{
		"unknown field":   strings.Replace(valid, `"generation"`, `"extra":"x","generation"`, 1),
		"duplicate key":   strings.Replace(valid, `"operation":"op-1"`, `"operation":"op-1","operation":"op-1"`, 1),
		"escaped dup":     strings.Replace(valid, `"operation":"op-1"`, `"operation":"op-1",`+escapedOperationKey+`:"op-1"`, 1),
		"escaped dup alt": strings.Replace(valid, `"operation":"op-1"`, `"operation":"op-1",`+escapedOperationKey+`:"op-2"`, 1),
		"trailing json":   valid + `{}`,
		"trailing text":   valid + ` x`,
		"missing field":   `{"operation":"op-1","owner_ref":"owner-1","account_ref":"` + testDescAccountRef + `"}`,
		"non string":      strings.Replace(valid, `"op-1"`, `1`, 1),
		"array":           `[]`,
		"nested":          strings.Replace(valid, `"op-1"`, `{"a":"b"}`, 1),
		"bad account":     strings.Replace(valid, testDescAccountRef, "not-a-uuid", 1),
		"empty operation": strings.Replace(valid, `"op-1"`, `""`, 1),
		"empty body":      ``,
	}
	for name, body := range cases {
		w := h.post(body)
		require.Equal(t, http.StatusBadRequest, w.Code, name)
		require.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String(), name)
	}
	oversize := `{"operation":"` + strings.Repeat("a", oauthDescriptorBodyLimit) + `"}`
	require.Equal(t, http.StatusRequestEntityTooLarge, h.post(oversize).Code)
	require.Equal(t, http.StatusBadRequest, h.do(http.MethodPost, "Bearer test-owner-1", "text/plain", valid).Code)
	require.Equal(t, http.StatusMethodNotAllowed, h.do(http.MethodGet, "Bearer test-owner-1", "application/json", valid).Code)
	require.Zero(t, h.qualifier.calls.Load())
}

func TestOAuthDescriptorHandlerRequiresAuthenticatedOwner(t *testing.T) {
	h := newDescHandlerHarness(t)
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodPost, "", "application/json", testDescBody).Code)
	require.Equal(t, http.StatusUnauthorized, h.do(http.MethodPost, "Bearer wrong", "application/json", testDescBody).Code)
	// Authenticated as owner-2 but body names owner-1.
	require.Equal(t, http.StatusForbidden, h.do(http.MethodPost, "Bearer test-owner-2", "application/json", testDescBody).Code)
	// Body owner substitution while authenticated as owner-1.
	other := strings.Replace(testDescBody, `"owner-1"`, `"owner-2"`, 1)
	require.Equal(t, http.StatusForbidden, h.post(other).Code)
	// Authenticated owner-2 with matching body has no custody for that scope.
	w := h.do(http.MethodPost, "Bearer test-owner-2", "application/json", other)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Zero(t, h.qualifier.calls.Load())
}

func TestOAuthDescriptorHandlerSubstitutedScopeIsDenied(t *testing.T) {
	h := newDescHandlerHarness(t)
	for name, body := range map[string]string{
		"operation":  strings.Replace(testDescBody, `"op-1"`, `"op-2"`, 1),
		"account":    strings.Replace(testDescBody, testDescAccountRef, "33333333-3333-4333-8333-333333333333", 1),
		"generation": strings.Replace(testDescBody, testDescGeneration, "33333333-3333-4333-8333-333333333333", 1),
	} {
		w := h.post(body)
		require.Equal(t, http.StatusForbidden, w.Code, name)
		require.JSONEq(t, `{"error":"denied"}`, w.Body.String(), name)
	}
	require.Zero(t, h.qualifier.calls.Load())
}

func TestOAuthDescriptorHandlerUnqualifiedIsNotCached(t *testing.T) {
	h := newDescHandlerHarness(t)
	h.qualifier.fail.Store(true)
	w := h.post(testDescBody)
	require.Equal(t, http.StatusConflict, w.Code)
	require.JSONEq(t, `{"error":"not_qualified"}`, w.Body.String())
	h.qualifier.fail.Store(false)
	require.Equal(t, http.StatusOK, h.post(testDescBody).Code)
	require.Equal(t, int32(2), h.qualifier.calls.Load())
}
