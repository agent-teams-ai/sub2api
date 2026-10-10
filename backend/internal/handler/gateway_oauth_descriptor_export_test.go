package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
)

// TEST-only joined producer. The REAL handler, service, memory cache and
// OAuthChatGPTAccountQualifier (which runs the real fetchChatGPTAccountInfo
// parser) run against a local httptest upstream. The signed custody and the
// credential lookup are TEST adapters, not production authority. Fixtures are
// exported only when AG_OAUTH_JOINED_DESCRIPTOR_FIXTURE_DIR names a new
// absolute directory; the pipeline and its assertions always run.

const (
	exportFixtureEnv = "AG_OAUTH_JOINED_DESCRIPTOR_FIXTURE_DIR"

	exportAccountsCheckPath = "/backend-api/accounts/check/v4-2023-04-27"
	exportToken             = "test-access-token-do-not-export"
	exportOrg               = "org-test-1"
	exportOperation         = "op-joined-1"
	exportAccountRef        = "44444444-4444-4444-8444-444444444444"
	exportGeneration        = "55555555-5555-4555-8555-555555555555"

	// Independently seeded literals; expected is never derived from a response.
	// exportScopeJSON is the HTTP request wire body only; it is never exported.
	exportScopeJSON = `{"operation":"op-joined-1","owner_ref":"owner-1","account_ref":"44444444-4444-4444-8444-444444444444","generation":"55555555-5555-4555-8555-555555555555"}`
	// exportOAuthScopeJSON is the exported scope.json: the full camelCase OAuthScope.
	exportOAuthScopeJSON = `{"consumerId":"consumer-1","ownerRef":"owner-1","operationId":"op-joined-1",` +
		`"accountRef":"44444444-4444-4444-8444-444444444444","generation":"55555555-5555-4555-8555-555555555555"}`
	// exportNativeJSON is the exported expected.json: the native tuple only.
	exportNativeJSON = `{"account_id":42,"generation":"55555555-5555-4555-8555-555555555555","created_at":"2026-10-08T12:34:56.123456Z",` +
		`"profile":"openai-codex-oauth-responses-v1","base_url":"https://chatgpt.com/backend-api/codex","model":"gpt-6.1-sol"}`
	// exportExpectedJSON is the independent full-response expectation used only for assertions.
	exportExpectedJSON = `{"operation":"op-joined-1","account_ref":"44444444-4444-4444-8444-444444444444","state":"staged","qualification":"controlled-source-v1",` +
		`"native":` + exportNativeJSON + `}`

	exportAccountsOK = `{"accounts":{"` + exportOrg + `":{"account":{"account_id":"` + exportOrg + `","plan_type":"plus"}}}}`
)

// testExportLookup is the TEST credential lookup, keyed by the full birth.
type testExportLookup struct {
	creds map[service.OAuthVerifiedBirth]service.OAuthAccountCredential
	calls atomic.Int32
	err   error
}

func (l *testExportLookup) Lookup(_ context.Context, birth service.OAuthVerifiedBirth) (service.OAuthAccountCredential, error) {
	l.calls.Add(1)
	if l.err != nil {
		return service.OAuthAccountCredential{}, l.err
	}
	cred, ok := l.creds[birth]
	if !ok {
		return service.OAuthAccountCredential{}, service.ErrOAuthDescriptorDenied
	}
	return cred, nil
}

type exportHarness struct {
	router   *gin.Engine
	lookup   *testExportLookup
	hits     atomic.Int32
	rejected atomic.Bool
	mu       sync.Mutex
	hosts    []string
	paths    []string
}

func newExportHarness(t *testing.T, upstreamBody string, withCredential bool) *exportHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &exportHarness{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.hits.Add(1) > 1 || r.URL.Path != exportAccountsCheckPath || r.Header.Get("Authorization") != "Bearer "+exportToken {
			h.rejected.Store(true)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// Redirect every outbound request to the local server, recording what the
	// production code actually asked for.
	factory := func(string) (*req.Client, error) {
		return req.C().WrapRoundTripFunc(func(rt req.RoundTripper) req.RoundTripFunc {
			return func(r *req.Request) (*req.Response, error) {
				h.mu.Lock()
				h.hosts = append(h.hosts, r.URL.Host)
				h.paths = append(h.paths, r.URL.Path)
				h.mu.Unlock()
				r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
				return rt.RoundTrip(r)
			}
		}), nil
	}

	clock := &testDescClock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	scope := service.OAuthDescriptorScope{ConsumerID: "consumer-1", OwnerRef: "owner-1", OperationID: exportOperation,
		AccountRef: exportAccountRef, Generation: exportGeneration}
	birth := service.OAuthVerifiedBirth{Scope: scope, AccountID: 42, CreatedAt: "2026-10-08T12:34:56.123456Z",
		Profile: "openai-codex-oauth-responses-v1", BaseURL: "https://chatgpt.com/backend-api/codex", Model: "gpt-6.1-sol",
		CustodyRevision: "rev-joined-1", ExpiresAt: clock.Now().Add(time.Hour)}
	verifier := &testDescVerifier{pub: priv.Public().(ed25519.PublicKey), birth: birth, sig: ed25519.Sign(priv, testDescCanonical(birth))}

	h.lookup = &testExportLookup{creds: map[service.OAuthVerifiedBirth]service.OAuthAccountCredential{}}
	if withCredential {
		h.lookup.creds[birth] = service.OAuthAccountCredential{AccessToken: exportToken, OrgID: exportOrg}
	}
	qualifier, err := service.NewOAuthChatGPTAccountQualifier(h.lookup, factory)
	require.NoError(t, err)
	cache, err := service.NewOAuthDescriptorMemoryCache(4)
	require.NoError(t, err)
	svc, err := service.NewOAuthDescriptorService(verifier, qualifier, cache, clock,
		service.OAuthDescriptorProfile{Profile: birth.Profile, BaseURL: birth.BaseURL, Model: birth.Model}, 10*time.Minute)
	require.NoError(t, err)

	principal := func(c *gin.Context) (string, string, bool) {
		if c.GetHeader("Authorization") == "Bearer test-owner-1" {
			return "consumer-1", "owner-1", true
		}
		return "", "", false
	}
	h.router = gin.New()
	h.router.POST(OAuthDescriptorPath, NewOAuthDescriptorHandler(svc, principal).Describe)
	return h
}

// post returns a private copy of the recorder body, exactly as written.
func (h *exportHarness) post(body string) (int, []byte) {
	r := httptest.NewRequest(http.MethodPost, OAuthDescriptorPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer test-owner-1")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, r)
	return w.Code, append([]byte(nil), w.Body.Bytes()...)
}

// exportTarget validates the optional export directory before any request.
func exportTarget(t *testing.T) string {
	t.Helper()
	dir := os.Getenv(exportFixtureEnv)
	if dir == "" {
		return ""
	}
	require.True(t, filepath.IsAbs(dir) && filepath.Clean(dir) == dir, "fixture dir must be a clean absolute path")
	_, err := os.Lstat(dir)
	require.True(t, errors.Is(err, fs.ErrNotExist), "fixture dir must not exist")
	parent, err := os.Stat(filepath.Dir(dir))
	require.NoError(t, err)
	require.True(t, parent.IsDir())
	return dir
}

// removeOwnedExport removes the contents of a directory this test created with
// its own successful Mkdir, then the directory itself.
func removeOwnedExport(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

// exportFiles writes each file via an exclusive 0600 temp file and a
// no-overwrite hard link, removes the temp, then makes the final file 0400.
func exportFiles(t *testing.T, dir string, files [][2]string) {
	t.Helper()
	for _, f := range files {
		tmp := filepath.Join(dir, ".tmp-"+f[0])
		fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		require.NoError(t, err)
		_, werr := fh.WriteString(f[1])
		serr := fh.Sync()
		cerr := fh.Close()
		require.NoError(t, werr)
		require.NoError(t, serr)
		require.NoError(t, cerr)
		require.NoError(t, os.Link(tmp, filepath.Join(dir, f[0])))
		require.NoError(t, os.Remove(tmp))
		require.NoError(t, os.Chmod(filepath.Join(dir, f[0]), 0o400))
	}
}

func TestOAuthDescriptorExportFilesAreImmutableAndCleanable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export")
	require.NoError(t, os.Mkdir(dir, 0o700))
	exportFiles(t, dir, [][2]string{{"a.json", `{"a":1}`}, {"b.json", `{"b":2}`}})

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		info, err := e.Info()
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o400), info.Mode().Perm(), e.Name())
	}
	require.Equal(t, []string{"a.json", "b.json"}, names, "no temp files may remain")
	if os.Geteuid() != 0 {
		_, err = os.OpenFile(filepath.Join(dir, "a.json"), os.O_WRONLY, 0)
		require.Error(t, err, "exported file must be read-only")
	}

	require.NoError(t, removeOwnedExport(dir))
	_, err = os.Lstat(dir)
	require.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestOAuthDescriptorJoinedProducerExport(t *testing.T) {
	dir := exportTarget(t)
	if dir != "" {
		// Seed independent scope and expected files before any handler call.
		require.NoError(t, os.Mkdir(dir, 0o700))
		// Mkdir succeeded, so this test owns dir exactly; on failure leave nothing behind.
		t.Cleanup(func() {
			if t.Failed() {
				_ = removeOwnedExport(dir)
			}
		})
		exportFiles(t, dir, [][2]string{{"scope.json", exportOAuthScopeJSON}, {"expected.json", exportNativeJSON}})
	}
	h := newExportHarness(t, exportAccountsOK, true)

	firstCode, first := h.post(exportScopeJSON)
	require.Equal(t, http.StatusOK, firstCode)
	require.Equal(t, int32(1), h.hits.Load())
	require.Equal(t, int32(1), h.lookup.calls.Load())

	cachedCode, cached := h.post(exportScopeJSON)
	require.Equal(t, http.StatusOK, cachedCode)
	require.Equal(t, int32(1), h.hits.Load(), "cache hit must not reach upstream")
	require.Equal(t, int32(1), h.lookup.calls.Load(), "cache hit must not look up credentials")
	require.False(t, h.rejected.Load(), "upstream must never see a second or malformed call")

	h.mu.Lock()
	require.Equal(t, []string{"chatgpt.com"}, h.hosts)
	require.Equal(t, []string{exportAccountsCheckPath}, h.paths)
	h.mu.Unlock()

	require.JSONEq(t, exportExpectedJSON, string(first))
	require.JSONEq(t, exportExpectedJSON, string(cached))
	for _, b := range [][]byte{first, cached} {
		for _, secret := range []string{exportToken, "email", "Bearer", "rev-joined-1", "custody"} {
			require.NotContains(t, string(b), secret)
		}
	}

	if dir == "" {
		return
	}
	exportFiles(t, dir, [][2]string{
		{"first.json", string(first)}, {"cached.json", string(cached)},
	})
}

func TestOAuthDescriptorJoinedQualifierRefusals(t *testing.T) {
	notQualified := `{"error":"not_qualified"}`
	cases := map[string]struct {
		upstream   string
		credential bool
		lookupErr  error
		status     int
		body       string
		wantHits   int32
	}{
		// Upstream only knows a different organisation.
		"wrong org": {upstream: `{"accounts":{"org-other":{"account":{"account_id":"org-other","plan_type":"plus"}}}}`,
			credential: true, status: http.StatusConflict, body: notQualified, wantHits: 1},
		"no account": {upstream: `{"accounts":{}}`, credential: true, status: http.StatusConflict, body: notQualified, wantHits: 1},
		// The owner has no credential for this birth: upstream is never called.
		"unbound credential": {upstream: exportAccountsOK, credential: false, status: http.StatusConflict, body: notQualified},
		"failed lookup": {upstream: exportAccountsOK, credential: true, lookupErr: errors.New("secret-store down " + exportToken),
			status: http.StatusServiceUnavailable, body: `{"error":"unavailable"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newExportHarness(t, tc.upstream, tc.credential)
			h.lookup.err = tc.lookupErr
			code, body := h.post(exportScopeJSON)
			require.Equal(t, tc.status, code)
			require.JSONEq(t, tc.body, string(body))
			require.NotContains(t, string(body), exportToken)
			require.Equal(t, tc.wantHits, h.hits.Load())
		})
	}
}
