//go:build unit

package service

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayAccountModelsProjectionCountsAndRedaction(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	f.qualify(t)
	f.modelsBody = `{"models":[{"slug":"ordinary","visibility":"hide","instructions":"PRIVATE-INSTRUCTIONS","display_name":"PRIVATE-LABEL"},{"slug":"special-review","visibility":"hide"},{"slug":"media","output_modalities":["image"]},{"slug":"image-input","input_modalities":["image"]},{"slug":"incompatible","supported_endpoints":["chat_completions"]},{"slug":"disabled","available":false}]}`
	stderr, err := os.CreateTemp(t.TempDir(), "catalog-counts-*")
	require.NoError(t, err)
	original := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = original; _ = stderr.Close() }()
	result := f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, false)
	require.Equal(t, "snapshot", result.Status)
	require.Len(t, *result.Models, 1)
	require.Equal(t, int32(0), f.entries.Load(), "catalog reads must never enter Responses")
	require.NoError(t, stderr.Sync())
	_, err = stderr.Seek(0, 0)
	require.NoError(t, err)
	raw, err := io.ReadAll(stderr)
	require.NoError(t, err)
	var event struct {
		Event    string         `json:"event"`
		Version  string         `json:"client_version"`
		Raw      int            `json:"raw_count"`
		Returned int            `json:"returned_count"`
		Excluded map[string]int `json:"excluded_counts"`
	}
	require.NoError(t, json.Unmarshal(raw, &event))
	require.Equal(t, "gateway_native_codex_model_catalog", event.Event)
	require.Equal(t, CodexCanonicalClientVersion(), event.Version)
	require.Equal(t, 6, event.Raw)
	require.Equal(t, 1, event.Returned)
	require.Equal(t, map[string]int{"review_only": 1, "output_modalities": 1, "input_modalities": 1, "supported_endpoints": 1, "unavailable": 1}, event.Excluded)
	for _, secret := range []string{f.bundle.AccessToken, f.scope.Owner, f.scope.Account, f.scope.Generation, "PRIVATE-INSTRUCTIONS", "PRIVATE-LABEL", "ordinary", "special-review"} {
		require.NotContains(t, string(raw), secret)
	}
}

type gatewayCodexReleaseFixture func(*http.Request) (*http.Response, error)

func (f gatewayCodexReleaseFixture) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayAccountModelsLatestIdentityCacheAndOffline(t *testing.T) {
	f := newOAuthDispatchFixture(t)
	route := f.qualify(t)
	reads := 0
	latest := "0.999.0"
	offline := false
	versions := NewGatewayCodexVersionResolver(gatewayCodexReleaseFixture(func(request *http.Request) (*http.Response, error) {
		reads++
		require.Equal(t, gatewayCodexLatestReleaseURL, request.URL.String())
		require.Equal(t, http.MethodGet, request.Method)
		require.Empty(t, request.Header.Get("Authorization"))
		require.Empty(t, request.Header.Get("Cookie"))
		if offline {
			return nil, errors.New("controlled offline")
		}
		return &http.Response{StatusCode: http.StatusOK, Request: request, Body: io.NopCloser(strings.NewReader(`{"tag_name":"rust-v` + latest + `","draft":false,"prerelease":false}`))}, nil
	}))
	now := time.Now()
	versions.now = func() time.Time { return now }
	f.dispatch.modelVersions = versions
	SetCodexCanonicalUserAgentResolver(versions.CanonicalUserAgent)
	t.Cleanup(func() { SetCodexCanonicalUserAgentResolver(nil) })
	f.modelsBody = `{"models":[{"slug":"future-hidden-preview","visibility":"hide"}]}`
	read := func(force bool) {
		result := f.dispatch.accountModels(f.ctx, f.store.row, f.store.physical, force)
		require.Equal(t, "snapshot", result.Status)
		require.Len(t, *result.Models, 1)
	}
	read(false)
	read(false)
	require.Equal(t, 1, reads)
	require.Equal(t, int32(1), f.modelsReads.Load())
	require.Equal(t, "0.999.0", CodexCanonicalClientVersion())
	// Even a fresh account snapshot must miss its old key after client negotiation changes.
	latest = "0.999.1"
	now = now.Add(openAICodexVersionSyncInterval + time.Second)
	read(false)
	require.Equal(t, 2, reads)
	require.Equal(t, int32(2), f.modelsReads.Load())
	require.Equal(t, "0.999.1", CodexCanonicalClientVersion())
	offline = true
	now = now.Add(time.Minute + time.Second)
	read(true)
	read(true)
	require.Equal(t, 3, reads, "forced refresh must honor the release cooldown")
	require.Equal(t, "0.999.1", CodexCanonicalClientVersion())
	// Existing TLS fixture checks the same canonical UA/version on models and inference.
	payload := []byte(strings.Replace(string(oauthDispatchPayload()), GatewayCodexOAuthModel, "future-hidden-preview", 1))
	_, entered, err, _ := f.call(t, route, payload)
	require.NoError(t, err)
	require.True(t, entered)
	require.Equal(t, GatewayCodexOAuthModel, route.Model)
}
