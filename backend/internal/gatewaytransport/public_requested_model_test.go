//go:build unit

package gatewaytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Real public HTTP and callback metadata: model attribution follows the validated
// payload rather than the canonical Codex descriptor anchor. Dispatch verification
// deliberately denies entry; catalog/model authority is exercised separately by
// TestProtectedOAuthTransportPostAdmitCanonicalBinding.
func TestPublicRequestedModelMetadataRemainsBoundToReservation(t *testing.T) {
	const requestedModel = "unseen-native-model"
	const privateInput = "synthetic-prompt-must-never-enter-callback-metadata"
	var original Request
	var admits, settlements, entries atomic.Int32
	admitted := make(chan string, 1)
	releaseAdmission := make(chan struct{})
	var release sync.Once
	resume := func() { release.Do(func() { close(releaseAdmission) }) }
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
		case "/private/native/v1/public-admit":
			admits.Add(1)
			raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			require.NoError(t, err)
			require.LessOrEqual(t, len(raw), 65536)
			require.NotContains(t, string(raw), privateInput)
			require.NotContains(t, string(raw), `"payload"`)
			var input struct {
				admitRequest
				ExecutionBearer string `json:"executionBearer"`
				RequestedModel  string `json:"requestedModel"`
			}
			require.NoError(t, json.Unmarshal(raw, &input))
			require.Equal(t, requestedModel, input.RequestedModel)
			require.Equal(t, service.GatewayCodexOAuthModel, input.Descriptor.Model)
			admitted <- input.RequestedModel
			select {
			case <-releaseAdmission:
			case <-r.Context().Done():
				return
			}
			_ = json.NewEncoder(w).Encode(ownerReply(input.admitRequest))
		case "/private/native/v1/execution-settle":
			settlements.Add(1)
			raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			require.NoError(t, err)
			require.LessOrEqual(t, len(raw), 65536)
			require.NotContains(t, string(raw), privateInput)
			require.NotContains(t, string(raw), `"payload"`)
			var input struct {
				RequestedModel string  `json:"requestedModel"`
				Receipt        Receipt `json:"receipt"`
			}
			require.NoError(t, json.Unmarshal(raw, &input))
			require.Equal(t, requestedModel, input.RequestedModel, "a duplicate cannot change original attribution")
			require.False(t, input.Receipt.Lifetime.Entered)
			require.True(t, closed(input.Receipt.Lifetime))
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Error("unexpected callback")
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entries.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) {
		codex := QualifiedProfile{Profile: service.GatewayCodexOAuthResponsesProfile, Model: service.GatewayCodexOAuthModel,
			BaseURL: service.GatewayCodexOAuthBaseURL, QualificationRef: "codex-fixture-qualification",
			RequestBytes: 4096, OutputBytes: 4096, Tokens: 100, ProviderTokenUpperBound: 200}
		cfg.Codex = &codex
		// The postclaim authority below denies before BindApproved/provider use.
		cfg.OAuth = &service.GatewayNativeOAuthDispatch{}
		cfg.CallbackOrigin = authority.URL
		cfg.CallbackTimeout = 5 * time.Second
		cfg.VerifyDispatch = func(context.Context, string, Proof, time.Time) error { return errDenied }
		original = ownerRequest()
		original.Admission.ProfileID = codex.Profile
		original.Descriptor.Profile, original.Descriptor.BaseURL, original.Descriptor.Model = codex.Profile, codex.BaseURL, codex.Model
		original.Payload = json.RawMessage(`{"model":"` + requestedModel + `","input":"` + privateInput + `","stream":true}`)
	})
	public := httptest.NewServer(h.PublicHandler(4))
	defer public.Close()
	defer resume()
	client := &http.Client{Timeout: 4 * time.Second}
	call := func(payload []byte) (int, error) {
		request, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		request.Header.Set("Authorization", "Bearer synthetic-capability-123")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Gateway-Request-Id", "same-request")
		response, err := client.Do(request)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, response.Body)
		return response.StatusCode, err
	}
	type result struct {
		status int
		err    error
	}
	finished := make(chan result, 1)
	go func() { status, err := call(original.Payload); finished <- result{status, err} }()
	select {
	case model := <-admitted:
		require.Equal(t, requestedModel, model)
	case <-time.After(2 * time.Second):
		t.Fatal("original public admission did not arrive")
	}
	status, err := call(original.Payload)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, status, "an identical duplicate only reads the retained receipt")
	changed := bytes.Replace(original.Payload, []byte(requestedModel), []byte("different-native-model"), 1)
	status, err = call(changed)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, status, "a changed model cannot replace the original reservation")
	resume()
	select {
	case completed := <-finished:
		require.NoError(t, completed.err)
		require.Equal(t, http.StatusAccepted, completed.status)
	case <-time.After(2 * time.Second):
		t.Fatal("original public settlement did not complete")
	}
	for _, invalid := range []string{
		`{"model":"` + requestedModel + `","model":"other","stream":true}`,
		`{"model":"` + strings.Repeat("x", 129) + `","stream":true}`,
	} {
		status, err = call([]byte(invalid))
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status, "invalid model metadata must fail before public claim")
	}
	require.EqualValues(t, 1, admits.Load(), "duplicates and invalid models must not claim or retry")
	require.EqualValues(t, 1, settlements.Load(), "only the original reservation settles")
	require.Zero(t, entries.Load(), "usage metadata never grants provider entry")
}
