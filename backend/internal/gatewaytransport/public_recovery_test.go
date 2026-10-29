//go:build unit

package gatewaytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPublicPostclaimVerificationFailureRetainsProofForIndependentNoEntrySettlement(t *testing.T) {
	for _, mode := range []string{"verificationDenied", "expiredLease", "foreignProof"} {
		t.Run(mode, func(t *testing.T) {
			var original Request
			var entries, settlements, verifications atomic.Int32
			var claimed atomic.Pointer[Proof]
			var rejected atomic.Bool
			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/private/native/v1/execution-authority":
					var input publicAuthorizationRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
				case "/private/native/v1/public-admit":
					var input admitRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					reply := ownerReply(input)
					claim := reply.Dispatch.Closure
					claimed.Store(&claim)
					if mode == "expiredLease" {
						reply.LeaseExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
					}
					if mode == "foreignProof" {
						reply.Dispatch.Closure.RequestRef = "foreign-request"
					}
					_ = json.NewEncoder(w).Encode(reply)
				case "/private/native/v1/execution-settle":
					var input struct {
						Proof   Proof   `json:"proof"`
						Receipt Receipt `json:"receipt"`
					}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					require.NotNil(t, claimed.Load())
					require.Equal(t, *claimed.Load(), input.Proof)
					require.NotNil(t, input.Receipt.Proof)
					require.Equal(t, *claimed.Load(), *input.Receipt.Proof)
					require.False(t, input.Receipt.Lifetime.Entered)
					require.True(t, closed(input.Receipt.Lifetime))
					settlements.Add(1)
					rejected.Store(true)
					_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				default:
					t.Error("unexpected callback")
					w.WriteHeader(403)
				}
			}))
			defer authority.Close()
			h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entries.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) {
				original = ownerRequest()
				original.Descriptor.BaseURL = cfg.Profile.BaseURL
				cfg.CallbackOrigin = authority.URL
				cfg.VerifyDispatch = func(context.Context, string, Proof, time.Time) error { verifications.Add(1); return errDenied }
			})
			public := httptest.NewServer(h.PublicHandler(4))
			defer public.Close()
			call := func() map[string]any {
				req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer synthetic-capability-123")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Gateway-Request-Id", "original")
				response, err := public.Client().Do(req)
				require.NoError(t, err)
				defer response.Body.Close()
				require.Equal(t, 202, response.StatusCode)
				var status map[string]any
				require.NoError(t, json.NewDecoder(response.Body).Decode(&status))
				return status
			}
			status := call()
			require.NotEqual(t, "completed", status["effect"])
			require.Zero(t, entries.Load())
			h.mu.Lock()
			for _, e := range h.entries {
				require.False(t, e.admitted)
				require.False(t, e.preclaimRefused)
				require.False(t, e.statusOnly)
				if mode == "foreignProof" {
					require.Nil(t, e.proof)
					require.False(t, e.acknowledged)
				} else {
					require.NotNil(t, e.proof)
					require.Equal(t, *claimed.Load(), *e.proof)
					require.True(t, e.acknowledged)
				}
			}
			h.mu.Unlock()
			if mode == "foreignProof" {
				require.Zero(t, settlements.Load())
				require.False(t, rejected.Load())
			} else {
				require.EqualValues(t, 1, settlements.Load())
				require.True(t, rejected.Load())
			}
			if mode == "verificationDenied" {
				require.EqualValues(t, 1, verifications.Load())
			} else {
				require.Zero(t, verifications.Load())
			}
			_ = call()
			require.Zero(t, entries.Load())
			if mode != "foreignProof" {
				require.EqualValues(t, 1, settlements.Load(), "duplicate cannot resettle or dispatch")
			}
		})
	}
}

func TestPublicPreclaimRPCProducersWaitBoundedlyWithoutBlockingCriticalCallbacks(t *testing.T) {
	var active, peak, metadata, admits, critical atomic.Int32
	arrived := make(chan struct{}, 4)
	release := make(chan struct{})
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/private/native/v1/execution-authority" {
			metadata.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			select {
			case arrived <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		} else if r.URL.Path == "/private/native/v1/public-admit" {
			admits.Add(1)
		} else {
			critical.Add(1)
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer authority.Close()
	defer close(release)
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("must not enter provider") }), func(cfg *Config, _ *ownerFixtureRepo) {
		cfg.CallbackOrigin = authority.URL
		cfg.CallbackTimeout = time.Second
	})
	type acknowledgment struct {
		OK bool `json:"ok"`
	}
	done := make(chan error, 5)
	for i := 0; i < 4; i++ {
		go func() {
			var reply acknowledgment
			done <- h.publicPost(context.Background(), "/private/native/v1/execution-authority", map[string]bool{}, &reply)
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-arrived:
		case <-time.After(time.Second):
			t.Fatal("four callback producers did not enter")
		}
	}
	go func() {
		var reply acknowledgment
		done <- h.publicPost(context.Background(), "/private/native/v1/execution-authority", map[string]bool{}, &reply)
	}()
	requestCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	e := ownerReserve(t, h, ownerRequest())
	h.mu.Lock()
	e.executionBearer = "synthetic-capability-123"
	h.mu.Unlock()
	allowed, err := h.admit(requestCtx, "fixture-consumer", e)
	require.NoError(t, err)
	require.False(t, allowed)
	h.finishNoEntry(e)
	h.seal(e)
	h.mu.Lock()
	require.True(t, e.preclaimRefused)
	require.True(t, e.statusOnly)
	require.Nil(t, e.proof)
	h.mu.Unlock()
	var reply acknowledgment
	require.NoError(t, h.publicPost(context.Background(), "/private/native/v1/dispatch-proof", map[string]bool{}, &reply))
	require.EqualValues(t, 1, critical.Load())
	require.EqualValues(t, 4, metadata.Load())
	require.Zero(t, admits.Load())
	require.EqualValues(t, 4, peak.Load())
	// Waiting is useful admission, not immediate refusal merely because four RPCs raced.
	for i := 0; i < 5; i++ {
		release <- struct{}{}
	}
	for i := 0; i < 5; i++ {
		require.NoError(t, <-done)
	}
	require.EqualValues(t, 5, metadata.Load())
	require.LessOrEqual(t, peak.Load(), int32(4))
}

func TestPublicLateClaimReplyCannotOverwriteRecoveredOriginalProof(t *testing.T) {
	arrived := make(chan admitRequest, 1)
	resume := make(chan struct{})
	var resumeOnce sync.Once
	resumeCallback := func() { resumeOnce.Do(func() { close(resume) }) }
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input admitRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		arrived <- input
		<-resume
		reply := ownerReply(input)
		reply.Dispatch.Closure.Token = "different-structurally-valid-token"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer authority.Close()
	defer resumeCallback()
	var verified atomic.Int32
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("must not enter") }), func(cfg *Config, _ *ownerFixtureRepo) {
		cfg.CallbackOrigin = authority.URL
		cfg.AuthorizeOwnerClosure = func(context.Context, string, Proof) error { return nil }
		cfg.VerifyDispatch = func(context.Context, string, Proof, time.Time) error { verified.Add(1); return errDenied }
	})
	e := ownerReserve(t, h, ownerRequest())
	h.mu.Lock()
	e.executionBearer = "synthetic-capability-123"
	h.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := h.admit(context.Background(), "fixture-consumer", e); done <- err }()
	input := <-arrived
	original := ownerReply(input).Dispatch.Closure
	original.Token = "original-recovered-token"
	h.finishNoEntry(e)
	h.seal(e)
	recovered, err := h.ownerClosure(context.Background(), "fixture-consumer", "read-owner", original)
	require.NoError(t, err)
	require.NotNil(t, recovered.Proof)
	require.Equal(t, original, *recovered.Proof)
	resumeCallback()
	require.Error(t, <-done)
	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotNil(t, e.proof)
	require.Equal(t, original, *e.proof)
	require.False(t, e.admitted)
	require.Zero(t, verified.Load())
}
