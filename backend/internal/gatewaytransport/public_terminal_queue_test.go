//go:build unit

package gatewaytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This fixture exercises real bounded callback HTTP and registry/lifetime
// ownership. Durable SQL authority is independently qualified by joined CI.
func terminalQueueFixture(t *testing.T) (*Handler, <-chan string, func(), *atomic.Int32, *atomic.Int32) {
	t.Helper()
	arrived := make(chan string, 8)
	release := make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	var active, peak, callbacks atomic.Int32
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/private/native/v1/execution-settle" {
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		var input struct {
			Proof   Proof   `json:"proof"`
			Receipt Receipt `json:"receipt"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("invalid bounded settlement request")
			w.WriteHeader(400)
			return
		}
		require.Equal(t, "Bearer "+fixtureCallbackToken, r.Header.Get("Authorization"))
		require.NotNil(t, input.Receipt.Proof)
		require.Equal(t, input.Proof, *input.Receipt.Proof)
		require.True(t, closed(input.Receipt.Lifetime))
		callbacks.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		arrived <- input.Proof.RequestRef
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if input.Proof.RequestRef == "queued" {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(authority.Close)
	t.Cleanup(resume)
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("must not enter provider") }), func(cfg *Config, _ *ownerFixtureRepo) {
		cfg.CallbackOrigin = authority.URL
		cfg.CallbackTimeout = 2 * time.Second
		cfg.MaxEntries = 16
	})
	return h, arrived, resume, &callbacks, &peak
}

func terminalNoEntryReservation(t *testing.T, h *Handler, ref string) *reservation {
	t.Helper()
	request := ownerRequest()
	request.RequestRef = ref
	e := ownerReserve(t, h, request)
	p := Proof{ExecutionRef: request.Admission.ExecutionRef, RequestRef: ref, Worker: request.Worker, Token: "fixture-original-proof", Native: e.native}
	h.mu.Lock()
	e.proof = &p
	e.callbackStarted = true
	h.mu.Unlock()
	h.finishNoEntry(e)
	h.seal(e)
	return e
}

func holdFourTerminalCallbacks(t *testing.T, h *Handler, arrived <-chan string) <-chan bool {
	t.Helper()
	done := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		e := terminalNoEntryReservation(t, h, fmt.Sprintf("holder-%d", i))
		go func() { done <- h.settlePublicWithin("fixture-consumer", e, time.Second, 2*time.Second) }()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-arrived:
		case <-time.After(time.Second):
			t.Fatal("four terminal callback owners did not enter")
		}
	}
	return done
}

func TestPublicTerminalQueueWaitHasIndependentActiveBudgetAndFourOwners(t *testing.T) {
	h, arrived, resume, callbacks, peak := terminalQueueFixture(t)
	holders := holdFourTerminalCallbacks(t, h, arrived)
	e := terminalNoEntryReservation(t, h, "queued")
	done := make(chan bool, 1)
	go func() { done <- h.settlePublicWithin("fixture-consumer", e, time.Second, 200*time.Millisecond) }()
	// The queued request waits longer than its entire active budget. It must
	// still get a fresh active context once one of the four owners releases.
	select {
	case <-done:
		t.Fatal("queue wait consumed the independent active settlement budget")
	case <-time.After(300 * time.Millisecond):
	}
	var acknowledgment struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, h.publicPost(context.Background(), "/private/native/v1/dispatch-proof", map[string]bool{}, &acknowledgment))
	require.True(t, acknowledgment.OK, "critical callback progresses while four terminal owners are held")
	require.EqualValues(t, 4, callbacks.Load())
	require.EqualValues(t, 4, peak.Load())
	resume()
	for i := 0; i < 4; i++ {
		select {
		case ok := <-holders:
			require.True(t, ok)
		case <-time.After(time.Second):
			t.Fatal("terminal holder did not drain")
		}
	}
	select {
	case ok := <-done:
		require.True(t, ok)
	case <-time.After(time.Second):
		t.Fatal("queued terminal did not get its fresh active budget")
	}
	require.EqualValues(t, 5, callbacks.Load())
	require.LessOrEqual(t, peak.Load(), int32(4))
	h.mu.Lock()
	require.True(t, e.acknowledged)
	h.mu.Unlock()
}

func TestPublicTerminalQueueExpiryRetainsEvidenceWithoutCallbackOrReplay(t *testing.T) {
	h, arrived, resume, callbacks, _ := terminalQueueFixture(t)
	holders := holdFourTerminalCallbacks(t, h, arrived)
	e := terminalNoEntryReservation(t, h, "queue-expired")
	original := *e.proof
	require.False(t, h.settlePublicWithin("fixture-consumer", e, 40*time.Millisecond, time.Second))
	require.EqualValues(t, 4, callbacks.Load(), "queue expiry must not open a callback socket")
	h.mu.Lock()
	require.Equal(t, original, *e.proof)
	require.False(t, e.acknowledged)
	require.False(t, e.preclaimRefused)
	require.False(t, e.statusOnly)
	h.mu.Unlock()
	require.True(t, closed(e.life.Snapshot()))
	require.False(t, e.life.Snapshot().Entered)
	allowed, err := h.admit(context.Background(), "fixture-consumer", e)
	require.NoError(t, err)
	require.False(t, allowed, "retained original reservation cannot attempt claim or paid replay")
	require.EqualValues(t, 4, callbacks.Load())
	resume()
	for i := 0; i < 4; i++ {
		select {
		case ok := <-holders:
			require.True(t, ok)
		case <-time.After(time.Second):
			t.Fatal("terminal holder did not drain")
		}
	}
}

func TestPublicTerminalDeliveryRefreshesOnlyWriteDeadlineAfterDurableSettlement(t *testing.T) {
	var original Request
	var settled atomic.Bool
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
			_ = json.NewEncoder(w).Encode(ownerReply(input))
		case "/private/native/v1/execution-settle":
			var input struct {
				Receipt Receipt `json:"receipt"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			require.True(t, closed(input.Receipt.Lifetime))
			require.True(t, input.Receipt.Lifetime.Completed)
			// The original finite writer deadline expires during durable
			// metadata work, after the provider and physical body are closed.
			select {
			case <-time.After(300 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			settled.Store(true)
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(403)
		}
	}))
	defer authority.Close()
	h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\n")
	}), func(cfg *Config, _ *ownerFixtureRepo) {
		original = ownerRequest()
		original.Descriptor.BaseURL = cfg.Profile.BaseURL
		cfg.CallbackOrigin = authority.URL
		cfg.IOTimeout = 150 * time.Millisecond
		cfg.ProviderReadIdle = cfg.IOTimeout
	})
	public := httptest.NewServer(h.PublicHandler(1))
	defer public.Close()
	req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer synthetic-capability-123")
	req.Header.Set("Content-Type", "application/json")
	response, err := public.Client().Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.True(t, settled.Load())
	require.Contains(t, string(data), "response.completed")
	h.mu.Lock()
	for _, e := range h.entries {
		require.True(t, e.acknowledged)
		require.True(t, e.life.Snapshot().Sealed)
		require.True(t, closed(e.life.Snapshot()))
	}
	h.mu.Unlock()
}
