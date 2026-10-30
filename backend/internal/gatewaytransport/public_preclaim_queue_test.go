//go:build unit

package gatewaytransport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type preclaimQueueGate struct {
	arrived chan string
	release chan struct{}
	once    sync.Once
}

func (g *preclaimQueueGate) resume() { g.once.Do(func() { close(g.release) }) }

type preclaimQueueFixture struct {
	h          *Handler
	original   Request
	gates      map[string]*preclaimQueueGate
	lostClaim  chan Proof
	resumeLost func()
	mu         sync.Mutex
	posts      map[string]int
	claims     map[string]Proof
	settled    map[string]int
	active     atomic.Int32
	peak       atomic.Int32
	providers  atomic.Int32
}

// Real callback HTTP and the production registry/lifetime are exercised here.
// The retained fixture claim is independent of Go's received proof; durable SQL
// authority remains the responsibility of joined integration qualification.
func newPreclaimQueueFixture(t *testing.T, lostRef string) *preclaimQueueFixture {
	t.Helper()
	f := &preclaimQueueFixture{gates: make(map[string]*preclaimQueueGate), lostClaim: make(chan Proof, 1),
		posts: make(map[string]int), claims: make(map[string]Proof), settled: make(map[string]int)}
	for _, name := range []string{"holder", "probe"} {
		f.gates[name] = &preclaimQueueGate{arrived: make(chan string, 4), release: make(chan struct{})}
	}
	lostRelease := make(chan struct{})
	var lostOnce sync.Once
	f.resumeLost = func() { lostOnce.Do(func() { close(lostRelease) }) }
	begin := func(path, ref string) func() {
		f.mu.Lock()
		f.posts[path+" "+ref]++
		f.mu.Unlock()
		n := f.active.Add(1)
		for old := f.peak.Load(); n > old; old = f.peak.Load() {
			if f.peak.CompareAndSwap(old, n) {
				break
			}
		}
		return func() { f.active.Add(-1) }
	}
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+fixtureCallbackToken, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/private/native/v1/execution-authority":
			var input publicAuthorizationRequest
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				t.Error("invalid authority metadata")
				w.WriteHeader(400)
				return
			}
			defer begin(r.URL.Path, input.RequestRef)()
			for name, gate := range f.gates {
				if strings.HasPrefix(input.RequestRef, name+"-") {
					gate.arrived <- input.RequestRef
					select {
					case <-gate.release:
					case <-r.Context().Done():
						return
					}
				}
			}
			if input.RequestRef == "queued" {
				select {
				case <-time.After(50 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
			_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, f.original.Worker, f.original.Admission, f.original.Descriptor})
		case "/private/native/v1/public-admit":
			var input admitRequest
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				t.Error("invalid claim metadata")
				w.WriteHeader(400)
				return
			}
			defer begin(r.URL.Path, input.RequestRef)()
			require.Equal(t, input.Native.RequestNonce, r.Header.Get("X-Gateway-Reservation-Nonce"))
			reply := ownerReply(input)
			f.mu.Lock()
			f.claims[input.RequestRef] = reply.Dispatch.Closure
			f.mu.Unlock()
			if input.RequestRef == lostRef {
				// The authority has accepted the exact claim, but its reply is
				// withheld until the active attempt is already canceled.
				f.lostClaim <- reply.Dispatch.Closure
				select {
				case <-lostRelease:
				case <-r.Context().Done():
				}
				return
			}
			if input.RequestRef == "queued" {
				select {
				case <-time.After(50 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
			_ = json.NewEncoder(w).Encode(reply)
		case "/private/native/v1/execution-settle":
			var input struct {
				ConsumerID string  `json:"consumerId"`
				Proof      Proof   `json:"proof"`
				Receipt    Receipt `json:"receipt"`
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				t.Error("invalid settlement metadata")
				w.WriteHeader(400)
				return
			}
			f.mu.Lock()
			original, claimed := f.claims[input.Proof.RequestRef]
			f.settled[input.Proof.RequestRef]++
			f.mu.Unlock()
			require.True(t, claimed, "settlement requires an independently accepted exact claim")
			require.Equal(t, original, input.Proof)
			require.Equal(t, "fixture-consumer", input.ConsumerID)
			require.NotNil(t, input.Receipt.Proof)
			require.Equal(t, original, *input.Receipt.Proof)
			require.True(t, closed(input.Receipt.Lifetime))
			require.False(t, input.Receipt.Lifetime.Entered)
			require.False(t, input.Receipt.Lifetime.Completed)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Error("unexpected callback path")
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(authority.Close)
	f.h, _, _, _ = ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { f.providers.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) {
		f.original = ownerRequest()
		f.original.Descriptor.BaseURL = cfg.Profile.BaseURL
		cfg.CallbackOrigin = authority.URL
		cfg.CallbackTimeout = 3 * time.Second
		cfg.MaxEntries = 32
	})
	t.Cleanup(f.resumeLost)
	for _, gate := range f.gates {
		t.Cleanup(gate.resume)
	}
	return f
}

func (f *preclaimQueueFixture) reserve(t *testing.T, ref string) *reservation {
	t.Helper()
	input := f.original
	input.RequestRef = ref
	e := ownerReserve(t, f.h, input)
	f.h.mu.Lock()
	e.executionBearer = "synthetic-capability-123"
	f.h.mu.Unlock()
	return e
}

func (f *preclaimQueueFixture) count(path, ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts[path+" "+ref]
}

func (f *preclaimQueueFixture) settlementCount(ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settled[ref]
}

func (f *preclaimQueueFixture) claim(ref string) Proof {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claims[ref]
}

func (f *preclaimQueueFixture) holdFour(t *testing.T, name string) <-chan error {
	t.Helper()
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		ref := fmt.Sprintf("%s-%d", name, i)
		go func() {
			var reply publicAuthorizationReply
			done <- f.h.publicPost(context.Background(), "/private/native/v1/execution-authority", publicAuthorizationRequest{RequestRef: ref}, &reply)
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-f.gates[name].arrived:
		case <-time.After(time.Second):
			t.Fatal("four real preclaim callback producers did not enter")
		}
	}
	return done
}

func drainPreclaimHolders(t *testing.T, done <-chan error) {
	t.Helper()
	for i := 0; i < 4; i++ {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("held preclaim callback did not drain")
		}
	}
}

type preclaimQueueOutcome struct {
	allowed   bool
	authority publicAuthorizationReply
	err       error
}

func TestPublicPreclaimQueueHasFreshActiveBudgetForAuthorityAndClaim(t *testing.T) {
	for _, producer := range []string{"authority", "claim"} {
		t.Run(producer, func(t *testing.T) {
			f := newPreclaimQueueFixture(t, "")
			independent := f.reserve(t, "independent")
			allowed, err := f.h.admit(context.Background(), "fixture-consumer", independent)
			require.NoError(t, err)
			require.True(t, allowed)
			f.h.finishNoEntry(independent)
			f.h.seal(independent)
			holders := f.holdFour(t, "holder")
			e := f.reserve(t, "queued")
			done := make(chan preclaimQueueOutcome, 1)
			go func() {
				var result preclaimQueueOutcome
				if producer == "authority" {
					result.err = f.h.publicPostWithin(context.Background(), "/private/native/v1/execution-authority", publicAuthorizationRequest{RequestRef: "queued"}, &result.authority, 2*time.Second, 250*time.Millisecond)
				} else {
					result.allowed, result.err = f.h.admitWithin(context.Background(), "fixture-consumer", e, 2*time.Second, 250*time.Millisecond)
				}
				done <- result
			}()
			// The queue stays occupied longer than the entire active budget.
			select {
			case <-done:
				t.Fatal("queue waiting consumed the fresh active callback budget")
			case <-time.After(400 * time.Millisecond):
			}
			require.Zero(t, f.count("/private/native/v1/execution-authority", "queued"))
			require.Zero(t, f.count("/private/native/v1/public-admit", "queued"))
			require.EqualValues(t, 4, f.peak.Load())
			// Exact no-entry settlement has its own callback capacity and does
			// not depend on the queued producer or original caller's lifetime.
			require.True(t, f.h.settlePublicWithin("fixture-consumer", independent, time.Second, time.Second))
			require.Equal(t, 1, f.settlementCount("independent"))
			require.True(t, f.h.receipt("fixture-consumer", independent).Acknowledged)
			f.gates["holder"].resume()
			drainPreclaimHolders(t, holders)
			var result preclaimQueueOutcome
			select {
			case result = <-done:
			case <-time.After(time.Second):
				t.Fatal("queued producer did not receive its independent active budget")
			}
			require.NoError(t, result.err)
			if producer == "authority" {
				require.Equal(t, publicAuthorizationReply{"fixture-consumer", "queued", f.original.Worker, f.original.Admission, f.original.Descriptor}, result.authority)
				result.allowed, result.err = f.h.admitWithin(context.Background(), "fixture-consumer", e, time.Second, 250*time.Millisecond)
				require.NoError(t, result.err)
			}
			require.True(t, result.allowed)
			r := f.h.receipt("fixture-consumer", e)
			require.NotNil(t, r.Proof)
			require.Equal(t, f.claim("queued"), *r.Proof)
			require.False(t, r.Acknowledged)
			f.h.finishNoEntry(e)
			f.h.seal(e)
			require.True(t, f.h.settlePublicWithin("fixture-consumer", e, time.Second, time.Second))
			require.Equal(t, 1, f.settlementCount("queued"))
			require.True(t, f.h.receipt("fixture-consumer", e).Acknowledged)
			require.Zero(t, f.providers.Load())
			require.LessOrEqual(t, f.peak.Load(), int32(4))
		})
	}
}

func TestPublicPreclaimQueueExpiryAndCallerCancellationNeverPost(t *testing.T) {
	for _, producer := range []string{"authority", "claim"} {
		for _, mode := range []string{"queueExpiry", "callerDeadline", "callerCancel", "alreadyCanceled"} {
			t.Run(producer+"/"+mode, func(t *testing.T) {
				f := newPreclaimQueueFixture(t, "")
				holders := f.holdFour(t, "holder")
				e := f.reserve(t, "expired")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				queueBudget := time.Second
				if mode == "queueExpiry" {
					queueBudget = 40 * time.Millisecond
				} else if mode == "callerDeadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 40*time.Millisecond)
					defer stop()
				} else if mode == "alreadyCanceled" {
					cancel()
				}
				done := make(chan preclaimQueueOutcome, 1)
				started := time.Now()
				go func() {
					var result preclaimQueueOutcome
					if producer == "authority" {
						result.err = f.h.publicPostWithin(ctx, "/private/native/v1/execution-authority", publicAuthorizationRequest{RequestRef: "expired"}, &result.authority, queueBudget, time.Second)
					} else {
						result.allowed, result.err = f.h.admitWithin(ctx, "fixture-consumer", e, queueBudget, time.Second)
					}
					done <- result
				}()
				if mode == "callerCancel" {
					if producer == "claim" {
						// Cancel after this invocation enters the admission path,
						// independently of how quickly its goroutine is scheduled.
						require.Eventually(t, func() bool {
							f.h.mu.Lock()
							defer f.h.mu.Unlock()
							return e.callbackStarted
						}, 500*time.Millisecond, time.Millisecond)
					}
					select {
					case <-done:
						t.Fatal("queued producer returned before caller cancellation")
					default:
					}
					cancel()
				}
				select {
				case result := <-done:
					require.False(t, result.allowed)
					if producer == "authority" {
						require.ErrorIs(t, result.err, errAuthorityUnavailable)
					} else if mode == "alreadyCanceled" {
						require.Error(t, result.err)
					} else {
						require.NoError(t, result.err)
					}
				case <-time.After(time.Second):
					t.Fatal("expired or canceled queued producer failed to return boundedly")
				}
				require.Less(t, time.Since(started), time.Second)
				require.Zero(t, f.count("/private/native/v1/execution-authority", "expired"))
				require.Zero(t, f.count("/private/native/v1/public-admit", "expired"))
				f.h.finishNoEntry(e)
				f.h.seal(e)
				_ = f.h.settlePublicWithin("fixture-consumer", e, time.Second, 100*time.Millisecond)
				r := f.h.receipt("fixture-consumer", e)
				require.Nil(t, r.Proof)
				require.False(t, r.Acknowledged)
				require.False(t, r.Lifetime.Entered)
				require.True(t, closed(r.Lifetime))
				require.Zero(t, f.settlementCount("expired"))
				f.gates["holder"].resume()
				drainPreclaimHolders(t, holders)
				// Four subsequent real callbacks must enter concurrently. Merely
				// accepting one healthy callback would miss a leaked permit.
				probes := f.holdFour(t, "probe")
				f.gates["probe"].resume()
				drainPreclaimHolders(t, probes)
				healthy := f.reserve(t, "healthy")
				allowed, err := f.h.admit(context.Background(), "fixture-consumer", healthy)
				require.NoError(t, err)
				require.True(t, allowed)
				require.NotNil(t, f.h.receipt("fixture-consumer", healthy).Proof)
				require.Zero(t, f.providers.Load())
				require.EqualValues(t, 4, f.peak.Load())
			})
		}
	}
}

func TestPublicPreclaimActiveTimeoutOrCancellationPreservesAttemptAmbiguity(t *testing.T) {
	for _, mode := range []string{"activeTimeout", "callerDeadline", "callerCancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreclaimQueueFixture(t, "ambiguous")
			e := f.reserve(t, "ambiguous")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			activeBudget := time.Second
			if mode == "activeTimeout" {
				activeBudget = 250 * time.Millisecond
			} else if mode == "callerDeadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 250*time.Millisecond)
				defer stop()
			}
			done := make(chan preclaimQueueOutcome, 1)
			started := time.Now()
			go func() {
				allowed, err := f.h.admitWithin(ctx, "fixture-consumer", e, time.Second, activeBudget)
				done <- preclaimQueueOutcome{allowed: allowed, err: err}
			}()
			var committed Proof
			select {
			case committed = <-f.lostClaim:
			case <-time.After(time.Second):
				t.Fatal("claim POST did not begin before its reply was lost")
			}
			require.Equal(t, f.claim("ambiguous"), committed)
			require.Equal(t, e.native, committed.Native)
			if mode == "callerCancel" {
				cancel()
			}
			select {
			case result := <-done:
				require.False(t, result.allowed)
				require.Error(t, result.err)
			case <-time.After(time.Second):
				t.Fatal("active claim cancellation failed to return boundedly")
			}
			require.Less(t, time.Since(started), time.Second)
			f.h.finishNoEntry(e)
			f.h.seal(e)
			r := f.h.receipt("fixture-consumer", e)
			require.Nil(t, r.Proof)
			require.Nil(t, r.Status)
			require.Equal(t, "effect_unknown", r.Effect)
			require.False(t, r.Acknowledged)
			require.False(t, r.Lifetime.Entered)
			require.True(t, closed(r.Lifetime))
			f.h.mu.Lock()
			callbackStarted, preclaimRefused, statusOnly := e.callbackStarted, e.preclaimRefused, e.statusOnly
			f.h.mu.Unlock()
			require.True(t, callbackStarted)
			require.False(t, preclaimRefused)
			require.False(t, statusOnly)
			response := httptest.NewRecorder()
			f.h.writeExecutionReceipt(response, "fixture-consumer", e, true)
			require.Equal(t, http.StatusAccepted, response.Code)
			var status struct {
				Effect string `json:"effect"`
				Status string `json:"status"`
			}
			require.NoError(t, json.NewDecoder(response.Body).Decode(&status))
			require.Equal(t, "effect_unknown", status.Effect)
			require.Equal(t, "unknown", status.Status)
			require.False(t, f.h.settlePublicWithin("fixture-consumer", e, time.Second, 100*time.Millisecond))
			require.Zero(t, f.settlementCount("ambiguous"))
			// The exact same reservation remains latched after an ambiguous
			// POST. Neither a fresh context nor duplicate reserve can replay it.
			allowed, err := f.h.admit(context.Background(), "fixture-consumer", e)
			require.NoError(t, err)
			require.False(t, allowed)
			input := f.original
			input.RequestRef = "ambiguous"
			duplicateCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			retained, first, err := f.h.reserve("fixture-consumer", input, duplicateCtx, stop, func() {})
			require.NoError(t, err)
			require.False(t, first)
			require.Same(t, e, retained)
			allowed, err = f.h.admit(context.Background(), "fixture-consumer", retained)
			require.NoError(t, err)
			require.False(t, allowed)
			require.Equal(t, 1, f.count("/private/native/v1/public-admit", "ambiguous"))
			require.Zero(t, f.providers.Load())
			f.resumeLost()
		})
	}
}
