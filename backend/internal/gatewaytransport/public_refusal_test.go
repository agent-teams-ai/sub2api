//go:build unit

package gatewaytransport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPublicPreworkRefusalIsExactNonceBoundAndNeverReplaysAmbiguousAdmission(t *testing.T) {
	for _, kind := range []string{"qualified", "bare503", "wrongNonce", "wrongKind", "wrongClaim", "unknownField", "duplicate", "alias", "oversized", "wrongStatus", "wrongType", "duplicateType", "encoded", "committedLostReply"} {
		t.Run(kind, func(t *testing.T) {
			var original Request
			var admits, entries, claims atomic.Int32
			var useQualified atomic.Bool
			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.True(t, r.Header.Get("Authorization") == "Bearer "+fixtureCallbackToken)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/private/native/v1/execution-authority":
					var input publicAuthorizationRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					_ = json.NewEncoder(w).Encode(publicAuthorizationReply{"fixture-consumer", input.RequestRef, original.Worker, original.Admission, original.Descriptor})
				case "/private/native/v1/public-admit":
					admits.Add(1)
					var input admitRequest
					// The additive bearer is deliberately ignored by this fixture decoder.
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					nonce := r.Header.Get("X-Gateway-Reservation-Nonce")
					require.True(t, nonce == input.Native.RequestNonce)
					responseKind := kind
					if useQualified.Load() {
						responseKind = "qualified"
					}
					if responseKind == "committedLostReply" {
						claims.Add(1)
						conn, _, err := w.(http.Hijacker).Hijack()
						require.NoError(t, err)
						_ = conn.Close()
						return
					}
					status := 503
					body := `{"kind":"account-gateway/public-admit-capacity/v1","claim":"not_started","requestNonce":"` + nonce + `"}`
					switch responseKind {
					case "bare503":
						body = ""
					case "wrongNonce":
						body = strings.Replace(body, nonce, uuid.NewString(), 1)
					case "wrongKind":
						body = strings.Replace(body, "public-admit-capacity", "execution-settle-capacity", 1)
					case "wrongClaim":
						body = strings.Replace(body, "not_started", "unknown", 1)
					case "unknownField":
						body = strings.TrimSuffix(body, "}") + `,"extra":true}`
					case "duplicate":
						body = strings.TrimSuffix(body, "}") + `,"claim":"not_started"}`
					case "alias":
						body = strings.Replace(body, `"claim"`, `"Claim"`, 1)
					case "oversized":
						body += strings.Repeat(" ", 1025)
					case "wrongStatus":
						status = 403
					case "wrongType":
						w.Header().Set("Content-Type", "text/plain")
					case "duplicateType":
						w.Header().Add("Content-Type", "application/json")
					case "encoded":
						w.Header().Set("Content-Encoding", "identity")
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, body)
				default:
					t.Error("refused or ambiguous local reservation must not acknowledge SQL closure")
					w.WriteHeader(403)
				}
			}))
			defer authority.Close()
			h, _, _, _ := ownerIngressFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { entries.Add(1) }), func(cfg *Config, _ *ownerFixtureRepo) {
				original = ownerRequest()
				original.Descriptor.BaseURL = cfg.Profile.BaseURL
				cfg.CallbackOrigin, cfg.MaxEntries = authority.URL, 2
			})
			public := httptest.NewServer(h.PublicHandler(4))
			defer public.Close()
			call := func(id string) (int, map[string]any) {
				req, err := http.NewRequest(http.MethodPost, public.URL+"/v1/responses", bytes.NewReader(original.Payload))
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer synthetic-capability-123")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Gateway-Request-Id", id)
				req.Header.Set("X-Gateway-Reservation-Nonce", "public-injected-value-must-not-propagate")
				response, err := public.Client().Do(req)
				require.NoError(t, err)
				defer response.Body.Close()
				var body map[string]any
				require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
				return response.StatusCode, body
			}
			status, body := call("original")
			if kind == "qualified" {
				require.Equal(t, 503, status)
				require.Equal(t, "admission_limited", body["code"])
				require.Equal(t, "not_dispatched", body["effect"])
				require.Equal(t, "never", body["retry"].(map[string]any)["kind"])
			} else {
				require.Equal(t, 202, status)
				require.Equal(t, "effect_unknown", body["effect"])
			}
			// Even after a lost reply representing a committed claim, presenting a
			// qualified marker on a later callback cannot replace this reservation.
			useQualified.Store(true)
			again, repeated := call("original")
			require.Equal(t, status, again)
			require.Equal(t, body["effect"], repeated["effect"])
			require.EqualValues(t, 1, admits.Load(), "duplicate never reissues admission")
			h.mu.Lock()
			for _, e := range h.entries {
				require.Equal(t, kind == "qualified", e.preclaimRefused)
				require.Equal(t, kind == "qualified", e.statusOnly)
				require.Nil(t, e.status, "no synthetic durable request status")
				require.Nil(t, e.proof)
				require.False(t, e.acknowledged)
				require.True(t, closed(e.life.Snapshot()))
			}
			h.mu.Unlock()
			if kind == "qualified" {
				for _, id := range []string{"next-one", "next-two", "next-three", "next-four"} {
					code, _ := call(id)
					require.Equal(t, 503, code)
				}
				h.mu.Lock()
				require.Len(t, h.entries, 2)
				h.mu.Unlock()
			} else {
				// A positive refusal may be reclaimed, but the ambiguous original must
				// survive every turn of the same bounded registry.
				for _, id := range []string{"next-one", "next-two", "next-three"} {
					code, _ := call(id)
					require.Equal(t, 503, code)
				}
				code, old := call("original")
				require.Equal(t, 202, code)
				require.Equal(t, "effect_unknown", old["effect"])
			}
			require.Zero(t, entries.Load())
			if kind == "committedLostReply" {
				require.EqualValues(t, 1, claims.Load())
			} else {
				require.Zero(t, claims.Load())
			}
		})
	}
}
