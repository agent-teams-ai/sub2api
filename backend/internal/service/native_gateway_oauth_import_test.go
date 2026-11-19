package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeOAuthImportOrdinaryCodexContainer(t *testing.T) {
	file := func(fields map[string]any) string {
		raw, err := json.Marshal(fields)
		require.NoError(t, err)
		return string(raw)
	}
	ordinary := map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil, "last_refresh": "2020-01-01T00:00:00Z", "tokens": map[string]any{"refresh_token": "fixture-refresh", "access_token": "expired-supplied-access", "id_token": "expired-supplied-id", "account_id": "untrusted-hint", "oauth_provenance": map[string]string{"issuer": GatewayOAuthIssuer, "client_id": openai.ClientID}}}
	refresh, err := gatewayParseCodexImport("auth_json", file(ordinary))
	require.NoError(t, err)
	require.Equal(t, "fixture-refresh", refresh)
	for _, input := range []string{
		`{"tokens":{"access_token":"at-only"}}`,
		`{"tokens":{"refresh_token":"first","refresh_token":"second"}}`,
		`{"tokens":{"refresh_token":"first","Refresh_Token":"second"}}`,
		`{"tokens":{"refresh_token":"first","oauth_provenance":{"issuer":"https://foreign.invalid","client_id":"foreign"}}}`,
		`{"tokens":{"refresh_token":"first","id_token":"\ud800"}}`,
		`{"auth_mode":"personalAccessToken","tokens":{"refresh_token":"first"}}`,
		`{"auth_mode":"agentIdentity","tokens":{"refresh_token":"first"}}`,
		`{"OPENAI_API_KEY":"key","tokens":{"refresh_token":"first"}}`,
		`{"tokens":{"refresh_token":"first"},"proxy":"https://foreign.invalid"}`,
		`[{"tokens":{"refresh_token":"first"}}]`,
	} {
		_, err = gatewayParseCodexImport("auth_json", input)
		require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	}
	for _, method := range []string{"mobile_rt", "access_token", "agent_identity", "personal_access_token"} {
		_, err = gatewayParseCodexImport(method, "fixture-refresh")
		require.Error(t, err)
	}
	_, err = gatewayParseCodexImport("refresh_token", strings.Repeat("x", 32769))
	require.Error(t, err)
	_, err = gatewayParseCodexImport("refresh_token", "refresh\n")
	require.Error(t, err)
}

func TestGatewayNativeOAuthImportStrictEscapedIngressAndSeparateCodec(t *testing.T) {
	s, _, _, scope := connectPureFixture(t)
	prefix := `{"operation":"operation","owner_ref":"owner","account_ref":"logical","generation":"` + scope.Generation + `","method":"auth_json","input":"`
	// A maximal decoded input may require six bytes for each UTF-16 escape.
	in, ok := DecodeGatewayNativeOAuthImport([]byte(prefix + strings.Repeat(`\u0061`, 65536) + `"}`))
	require.True(t, ok)
	require.Len(t, in.Input, 65536)
	for _, raw := range []string{prefix + strings.Repeat(`\u0061`, 65537) + `"}`, prefix + `\ud800"}`, prefix + `x","input":"y"}`, prefix + `x","unknown":true}`, prefix + `x"} {}`, prefix + `x"`} {
		_, valid := DecodeGatewayNativeOAuthImport([]byte(raw))
		require.False(t, valid)
	}
	refresh := strings.Repeat(`\"`, 16384) // Maximum RT containing JSON-escaped bytes.
	inputMAC, claimMAC := s.importCommitments(scope, "operation", "refresh_token", refresh, refresh)
	intent := GatewayNativeOAuthConnectIntent{Scope: scope, Operation: "operation", EnrollmentOperation: "connect-" + uuid.NewString(), ClientID: openai.ClientID, Method: "refresh_token", Deadline: time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute), StateHash: strings.Repeat("a", 64), ImportInputMAC: inputMAC, ImportClaimMAC: claimMAC}
	envelope, err := s.sealImport(intent, refresh)
	require.NoError(t, err)
	require.LessOrEqual(t, len(envelope), GatewayOAuthImportEnvelopeLimit)
	require.NotContains(t, envelope, refresh)
	intent.Envelope = envelope
	opened, err := s.openImport(intent)
	require.NoError(t, err)
	require.Equal(t, refresh, opened)
	changed := intent
	changed.Method = "auth_json"
	_, err = s.openImport(changed)
	require.Error(t, err)
	changed = intent
	changed.Scope.Owner = "other-owner"
	_, err = s.openImport(changed)
	require.Error(t, err)
	_, err = s.open(intent)
	require.Error(t, err, "browser codec cannot accept import envelope")
	result, err := json.Marshal(connectResult(intent))
	require.NoError(t, err)
	require.NotContains(t, string(result), "method")
	require.NotContains(t, string(result), claimMAC)
	other := scope
	other.Owner = "other"
	other.Account = "other"
	other.Generation = uuid.NewString()
	otherInput, otherClaim := s.importCommitments(other, "other-operation", "auth_json", "other-file", refresh)
	require.NotEqual(t, inputMAC, otherInput)
	require.Equal(t, claimMAC, otherClaim, "same RT cannot bypass unresolved claim through method or owner")
}
