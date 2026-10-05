package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Sequential fixture only. Durable races/restart are tested at actual PG.
type connectPureStore struct {
	GatewayNativeOAuthConnectRepository
	row   GatewayNativeOAuthConnectIntent
	calls int
	fail  bool
}

func (r *connectPureStore) PrepareConnect(_ context.Context, in GatewayNativeOAuthConnectIntent) (GatewayNativeOAuthConnectIntent, error) {
	r.calls++
	if r.row.Operation == "" {
		r.row = in
	}
	if r.fail {
		return GatewayNativeOAuthConnectIntent{}, ErrGatewayNativeIdentity
	}
	if !SameGatewayNativeOAuthConnectIntent(in, r.row) {
		return GatewayNativeOAuthConnectIntent{}, ErrGatewayOAuthConflict
	}
	return r.row, nil
}
func (r *connectPureStore) ReadConnectIntent(_ context.Context, s GatewayNativeCredentialScope, op string) (GatewayNativeOAuthConnectIntent, error) {
	if r.row.Scope != s || r.row.Operation != op {
		return GatewayNativeOAuthConnectIntent{}, ErrGatewayNativeIdentity
	}
	return r.row, nil
}
func (r *connectPureStore) FindConnectState(_ context.Context, hash string) (GatewayNativeOAuthConnectIntent, error) {
	if hash != r.row.StateHash {
		return GatewayNativeOAuthConnectIntent{}, ErrGatewayNativeIdentity
	}
	return r.row, nil
}
func (r *connectPureStore) FinishConnect(_ context.Context, _ GatewayNativeOAuthConnectIntent, state string, out GatewayNativeOAuthOutcome) (GatewayNativeOAuthConnectIntent, error) {
	r.row.State = state
	r.row.Envelope = ""
	r.row.Outcome = out
	return r.row, nil
}

type connectNoOutcome struct{}

func (connectNoOutcome) ReadGatewayNativeOAuth(context.Context, GatewayNativeCredentialScope, string) (GatewayNativeOAuthOutcome, error) {
	return GatewayNativeOAuthOutcome{}, ErrGatewayNativeIdentity
}

func connectPureFixture(t *testing.T) (*GatewayNativeOAuthConnect, *connectPureStore, context.Context, GatewayNativeCredentialScope) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	r := &connectPureStore{}
	s, err := NewGatewayNativeOAuthConnect(key, nil, r, &GatewayNativeOAuthEnrollment{}, connectNoOutcome{})
	require.NoError(t, err)
	ctx, err := WithGatewayNativeConsumer(context.Background(), "consumer")
	require.NoError(t, err)
	ctx, err = WithGatewayNativeOAuthOwner(ctx, "owner")
	require.NoError(t, err)
	scope := GatewayNativeCredentialScope{Consumer: "consumer", Owner: "owner", Account: "logical", Generation: uuid.NewString(), Purpose: GatewayOAuthBundlePurpose}
	return s, r, ctx, scope
}

// Failure: a lost prepare ACK could expose an unpersisted URL, mint another
// capability/deadline, or let stock admin/foreign owner change a stable intent.
func TestGatewayNativeOAuthConnectPrepareCustodyAndAuthority(t *testing.T) {
	s, r, ctx, scope := connectPureFixture(t)
	r.fail = true
	out, err := s.BeginConnect(ctx, scope, "operation")
	require.Error(t, err)
	require.Empty(t, out.AuthorizeURL)
	original := r.row
	r.fail = false
	s.now = func() time.Time { return original.Deadline.Add(-time.Minute) }
	out, err = s.BeginConnect(ctx, scope, "operation")
	require.NoError(t, err)
	require.Equal(t, original, r.row)
	u, err := url.Parse(out.AuthorizeURL)
	require.NoError(t, err)
	require.Equal(t, openai.AuthorizeURL, u.Scheme+"://"+u.Host+u.Path)
	material, err := s.open(r.row)
	require.NoError(t, err)
	q := u.Query()
	require.Len(t, material.State, 64)
	require.Len(t, material.Verifier, 128)
	for k, v := range map[string]string{"state": material.State, "code_challenge": openai.GenerateCodeChallenge(material.Verifier), "code_challenge_method": "S256", "client_id": openai.ClientID, "redirect_uri": GatewayOAuthConnectRedirect, "scope": openai.DefaultScopes, "response_type": "code", "codex_cli_simplified_flow": "true", "id_token_add_organizations": "true"} {
		require.Equal(t, v, q.Get(k))
	}
	encoded, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), material.Verifier)
	require.NotContains(t, r.row.Envelope, material.State)
	require.NotContains(t, r.row.Envelope, material.Verifier)
	private, err := json.Marshal(r.row)
	require.NoError(t, err)
	require.Equal(t, "{}", string(private))
	read, err := s.ReadConnect(ctx, scope, "operation")
	require.NoError(t, err)
	require.Empty(t, read.AuthorizeURL)
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
			foreign.Generation = uuid.NewString()
		case "purpose":
			foreign.Purpose = GatewayCredentialPurpose
		}
		before := r.calls
		_, err = s.BeginConnect(ctx, foreign, "operation")
		require.Error(t, err)
		if field == "consumer" || field == "owner" || field == "purpose" {
			require.Equal(t, before, r.calls)
		}
	}
	_, err = s.BeginConnect(context.Background(), scope, "operation")
	require.Error(t, err)
	require.Equal(t, original, r.row)
	transport := s.client.Transport.(*http.Transport)
	require.Nil(t, transport.Proxy)
	require.True(t, transport.DisableKeepAlives)
	require.NotZero(t, s.client.Timeout)
	require.NotNil(t, s.client.CheckRedirect)
	// Expiry clears ONLY material, retaining capability hash and replay outcome.
	s.now = func() time.Time { return original.Deadline }
	read, err = s.CompleteCallback(context.Background(), material.State, "fixture-code")
	require.NoError(t, err)
	require.Equal(t, "expired", read.State)
	require.Empty(t, r.row.Envelope)
	require.Equal(t, original.StateHash, r.row.StateHash)
}

// Failure: copied envelopes could reopen with a different scope/op/deadline,
// capability hash, domain or key; DB metadata must never be decryption authority.
func TestGatewayNativeOAuthConnectMaterialExactAAD(t *testing.T) {
	s, r, ctx, scope := connectPureFixture(t)
	_, err := s.BeginConnect(ctx, scope, "operation")
	require.NoError(t, err)
	for _, field := range []string{"consumer", "owner", "account", "generation", "purpose", "operation", "deadline", "client", "redirect", "hash", "cipher"} {
		t.Run(field, func(t *testing.T) {
			in := r.row
			switch field {
			case "consumer":
				in.Scope.Consumer = "other"
			case "owner":
				in.Scope.Owner = "other"
			case "account":
				in.Scope.Account = "other"
			case "generation":
				in.Scope.Generation = uuid.NewString()
			case "purpose":
				in.Scope.Purpose = GatewayCredentialPurpose
			case "operation":
				in.Operation = "other"
			case "deadline":
				in.Deadline = in.Deadline.Add(time.Microsecond)
			case "client":
				in.ClientID = "other"
			case "redirect":
				in.Redirect = "http://127.0.0.1:1455/auth/callback"
			case "hash":
				in.StateHash = connectStateHash("other")
			case "cipher":
				in.Envelope = "gco1." + in.Envelope[5:]
			}
			_, err := s.open(in)
			require.ErrorIs(t, err, ErrGatewayNativeIdentity)
		})
	}
	other, _, _, _ := connectPureFixture(t)
	_, err = other.open(r.row)
	require.ErrorIs(t, err, ErrGatewayNativeIdentity)
	for _, code := range []string{"", "\ncode", "code\x00", " code", "code "} {
		require.False(t, connectCodeValid(code))
	}
}
