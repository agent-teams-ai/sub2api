//go:build integration

package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type codexInfoCountHTTP struct {
	http.RoundTripper
	calls atomic.Int32
}

func (c *codexInfoCountHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.RoundTripper.RoundTrip(r)
}

// Reuses the already migrated isolated M1 database. The actual token/JWKS and
// account-check transports, custody, connect FSM, refresh writer and snapshot
// repository all run; only the upstream account is a signed synthetic fixture.
func gatewayCodexInfoPostgresLifecycle(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var phase atomic.Int32
	providerID := uuid.NewString()
	_, transport, _ := oauthPGRefreshFixture(t, func(w http.ResponseWriter, r *http.Request, bundleFor func(string) service.GatewayNativeOAuthBundle) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		bundle := bundleFor("codex-info-owner")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": bundle.AccessToken, "refresh_token": bundle.RefreshToken, "id_token": bundle.IDToken, "token_type": "Bearer", "expires_in": 3600, "scope": openai.RefreshScopes})
	}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"accounts":{"selected":{"account":{"account_id":%q,"account_structure":"personal","plan_type":"plus","name":"Review account"}}}}`, providerID)
	}, func(claims map[string]any) {
		claims["email"] = fmt.Sprintf("native%d@example.test", phase.Load())
		claims["name"] = "Signed account"
		claims["https://api.openai.com/auth"] = map[string]string{"chatgpt_plan_type": "plus"}
	})
	counted := &codexInfoCountHTTP{RoundTripper: transport}
	verifier := service.NewGatewayNativeOAuthVerifier(counted)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	custody, err := service.NewGatewayNativeCredentialCustody("info-codex", map[string][]byte{"info-codex": key})
	require.NoError(t, err)
	repo := NewAccountRepository(nil, db, nil)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, repo.(service.GatewayNativeOAuthRepository), key)
	require.NoError(t, err)
	journal, err := NewGatewayNativeOAuthConnectRepository(db)
	require.NoError(t, err)
	connect, err := service.NewGatewayNativeOAuthConnect(key, counted, journal, enrollment, repo.(service.GatewayNativeOAuthRepository))
	require.NoError(t, err)
	require.NoError(t, connect.SetEntryAuthorizer(func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }))
	owner, scope := oauthPGScope(t, "info-codex-consumer", "info-codex-owner", "info-codex-account")
	owner, stop := context.WithTimeout(owner, 55*time.Second)
	defer stop()
	const operation = "info-codex-import"
	connected, err := connect.ImportConnect(owner, scope, operation, "refresh_token", "info-codex-refresh")
	require.NoError(t, err)
	require.Equal(t, "completed", connected.State)
	dispatch, err := service.NewGatewayNativeOAuthDispatch(repo.(service.GatewayNativeOAuthDispatchRepository), custody, verifier, counted)
	require.NoError(t, err)
	descriptor, err := dispatch.Descriptor(owner, scope, operation)
	require.NoError(t, err)
	require.NotNil(t, descriptor.Native)
	route := *descriptor.Native
	info := NewGatewayAccountInfoRepository(db)
	input := service.GatewayAccountLimitsInput{OwnerRef: scope.Owner, AccountRef: scope.Account, ProfileID: route.Profile}
	initial, err := info.ReadGatewayAccountInfo(owner, input, route)
	require.NoError(t, err)
	require.Equal(t, "native0@example.test", *initial.Sources["verified_claims"].Fields.Email.Value)
	require.Equal(t, "plus", initial.Sources["account_check"].Fields.Subscription.Value.Code)
	originalObserved := initial.Sources["credential"].Fields.CredentialExpiresAt.ObservedAt
	require.NotEmpty(t, originalObserved)
	_, err = db.ExecContext(ctx, `DELETE FROM gateway_account_info_snapshots WHERE account_id=$1`, route.AccountID)
	require.NoError(t, err)
	refresh, err := service.NewGatewayNativeOAuthRefresh(repo.(service.GatewayNativeOAuthRefreshRepository), custody, verifier, counted)
	require.NoError(t, err)
	require.NoError(t, refresh.SetEntryAuthorizer(func(context.Context, service.GatewayNativeCredentialScope, string) error { return nil }))
	before := counted.calls.Load()
	maintained, err := refresh.Maintain(owner, scope, operation)
	require.NoError(t, err)
	require.Equal(t, "idle", maintained.State)
	require.Equal(t, before, counted.calls.Load(), "retained hydration performs no HTTP")
	hydrated, err := info.ReadGatewayAccountInfo(owner, input, route)
	require.NoError(t, err)
	require.Len(t, hydrated.Sources, 2)
	require.EqualValues(t, 0, hydrated.Sources["verified_claims"].Order)
	require.EqualValues(t, 0, hydrated.Sources["credential"].Order)
	require.Equal(t, "native0@example.test", *hydrated.Sources["verified_claims"].Fields.Email.Value)
	require.Equal(t, originalObserved, hydrated.Sources["credential"].Fields.CredentialExpiresAt.ObservedAt)
	_, err = refresh.Maintain(owner, scope, operation)
	require.NoError(t, err)
	repeated, err := info.ReadGatewayAccountInfo(owner, input, route)
	require.NoError(t, err)
	require.Equal(t, hydrated.Revision, repeated.Revision)
	require.Equal(t, before, counted.calls.Load())
	_, physical, release, err := repo.(service.GatewayNativeOAuthDispatchRepository).LockGatewayNativeOAuthDispatch(owner, scope, operation, route.AccountID)
	require.NoError(t, err)
	release()
	physical.CredentialRevision = 1
	order, err := info.ReserveGatewayAccountInfoOrder(owner)
	require.NoError(t, err)
	omission := service.GatewayAccountInfoObservation{Source: "verified_claims", Order: order, CredentialRevision: 1, Fields: service.GatewayAccountInfoEmptyFields(route.Profile)}
	require.NoError(t, info.StoreGatewayAccountInfo(owner, physical, omission, false))
	require.NoError(t, refresh.HydrateAccountInfo(owner, scope, operation))
	tombstone, err := info.ReadGatewayAccountInfo(owner, input, route)
	require.NoError(t, err)
	require.Equal(t, "unknown", tombstone.Sources["verified_claims"].Fields.Email.Status)
	require.Equal(t, order, tombstone.Sources["verified_claims"].Order, "legacy source cannot resurrect an authoritative omission")
	phase.Store(1)
	intent := service.GatewayNativeOAuthRefreshIntent{Scope: scope, AccountID: route.AccountID, CreatedAt: route.CreatedAt, ExpectedVersion: 1, Operation: "info-codex-rotate-one", Intent: "info-codex-rotation-one", ConnectOperation: operation}
	out, err := refresh.Refresh(owner, intent)
	require.NoError(t, err)
	require.Equal(t, "completed", out.State)
	require.EqualValues(t, 2, out.Version)
	fresh, err := info.ReadGatewayAccountInfo(owner, input, route)
	require.NoError(t, err)
	require.EqualValues(t, 2, fresh.CredentialRevision)
	require.Equal(t, "native1@example.test", *fresh.Sources["verified_claims"].Fields.Email.Value)
	require.EqualValues(t, 2, fresh.Sources["credential"].CredentialRevision)
	require.Equal(t, initial.PrincipalVersion, fresh.PrincipalVersion)
	require.Error(t, info.StoreGatewayAccountInfo(owner, physical, omission, false), "old credential observation loses current revision CAS")
	// Fail metadata publication after provider exchange. The same transaction
	// must roll credential/version back and the original operation becomes unknown.
	_, err = db.ExecContext(ctx, `CREATE FUNCTION gateway_info_test_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic info commit failure'; END $$;
 CREATE TRIGGER gateway_info_test_reject BEFORE INSERT OR UPDATE ON gateway_account_info_snapshots FOR EACH ROW EXECUTE FUNCTION gateway_info_test_reject()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS gateway_info_test_reject ON gateway_account_info_snapshots; DROP FUNCTION IF EXISTS gateway_info_test_reject()`)
	})
	phase.Store(2)
	intent.ExpectedVersion, intent.Operation, intent.Intent = 2, "info-codex-rotate-two", "info-codex-rotation-two"
	out, err = refresh.Refresh(owner, intent)
	require.Error(t, err)
	require.Equal(t, "unknown", out.State)
	var credentialVersion, infoRevision int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT gateway_oauth_credential_version(credentials) FROM accounts WHERE id=$1`, route.AccountID).Scan(&credentialVersion))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT revision FROM gateway_account_info_snapshots WHERE account_id=$1`, route.AccountID).Scan(&infoRevision))
	require.EqualValues(t, 2, credentialVersion)
	require.Equal(t, fresh.Revision, infoRevision)
}
