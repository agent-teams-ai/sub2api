//go:build integration || gatewaycustody

package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func nativeRetainedCustody(t *testing.T, id string) *service.GatewayNativeCredentialCustody {
	t.Helper()
	custody, err := service.NewGatewayNativeCredentialCustody(id, map[string][]byte{id: custodyPGBytes(t, 32)})
	require.NoError(t, err)
	return custody
}

func retainedCustodyAPIPostgres(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_RETAINED_API_PG_DSN", "native_retained_api_")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, repo := custodyPGOpen(t, ctx, dsn)
	custody := nativeRetainedCustody(t, "retained-k1")
	scope := service.GatewayNativeCredentialScope{Consumer: "consumer/api", Owner: "owner/api", Account: "account/api",
		Generation: uuid.NewString(), Purpose: service.GatewayCredentialPurpose}
	envelope, err := custody.Seal(scope, "synthetic-api-key")
	require.NoError(t, err)
	row := custodyPGRow(scope, envelope, "https://synthetic.invalid/v1")
	require.NoError(t, repo.Create(ctx, row))
	row, err = repo.GetByID(ctx, row.ID)
	require.NoError(t, err)
	route, err := service.GatewayNativeDescriptor(row)
	require.NoError(t, err)
	var before []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", row.ID).Scan(&before))
	reader, ok := repo.(service.GatewayNativeRetainedAPIKeyCustodyRepository)
	require.True(t, ok)
	a, release, err := reader.LockGatewayNativeRetainedAPIKeyCustody(ctx, scope, route)
	require.NoError(t, err)
	require.Equal(t, row.ID, a.ID)
	release()
	proofCtx, err := service.WithGatewayNativeConsumer(ctx, scope.Consumer)
	require.NoError(t, err)
	gateway := custodyPGGateway(repo, nil)
	prove := func(adapter *service.GatewayNativeCredentialCustody) (service.GatewayNativeRetainedCustodyResult, error) {
		return gateway.ReadGatewayNativeRetainedAPIKeyCustody(service.WithGatewayNativeCustody(proofCtx, adapter), scope, route)
	}
	proof, err := prove(custody)
	require.NoError(t, err)
	require.True(t, proof.Proof.Authenticated)
	require.Equal(t, "inactive", proof.Retention.State)
	for _, id := range []string{"retained-k1", "retired-key"} {
		_, err = prove(nativeRetainedCustody(t, id))
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity, "wrong/retired key must fail real AEAD")
	}
	var after []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", row.ID).Scan(&after))
	require.JSONEq(t, string(before), string(after), "custody readback must not mutate state or revision")
	parts := strings.Split(envelope, ".")
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	ciphertext[0] ^= 1
	parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)
	_, err = db.ExecContext(ctx, "UPDATE accounts SET credentials=jsonb_set(credentials,'{api_key}',to_jsonb($1::text)) WHERE id=$2", strings.Join(parts, "."), row.ID)
	require.Error(t, err, "real immutable guard rejects valid-shaped ciphertext replacement")
	_, err = prove(custody)
	require.NoError(t, err, "rejected replacement preserves original decryptable custody")

	for name, changed := range map[string]service.GatewayNativeCredentialScope{
		"consumer": {Consumer: "consumer/foreign", Owner: scope.Owner, Account: scope.Account, Generation: scope.Generation, Purpose: scope.Purpose},
		"owner":    {Consumer: scope.Consumer, Owner: "owner/foreign", Account: scope.Account, Generation: scope.Generation, Purpose: scope.Purpose},
		"account":  {Consumer: scope.Consumer, Owner: scope.Owner, Account: "account/foreign", Generation: scope.Generation, Purpose: scope.Purpose},
		"purpose":  {Consumer: scope.Consumer, Owner: scope.Owner, Account: scope.Account, Generation: scope.Generation, Purpose: "foreign"},
	} {
		_, release, err = reader.LockGatewayNativeRetainedAPIKeyCustody(ctx, changed, route)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity, name)
		if release != nil {
			release()
		}
	}
	changedGeneration := scope
	changedGeneration.Generation = uuid.NewString()
	changedRoute := route
	changedRoute.Generation = changedGeneration.Generation
	_, release, err = reader.LockGatewayNativeRetainedAPIKeyCustody(ctx, changedGeneration, changedRoute)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	badRoute := route
	badRoute.CreatedAt = badRoute.CreatedAt.Add(time.Microsecond)
	_, release, err = reader.LockGatewayNativeRetainedAPIKeyCustody(ctx, scope, badRoute)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	eraseCtx, err := service.WithGatewayNativeConsumer(context.Background(), scope.Consumer)
	require.NoError(t, err)
	require.NoError(t, repo.(service.GatewayNativeAccountEraser).EraseGatewayNativeAccount(eraseCtx, route))
	_, release, err = reader.LockGatewayNativeRetainedAPIKeyCustody(ctx, scope, route)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	_, err = db.ExecContext(ctx, "UPDATE accounts SET deleted_at=NULL,credentials=jsonb_set(credentials,'{api_key}',to_jsonb($1::text)) WHERE id=$2", envelope, row.ID)
	require.Error(t, err, "old tombstone restoration remains denied by the real guard")
}

func retainedCustodyOAuthPostgres(t *testing.T) {
	dsn := custodyPGDSN(t, "GATEWAY_NATIVE_RETAINED_OAUTH_PG_DSN", "native_retained_oauth_")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, repo := custodyPGOpen(t, ctx, dsn)
	custody := nativeRetainedCustody(t, "retained-oauth-k1")
	verifier, bundleFor := oauthPGFixture(t)
	authCtx, scope := oauthPGScope(t, "consumer/oauth", "owner/oauth", "account/oauth")
	bundle := bundleFor("subject-retained")
	intentKey := custodyPGBytes(t, 32)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, repo.(service.GatewayNativeOAuthRepository), intentKey)
	require.NoError(t, err)
	originalOperation := "original-retained-operation"
	enrollmentOperation := "connect-" + uuid.NewString()
	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, intentKey)
	_, _ = mac.Write([]byte("account-gateway/native/oauth-enrollment-intent/v1\x00"))
	scopeRaw, _ := json.Marshal(scope)
	_, _ = mac.Write(scopeRaw)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(enrollmentOperation))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(raw)
	commitment := hex.EncodeToString(mac.Sum(nil))
	stateHash := hex.EncodeToString(custodyPGBytes(t, 32))
	_, err = db.ExecContext(ctx, `INSERT INTO gateway_oauth_connect_intents
 (consumer,owner_ref,account_ref,generation,purpose,operation_ref,enrollment_operation,client_id,redirect_uri,deadline,state_hash,material_envelope,state)
 VALUES ($1,$2,$3,$4,$5,$6,$7,'app_EMoamEEZ73f0CkXaXp7hrann','http://localhost:1455/auth/callback',NOW()+interval '5 minutes',$8,$9,'prepared')`,
		scope.Consumer, scope.Owner, scope.Account, scope.Generation, scope.Purpose, originalOperation, enrollmentOperation, stateHash, "gcc1."+strings.Repeat("A", 80))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_connect_intents SET state='entered',entered_at=NOW() WHERE consumer=$1 AND operation_ref=$2`,
		scope.Consumer, originalOperation)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_connect_intents SET enrollment_mac=$1 WHERE consumer=$2 AND operation_ref=$3`,
		commitment, scope.Consumer, originalOperation)
	require.NoError(t, err)
	outcome, err := enrollment.Stage(authCtx, scope, enrollmentOperation, bundle)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE gateway_oauth_connect_intents SET state='completed',material_envelope='',outcome_operation=$1,outcome_account_id=$2,outcome_generation=$3,outcome_state='staged' WHERE consumer=$4 AND operation_ref=$5`,
		enrollmentOperation, outcome.AccountID, outcome.Generation, scope.Consumer, originalOperation)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO gateway_oauth_profile_qualifications
 (account_id,native_created_at,consumer,owner_ref,account_ref,generation,operation_ref,issuer,subject,provider_account_id,profile,base_url,model,qualification,qualified_at)
 SELECT a.id,a.created_at,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW()
 FROM accounts a JOIN gateway_oauth_identity_reservations r ON r.account_id=a.id
 WHERE a.id=$13`,
		scope.Consumer, scope.Owner, scope.Account, scope.Generation, originalOperation, service.GatewayOAuthIssuer, "subject-retained", uuid.NewString(),
		service.GatewayCodexOAuthResponsesProfile, service.GatewayCodexOAuthBaseURL, service.GatewayCodexOAuthModel, service.GatewayCodexOAuthQualification, outcome.AccountID)
	require.NoError(t, err)
	reader, ok := repo.(service.GatewayNativeRetainedOAuthCustodyRepository)
	require.True(t, ok)
	a, err := repo.GetByID(ctx, outcome.AccountID)
	require.NoError(t, err)
	route := service.GatewayNativeRoute{AccountID: a.ID, Generation: scope.Generation, CreatedAt: a.CreatedAt,
		Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}
	var before []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", a.ID).Scan(&before))
	locked, release, err := reader.LockGatewayNativeRetainedOAuthCustody(authCtx, scope, originalOperation, route)
	require.NoError(t, err)
	require.Equal(t, outcome.AccountID, locked.ID)
	release()
	dispatch, err := service.NewGatewayNativeOAuthDispatch(repo.(service.GatewayNativeOAuthDispatchRepository), custody, verifier, nil)
	require.NoError(t, err)
	proof, err := dispatch.RetainedCustody(authCtx, scope, originalOperation, route)
	require.NoError(t, err)
	require.True(t, proof.Proof.Authenticated)
	require.Equal(t, "inactive", proof.Retention.State)
	require.Equal(t, "unasserted", proof.OAuthPolicy.ProviderValidity)
	for _, id := range []string{"retained-oauth-k1", "retired-oauth-key"} {
		wrong, err := service.NewGatewayNativeOAuthDispatch(repo.(service.GatewayNativeOAuthDispatchRepository), nativeRetainedCustody(t, id), verifier, nil)
		require.NoError(t, err)
		_, err = wrong.RetainedCustody(authCtx, scope, originalOperation, route)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity, "wrong/retired key must fail real AEAD")
	}
	var after []byte
	require.NoError(t, db.QueryRowContext(ctx, "SELECT row_to_json(accounts)::text FROM accounts WHERE id=$1", a.ID).Scan(&after))
	require.JSONEq(t, string(before), string(after), "OAuth custody readback must not mutate state or revision")
	for name, changed := range map[string]service.GatewayNativeCredentialScope{
		"consumer": {Consumer: "consumer/foreign", Owner: scope.Owner, Account: scope.Account, Generation: scope.Generation, Purpose: scope.Purpose},
		"owner":    {Consumer: scope.Consumer, Owner: "owner/foreign", Account: scope.Account, Generation: scope.Generation, Purpose: scope.Purpose},
		"account":  {Consumer: scope.Consumer, Owner: scope.Owner, Account: "account/foreign", Generation: scope.Generation, Purpose: scope.Purpose},
	} {
		_, release, err = reader.LockGatewayNativeRetainedOAuthCustody(authCtx, changed, originalOperation, route)
		require.ErrorIs(t, err, service.ErrGatewayNativeIdentity, name)
		if release != nil {
			release()
		}
	}
	changedGeneration := scope
	changedGeneration.Generation = uuid.NewString()
	changedRoute := route
	changedRoute.Generation = changedGeneration.Generation
	_, release, err = reader.LockGatewayNativeRetainedOAuthCustody(authCtx, changedGeneration, originalOperation, changedRoute)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	badRoute := route
	badRoute.CreatedAt = badRoute.CreatedAt.Add(time.Microsecond)
	_, release, err = reader.LockGatewayNativeRetainedOAuthCustody(authCtx, scope, originalOperation, badRoute)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	eraseCtx, err := service.WithGatewayNativeConsumer(context.Background(), scope.Consumer)
	require.NoError(t, err)
	eraseCtx, err = service.WithGatewayNativeOAuthOwner(eraseCtx, scope.Owner)
	require.NoError(t, err)
	require.NoError(t, repo.(service.GatewayNativeOAuthRepository).EraseGatewayNativeOAuth(eraseCtx, scope, enrollmentOperation))
	_, release, err = reader.LockGatewayNativeRetainedOAuthCustody(authCtx, scope, originalOperation, route)
	require.ErrorIs(t, err, service.ErrGatewayNativeIdentity)
	if release != nil {
		release()
	}
	_, err = db.ExecContext(ctx, "UPDATE accounts SET deleted_at=NULL,credentials=jsonb_set(credentials,'{oauth_bundle}',to_jsonb($1::text)) WHERE id=$2", "gco1.retained-oauth-k1.synthetic.synthetic", outcome.AccountID)
	require.Error(t, err, "old OAuth tombstone restoration remains denied by the real guard")
}

func TestGatewayNativeRetainedCustodyPostgres(t *testing.T) {
	t.Run("api-key", retainedCustodyAPIPostgres)
	t.Run("oauth", retainedCustodyOAuthPostgres)
}
