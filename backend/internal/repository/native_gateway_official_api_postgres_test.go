//go:build integration

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Runs in the same fresh migrated M1 database. The database trigger is an
// independent boundary: accepting a Go profile is insufficient for enrollment.
func gatewayOfficialAPIProfilesPostgres(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	custody, err := service.NewGatewayNativeCredentialCustody("official-fixture", map[string][]byte{"official-fixture": custodyPGBytes(t, 32)})
	require.NoError(t, err)
	for _, profile := range []struct{ id, base, model string }{
		{service.GatewayAnthropicAPIKeyProfile, service.GatewayAnthropicAPIBaseURL, service.GatewayAnthropicAPIModel},
		{service.GatewayGeminiAPIKeyProfile, service.GatewayGeminiAPIBaseURL, service.GatewayGeminiAPIModel},
	} {
		t.Run(profile.id, func(t *testing.T) {
			for _, mutation := range []string{"valid", "wrong origin", "wrong model", "wrong mode", "wrong passthrough", "plaintext credential"} {
				t.Run(mutation, func(t *testing.T) {
					scope := service.GatewayNativeCredentialScope{Consumer: "official-consumer", Owner: "official-owner", Account: "official-account", Generation: uuid.NewString(), Purpose: service.GatewayCredentialPurpose}
					envelope, err := custody.Seal(scope, "synthetic-official-api-key")
					require.NoError(t, err)
					credentials := map[string]any{"api_key": envelope, "base_url": profile.base}
					extra := map[string]any{service.GatewayGenerationExtraKey: scope.Generation, service.GatewayProfileExtraKey: profile.id, service.GatewayModelExtraKey: profile.model, service.GatewayCredentialScopeExtraKey: scope.Metadata(), "openai_responses_mode": "force_responses", "openai_passthrough": true, "native_api_key_cancel_on_disconnect": true, "openai_preserve_compatible_reasoning": true}
					switch mutation {
					case "wrong origin":
						credentials["base_url"] = "https://arbitrary.invalid/v1"
					case "wrong model":
						extra[service.GatewayModelExtraKey] = "unqualified-model"
					case "wrong mode":
						extra["openai_responses_mode"] = "force_chat_completions"
					case "wrong passthrough":
						extra["openai_passthrough"] = false
					case "plaintext credential":
						credentials["api_key"] = "synthetic-plaintext-key"
					}
					credentialJSON, err := json.Marshal(credentials)
					require.NoError(t, err)
					extraJSON, err := json.Marshal(extra)
					require.NoError(t, err)
					var accountID int64
					err = db.QueryRowContext(ctx, `INSERT INTO accounts(name,platform,type,status,schedulable,credentials,extra) VALUES('official API fixture','openai','apikey','disabled',false,$1::jsonb,$2::jsonb) RETURNING id`, string(credentialJSON), string(extraJSON)).Scan(&accountID)
					if mutation != "valid" {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)
					require.Positive(t, accountID)
					_, err = db.ExecContext(ctx, `UPDATE accounts SET extra=jsonb_set(extra,'{gateway_model_v1}','"unqualified-model"') WHERE id=$1`, accountID)
					require.Error(t, err, "a valid candidate cannot mutate its protected profile")
				})
			}
		})
	}
}
