//go:build unit

package service

import "testing"

func TestValidateScopedOpenAIOptionsRejectsBillingPolicyMutation(t *testing.T) {
	for _, raw := range []string{
		`{"openai_long_context_billing_enabled":true}`,
		`{"openai_long_context_billing_enabled":false}`,
		`{"email":"user@example.com","openai_long_context_billing_enabled":true}`,
	} {
		if err := validateScopedOpenAIOptions([]byte(raw)); err == nil {
			t.Errorf("scoped admin accepted billing-policy mutation: %s", raw)
		}
	}
}

func TestValidateScopedOpenAIOptionsKeepsSupportedConnectionControls(t *testing.T) {
	for _, raw := range []string{
		`{"email":"user@example.com"}`,
		`{"openai_oauth_responses_websockets_v2_enabled":true}`,
		`{"openai_oauth_responses_websockets_v2_mode":"shared"}`,
	} {
		if err := validateScopedOpenAIOptions([]byte(raw)); err != nil {
			t.Errorf("scoped admin rejected supported connection controls %s: %v", raw, err)
		}
	}
}
