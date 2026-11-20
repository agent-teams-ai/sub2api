package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
)

// One qualified review model per official API. Credentials, caller input and
// auth.json cannot select another issuer, endpoint or subscription identity.
const (
	GatewayAnthropicAPIKeyProfile = "anthropic-messages-apikey-v1"
	GatewayAnthropicAPIBaseURL    = "https://api.anthropic.com/v1"
	GatewayAnthropicAPIModel      = "claude-sonnet-4-6"
	GatewayGeminiAPIKeyProfile    = "gemini-openai-chat-apikey-v1"
	GatewayGeminiAPIBaseURL       = "https://generativelanguage.googleapis.com/v1beta/openai"
	GatewayGeminiAPIModel         = "gemini-3.1-pro-preview"
)

func GatewayNativeOfficialAPIProfileIDValid(profile string) bool {
	return profile == GatewayAnthropicAPIKeyProfile || profile == GatewayGeminiAPIKeyProfile
}

func GatewayNativeOfficialAPIProfileValid(profile, baseURL, model string) bool {
	return profile == GatewayAnthropicAPIKeyProfile && baseURL == GatewayAnthropicAPIBaseURL && model == GatewayAnthropicAPIModel ||
		profile == GatewayGeminiAPIKeyProfile && baseURL == GatewayGeminiAPIBaseURL && model == GatewayGeminiAPIModel
}

func gatewayNativePrepareAnthropicAPI(body []byte) ([]byte, func([]apicompat.ResponsesOutput) bool, error) {
	var input apicompat.ResponsesRequest
	if json.Unmarshal(body, &input) != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	converted, err := apicompat.ResponsesToAnthropicRequest(&input)
	if err != nil {
		return nil, nil, ErrGatewayNativeIdentity
	}
	// This bounded API slice has no reasoning control. The generic converter's
	// automatic thinking default must not introduce an unadvertised option.
	converted.Thinking = nil
	var validate func([]apicompat.ResponsesOutput) bool
	if converted.OutputConfig != nil {
		converted.OutputConfig.Effort = ""
		if converted.OutputConfig.Format != nil {
			converted.OutputConfig.Format.Schema, validate, err = gatewayAnthropicOutputSchema(converted.OutputConfig.Format.Schema)
			if err != nil {
				return nil, nil, ErrGatewayNativeIdentity
			}
		} else {
			converted.OutputConfig = nil
		}
	}
	wire, err := json.Marshal(converted)
	if err != nil || len(wire) > 4<<20 {
		return nil, nil, ErrGatewayNativeIdentity
	}
	return wire, validate, nil
}

func (s *OpenAIGatewayService) forwardGatewayAnthropicAPI(ctx context.Context, c *gin.Context, account *Account, body []byte) (*OpenAIForwardResult, error) {
	wire, validate, err := gatewayNativePrepareAnthropicAPI(body)
	if err != nil {
		return nil, err
	}
	upstreamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(upstreamCtx, http.MethodPost, GatewayAnthropicAPIBaseURL+"/messages", bytes.NewReader(wire))
	if err != nil {
		return nil, ErrGatewayNativeIdentity
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("anthropic-version", "2023-06-01")
	// The shared final custody seam replaces this encrypted placeholder with
	// x-api-key under the same physical lock and one-use dispatch fence.
	request.Header.Set("Authorization", "Bearer "+account.GetCredential("api_key"))
	start := time.Now()
	observation := GatewayNativeUsage{Source: "native_provider_response", State: "unknown", CostState: "unknown"}
	defer func() {
		observation.Finalized = true
		if observe, ok := ctx.Value(gatewayNativeUsageObserverKey{}).(func(GatewayNativeUsage)); ok {
			observe(observation)
		}
	}()
	response, err := s.doOpenAIUpstream(request, "", account)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil {
		return nil, ErrGatewayNativeEffectUnknown
	}
	return gatewayNativeAnthropicResponse(ctx, c, response, GatewayAnthropicAPIModel, start, cancel, &observation, validate)
}
