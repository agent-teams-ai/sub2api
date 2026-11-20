package service

// Connection discovery is a safe projection of deployed native profiles. Model
// membership/entitlement remains with the existing account-scoped catalog.
type GatewayAccountCapabilityLabel struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type GatewayAccountConnectionMethod struct {
	Kind                string `json:"kind"`
	Create              bool   `json:"create"`
	Reconnect           bool   `json:"reconnect"`
	CompletionInputKind string `json:"completionInputKind,omitempty"`
	CallbackMode        string `json:"callbackMode,omitempty"`
	Method              string `json:"method,omitempty"`
	MaxBytes            int    `json:"maxBytes,omitempty"`
}
type GatewayAccountCapability struct {
	ProfileID      string                           `json:"profileId"`
	Provider       GatewayAccountCapabilityLabel    `json:"provider"`
	Product        GatewayAccountCapabilityLabel    `json:"product"`
	Region         GatewayAccountCapabilityLabel    `json:"region"`
	Protocol       string                           `json:"protocol"`
	Models         []GatewayAccountModel            `json:"models"`
	Methods        []GatewayAccountConnectionMethod `json:"methods"`
	AccountInfo    bool                             `json:"accountInfo"`
	LimitsContract string                           `json:"limitsContract"`
	Availability   string                           `json:"availability"`
}
type GatewayAccountCapabilities struct {
	Contract string                     `json:"contract"`
	Profiles []GatewayAccountCapability `json:"profiles"`
}

// The caller supplies only an actually mounted profile/anchor. This pure
// definition never enumerates the broad admin catalog or requests provider HTTP.
func GatewayNativeAccountCapability(profile, anchor string, info, imports bool) (GatewayAccountCapability, bool) {
	provider := GatewayAccountInfoProvider(profile)
	if provider == "" || !GatewayAccountModelIDValid(anchor) {
		return GatewayAccountCapability{}, false
	}
	out := GatewayAccountCapability{ProfileID: profile, Provider: GatewayAccountCapabilityLabel{ID: provider}, Region: GatewayAccountCapabilityLabel{ID: "global", Label: "Global"}, Protocol: "openai-responses", Models: []GatewayAccountModel{{ModelID: anchor, Tools: GatewayAccountModelChoices{Allowed: []string{"function"}, Default: "function"}}}, Methods: []GatewayAccountConnectionMethod{{Kind: "api_key", Create: true, Reconnect: true}}, AccountInfo: info, LimitsContract: "none", Availability: "enabled"}
	switch profile {
	case GatewayAnthropicAPIKeyProfile:
		out.Provider.Label = "Anthropic"
		out.Product = GatewayAccountCapabilityLabel{ID: "pay_as_you_go", Label: "Anthropic API"}
	case GatewayGeminiAPIKeyProfile:
		out.Provider.Label = "Gemini"
		out.Product = GatewayAccountCapabilityLabel{ID: "pay_as_you_go", Label: "Gemini API"}
	case GatewayMiMoResponsesProfile, GatewayLegacyBridgeProfile:
		out.Provider.Label = "MiMo"
		out.Product = GatewayAccountCapabilityLabel{ID: "unknown", Label: "MiMo"}
		out.Region = GatewayAccountCapabilityLabel{ID: "unknown", Label: "Default"}
	case GatewayOpenRouterResponsesProfile:
		out.Provider.Label = "OpenRouter"
		out.Product = GatewayAccountCapabilityLabel{ID: "pay_as_you_go", Label: "OpenRouter credits"}
	case GatewayNVIDIABuildChatProfile:
		out.Provider.Label = "NVIDIA Build"
		out.Product = GatewayAccountCapabilityLabel{ID: "unknown", Label: "NVIDIA API trial (evaluation only)"}
	case GatewayCodexOAuthResponsesProfile:
		out.Provider.Label = "OpenAI Codex"
		out.Product = GatewayAccountCapabilityLabel{ID: "subscription", Label: "ChatGPT subscription"}
		out.LimitsContract = GatewayAccountLimitsContract
		out.Methods = []GatewayAccountConnectionMethod{{Kind: "browser", Create: true, Reconnect: true, CompletionInputKind: "callback_url", CallbackMode: "automatic"}, {Kind: "device_code", Create: true, Reconnect: true}}
		out.Models[0].Reasoning = &GatewayAccountModelChoices{Allowed: []string{"minimal", "low", "medium", "high", "xhigh"}, Default: "high"}
		out.Models[0].Fast = &GatewayAccountModelChoices{Allowed: []string{"balanced"}, Default: "balanced"}
		if imports {
			out.Methods = append(out.Methods, GatewayAccountConnectionMethod{Kind: "credential_import", Method: "refresh_token", MaxBytes: 65536, Create: true, Reconnect: true}, GatewayAccountConnectionMethod{Kind: "credential_import", Method: "oauth_auth_json", MaxBytes: 65536, Create: true, Reconnect: true})
		}
	case GatewayClaudeOAuthMessagesProfile:
		out.Provider.Label = "Anthropic Claude"
		out.Product = GatewayAccountCapabilityLabel{ID: "subscription", Label: "Claude subscription"}
		out.LimitsContract = GatewayAccountLimitsContract
		out.Methods = []GatewayAccountConnectionMethod{{Kind: "browser", Create: true, Reconnect: true, CompletionInputKind: "authorization_code", CallbackMode: "manual_callback_url"}}
		out.Models[0].Reasoning = &GatewayAccountModelChoices{Allowed: []string{"low", "medium", "high"}, Default: "medium"}
		out.Models[0].Fast = &GatewayAccountModelChoices{Allowed: []string{"balanced"}, Default: "balanced"}
	case GatewayGrokOAuthResponsesProfile:
		out.Provider.Label = "Grok Subscription"
		out.Product = GatewayAccountCapabilityLabel{ID: "subscription", Label: "Grok subscription"}
		out.LimitsContract = GatewayAccountLimitsContractV2
		out.Methods = []GatewayAccountConnectionMethod{{Kind: "browser", Create: true, Reconnect: true, CompletionInputKind: "authorization_code", CallbackMode: "manual_callback_url"}}
	case GatewayKimiCodeResponsesProfile:
		out.Provider.Label = "Kimi Code"
		out.Product = GatewayAccountCapabilityLabel{ID: "coding_plan", Label: "Kimi Coding Plan"}
		out.LimitsContract = GatewayAccountLimitsContractV2
	case GatewayGLMCodingResponsesProfile:
		out.Provider.Label = "GLM Coding Plan"
		out.Product = GatewayAccountCapabilityLabel{ID: "coding_plan", Label: "GLM Coding Plan"}
		out.LimitsContract = GatewayAccountLimitsContractV2
	case GatewayMiniMaxMPlanResponsesProfile:
		out.Provider.Label = "MiniMax M Plan"
		out.Product = GatewayAccountCapabilityLabel{ID: "m_plan", Label: "MiniMax M Plan"}
		out.LimitsContract = GatewayAccountLimitsContractV2
	default:
		return GatewayAccountCapability{}, false
	}
	if GatewayModelCatalogProfile(profile) {
		out.Models = gatewayCatalogAccountModels(profile, anchor, nil)
	}
	return out, true
}
