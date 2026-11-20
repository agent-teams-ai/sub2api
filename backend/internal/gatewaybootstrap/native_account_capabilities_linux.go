//go:build linux

package gatewaybootstrap

import (
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func privateAccountCapabilities(profile ProfileConfig, transport *gatewaytransport.Handler, oauth *privateOAuth) service.GatewayAccountCapabilities {
	out := service.GatewayAccountCapabilities{Contract: "native-account-capabilities/v1", Profiles: []service.GatewayAccountCapability{}}
	info := oauth != nil && oauth.info != nil
	imports := oauth != nil && oauth.connect != nil && oauth.dispatch != nil
	add := func(id, model string) {
		if p, ok := service.GatewayNativeAccountCapability(id, model, info, imports); ok {
			out.Profiles = append(out.Profiles, p)
		}
	}
	add(service.GatewayMiMoResponsesProfile, profile.Model)
	if p, ok := transport.OpenRouterProfile(); ok {
		add(p.Profile, p.Model)
	}
	if p, ok := transport.NVIDIAProfile(); ok {
		add(p.Profile, p.Model)
	}
	for _, p := range transport.CodingPlanProfiles() {
		add(p.Profile, p.Model)
	}
	for _, p := range transport.OfficialAPIProfiles() {
		add(p.Profile, p.Model)
	}
	if oauth != nil {
		if oauth.connect != nil && oauth.dispatch != nil {
			add(service.GatewayCodexOAuthResponsesProfile, service.GatewayCodexOAuthModel)
		}
		if oauth.claude != nil {
			add(service.GatewayClaudeOAuthMessagesProfile, service.GatewayClaudeOAuthModel)
		}
		if oauth.grok != nil {
			add(service.GatewayGrokOAuthResponsesProfile, service.GatewayGrokOAuthModel)
		}
	}
	return out
}
