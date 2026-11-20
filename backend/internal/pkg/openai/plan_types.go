package openai

import (
	"strings"
	"unicode"
)

// Native owns both display contexts. The admin UI consumes generated data from
// this catalog instead of maintaining another subscription-label switch.
// Regenerate admin data from backend with: make generate-plan-catalog.
type PlanTypeDefinition struct {
	Code      string `json:"code"`
	Key       string `json:"key"`
	Status    string `json:"status"`
	Analytics string `json:"analytics"`
}

type PlanTypeCatalog struct {
	Aliases map[string]string    `json:"aliases"`
	Plans   []PlanTypeDefinition `json:"plans"`
}

func PlanCatalog() PlanTypeCatalog {
	return PlanTypeCatalog{Aliases: map[string]string{"chatgptpro": "pro"}, Plans: PlanTypes()}
}

func PlanTypes() []PlanTypeDefinition {
	return []PlanTypeDefinition{
		{Code: "free", Key: "free", Status: "Free", Analytics: "Free"}, {Code: "go", Key: "go", Status: "Go", Analytics: "Go"}, {Code: "plus", Key: "plus", Status: "Plus", Analytics: "Plus"},
		{Code: "prolite", Key: "prolite", Status: "Pro 100", Analytics: "Pro 100"}, {Code: "pro", Key: "pro", Status: "Pro 200", Analytics: "Pro 200"}, {Code: "promax", Key: "promax", Status: "Pro 500", Analytics: "Pro 500"},
		{Code: "team", Key: "team", Status: "Business", Analytics: "Business"}, {Code: "self_serve_business_usage_based", Key: "selfservebusinessusagebased", Status: "Business", Analytics: "Business"},
		{Code: "self_serve_business_prolite", Key: "selfservebusinessprolite", Status: "Business Premium", Analytics: "Business"}, {Code: "business", Key: "business", Status: "Enterprise", Analytics: "Business"},
		{Code: "enterprise", Key: "enterprise", Status: "Enterprise", Analytics: "Enterprise"}, {Code: "ent26", Key: "ent26", Status: "Enterprise", Analytics: "Enterprise"},
		{Code: "enterprise_cbp_usage_based", Key: "enterprisecbpusagebased", Status: "Enterprise", Analytics: "Enterprise"}, {Code: "enterprise_cbp_automation", Key: "enterprisecbpautomation", Status: "Enterprise (Automation)", Analytics: "Enterprise"},
		{Code: "edu", Key: "edu", Status: "Edu", Analytics: "Education"}, {Code: "edu_plus", Key: "eduplus", Status: "Edu Plus", Analytics: "Education"}, {Code: "edu_pro", Key: "edupro", Status: "Edu Pro", Analytics: "Education"}, {Code: "unknown", Key: "unknown", Status: "Unknown", Analytics: "Account"},
	}
}
func PlanTypeKey(value string) string {
	key := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '_' || r == '-' {
			return -1
		}
		return unicode.ToLower(r)
	}, value)
	if alias, ok := PlanCatalog().Aliases[key]; ok {
		return alias
	}
	return key
}
func PlanTypeLabel(value string, analytics bool) string {
	key := PlanTypeKey(value)
	for _, p := range PlanTypes() {
		if p.Key == key {
			if analytics {
				return p.Analytics
			}
			return p.Status
		}
	}
	return ""
}
