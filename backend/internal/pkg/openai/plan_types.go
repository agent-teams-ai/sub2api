package openai

import (
	"strings"
	"unicode"
)

// Native owns both display contexts. The admin UI consumes generated data from
// this catalog instead of maintaining another subscription-label switch.
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
		{"free", "free", "Free", "Free"}, {"go", "go", "Go", "Go"}, {"plus", "plus", "Plus", "Plus"},
		{"prolite", "prolite", "Pro 100", "Pro 100"}, {"pro", "pro", "Pro 200", "Pro 200"}, {"promax", "promax", "Pro 500", "Pro 500"},
		{"team", "team", "Business", "Business"}, {"self_serve_business_usage_based", "selfservebusinessusagebased", "Business", "Business"},
		{"self_serve_business_prolite", "selfservebusinessprolite", "Business Premium", "Business"}, {"business", "business", "Enterprise", "Business"},
		{"enterprise", "enterprise", "Enterprise", "Enterprise"}, {"ent26", "ent26", "Enterprise", "Enterprise"},
		{"enterprise_cbp_usage_based", "enterprisecbpusagebased", "Enterprise", "Enterprise"}, {"enterprise_cbp_automation", "enterprisecbpautomation", "Enterprise (Automation)", "Enterprise"},
		{"edu", "edu", "Edu", "Education"}, {"edu_plus", "eduplus", "Edu Plus", "Education"}, {"edu_pro", "edupro", "Edu Pro", "Education"}, {"unknown", "unknown", "Unknown", "Account"},
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
