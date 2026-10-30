package service

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Only closed gate names reach the existing private native stderr channel.
// No caller/provider text, identity, credential, payload or success is logged.
type gatewayNativeAdmissionPhase uint8

const (
	gatewayAdmissionPayload gatewayNativeAdmissionPhase = iota + 1
	gatewayAdmissionInput
	gatewayAdmissionTools
	gatewayAdmissionMapping
	gatewayAdmissionDescriptor
	gatewayAdmissionCredential
	gatewayAdmissionLifetime
	gatewayAdmissionCatalogUnavailable
	gatewayAdmissionCatalogExpired
	gatewayAdmissionCatalogPolicy
	gatewayAdmissionDispatchTarget
	gatewayAdmissionAccountLock
	gatewayAdmissionAccountChanged
	gatewayAdmissionReplay
	gatewayAdmissionRuntime
)

func gatewayNativeAdmissionPhaseName(phase gatewayNativeAdmissionPhase) string {
	switch phase {
	case gatewayAdmissionPayload:
		return "admission_payload"
	case gatewayAdmissionInput:
		return "admission_input"
	case gatewayAdmissionTools:
		return "admission_tools"
	case gatewayAdmissionMapping:
		return "admission_mapping"
	case gatewayAdmissionDescriptor:
		return "admission_descriptor"
	case gatewayAdmissionCredential:
		return "admission_credential"
	case gatewayAdmissionLifetime:
		return "admission_lifetime"
	case gatewayAdmissionCatalogUnavailable:
		return "admission_catalog_unavailable"
	case gatewayAdmissionCatalogExpired:
		return "admission_catalog_expired"
	case gatewayAdmissionCatalogPolicy:
		return "admission_catalog_policy"
	case gatewayAdmissionDispatchTarget:
		return "admission_dispatch_target"
	case gatewayAdmissionAccountLock:
		return "admission_account_lock"
	case gatewayAdmissionAccountChanged:
		return "admission_account_changed"
	case gatewayAdmissionReplay:
		return "admission_replay"
	case gatewayAdmissionRuntime:
		return "admission_runtime"
	default:
		return ""
	}
}
func gatewayNativeAdmissionDiagnostic(phase gatewayNativeAdmissionPhase) {
	name := gatewayNativeAdmissionPhaseName(phase)
	if name == "" {
		return
	}
	line, _ := json.Marshal(struct {
		Event string `json:"event"`
		Phase string `json:"phase"`
	}{"gateway_native_response_failure", name})
	_, _ = fmt.Fprintln(os.Stderr, string(line))
}

// This only categorizes an already rejected observation. Admission continues to
// use gatewayOpenRouterModelsAllow unchanged, including the final fresh fence.
func gatewayNativeCatalogAdmissionDiagnostic(result GatewayAccountModelsResult) {
	phase := gatewayAdmissionCatalogPolicy
	if result.Status != "snapshot" || result.Models == nil || result.Source != "openrouter" {
		phase = gatewayAdmissionCatalogUnavailable
	} else if expires, err := time.Parse(time.RFC3339Nano, result.ExpiresAt); err != nil || !expires.After(time.Now()) {
		phase = gatewayAdmissionCatalogExpired
	}
	gatewayNativeAdmissionDiagnostic(phase)
}
