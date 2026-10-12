// Package gatewaytransport is an opt-in private native HTTP component. SQL,
// admission policy and process enrollment remain owned by its trusted host.
package gatewaytransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

var errDenied = errors.New("private native transport denied")
var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
var qualifiedModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var integerToken = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var instant = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,9})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$`)

const maxSafeInteger = 9007199254740991
const transportsPath = "/private/native/v1/transports"

// These private fields map kernel-domain.ts, not SDK public admission authority.
type Limits struct {
	Requests     int64 `json:"requests"`
	Concurrency  int64 `json:"concurrency"`
	RequestBytes int64 `json:"requestBytes"`
	OutputBytes  int64 `json:"outputBytes"`
	Tokens       int64 `json:"tokens"`
}

type Admission struct {
	ExecutionRef       string `json:"executionRef"`
	IssuerEpoch        string `json:"issuerEpoch"`
	InvocationRef      string `json:"invocationRef"`
	AttemptRef         string `json:"attemptRef"`
	AccountRef         string `json:"accountRef"`
	AuthorizationEpoch int64  `json:"authorizationEpoch"`
	SubjectRef         string `json:"subjectRef"`
	PolicyRevision     int64  `json:"policyRevision"`
	BindingRevision    int64  `json:"bindingRevision"`
	ProfileID          string `json:"profileId"`
	Limits             Limits `json:"limits"`
	ExpiresAt          string `json:"expiresAt"`
}

type NativeBinding struct {
	OriginRef         string `json:"originRef"`
	EngineIncarnation string `json:"engineIncarnation"`
	RequestNonce      string `json:"requestNonce"`
	Generation        string `json:"generation"`
}

type Proof struct {
	ExecutionRef string        `json:"executionRef"`
	RequestRef   string        `json:"requestRef"`
	Worker       string        `json:"worker"`
	Token        string        `json:"token"`
	Native       NativeBinding `json:"native"`
}

// Only the trusted TS adapter supplies a resolved descriptor and worker. CI's
// public request has neither a consumer nor these protected mapping fields.
type Request struct {
	RequestRef string                     `json:"requestRef"`
	Worker     string                     `json:"worker"`
	Admission  Admission                  `json:"admission"`
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
	Payload    json.RawMessage            `json:"payload"`
}

type admitRequest struct {
	ConsumerID string                     `json:"consumerId"`
	RequestRef string                     `json:"requestRef"`
	Worker     string                     `json:"worker"`
	Admission  Admission                  `json:"admission"`
	Descriptor service.GatewayNativeRoute `json:"descriptor"`
	Native     NativeBinding              `json:"native"`
}

type requestStatus struct {
	RequestRef string `json:"requestRef"`
	Effect     string `json:"effect"`
	Code       string `json:"code,omitempty"`
}

type kernelDescriptor struct {
	Generation             string `json:"generation"`
	NativePhysicalIdentity string `json:"nativePhysicalIdentity"`
	Profile                string `json:"profile"`
}

type dispatch struct {
	Descriptor   kernelDescriptor `json:"descriptor"`
	ExecutionRef string           `json:"executionRef"`
	RequestRef   string           `json:"requestRef"`
	Limits       Limits           `json:"limits"`
	Deadline     string           `json:"deadline"`
	Closure      Proof            `json:"closure"`
}

type admitReply struct {
	ConsumerID       string                      `json:"consumerId"`
	Admission        Admission                   `json:"admission"`
	Status           requestStatus               `json:"status"`
	Dispatch         *dispatch                   `json:"dispatch,omitempty"`
	NativeDescriptor *service.GatewayNativeRoute `json:"nativeDescriptor,omitempty"`
	LeaseExpiresAt   string                      `json:"leaseExpiresAt,omitempty"`
}

type CleanupLease struct {
	CleanupRef     string `json:"cleanupRef"`
	Worker         string `json:"worker"`
	Token          string `json:"token"`
	LeaseExpiresAt string `json:"leaseExpiresAt"`
}

type cleanupRequest struct {
	Proof   Proof        `json:"proof"`
	Cleanup CleanupLease `json:"cleanup"`
}

// Original-owner closure carries no delegated cleanup lease or dispatch input.
type ownerClosureRequest struct {
	Proof Proof `json:"proof"`
}

func parseInstant(s string) (time.Time, error) {
	if len(s) > 64 || !instant.MatchString(s) || strings.HasPrefix(s, "0000-") {
		return time.Time{}, errDenied
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() {
		return time.Time{}, errDenied
	}
	return t, nil
}

func (a Admission) valid(now time.Time) bool {
	t, err := parseInstant(a.ExpiresAt)
	l := a.Limits
	return err == nil && t.After(now) && identifier.MatchString(a.ExecutionRef) &&
		identifier.MatchString(a.IssuerEpoch) && identifier.MatchString(a.AccountRef) &&
		identifier.MatchString(a.InvocationRef) && identifier.MatchString(a.AttemptRef) && identifier.MatchString(a.SubjectRef) &&
		(a.ProfileID == service.GatewayMiMoResponsesProfile || a.ProfileID == service.GatewayOpenRouterResponsesProfile || a.ProfileID == service.GatewayCodexOAuthResponsesProfile) &&
		a.AuthorizationEpoch >= 0 && a.AuthorizationEpoch <= maxSafeInteger &&
		a.PolicyRevision >= 0 && a.PolicyRevision <= maxSafeInteger && a.BindingRevision >= 0 && a.BindingRevision <= maxSafeInteger &&
		l.Requests >= 1 && l.Requests <= 10000 && l.Concurrency >= 1 && l.Concurrency <= 128 && l.Concurrency <= l.Requests &&
		l.RequestBytes >= 1 && l.RequestBytes <= 4<<20 && l.OutputBytes >= 1 && l.OutputBytes <= 8<<20 && l.Tokens >= 1 && l.Tokens <= 10000000
}

func (p Proof) valid() bool {
	return identifier.MatchString(p.ExecutionRef) && identifier.MatchString(p.RequestRef) && canonicalUUID.MatchString(p.Worker) &&
		identifier.MatchString(p.Token) && identifier.MatchString(p.Native.OriginRef) && identifier.MatchString(p.Native.EngineIncarnation) &&
		canonicalUUID.MatchString(p.Native.Generation) && canonicalUUID.MatchString(p.Native.RequestNonce)
}

// Decode original numbers and names before encoding/json can fold aliases or
// select the last duplicate. Required field shapes come from the private types.
// Payload is intentionally opaque here; only its protocol policy fields are
// inspected separately, leaving tool/user objects and bytes alone.
func strictJSON(data []byte, target any) error {
	if !utf8.Valid(data) || !json.Valid(data) {
		return errDenied
	}
	if err := strictValue(data, reflect.TypeOf(target).Elem(), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return errDenied
	}
	return nil
}

func strictValue(data []byte, typ reflect.Type, depth int) error {
	if depth > 10 {
		return errDenied
	}
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if typ == reflect.TypeOf(time.Time{}) {
		var s string
		if json.Unmarshal(data, &s) != nil {
			return errDenied
		}
		_, err := parseInstant(s)
		return err
	}
	if typ.Kind() == reflect.Int64 {
		if !integerToken.Match(bytes.TrimSpace(data)) {
			return errDenied
		}
		var n int64
		if json.Unmarshal(data, &n) != nil || n > maxSafeInteger {
			return errDenied
		}
		return nil
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errDenied
	}
	seen := make(map[string]bool, typ.NumField())
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return errDenied
		}
		name, ok := t.(string)
		if !ok || seen[name] {
			return errDenied
		}
		seen[name] = true
		var field reflect.StructField
		found := false
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			canonical := strings.Split(f.Tag.Get("json"), ",")[0]
			if strings.EqualFold(name, canonical) {
				if name != canonical {
					return errDenied
				}
				field, found = f, true
				break
			}
		}
		if !found {
			return errDenied
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || strictValue(raw, field.Type, depth+1) != nil {
			return errDenied
		}
	}
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")
		if len(tag) == 1 && !seen[tag[0]] {
			return errDenied
		}
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return errDenied
	}
	if _, err = d.Token(); err != io.EOF {
		return errDenied
	}
	return nil
}

// Preserve every non-cap byte, including custom tools and user input. The
// original cap token must be a canonical positive integer before clamping.
func qualifyPayload(raw []byte, model string, approved, upper int64) ([]byte, error) {
	if _, ok := service.GatewayNativePayloadFields(raw, "model", "store", "stream", "service_tier", "previous_response_id", "max_output_tokens"); !ok {
		return nil, errDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errDenied
	}
	critical := []string{"model", "store", "stream", "service_tier", "previous_response_id", "max_output_tokens"}
	seen := make(map[string]bool)
	capStart, capEnd := -1, -1
	capValue := approved
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, errDenied
		}
		name, ok := t.(string)
		if !ok {
			return nil, errDenied
		}
		start := int(d.InputOffset())
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errDenied
		}
		end := int(d.InputOffset())
		for _, canonical := range critical {
			if !strings.EqualFold(name, canonical) {
				continue
			}
			if name != canonical || seen[canonical] {
				return nil, errDenied
			}
			seen[canonical] = true
			switch canonical {
			case "model", "service_tier":
				var s string
				if json.Unmarshal(value, &s) != nil || (canonical == "model" && s != model) || (canonical == "service_tier" && s != "default") {
					return nil, errDenied
				}
			case "store":
				if string(bytes.TrimSpace(value)) != "false" {
					return nil, errDenied
				}
			case "stream":
				if string(bytes.TrimSpace(value)) != "true" {
					return nil, errDenied
				}
			case "previous_response_id":
				return nil, errDenied
			case "max_output_tokens":
				var n int64
				if !integerToken.Match(value) || json.Unmarshal(value, &n) != nil || n < 1 || n > upper {
					return nil, errDenied
				}
				if n < capValue {
					capValue = n
				}
				// InputOffset after a key precedes ':' and whitespace.
				for start < end && (raw[start] == ':' || raw[start] == ' ' || raw[start] == '\n' || raw[start] == '\r' || raw[start] == '\t') {
					start++
				}
				capStart, capEnd = start, end
			}
		}
	}
	if !seen["model"] || !seen["store"] || !seen["stream"] || !seen["service_tier"] {
		return nil, errDenied
	}
	encoded, _ := json.Marshal(capValue)
	if capStart >= 0 {
		out := append([]byte(nil), raw[:capStart]...)
		out = append(out, encoded...)
		return append(out, raw[capEnd:]...), nil
	}
	end := bytes.LastIndexByte(raw, '}')
	out := append([]byte(nil), raw[:end]...)
	out = append(out, []byte(`,"max_output_tokens":`)...)
	out = append(out, encoded...)
	return append(out, raw[end:]...), nil
}
