//go:build unit

package gatewaytransport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNEWTESTOriginalIntegerAndDecodedEnvelopeNames(t *testing.T) {
	raw, _ := json.Marshal(NEWTESTRequest())
	for _, mutation := range []string{
		strings.Replace(string(raw), `"account_id":7`, `"account_id":7.0`, 1),
		strings.Replace(string(raw), `"account_id":7`, `"account_id":7e0`, 1),
		strings.Replace(string(raw), `"account_id":7`, `"account_id":9007199254740992`, 1),
		strings.Replace(string(raw), `"account_id":7`, `"account_id":7,"account_\u0069d":7`, 1),
		strings.Replace(string(raw), `"issuerEpoch"`, `"IssuerEpoch"`, 1),
		strings.Replace(string(raw), `"subjectRef"`, `"ſubjectRef"`, 1),
		strings.Replace(string(raw), `"tokens":100`, `"tokens":100,"tokens":100`, 1),
		strings.Replace(string(raw), `"policyRevision":4,`, ``, 1),
		strings.Replace(string(raw), `"requestBytes":4096`, `"requestBytes":null`, 1),
	} {
		var r Request
		if strictJSON([]byte(mutation), &r) == nil {
			t.Fatal("ambiguous or noncanonical envelope accepted", mutation)
		}
	}
	canonical := strings.Replace(string(raw), `"account_id"`, `"account_\u0069d"`, 1)
	var r Request
	if strictJSON([]byte(canonical), &r) != nil || r.Descriptor.AccountID != 7 {
		t.Fatal("canonical escaped decoded name denied")
	}
}

func TestNEWTESTPayloadCapsAndOpaqueToolBytes(t *testing.T) {
	base := `{"model":"NEWTESTmodel","store":false,"stream":true,"service_tier":"default","tools":[{"type":"custom","name":"NEWTEST","input":{"Store":true,"max_output_tokens":1.5}}]}`
	out, err := qualifyPayload([]byte(base), "NEWTESTmodel", 100, 200)
	if err != nil || !bytes.Contains(out, []byte(`"max_output_tokens":100`)) || !bytes.Contains(out, []byte(`"input":{"Store":true,"max_output_tokens":1.5}`)) {
		t.Fatal("cap/tool bytes changed", err)
	}
	for _, cap := range []string{"0", "-1", "1.0", "1e2", "201", "null", "\"100\""} {
		in := strings.TrimSuffix(base, "}") + `,"max_output_tokens":` + cap + `}`
		if _, err := qualifyPayload([]byte(in), "NEWTESTmodel", 100, 200); err == nil {
			t.Fatal("invalid original cap accepted", cap)
		}
	}
	for _, field := range []string{`"Max_Output_Tokens":10`, `"max_output_tokens":10,"max_output_\u0074okens":20`, `"Store":false`, `"ſtore":false`, `"stream":true`, `"previous_response_id":null`} {
		if _, err := qualifyPayload([]byte(strings.TrimSuffix(base, "}")+","+field+"}"), "NEWTESTmodel", 100, 200); err == nil {
			t.Fatal("critical alias/duplicate accepted", field)
		}
	}
	for _, tier := range []string{"auto", "priority", "flex"} {
		if _, err := qualifyPayload([]byte(strings.Replace(base, `"default"`, `"`+tier+`"`, 1)), "NEWTESTmodel", 100, 200); err == nil {
			t.Fatal("unapproved tier accepted")
		}
	}
	in := strings.TrimSuffix(base, "}") + `,"max_output_\u0074okens":200}`
	out, err = qualifyPayload([]byte(in), "NEWTESTmodel", 100, 200)
	if err != nil || !bytes.Contains(out, []byte(`"max_output_\u0074okens":100`)) {
		t.Fatal("canonical escaped cap did not clamp", err)
	}
}
