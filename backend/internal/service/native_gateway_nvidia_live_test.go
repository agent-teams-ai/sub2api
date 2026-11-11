//go:build unit && nvidia_live

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Explicit, never-on-default-CI synthetic canary. The key is read exclusively
// from the disposable sandbox Actions secret. It is sealed before entering the
// native route and never printed, persisted, or sent to any other URL.
func TestGatewayNVIDIABuildLiveProtectedStreamingToolReplay(t *testing.T) {
	key := os.Getenv("NVIDIA_API_KEY")
	if key == "" {
		t.Fatal("disposable NVIDIA_API_KEY Actions secret required")
	}
	gin.SetMode(gin.TestMode)
	a := &Account{
		ID: 17, CreatedAt: time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC),
		Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
		Credentials: map[string]any{"api_key": key, "base_url": GatewayNVIDIABuildBaseURL},
		Extra: map[string]any{
			GatewayGenerationExtraKey: "12345678-1234-4234-8234-123456789abc",
			GatewayProfileExtraKey: GatewayNVIDIABuildChatProfile,
			GatewayModelExtraKey: GatewayNVIDIABuildAnchorModel,
			"openai_responses_mode": "force_chat_completions",
			"openai_passthrough": false,
			"native_api_key_cancel_on_disconnect": true,
			"openai_preserve_compatible_reasoning": true,
		},
	}
	nativeFixtureSealAccount(t, a)
	route, err := GatewayNativeDescriptor(a)
	if err != nil { t.Fatal("native descriptor denied") }
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	svc := &OpenAIGatewayService{
		accountRepo: &gatewayIdentityRepoFixture{row:a},
		httpUpstream: &gatewayIdentityRealHTTP{client: client},
		cfg: rawChatCompletionsTestConfig(),
	}
	tool := map[string]any{
		"type":"function", "name":"echo_status", "description":"Return synthetic status",
		"parameters": map[string]any{
			"type":"object", "properties":map[string]any{"item":map[string]any{"type":"string"}},
			"required":[]string{"item"}, "additionalProperties":false,
		},
	}
	call := func(input any, choice any) (string, bool, bool) {
		t.Helper()
		payload, e := json.Marshal(map[string]any{
			"model":GatewayNVIDIABuildAnchorModel, "store":false, "stream":true,
			"max_output_tokens":192, "input":input, "tools":[]any{tool}, "tool_choice":choice,
		})
		if e != nil { t.Fatal("synthetic payload encode failed") }
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", bytes.NewReader(payload))
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		defer cancel()
		_, entered, forwardErr := svc.ForwardGatewayRoute(nativeFixtureContext(t, ctx), c, route, payload)
		if forwardErr != nil || !entered {
			t.Fatalf("NVIDIA protected request failed (entered=%t; no upstream response content retained)", entered)
		}
		body := rec.Body.String()
		return body, strings.Contains(body, "response.completed"), strings.Contains(body, "[DONE]")
	}
	question := "Synthetic only: call echo_status with item alpha; then summarize the returned status."
	first, completed, done := call(question,map[string]any{"type":"function","name":"echo_status"})
	if !completed || !done { t.Fatal("native first streamed tool response lacks complete terminal") }
	var callID, arguments string
	scanner := bufio.NewScanner(strings.NewReader(first))
	scanner.Buffer(make([]byte,4096),1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line,"data:") { continue }
		raw := strings.TrimSpace(strings.TrimPrefix(line,"data:"))
		if raw=="[DONE]" || raw=="" { continue }
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type string `json:"type"`
				Name string `json:"name"`
				CallID string `json:"call_id"`
				Arguments string `json:"arguments"`
			} `json:"item"`
		}
		if json.Unmarshal([]byte(raw),&event)==nil &&
			event.Type=="response.output_item.done" && event.Item.Type=="function_call" &&
			event.Item.Name=="echo_status" {
			callID,arguments=event.Item.CallID,event.Item.Arguments
		}
	}
	if scanner.Err()!=nil { t.Fatal("native SSE parse failed") }
	var args struct { Item string `json:"item"` }
	if callID=="" || len(callID)>128 || json.Unmarshal([]byte(arguments),&args)!=nil || args.Item!="alpha" {
		t.Fatal("native tool identity or argument roundtrip failed")
	}
	secondInput:=[]any{
		map[string]any{"role":"user","content":question},
		map[string]any{"type":"function_call","name":"echo_status","call_id":callID,"arguments":arguments},
		map[string]any{"type":"function_call_output","call_id":callID,"output":`{"status":"ok"}`},
	}
	second, secondComplete, secondDone:=call(secondInput,"none")
	if !secondComplete || !secondDone ||
		(!strings.Contains(second,"response.output_text.delta") && !strings.Contains(second,"response.output_text.done")) {
		t.Fatal("native tool replay did not produce a complete synthetic answer")
	}
	// No full text, prompt, key or provider headers are printed.
	t.Log("NVIDIA protected Responses-to-Chat streaming tool and next-turn continuation passed (2 entries)")
}
