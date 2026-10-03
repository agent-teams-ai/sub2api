package repository

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestGatewayNativeReviewReasoningDomains(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	nativeReviewReasoningDomains(t, NewGatewayCache(client))
}

// Exercise the actual extractor, converter, and backend APIs. The adversarial
// ID is accepted by stock ingestion, so rejecting it would hide the regression.
func nativeReviewReasoningDomains(t *testing.T, ordinary service.GatewayCache) {
	ctx := context.Background()
	managed, ok := ordinary.(service.GatewayNativeReasoningCache)
	require.True(t, ok)
	g1 := "11111111-1111-4111-8111-111111111111"
	g2 := "22222222-2222-4222-8222-222222222222"
	item := "review-item"
	require.NoError(t, managed.SetGatewayNativeReasoningContent(ctx, g1, item, "managed one", time.Minute))
	require.NoError(t, managed.SetGatewayNativeReasoningContent(ctx, g2, item, "managed two", time.Minute))
	aliases := []string{"gateway-native-v1:" + g1 + ":" + item, "gateway_native_reasoning_v1:" + g1 + ":" + item, " " + "gateway-native-v1:" + g1 + ":" + item + ":space "}
	for _, alias := range aliases {
		raw, err := json.Marshal(map[string]any{"type": "reasoning", "id": alias, "summary": []map[string]string{{"type": "summary_text", "text": "ordinary adversary"}}})
		require.NoError(t, err)
		id, text, ok := apicompat.ExtractResponsesReasoningItem(raw)
		require.True(t, ok)
		require.NotEmpty(t, id)
		// Before any ordinary write, an unrestricted ordinary lookup cannot see managed content.
		_, err = ordinary.GetReasoningContent(ctx, id)
		require.ErrorIs(t, err, service.ErrReasoningContentNotFound)
		require.NoError(t, ordinary.SetReasoningContent(ctx, id, text, time.Minute))
		got, err := ordinary.GetReasoningContent(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "ordinary adversary", got)
	}
	for _, pair := range []struct{ g, want string }{{g1, "managed one"}, {g2, "managed two"}} {
		got, err := managed.GetGatewayNativeReasoningContent(ctx, pair.g, item)
		require.NoError(t, err)
		require.Equal(t, pair.want, got)
		input := json.RawMessage(`[{"type":"reasoning","id":"review-item","summary":[],"encrypted_content":"opaque"},{"type":"function_call","call_id":"call","name":"fixture","arguments":"{}"},{"type":"function_call_output","call_id":"call","output":"fixture"}]`)
		out, err := apicompat.ResponsesToChatCompletionsRequestWithOptions(&apicompat.ResponsesRequest{Model: "mimo-test", Input: input}, &apicompat.ResponsesToChatOptions{ReasoningContentByID: func(id string) string {
			v, e := managed.GetGatewayNativeReasoningContent(ctx, pair.g, id)
			require.NoError(t, e)
			return v
		}})
		require.NoError(t, err)
		require.NotEmpty(t, out.Messages)
		require.Equal(t, pair.want, out.Messages[0].ReasoningContent)
	}
	// Historical ordinary encrypted-only roundtrip remains available.
	require.NoError(t, ordinary.SetReasoningContent(ctx, item, "ordinary baseline", time.Minute))
	input := json.RawMessage(`[{"type":"reasoning","id":"review-item","summary":[],"encrypted_content":"opaque"},{"type":"function_call","call_id":"call","name":"fixture","arguments":"{}"},{"type":"function_call_output","call_id":"call","output":"fixture"}]`)
	out, err := apicompat.ResponsesToChatCompletionsRequestWithOptions(&apicompat.ResponsesRequest{Model: "mimo-test", Input: input}, &apicompat.ResponsesToChatOptions{ReasoningContentByID: func(id string) string { v, e := ordinary.GetReasoningContent(ctx, id); require.NoError(t, e); return v }})
	require.NoError(t, err)
	require.NotEmpty(t, out.Messages)
	require.Equal(t, "ordinary baseline", out.Messages[0].ReasoningContent)
}
