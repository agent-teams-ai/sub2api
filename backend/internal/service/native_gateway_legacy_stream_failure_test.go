//go:build unit

package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type legacyStreamFailingBody struct {
	io.Reader
	err error
}

func (b legacyStreamFailingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		return n, b.err
	}
	return n, err
}

func (legacyStreamFailingBody) Close() error { return nil }

// A cancelled caller or a broken body used to be reported as sse_incomplete,
// which read as a provider cutting the stream. Each strict stop now carries
// its own closed phase; only an unfinished stream is sse_incomplete.
func TestGatewayNativeLegacyStrictStreamFailureCause(t *testing.T) {
	svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig()}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	body := func(wire string) io.ReadCloser { return io.NopCloser(strings.NewReader(wire)) }
	cases := []struct {
		name string
		ctx  context.Context
		body io.ReadCloser
		line string
	}{
		{"clean EOF without finish", context.Background(), body(nativeReviewCCDelta),
			`{"event":"gateway_native_response_failure","phase":"sse_incomplete"}`},
		{"broken body", context.Background(), legacyStreamFailingBody{strings.NewReader(nativeReviewCCDelta), io.ErrUnexpectedEOF},
			`{"event":"gateway_native_response_failure","phase":"sse_read","read_error_reason":"unexpected_eof"}`},
		{"cancelled caller", cancelled, body(nativeReviewCCDelta),
			`{"event":"gateway_native_response_failure","phase":"sse_read","read_error_reason":"context_canceled"}`},
		{"DONE before finish", context.Background(), body(nativeReviewCCDelta + nativeReviewDone),
			`{"event":"gateway_native_response_failure","phase":"invalid_final"}`},
		{"malformed event", context.Background(), body("data: {not json}\n\n"),
			`{"event":"gateway_native_response_failure","phase":"sse_invalid_event"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/private/native/v1/responses", nil).WithContext(tc.ctx)
			st := svc.scanCCStream(c, &http.Response{Body: tc.body}, "test", "", time.Now(), func(*apicompat.ChatCompletionsChunk) {}, true)
			require.ErrorIs(t, st.Err, ErrGatewayNativeEffectUnknown)
			raw := captureGatewayAdmissionDiagnostic(t, func() {
				require.ErrorIs(t, gatewayNativeLegacyStreamFailure(tc.ctx, st.StrictFailure, st.StrictReadErr), ErrGatewayNativeEffectUnknown)
			})
			require.JSONEq(t, tc.line, string(bytes.TrimSpace(raw)))
		})
	}

	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	raw := captureGatewayAdmissionDiagnostic(t, func() {
		_ = gatewayNativeLegacyStreamFailure(expired, gatewayNativeFailureSSERead, context.DeadlineExceeded)
	})
	require.JSONEq(t, `{"event":"gateway_native_response_failure","phase":"deadline"}`, string(bytes.TrimSpace(raw)))
}
