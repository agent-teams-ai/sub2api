//go:build unit

package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayNativeTransportFailureReasonClassification(t *testing.T) {
	const private = "PRIVATE_ERROR_TEXT_MUST_NOT_CLASSIFY"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"canceled", context.Canceled, "context_canceled"},
		{"deadline", context.DeadlineExceeded, "context_deadline"},
		{"EOF", io.EOF, "eof"},
		{"unexpected EOF", io.ErrUnexpectedEOF, "unexpected_eof"},
		{"reset", syscall.ECONNRESET, "connection_reset"},
		{"closed", net.ErrClosed, "connection_closed"},
		{"broken pipe", syscall.EPIPE, "broken_pipe"},
		{"refused", syscall.ECONNREFUSED, "connection_refused"},
		{"typed timeout", &net.DNSError{Name: private, IsTimeout: true}, "transport_timeout"},
		{"typed nontimeout", &net.DNSError{Name: private}, "other"},
		{"text counterexample", fmt.Errorf("connection reset unexpected EOF broken pipe: %s", private), "other"},
		{"nil", nil, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err
			if err != nil {
				err = &url.Error{Op: private, URL: "https://private.invalid/" + private, Err: fmt.Errorf("%s: %w", private, err)}
			}
			require.Equal(t, tc.want, gatewayNativeTransportErrorReason(err))
		})
	}
}

// Actual socket events must reach both the existing request trace and the native
// observation. Recording fixed metadata must not replace timing/tracing hooks.
func TestGatewayNativeTransportObservationComposesExistingTrace(t *testing.T) {
	var existingConnections, existingWrites, existingResponses, entries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entries.Add(1)
		_, _ = io.WriteString(w, "synthetic-response")
	}))
	defer server.Close()
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for _, connection := range []string{"new", "reused"} {
		observation := &gatewayNativeTransportObservation{}
		require.Equal(t, "not_obtained", observation.connectionKind())
		require.False(t, observation.requestWritten.Load())
		require.False(t, observation.responseStarted.Load())
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { existingConnections.Add(1) },
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				if info.Err == nil {
					existingWrites.Add(1)
				}
			},
			GotFirstResponseByte: func() { existingResponses.Add(1) },
		})
		request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, observation.trace()), http.MethodPost, server.URL, strings.NewReader("synthetic-input"))
		require.NoError(t, err)
		response, err := client.Do(request)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, connection, observation.connectionKind())
		require.True(t, observation.requestWritten.Load())
		require.True(t, observation.responseStarted.Load())
	}
	require.EqualValues(t, 2, entries.Load())
	require.EqualValues(t, 2, existingConnections.Load())
	require.EqualValues(t, 2, existingWrites.Load())
	require.EqualValues(t, 2, existingResponses.Load())
}
