//go:build linux

package gatewaybootstrap

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Exercise the production constructor over real HTTP. Even a client that asks
// for keepalive must see close on the wire and use a fresh socket next time.
func TestPublicHTTPServerClosesEachConnection(t *testing.T) {
	var handled atomic.Int32
	server := newPublicHTTPServer(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		handled.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-served:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(time.Second):
			t.Error("public server did not stop")
		}
	})

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = io.WriteString(conn, "POST /v1/responses HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	wire, err := io.ReadAll(io.LimitReader(conn, 4097))
	require.NoError(t, err, "server must close after the response without waiting for its idle timeout")
	require.LessOrEqual(t, len(wire), 4096)
	headers, body, found := strings.Cut(string(wire), "\r\n\r\n")
	require.True(t, found)
	require.Contains(t, strings.ToLower(headers+"\r\n"), "\r\nconnection: close\r\n")
	require.JSONEq(t, `{"ok":true}`, body)

	// Keep client pooling enabled: the server alone must prevent stale reuse.
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: time.Minute}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	traces := make(chan httptrace.GotConnInfo, 4)
	var previous net.Conn
	for range 3 {
		request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/v1/responses", strings.NewReader("{}"))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { traces <- info },
		}))
		response, err := client.Do(request)
		require.NoError(t, err)
		data, err := io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.True(t, response.Close, "client must observe the server's close policy")
		require.JSONEq(t, `{"ok":true}`, string(data))
		trace := <-traces
		require.False(t, trace.Reused, "public inference must never reuse a pooled connection")
		require.False(t, previous == trace.Conn, "each request must own a different connection")
		previous = trace.Conn
	}
	require.Equal(t, int32(4), handled.Load(), "one handler invocation per request")
	require.Empty(t, traces, "no transparent transport retry")
}
