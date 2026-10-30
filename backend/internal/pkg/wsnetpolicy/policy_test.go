package wsnetpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coderws "github.com/coder/websocket"
	"golang.org/x/net/http/httpproxy"
)

func TestTargetPolicyAndScopedOfficialExceptions(t *testing.T) {
	p := New([]string{"relay.example"}, false)
	for _, raw := range []string{"wss://relay.example/v1?model=x", "https://relay.example/v1", "wss://chatgpt.com/backend-api/codex/responses", "wss://us-east.api.x.ai/v1/realtime"} {
		if _, err := p.PrepareDial(context.Background(), raw); err != nil {
			t.Fatalf("permitted target rejected: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{"ws://relay.example/v1", "http://relay.example/v1", "wss://blocked.example", "wss://user:secret@relay.example", "wss://relay.example:0", "wss://relay.example/#fragment", "wss://[fe80::1%25eth0]"} {
		if _, err := p.PrepareDial(context.Background(), raw); err == nil {
			t.Fatalf("unsafe target accepted: %s", raw)
		}
	}
	ctx, _ := p.PrepareDial(context.Background(), "wss://chatgpt.com/path")
	for _, raw := range []string{"https://chatgpt.com/next", "https://relay.example/next"} {
		u, _ := url.Parse(raw)
		if err := p.validate(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, initial := range []string{"wss://relay.example", "wss://api.x.ai"} {
		ctx, _ := p.PrepareDial(context.Background(), initial)
		u, _ := url.Parse("https://chatgpt.com/next")
		if err := p.validate(ctx, u); err == nil {
			t.Fatal("unrelated official host gained a redirect exception")
		}
	}
}

func TestPublicDialPinsCheckedIPsAndRejectsMixedAnswers(t *testing.T) {
	for _, blocked := range []string{"127.0.0.1", "10.0.0.1", "::ffff:192.168.1.1", "169.254.169.254", "fe80::1", "::", "224.0.0.1", "255.255.255.255", "100.100.100.200"} {
		t.Run(blocked, func(t *testing.T) {
			p := New(nil, false)
			p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}, {IP: net.ParseIP(blocked)}}, nil
			}
			p.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("a mixed DNS answer reached the socket dial")
				return nil, errors.New("unexpected dial")
			}
			if _, err := p.dialPublic(context.Background(), "tcp", "relay.example:443"); err == nil {
				t.Fatal("prohibited DNS answer accepted")
			}
		})
	}
	p := New(nil, false)
	lookups := 0
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups > 1 {
			t.Fatal("hostname was resolved again after validation")
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}, nil
	}
	stop := errors.New("socket fixture")
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "203.0.113.8:443" {
			t.Fatalf("checked IP was not pinned: %s %s", network, address)
		}
		return nil, stop
	}
	if _, err := p.dialPublic(context.Background(), "tcp", "relay.example:443"); !errors.Is(err, stop) || lookups != 1 {
		t.Fatalf("unexpected direct dial result: %v, lookups=%d", err, lookups)
	}
}

func TestEffectiveEnvironmentProxyAndPrivateHostOptIn(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://user:secret@proxy.example:8080")
	t.Setenv("NO_PROXY", "direct.example")
	t.Setenv("https_proxy", "http://user:secret@proxy.example:8080")
	t.Setenv("no_proxy", "direct.example")
	for _, allowPrivate := range []bool{false, true} {
		p := New([]string{"relay.example", "direct.example"}, allowPrivate)
		proxyFunc := httpproxy.FromEnvironment().ProxyFunc()
		calls := 0
		client, err := p.WrapClient(&http.Client{Transport: &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			calls++
			return proxyFunc(req.URL)
		}}})
		if err != nil {
			t.Fatal(err)
		}
		checked, ok := client.Transport.(*checkedTransport)
		if !ok {
			t.Fatal("policy transport was not installed")
		}
		for _, host := range []string{"relay.example", "direct.example"} {
			ctx, _ := p.PrepareDial(context.Background(), "wss://"+host)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host, nil)
			proxy, err := checked.transport.Proxy(req)
			if host == "direct.example" {
				if err != nil || proxy != nil {
					t.Fatal("NO_PROXY direct selection changed", proxy, err)
				}
			} else if allowPrivate {
				if err != nil || proxy == nil || proxy.User == nil {
					t.Fatal("permitted proxy credentials/path changed", proxy, err)
				}
			} else if err == nil || proxy != nil {
				t.Fatal("unverifiable effective proxy was accepted")
			}
		}
		if calls != 2 {
			t.Fatalf("proxy callback must run once per request, got %d", calls)
		}
	}
}

type opaqueTransport struct{}

func (opaqueTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("must not run") }

func TestCustomDialHooksAndOpaqueTransportsCannotBypassPolicy(t *testing.T) {
	p := New([]string{"relay.example"}, false)
	if _, err := p.WrapClient(&http.Client{Transport: opaqueTransport{}}); err == nil {
		t.Fatal("opaque transport accepted")
	}
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	unexpected := func() { t.Error("custom dial hook bypassed policy") }
	base := &http.Transport{
		Dial: func(string, string) (net.Conn, error) { unexpected(); return nil, errors.New("fixture") }, //nolint:staticcheck // Intentionally exercise the deprecated hook as bypass regression coverage.
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			unexpected()
			return nil, errors.New("fixture")
		},
		DialTLS: func(string, string) (net.Conn, error) { unexpected(); return nil, errors.New("fixture") }, //nolint:staticcheck // Intentionally exercise the deprecated hook as bypass regression coverage.
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			unexpected()
			return nil, errors.New("fixture")
		},
	}
	client, err := p.WrapClient(&http.Client{Transport: base})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := p.PrepareDial(context.Background(), "wss://relay.example")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.example", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("private destination reached transport")
	}
}

func TestRedirectsAndMutatingCallbacksAreValidatedBeforeNetwork(t *testing.T) {
	for _, redirect := range []string{"https://blocked.example/finish", "http://allowed.example/finish", "https://allowed.example/finish"} {
		t.Run(redirect, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Redirect(w, r, redirect, http.StatusFound)
			}))
			defer server.Close()
			original, ok := server.Client().Transport.(*http.Transport)
			if !ok {
				t.Fatal("fixture transport is unavailable")
			}
			transport := original.Clone()
			transport.TLSClientConfig.ServerName = "127.0.0.1"
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			base := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if strings.Contains(redirect, "https://allowed.example") {
					req.URL.Host = "blocked.example"
				}
				return nil
			}}
			p := New([]string{"allowed.example"}, true)
			client, err := p.WrapClient(base)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			ctx, _ := p.PrepareDial(context.Background(), "wss://allowed.example/start")
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://allowed.example/start", nil)
			if _, err := client.Do(req); err == nil {
				t.Fatal("forbidden redirect accepted")
			}
			if requests.Load() != 1 {
				t.Fatalf("redirect destination received %d requests", requests.Load()-1)
			}
		})
	}
}

func TestProxyCallbackMutationIsRechecked(t *testing.T) {
	p := New([]string{"relay.example"}, true)
	client, err := p.WrapClient(&http.Client{Transport: &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) { req.URL.Host = "blocked.example"; return nil, nil },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("mutated destination reached dial")
			return nil, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := p.PrepareDial(context.Background(), "wss://relay.example")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.example", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("mutating proxy callback escaped URL policy")
	}
}

func TestPublicOnlyWebSocketHandshakeRetainsTLSAndRequestIdentity(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS.ServerName != "example.com" || r.Host != "example.com" || r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Errorf("original TLS/HTTP identity changed: SNI=%q host=%q auth=%q", r.TLS.ServerName, r.Host, r.Header.Get("Authorization"))
			http.Error(w, "identity changed", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/socket/a%2Fb?model=gpt%2Ftest&x=1", http.StatusFound)
			return
		}
		if r.RequestURI != "/socket/a%2Fb?model=gpt%2Ftest&x=1" {
			t.Errorf("escaped request path/query changed: %q", r.RequestURI)
		}
		conn, err := coderws.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.CloseNow() }()
		kind, payload, err := conn.Read(r.Context())
		if err != nil || kind != coderws.MessageText || string(payload) != "hello" {
			t.Errorf("WebSocket read failed: %s %v", payload, err)
			return
		}
		if err := conn.Write(r.Context(), coderws.MessageText, []byte("world")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	p := New([]string{"example.com"}, false)
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}, nil
	}
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "203.0.113.8:443" {
			t.Errorf("dial was not pinned to checked IP: %q", address)
		}
		// Only the fixture substitutes the local listener for the checked public IP.
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client, err := p.WrapClient(server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx, err = p.PrepareDial(ctx, "wss://example.com/start")
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := coderws.Dial(ctx, "wss://example.com/start", &coderws.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer fixture-secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	if err := conn.Write(ctx, coderws.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, payload, err := conn.Read(ctx)
	if err != nil || string(payload) != "world" {
		t.Fatalf("WebSocket exchange failed: %s %v", payload, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("expected allowed redirect and upgrade, got %d requests", requests.Load())
	}
}
