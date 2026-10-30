// Package wsnetpolicy applies the enabled upstream URL policy to WebSocket handshakes.
package wsnetpolicy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/Wei-Shaw/sub2api/internal/util/urlvalidator"
)

type trustedHostKey struct{}

// Policy is immutable after construction, apart from the unexported test dial seams.
type Policy struct {
	hosts        []string
	allowPrivate bool
	lookup       func(context.Context, string) ([]net.IPAddr, error)
	dial         func(context.Context, string, string) (net.Conn, error)
}

func New(hosts []string, allowPrivate bool) *Policy {
	return &Policy{hosts: append([]string(nil), hosts...), allowPrivate: allowPrivate,
		lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
}

// PrepareDial binds an official-host exception to this initial destination only.
// Custom relays do not gain permission to redirect to unrelated official hosts.
func (p *Policy) PrepareDial(ctx context.Context, raw string) (context.Context, error) {
	u, err := parseURL(raw)
	if err != nil {
		return ctx, err
	}
	host := strings.ToLower(u.Hostname())
	trusted := ""
	if host == "chatgpt.com" || xai.IsOfficialBaseURLHost(host) {
		trusted = host
	}
	ctx = context.WithValue(ctx, trustedHostKey{}, trusted)
	return ctx, p.validate(ctx, u)
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, errors.New("WebSocket URL rejected by security policy")
	}
	if u.Scheme != "wss" && u.Scheme != "https" {
		return nil, errors.New("WebSocket URL requires HTTPS or WSS")
	}
	return u, nil
}

func (p *Policy) validate(ctx context.Context, u *url.URL) error {
	if u == nil {
		return errors.New("WebSocket URL rejected by security policy")
	}
	checked, err := parseURL(u.String())
	if err != nil {
		return err
	}
	if !p.allowPrivate && strings.Contains(checked.Hostname(), "%") {
		return errors.New("WebSocket URL rejected by security policy")
	}
	hosts := p.hosts
	if trusted, _ := ctx.Value(trustedHostKey{}).(string); trusted != "" && strings.EqualFold(checked.Hostname(), trusted) {
		hosts = append(append([]string(nil), hosts...), trusted)
	}
	checked.Scheme = "https" // Validation only; preserve the actual path, query and WS URL.
	if _, err := urlvalidator.ValidateHTTPSURL(checked.String(), urlvalidator.ValidationOptions{
		AllowedHosts: hosts, RequireAllowlist: true, AllowPrivate: p.allowPrivate,
	}); err != nil {
		return errors.New("WebSocket URL rejected by security policy")
	}
	return nil
}

type checkedTransport struct {
	policy    *Policy
	transport *http.Transport
}

func (t *checkedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.validate(req.Context(), req.URL); err != nil {
		return nil, err
	}
	return t.transport.RoundTrip(req)
}

func (t *checkedTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }

// WrapClient preserves a client's credential-specific transport/cache identity.
// Call it once when creating that client, rather than creating a new pool per dial.
func (p *Policy) WrapClient(base *http.Client) (*http.Client, error) {
	if base == nil {
		return nil, errors.New("WebSocket HTTP client is unavailable")
	}
	roundTripper := base.Transport
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	original, ok := roundTripper.(*http.Transport)
	if !ok || original == nil {
		return nil, errors.New("WebSocket transport cannot enforce URL security policy")
	}
	transport := original.Clone()
	if !p.allowPrivate {
		// Start fresh so custom TLS hooks and registered alternate protocols cannot
		// bypass the guarded dial. Retain ordinary TLS trust and timeout/pool settings.
		transport = &http.Transport{
			DialContext:     p.dialPublic,
			TLSClientConfig: original.TLSClientConfig, TLSHandshakeTimeout: original.TLSHandshakeTimeout,
			DisableKeepAlives: original.DisableKeepAlives, DisableCompression: original.DisableCompression,
			MaxIdleConns: original.MaxIdleConns, MaxIdleConnsPerHost: original.MaxIdleConnsPerHost,
			MaxConnsPerHost: original.MaxConnsPerHost, IdleConnTimeout: original.IdleConnTimeout,
			ResponseHeaderTimeout: original.ResponseHeaderTimeout, ExpectContinueTimeout: original.ExpectContinueTimeout,
			MaxResponseHeaderBytes: original.MaxResponseHeaderBytes, WriteBufferSize: original.WriteBufferSize,
			ReadBufferSize: original.ReadBufferSize,
			TLSNextProto:   make(map[string]func(string, *tls.Conn) http.RoundTripper),
		}
		if original.TLSClientConfig != nil {
			transport.TLSClientConfig = original.TLSClientConfig.Clone()
			transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
	}
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		var proxy *url.URL
		if original.Proxy != nil {
			var err error
			proxy, err = original.Proxy(req)
			if err != nil {
				return nil, errors.New("WebSocket proxy selection failed")
			}
		}
		// A custom proxy callback may mutate the destination; check after it runs.
		if err := p.validate(req.Context(), req.URL); err != nil {
			return nil, err
		}
		if proxy != nil && !p.allowPrivate {
			return nil, errors.New("WebSocket proxy DNS cannot enforce private-host policy")
		}
		return proxy, nil
	}
	client := *base
	client.Transport = &checkedTransport{policy: p, transport: transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 WebSocket redirects")
		}
		if base.CheckRedirect != nil {
			if err := base.CheckRedirect(req, via); err != nil {
				return err
			}
		}
		return p.validate(req.Context(), req.URL)
	}
	return &client, nil
}

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

func prohibitedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return !ok || !ip.IsGlobalUnicast() || urlvalidator.IsBlockedHost(ip.String()) || carrierGradeNAT.Contains(addr.Unmap())
}

func (p *Policy) dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.Contains(host, "%") {
		return nil, errors.New("WebSocket dial address rejected by security policy")
	}
	var addresses []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		addresses = []net.IPAddr{{IP: ip}}
	} else {
		addresses, err = p.lookup(ctx, host)
		if err != nil || len(addresses) == 0 {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("WebSocket destination DNS resolution failed")
		}
	}
	for _, address := range addresses {
		if address.Zone != "" || prohibitedIP(address.IP) {
			return nil, errors.New("WebSocket destination resolves to a prohibited private or special address")
		}
	}
	for _, address := range addresses {
		// Dial the checked numeric IP, never the hostname, to avoid DNS rebinding.
		var conn net.Conn
		conn, err = p.dial(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}
