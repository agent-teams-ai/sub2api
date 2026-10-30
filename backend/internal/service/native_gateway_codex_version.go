package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const gatewayCodexLatestReleaseURL = "https://api.github.com/repos/openai/codex/releases/latest"

// Private discovery shares the normal app's stable-release policy, without its
// settings writer, updater credentials or download client. Reads are lazy and
// coalesced; force refresh has a one-minute cooldown even on release failures.
type GatewayCodexVersionResolver struct {
	mu                    sync.Mutex
	client                *http.Client
	version               string
	attempted, freshUntil time.Time
	pending               chan struct{}
	now                   func() time.Time
}

func NewGatewayCodexVersionResolver(transport http.RoundTripper) *GatewayCodexVersionResolver {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, DisableKeepAlives: true}
	}
	return &GatewayCodexVersionResolver{client: &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGatewayNativeIdentity }}, version: CodexCanonicalClientVersion(), now: time.Now}
}
func (s *GatewayCodexVersionResolver) CanonicalUserAgent() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return buildCodexCLIUserAgent(s.version)
}
func (s *GatewayCodexVersionResolver) Refresh(ctx context.Context, force bool) {
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	s.mu.Lock()
	if pending := s.pending; pending != nil {
		s.mu.Unlock()
		select {
		case <-pending:
		case <-bounded.Done():
		}
		return
	}
	now := s.now()
	if !s.attempted.IsZero() && now.Sub(s.attempted) < time.Minute || !force && now.Before(s.freshUntil) {
		s.mu.Unlock()
		return
	}
	s.attempted = now
	s.pending = make(chan struct{})
	s.mu.Unlock()
	version := s.fetch(bounded)
	s.mu.Lock()
	defer s.mu.Unlock()
	if version != "" {
		if CompareVersions(version, s.version) > 0 {
			s.version = version
		}
		s.freshUntil = s.now().Add(openAICodexVersionSyncInterval)
	}
	close(s.pending)
	s.pending = nil
}
func (s *GatewayCodexVersionResolver) fetch(ctx context.Context) string {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, gatewayCodexLatestReleaseURL, nil)
	if err != nil {
		return ""
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "ReviewRouter/native-codex-version")
	response, err := s.client.Do(request)
	if err != nil {
		return ""
	}
	if response.Body == nil {
		return ""
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.String() != gatewayCodexLatestReleaseURL {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return ""
	}
	fields, ok := GatewayNativePayloadFields(raw, "tag_name", "draft", "prerelease")
	if !ok {
		return ""
	}
	var release GitHubRelease
	if json.Unmarshal(fields["tag_name"], &release.TagName) != nil {
		return ""
	}
	for name, dst := range map[string]*bool{"draft": &release.Draft, "prerelease": &release.Prerelease} {
		if string(fields[name]) != "true" && string(fields[name]) != "false" || json.Unmarshal(fields[name], dst) != nil {
			return ""
		}
	}
	return latestCodexStableReleaseVersion([]*GitHubRelease{&release})
}
