package service

import (
	"net/url"
	"testing"
)

func TestProxyURLForLogExcludesCredentialsAndSuffixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, want string
	}{
		{"direct", "", ""},
		{"whitespace", " \t ", ""},
		{"endpoint", "http://proxy.example.com:8080", "http://proxy.example.com:8080"},
		{"credentials", "https://proxy-user:proxy-secret@proxy.example.com:8080", "https://proxy.example.com:8080"},
		{"encoded credentials", "socks5://first%20last%40corp:p%40%20ss%3A%23word@socks.example.com:1080", "socks5h://socks.example.com:1080"},
		{"IPv6 and suffixes", "socks5h://user:secret@[2001:db8::1]:1080/private?token=query-secret#fragment-secret", "socks5h://[2001:db8::1]:1080"},
		{"malformed", "http://user:secret@%", "[invalid proxy URL]"},
		{"relative", "user:secret@proxy.example.com", "[invalid proxy URL]"},
		{"unsupported scheme", "ftp://user:secret@proxy.example.com", "[invalid proxy URL]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxyURLForLog(tc.raw); got != tc.want {
				t.Fatalf("unexpected safe proxy endpoint: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestProxyURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy Proxy
		want  string
	}{
		{
			name: "without auth",
			proxy: Proxy{
				Protocol: "http",
				Host:     "proxy.example.com",
				Port:     8080,
			},
			want: "http://proxy.example.com:8080",
		},
		{
			name: "with auth",
			proxy: Proxy{
				Protocol: "socks5",
				Host:     "socks.example.com",
				Port:     1080,
				Username: "user",
				Password: "pass",
			},
			want: "socks5://user:pass@socks.example.com:1080",
		},
		{
			name: "username only keeps no auth for compatibility",
			proxy: Proxy{
				Protocol: "http",
				Host:     "proxy.example.com",
				Port:     8080,
				Username: "user-only",
			},
			want: "http://proxy.example.com:8080",
		},
		{
			name: "with special characters in credentials",
			proxy: Proxy{
				Protocol: "http",
				Host:     "proxy.example.com",
				Port:     3128,
				Username: "first last@corp",
				Password: "p@ ss:#word",
			},
			want: "http://first%20last%40corp:p%40%20ss%3A%23word@proxy.example.com:3128",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.proxy.URL(); got != tc.want {
				t.Fatalf("Proxy.URL() mismatch: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestProxyURL_SpecialCharactersRoundTrip(t *testing.T) {
	t.Parallel()

	proxy := Proxy{
		Protocol: "http",
		Host:     "proxy.example.com",
		Port:     3128,
		Username: "first last@corp",
		Password: "p@ ss:#word",
	}

	parsed, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatalf("parse proxy URL failed: %v", err)
	}
	if got := parsed.User.Username(); got != proxy.Username {
		t.Fatalf("username mismatch after parse: got=%q want=%q", got, proxy.Username)
	}
	pass, ok := parsed.User.Password()
	if !ok {
		t.Fatal("password missing after parse")
	}
	if pass != proxy.Password {
		t.Fatalf("password mismatch after parse: got=%q want=%q", pass, proxy.Password)
	}
}
