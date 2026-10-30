package proxyurl

import "testing"

func TestForLogExcludesCredentialsAndSuffixes(t *testing.T) {
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
			if got := ForLog(tc.raw); got != tc.want {
				t.Fatalf("unexpected safe proxy endpoint: got=%q want=%q", got, tc.want)
			}
		})
	}
}
