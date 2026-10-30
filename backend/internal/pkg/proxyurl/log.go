package proxyurl

// ForLog preserves the proxy endpoint without credentials or URL suffixes.
func ForLog(raw string) string {
	_, parsed, err := Parse(raw)
	if err != nil {
		return "[invalid proxy URL]"
	}
	if parsed == nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
