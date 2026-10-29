package gatewaybootstrap

import (
	"encoding/json"
	"strings"
	"testing"
)

// Public inference is opt-in and cannot accidentally share the private control
// listener or inherit an unbounded number of long-lived streams.
func TestPublicInferenceConfigurationIsExplicitAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name, address string
		active        int64
		valid         bool
	}{
		{"disabled", "", 0, true},
		{"enabled", "127.0.0.1:18083", 1024, true},
		{"ipv6", "[::1]:18083", 2048, true},
		{"missing budget", "127.0.0.1:18083", 0, false},
		{"budget without listener", "", 16, false},
		{"over ceiling", "127.0.0.1:18083", 2049, false},
		{"private collision", "127.0.0.1:18081", 16, false},
		{"wildcard", "0.0.0.0:18083", 16, false},
		{"alias", "localhost:18083", 16, false},
		{"noncanonical port", "127.0.0.1:018083", 16, false},
		{"ephemeral port", "127.0.0.1:0", 16, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureConfig()
			c.PublicListenAddress, c.PublicMaxActive = tc.address, tc.active
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err := decodeStrict(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			_, err = decoded.validate()
			if (err == nil) != tc.valid {
				t.Fatalf("configuration valid=%v, want %v", err == nil, tc.valid)
			}
		})
	}
	c := fixtureConfig()
	c.PublicListenAddress, c.PublicMaxActive = "127.0.0.1:18083", 16
	raw, _ := json.Marshal(c)
	for _, malformed := range []string{
		strings.Replace(string(raw), `"publicMaxActive":16`, `"publicMaxActive":16.0`, 1),
		strings.Replace(string(raw), `"publicMaxActive":16`, `"publicMaxActive":16,"publicMaxActive":16`, 1),
		strings.Replace(string(raw), `"publicListenAddress":`, `"PublicListenAddress":`, 1),
	} {
		var decoded Config
		if decodeStrict([]byte(malformed), &decoded) == nil {
			t.Fatal("ambiguous public authority configuration accepted")
		}
	}
}
