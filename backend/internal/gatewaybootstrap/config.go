// Package gatewaybootstrap composes only the opt-in private native engine.
package gatewaybootstrap

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var ErrDenied = errors.New("private native bootstrap denied")

const configBytes = 64 * 1024

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var incarnation = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var bearer = regexp.MustCompile(`^[A-Za-z0-9._~+/-]{16,}=*$`)
var integer = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Config is decoded only from inherited FD 6. It has no CLI/env representation,
// provider credential, migration option, discovery or insecure-TLS switch.
type Config struct {
	ListenAddress string          `json:"listenAddress"`
	PostgresDSN   string          `json:"postgresDSN"`
	Authority     AuthorityConfig `json:"authority"`
	Custody       CustodyConfig   `json:"custody"`
	Peers         []ControlPeer   `json:"peers"`
	Profile       ProfileConfig   `json:"profile"`
	MaxEntries    int64           `json:"maxEntries"`
	OAuth         *OAuthConfig    `json:"oauth,omitempty"`
	OpenRouter    *ProfileConfig  `json:"openRouter,omitempty"`
}

// The optional OAuth key is separate from custody, inherited in protected FD6,
// never env/CLI. Its required profile has independent qualification and bounds;
// neither optional tuple inherits the primary MiMo qualification or limits.
type OAuthConfig struct {
	IntentKey string        `json:"intentKey"`
	Profile   ProfileConfig `json:"profile"`
}

type AuthorityConfig struct {
	Origin     string `json:"origin"`
	Credential string `json:"credential"`
}
type CustodyConfig struct {
	ActiveKeyID string       `json:"activeKeyId"`
	Keys        []CustodyKey `json:"keys"`
}
type CustodyKey struct {
	ID  string `json:"id"`
	Key string `json:"key"` // canonical standard base64 of 32 server-only bytes
}
type ControlPeer struct {
	ConsumerID string `json:"consumerId"`
	Role       string `json:"role"`
	Credential string `json:"credential"`
}
type ProfileConfig struct {
	Model                   string `json:"model"`
	BaseURL                 string `json:"baseURL"`
	QualificationRef        string `json:"qualificationRef"`
	RequestBytes            int64  `json:"requestBytes"`
	OutputBytes             int64  `json:"outputBytes"`
	Tokens                  int64  `json:"tokens"`
	ProviderTokenUpperBound int64  `json:"providerTokenUpperBound"`
}

func (p ProfileConfig) qualified() gatewaytransport.QualifiedProfile {
	return gatewaytransport.QualifiedProfile{Profile: service.GatewayMiMoResponsesProfile, Model: p.Model, BaseURL: p.BaseURL,
		QualificationRef: p.QualificationRef, RequestBytes: p.RequestBytes, OutputBytes: p.OutputBytes,
		Tokens: p.Tokens, ProviderTokenUpperBound: p.ProviderTokenUpperBound}
}

// Independent strict server-config/ACK boundary: every member is required, with
// decoded exact names, no duplicate/unknown members, canonical integer tokens,
// bounded depth, valid UTF-8 and no lossy replacement of escaped surrogates.
func decodeStrict(data []byte, target any) error {
	if len(data) > configBytes || !utf8.Valid(data) || !json.Valid(data) || checkValue(data, reflect.TypeOf(target).Elem(), 0) != nil {
		return ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrDenied
	}
	return nil
}
func checkValue(raw []byte, typ reflect.Type, depth int) error {
	if depth > 8 {
		return ErrDenied
	}
	switch typ.Kind() {
	case reflect.Struct:
		d := json.NewDecoder(bytes.NewReader(raw))
		t, err := d.Token()
		if err != nil || t != json.Delim('{') {
			return ErrDenied
		}
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			name, ok := t.(string)
			if err != nil || !ok || seen[name] {
				return ErrDenied
			}
			seen[name] = true
			var field reflect.Type
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if name == strings.Split(f.Tag.Get("json"), ",")[0] {
					field = f.Type
					break
				}
			}
			var value json.RawMessage
			if field == nil || d.Decode(&value) != nil || checkValue(value, field, depth+1) != nil {
				return ErrDenied
			}
		}
		required := typ.NumField()
		for i := 0; i < typ.NumField(); i++ {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")
			if len(tag) == 2 && tag[1] == "omitempty" && !seen[tag[0]] {
				required--
			}
		}
		if len(seen) != required {
			return ErrDenied
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('}') {
			return ErrDenied
		}
		if _, err = d.Token(); err != io.EOF {
			return ErrDenied
		}
	case reflect.Pointer:
		if (typ != reflect.TypeOf((*OAuthConfig)(nil)) && typ != reflect.TypeOf((*ProfileConfig)(nil))) || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrDenied
		}
		return checkValue(raw, typ.Elem(), depth+1)
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > 128 {
			return ErrDenied
		}
		for _, value := range values {
			if checkValue(value, typ.Elem(), depth+1) != nil {
				return ErrDenied
			}
		}
	case reflect.Int64:
		var n int64
		if !integer.Match(bytes.TrimSpace(raw)) || json.Unmarshal(raw, &n) != nil || n > 9007199254740991 {
			return ErrDenied
		}
	case reflect.String:
		var s string
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &s) != nil || strings.ContainsRune(s, utf8.RuneError) {
			return ErrDenied
		}
	case reflect.Bool:
		if string(bytes.TrimSpace(raw)) != "true" && string(bytes.TrimSpace(raw)) != "false" {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

func fixedOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && len(origin) <= 2048 && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" &&
		(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))
}
func (c Config) validate() (*service.GatewayNativeCredentialCustody, error) {
	host, port, err := net.SplitHostPort(c.ListenAddress)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || (host != "127.0.0.1" && host != "::1") || !integer.MatchString(port) || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		c.PostgresDSN == "" || len(c.PostgresDSN) > 8192 || strings.ContainsRune(c.PostgresDSN, 0) || !fixedOrigin(c.Authority.Origin) ||
		!bearer.MatchString(c.Authority.Credential) || len(c.Authority.Credential) > 2048 || c.MaxEntries < 1 || c.MaxEntries > 10000 ||
		len(c.Peers) < 1 || len(c.Peers) > 128 || len(c.Custody.Keys) < 1 || len(c.Custody.Keys) > 32 {
		return nil, ErrDenied
	}
	keys := map[string][]byte{}
	for _, k := range c.Custody.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(k.Key)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != k.Key || keys[k.ID] != nil {
			return nil, ErrDenied
		}
		keys[k.ID] = key
	}
	adapter, err := service.NewGatewayNativeCredentialCustody(c.Custody.ActiveKeyID, keys)
	if err != nil {
		return nil, ErrDenied
	}
	seen := map[string]bool{c.Authority.Credential: true}
	for _, p := range c.Peers {
		if !identifier.MatchString(p.ConsumerID) || (p.Role != "management" && p.Role != "execution" && p.Role != "cleanup") ||
			!bearer.MatchString(p.Credential) || len(p.Credential) > 2048 || seen[p.Credential] {
			return nil, ErrDenied
		}
		seen[p.Credential] = true
	}
	p := c.Profile
	if !p.valid() {
		return nil, ErrDenied
	}
	if c.OpenRouter != nil && (!c.OpenRouter.valid() || c.OpenRouter.BaseURL != service.GatewayOpenRouterBaseURL || c.OpenRouter.Model != service.GatewayOpenRouterModel) {
		return nil, ErrDenied
	}
	if c.OAuth != nil {
		codex := c.OAuth.Profile
		key, keyErr := base64.StdEncoding.Strict().DecodeString(c.OAuth.IntentKey)
		if keyErr != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != c.OAuth.IntentKey ||
			(c.ListenAddress != "127.0.0.1:1455" && c.ListenAddress != "[::1]:1455") || !codex.valid() ||
			codex.BaseURL != service.GatewayCodexOAuthBaseURL || codex.Model != service.GatewayCodexOAuthModel {
			return nil, ErrDenied
		}
		for _, custodyKey := range keys {
			if subtle.ConstantTimeCompare(key, custodyKey) == 1 {
				return nil, ErrDenied
			}
		}
	}
	return adapter, nil
}

func (p ProfileConfig) valid() bool {
	u, err := url.Parse(p.BaseURL)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && len(p.BaseURL) <= 2048 &&
		regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`).MatchString(p.Model) && identifier.MatchString(p.QualificationRef) &&
		p.RequestBytes >= 1 && p.RequestBytes <= 4<<20 && p.OutputBytes >= 1 && p.OutputBytes <= 8<<20 && p.Tokens >= 1 &&
		p.ProviderTokenUpperBound >= p.Tokens && p.ProviderTokenUpperBound <= 10000000
}

func (c Config) openRouterProfile() *gatewaytransport.QualifiedProfile {
	if c.OpenRouter == nil {
		return nil
	}
	p := c.OpenRouter.qualified()
	p.Profile = service.GatewayOpenRouterResponsesProfile
	return &p
}

// Consumer and purpose come exclusively from the captured control mapping.
func authorize(peers []ControlPeer) func(*http.Request) (gatewaytransport.Peer, error) {
	type entry struct {
		hash [32]byte
		peer gatewaytransport.Peer
	}
	entries := make([]entry, len(peers))
	for i, p := range peers {
		entries[i] = entry{sha256.Sum256([]byte("Bearer " + p.Credential)), gatewaytransport.Peer{ConsumerID: p.ConsumerID, Role: p.Role}}
	}
	return func(r *http.Request) (gatewaytransport.Peer, error) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 || len(values[0]) > len("Bearer ")+2048 || !strings.HasPrefix(values[0], "Bearer ") || !bearer.MatchString(strings.TrimPrefix(values[0], "Bearer ")) {
			return gatewaytransport.Peer{}, ErrDenied
		}
		hash := sha256.Sum256([]byte(values[0]))
		for _, e := range entries {
			if subtle.ConstantTimeCompare(hash[:], e.hash[:]) == 1 {
				return e.peer, nil
			}
		}
		return gatewaytransport.Peer{}, ErrDenied
	}
}

func (c Config) qualifiedProfile() gatewaytransport.QualifiedProfile {
	return c.Profile.qualified()
}

func (c Config) codexProfile() *gatewaytransport.QualifiedProfile {
	if c.OAuth == nil {
		return nil
	}
	p := c.OAuth.Profile.qualified()
	p.Profile = service.GatewayCodexOAuthResponsesProfile
	return &p
}
