//go:build unit

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

// Exercises the default constructor's real Firefox TLS/header path against a
// controlled challenge, then the two req-specific header/charset bounds.
// Synthetic authorization only; the fixed public URL is dialed to loopback.
func TestGatewayOAuthAccountCheckDefaultFirefoxTLSAndBounds(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"chatgpt.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "chatgpt.com"})
	require.NoError(t, err)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	for _, scenario := range []string{"firefox", "raw-charset", "http2-header-limit"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			var dials atomic.Int32
			var hellos atomic.Int32
			var remoteMatches atomic.Bool
			var sniMatches atomic.Bool
			var firefoxHello atomic.Bool
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				require.Equal(t, "chatgpt.com", r.Host)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/backend-api/accounts/check/v4-2023-04-27", r.URL.Path)
				require.Equal(t, "Bearer controlled-account-check-access", r.Header.Get("Authorization"))
				require.Equal(t, "application/json", r.Header.Get("Accept"))
				require.Empty(t, r.Header.Get("Cookie"))
				require.Empty(t, r.Header.Get("ChatGPT-Account-Id"))
				if !firefoxHello.Load() || !strings.Contains(r.UserAgent(), "Firefox/") || r.Header.Get("Origin") != "https://chatgpt.com" || r.Header.Get("Referer") != "https://chatgpt.com/" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				require.Equal(t, 2, r.ProtoMajor)
				w.Header().Set("Content-Type", "application/json")
				if scenario == "http2-header-limit" {
					w.Header().Set("X-Controlled-Large", strings.Repeat("X", 32<<10))
				}
				if scenario == "raw-charset" {
					w.Header().Set("Content-Type", "application/json; charset=iso-8859-1")
					_, _ = w.Write([]byte("{\"accounts\":{\"\xff\":{\"account\":{\"account_id\":\"11111111-1111-4111-8111-111111111111\"}}}}"))
					return
				}
				_, _ = w.Write([]byte(`{"accounts":{"controlled":{"account":{"account_id":"11111111-1111-4111-8111-111111111111"}}}}`))
			}))
			server.EnableHTTP2 = true
			servedTLS := &tls.Config{NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.TLS = servedTLS.Clone()
			server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				hellos.Add(1)
				sniMatches.Store(hello.ServerName == "chatgpt.com")
				expected := []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384}
				firefoxHello.Store(len(hello.CipherSuites) >= 3 && slices.Equal(hello.CipherSuites[:3], expected))
				return servedTLS, nil
			}
			server.StartTLS()
			require.Equal(t, der, server.TLS.Certificates[0].Certificate[0])
			defer server.Close()
			f := newOAuthDispatchFixture(t)
			dispatch, err := NewGatewayNativeOAuthDispatch(f.store, f.dispatch.custody, f.dispatch.verifier, nil)
			require.NoError(t, err)
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if address != "chatgpt.com:443" {
					return nil, ErrGatewayNativeIdentity
				}
				conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				if conn != nil {
					remoteMatches.Store(conn.RemoteAddr().String() == server.Listener.Addr().String())
				}
				return conn, err
			}
			switch transport := dispatch.client.Transport.(type) {
			case *req.Transport:
				transport.TLSClientConfig.RootCAs = roots
				transport.SetDialTLS(func(ctx context.Context, network, address string) (net.Conn, error) {
					plain, err := dial(ctx, network, address)
					if err != nil {
						return nil, err
					}
					conn, _, err := transport.TLSHandshakeContext(ctx, address, plain)
					if err != nil {
						plain.Close()
					}
					return conn, err
				})
				defer transport.CloseIdleConnections()
			case *http.Transport:
				transport.TLSClientConfig.RootCAs = roots
				transport.DialContext = dial
				defer transport.CloseIdleConnections()
			default:
				t.Fatal("unexpected controlled transport")
			}
			require.Equal(t, 5*time.Second, dispatch.client.Timeout)
			originalTransport := dispatch.client.Transport
			var transportError error
			var transportStatus int
			dispatch.client.Transport = req.HttpRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := originalTransport.RoundTrip(request)
				transportError = err
				if response != nil {
					transportStatus = response.StatusCode
				}
				return response, err
			})
			provider, err := dispatch.accountCheck(context.Background(), "controlled-account-check-access")
			if scenario == "firefox" {
				t.Logf("controlled hellos=%d remote_matches=%v sni_matches=%v", hellos.Load(), remoteMatches.Load(), sniMatches.Load())
				t.Logf("controlled transport status=%d dials=%d error=%v", transportStatus, dials.Load(), transportError)
				var verification *utls.CertificateVerificationError
				if errors.As(transportError, &verification) && len(verification.UnverifiedCertificates) > 0 {
					t.Logf("controlled peer_matches_fixture=%v configured_roots=%d", slices.Equal(verification.UnverifiedCertificates[0].Raw, der), len(roots.Subjects()))
					t.Logf("controlled peer_signed_by_root=%v", verification.UnverifiedCertificates[0].CheckSignatureFrom(root) == nil)
					t.Logf("controlled peer_chatgpt_name=%v peer_example_name=%v", slices.Contains(verification.UnverifiedCertificates[0].DNSNames, "chatgpt.com"), slices.Contains(verification.UnverifiedCertificates[0].DNSNames, "example.com"))
				}
				require.NoError(t, err)
				require.Equal(t, "11111111-1111-4111-8111-111111111111", provider)
			} else {
				require.Error(t, err)
				require.Empty(t, provider)
			}
			require.EqualValues(t, 1, calls.Load())
			require.Zero(t, f.store.qualifications)
			require.Zero(t, f.entries.Load())
		})
	}
}
