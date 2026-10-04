//go:build linux && integration

package gatewaybootstrap

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gatewaylauncher"
)

func TestNativeLifetimeProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "fixture-native-lifetime" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	if Run(bounded, Options{}) != nil {
		os.Exit(72)
	}
	os.Exit(0)
}

// Actual PG connection + protected launcher + production bootstrap/readiness
// and shutdown. Node is a controlled authority peer; this is not SQL claim or
// product qualification. The controller supplies a disposable existing DB.
func TestNativeProtectedReadyEnrollmentAndShutdown(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT_RUN: disposable root Linux qualification required")
	}
	dsn := os.Getenv("GATEWAY_NATIVE_BOOTSTRAP_PG_DSN")
	if dsn == "" {
		t.Skip("NOT_RUN: disposable bootstrap PostgreSQL DSN not supplied")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") ||
		!strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "native_bootstrap_") || (u.RawQuery != "" && u.RawQuery != "sslmode=disable") {
		t.Fatal("invalid disposable PostgreSQL fixture")
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			t.Fatal("password-bearing fixture DSN denied")
		}
	}
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "deniedEnrollment", true: "readyShutdown"}[allow], func(t *testing.T) {
			root, err := os.MkdirTemp("/run", "gatewaybootstrap-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			if os.Chmod(root, 0755) != nil || os.Mkdir(filepath.Join(root, "protected"), 0700) != nil {
				t.Fatal("fixture authority creation")
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
			image := filepath.Join(root, "engine")
			out, err := os.OpenFile(image, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(out, source)
			_ = source.Close()
			_ = out.Close()
			if err != nil {
				t.Fatal(err)
			}
			enrolled := make(chan enrollmentBody, 1)
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/private/native/v1/enrollment" || r.Header.Get("Authorization") != "Bearer "+fixtureConfig().Authority.Credential {
					t.Error("unexpected authority request")
				}
				var body enrollmentBody
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid enrollment")
				}
				enrolled <- body
				w.Header().Set("Content-Type", "application/json")
				if allow {
					_, _ = io.WriteString(w, `{"ok":true}`)
				} else {
					_, _ = io.WriteString(w, `{"ok":false}`)
				}
			}))
			defer node.Close()
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := probe.Addr().String()
			_ = probe.Close()
			c := fixtureConfig()
			c.ListenAddress = address
			c.PostgresDSN = dsn
			c.Authority.Origin = node.URL
			raw, _ := json.Marshal(c)
			path := filepath.Join(root, "protected", "bootstrap.json")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("fixture config")
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			lc := gatewaylauncher.Config{Authority: gatewaylauncher.AuthorityConfig{Directory: filepath.Join(root, "protected"), OriginRef: "fixture-origin"}, EnginePath: image,
				Args: []string{"-test.run=^TestNativeLifetimeProcess$", "--", "fixture-native-lifetime"}, EngineUID: 65534, EngineGID: 65534, BootstrapFile: file}
			l, err := gatewaylauncher.Start(lc)
			if l != nil {
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = l.Shutdown(ctx)
				}()
			}
			if err != nil || l == nil {
				t.Fatal("protected native start failed", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			readyErr := l.AwaitReady(ctx)
			select {
			case got := <-enrolled:
				if got.OriginRef != l.Binding().OriginRef || got.EngineIncarnation != l.Binding().Incarnation || got.QualificationRef != c.Profile.QualificationRef {
					t.Fatal("enrollment did not use original launcher binding")
				}
			case <-ctx.Done():
				t.Fatal("configured enrollment was not reached")
			}
			if !allow {
				if readyErr == nil {
					t.Fatal("denied enrollment became ready")
				}
				if _, err = l.Wait(ctx); err != nil {
					t.Fatal("failed bootstrap did not retire", err)
				}
			} else {
				if readyErr != nil {
					t.Fatal("qualified private bootstrap not ready", readyErr)
				}
				httpClient := &http.Client{Timeout: 2 * time.Second}
				resp, err := httpClient.Get("http://" + address + "/private/native/v1/responses")
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != 404 {
					t.Fatal("direct review route bypassed registry")
				}
				other, err := gatewaylauncher.Start(lc)
				if other != nil {
					defer func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						_, _ = other.Shutdown(ctx)
					}()
				}
				if other != nil || err != gatewaylauncher.ErrBusy {
					t.Fatal("live native lifetime lost occupancy")
				}
				if _, err = l.Shutdown(ctx); err != nil {
					t.Fatal("orderly native shutdown unproven", err)
				}
			}
			free, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("private listener survived exact process exit")
			}
			_ = free.Close()
		})
	}
}
