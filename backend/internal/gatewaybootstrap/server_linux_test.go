//go:build linux

package gatewaybootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestDedicatedHTTPRolesAndBypassDenial(t *testing.T) {
	c := fixtureConfig()
	var enrollments atomic.Int32
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/private/native/v1/enrollment" {
			t.Error("unexpected authority call")
		}
		enrollments.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer node.Close()
	c.Authority.Origin = node.URL
	custody, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", c.PostgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	repo := repository.NewAccountRepository(client, db, nil)
	svcCfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}}
	u, _ := service.NewGatewayNativeLifetimeUpstream(repository.NewHTTPUpstream(svcCfg))
	gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, svcCfg, nil, nil, nil, nil, nil, u, nil, nil, nil, nil, nil, nil, nil, nil)
	adminRepo, ok := repo.(service.AdminAccountRepository)
	if !ok {
		t.Fatal("fixture admin repository unavailable")
	}
	adminSvc := service.NewAdminService(nil, nil, nil, adminRepo, nil, nil, nil, nil, nil, nil, nil, nil, nil, client, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	a, _ := newAuthority(c.Authority, nil)
	auth := authorize(c.Peers)
	tcfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, Authorize: auth, Enrollment: gatewaytransport.Enrollment{OriginRef: "fixture-origin", EngineIncarnation: "11111111-1111-4111-8111-111111111111", QualificationRef: c.Profile.QualificationRef},
		Profile: c.Profile.qualified(), MaxEntries: 4, CallbackTimeout: time.Second, IOTimeout: time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 8192, CallbackBytes: 65536}
	a.compose(&tcfg)
	transport, err := gatewaytransport.New(context.Background(), tcfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(privateHandler(c.Profile, adminSvc, gateway, custody, transport, auth))
	defer server.Close()
	for _, check := range []struct {
		path, role, body string
		want             int
	}{
		{"/private/native/v1/responses", "management", `{}`, 404},
		{"/admin/accounts", "management", `{}`, 404},
		{"/v1/responses", "execution", `{}`, 404},
		{"/private/native/v1/candidates/../responses", "management", `{}`, 404},
		{"/private/native/v1/transports/unknown", "execution", `{}`, 404},
		{"/private/native/v1/candidates", "execution", `{}`, 403},
		{"/private/native/v1/candidates", "cleanup", `{}`, 403},
		{"/private/native/v1/transports", "management", `{}`, 403},
		{"/private/native/v1/transports/ack", "execution", `{}`, 403},
		{"/private/native/v1/transports/ack-owner", "cleanup", `{}`, 403},
		{"/private/native/v1/candidates", "management", `{"consumerId":"foreign"}`, 400},
		{"/private/native/v1/transports", "execution", `{"consumerId":"foreign"}`, 400},
		{"/private/native/v1/candidates?token=fixture", "management", `{}`, 400},
		{"/private/native/v1/candidates", "missing", `{}`, 403},
		{"/private/native/v1/candidates", "duplicate", `{}`, 403},
		{"/private/native/v1/candidates", "malformed", `{}`, 403},
	} {
		req, _ := http.NewRequest("POST", server.URL+check.path, strings.NewReader(check.body))
		req.Header.Set("Content-Type", "application/json")
		if check.role != "missing" {
			req.Header.Set("Authorization", "Bearer fixture-"+check.role+"-credential")
		}
		if check.role == "duplicate" {
			req.Header.Set("Authorization", "Bearer "+fixtureConfig().Peers[0].Credential)
			req.Header.Add("Authorization", "Bearer "+fixtureConfig().Peers[1].Credential)
		}
		if check.role == "malformed" {
			req.Header.Set("Authorization", "bearer "+fixtureConfig().Peers[0].Credential)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != check.want {
			t.Fatalf("private path %s role %s: %d", check.path, check.role, resp.StatusCode)
		}
		if bytes.Contains(data, []byte("credential")) {
			t.Fatal("control credential echoed")
		}
	}
	if enrollments.Load() != 1 {
		t.Fatal("denied request caused authority work")
	}
}

// Reexec invokes production Run with actual inherited descriptors and separate
// credentials. There is no production test mode, fake enrollment or UID bypass.
func TestBootstrapProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "fixture-bootstrap-child" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	if Run(ctx, Options{}) == nil {
		os.Exit(72)
	}
	os.Exit(0)
}
func TestStartupRequiresGateFDConfigAndEnrollmentBeforeListen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NOT_RUN: disposable root process qualification required")
	}
	for _, kind := range []string{"noGate", "badGate", "missingConfig", "writableConfig", "invalidConfig", "badIdentity", "gateThenPGDenied"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.MkdirTemp("/run", "gatewaybootstrap-negative-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(root); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			// Copy only this fixture test image into an explicitly executable
			// disposable directory, preserving the managed sandbox as installed.
			image := filepath.Join(root, "engine")
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
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
			pg, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = pg.Close() }()
			var connections atomic.Int32
			go func() {
				for {
					conn, err := pg.Accept()
					if err != nil {
						return
					}
					connections.Add(1)
					_ = conn.Close()
				}
			}()
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listenAddress := probe.Addr().String()
			_ = probe.Close()
			c := fixtureConfig()
			c.ListenAddress = listenAddress
			c.PostgresDSN = "postgres://fixture@" + pg.Addr().String() + "/fixture?sslmode=disable"
			raw, _ := json.Marshal(c)
			if kind == "invalidConfig" {
				raw = []byte(`{"postgresDSN":"fixture-secret-marker","postgresDSN":"repeated"}`)
			}
			path := filepath.Join(root, "bootstrap.json")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("fixture config creation")
			}
			flags := os.O_RDONLY
			if kind == "writableConfig" {
				flags = os.O_RDWR
			}
			file, err := os.OpenFile(path, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			lockPath := filepath.Join(root, "lock")
			if os.WriteFile(lockPath, nil, 0600) != nil {
				t.Fatal("fixture lock")
			}
			lock, err := os.Open(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lock.Close() }()
			if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				t.Fatal("fixture flock")
			}
			readyR, readyW, _ := os.Pipe()
			defer func() { _ = readyR.Close() }()
			defer func() { _ = readyW.Close() }()
			gateR, gateW, _ := os.Pipe()
			defer func() { _ = gateR.Close() }()
			defer func() { _ = gateW.Close() }()
			childCtx, stopChild := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopChild()
			cmd := exec.CommandContext(childCtx, image, "-test.run=^TestBootstrapProcess$", "--", "fixture-bootstrap-child")
			inc := "11111111-1111-4111-8111-111111111111"
			if kind == "badIdentity" {
				inc = "legacy-incarnation"
			}
			cmd.Env = []string{"GATEWAY_LAUNCHER_LOCK_FD=3", "GATEWAY_LAUNCHER_READY_FD=4", "GATEWAY_LAUNCHER_GATE_FD=5", "GATEWAY_LAUNCHER_ORIGIN_REF=fixture-origin", "GATEWAY_LAUNCHER_ENGINE_INCARNATION=" + inc}
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
			cmd.ExtraFiles = []*os.File{lock, readyW, gateR}
			if kind != "missingConfig" {
				cmd.ExtraFiles = append(cmd.ExtraFiles, file)
			}
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Skip("NOT_RUN: isolated synthetic credential exec unavailable")
			}
			_ = readyW.Close()
			_ = gateR.Close()
			if kind != "noGate" {
				gate := "G"
				if kind == "badGate" {
					gate = "X"
				}
				_, _ = gateW.Write([]byte(gate))
				_ = gateW.Close()
			}
			if err = cmd.Wait(); err != nil {
				t.Fatal("production bootstrap fixture failed", err)
			}
			data, err := io.ReadAll(readyR)
			if err != nil || len(data) != 0 {
				t.Fatal("unqualified bootstrap wrote ready")
			}
			if kind == "gateThenPGDenied" {
				if connections.Load() != 1 {
					t.Fatal("valid gate never reached configured PG boundary", strconv.Itoa(int(connections.Load())))
				}
			} else if connections.Load() != 0 {
				t.Fatal("network work before valid gate/config")
			}
			check, err := net.Listen("tcp", listenAddress)
			if err != nil {
				t.Fatal("unqualified engine bound private listener")
			}
			_ = check.Close()
			if strings.Contains(output.String(), "fixture-secret-marker") {
				t.Fatal("invalid config leaked in process output")
			}
		})
	}
}
