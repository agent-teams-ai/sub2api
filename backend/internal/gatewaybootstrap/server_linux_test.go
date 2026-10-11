//go:build linux

package gatewaybootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
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
	t.Run("native runtime management boundary", func(t *testing.T) {
		for _, check := range []struct {
			name, method, path, credential string
			want                           int
		}{
			{"missing", "GET", "/private/native/v1/runtime", "", 403},
			{"unknown", "GET", "/private/native/v1/runtime", "Bearer " + nativeRuntimeUnknownFixture(), 403},
			{"execution", "GET", "/private/native/v1/runtime", "Bearer " + c.Peers[1].Credential, 403},
			{"cleanup", "GET", "/private/native/v1/runtime", "Bearer " + c.Peers[2].Credential, 403},
			{"callback authority", "GET", "/private/native/v1/runtime", "Bearer " + c.Authority.Credential, 403},
			{"malformed", "GET", "/private/native/v1/runtime", "bearer " + c.Peers[0].Credential, 403},
			{"duplicate", "GET", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 403},
			{"management", "GET", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 200},
			{"POST", "POST", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"PUT", "PUT", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"PATCH", "PATCH", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"DELETE", "DELETE", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"HEAD", "HEAD", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"OPTIONS", "OPTIONS", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"TRACE", "TRACE", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
			{"query", "GET", "/private/native/v1/runtime?sample=1", "Bearer " + c.Peers[0].Credential, 400},
			{"empty query", "GET", "/private/native/v1/runtime?", "Bearer " + c.Peers[0].Credential, 400},
			{"encoding", "GET", "/private/native/v1/runtime", "Bearer " + c.Peers[0].Credential, 400},
			{"escaped path", "GET", "/private/native/v1/%72untime", "Bearer " + c.Peers[0].Credential, 400},
			{"suffix", "GET", "/private/native/v1/runtime/extra", "Bearer " + c.Peers[0].Credential, 404},
			{"public", "GET", "/v1/runtime", "Bearer " + c.Peers[0].Credential, 404},
		} {
			t.Run(check.name, func(t *testing.T) {
				req, err := http.NewRequest(check.method, server.URL+check.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if check.credential != "" {
					req.Header.Set("Authorization", check.credential)
				}
				if check.name == "duplicate" {
					req.Header.Add("Authorization", check.credential)
				}
				if check.name == "encoding" {
					req.Header.Set("Content-Encoding", "gzip")
				}
				resp, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				data, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
				if err != nil || len(data) > 1024 || resp.StatusCode != check.want {
					t.Fatalf("runtime status/body: status=%d bytes=%d err=%v", resp.StatusCode, len(data), err)
				}
				keys := []string{"heapAllocBytes", "heapInuseBytes", "sysBytes", "numGC", "numGoroutine", "heapLiveBytes", "automaticGCCycles", "forcedGCCycles"}
				if check.want != http.StatusOK {
					for _, key := range append(keys, "credential", "fixture-consumer", "fixture-model") {
						if bytes.Contains(data, []byte(key)) {
							t.Fatalf("denied response leaked %s", key)
						}
					}
					return
				}
				if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" || resp.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("runtime response media/cache contract")
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(data, &fields); err != nil || len(fields) != len(keys)+2 {
					t.Fatalf("runtime fixed JSON shape: %s err=%v", data, err)
				}
				var version string
				var consistent bool
				if json.Unmarshal(fields["metricVersion"], &version) != nil || version != "natural_gc_live_v2" || json.Unmarshal(fields["gcSnapshotConsistent"], &consistent) != nil {
					t.Fatal("runtime live metric version/consistency contract")
				}
				values := make(map[string]uint64, len(keys))
				for _, key := range keys {
					bits := 64
					if key == "numGC" {
						bits = 32
					}
					value, err := strconv.ParseUint(string(fields[key]), 10, bits)
					if err != nil {
						t.Fatalf("runtime %s must be a finite unsigned integer: %s", key, fields[key])
					}
					values[key] = value
				}
				if consistent && values["automaticGCCycles"]+values["forcedGCCycles"] != values["numGC"] {
					t.Fatal("consistent live snapshot requires completed cycle accounting")
				}
				if values["heapAllocBytes"] == 0 || values["heapInuseBytes"] < values["heapAllocBytes"] ||
					values["sysBytes"] < values["heapInuseBytes"] || values["numGoroutine"] == 0 {
					t.Fatalf("runtime counters inconsistent with this running HTTP process: %s", data)
				}
			})
		}
	})
	t.Run("native runtime shares eight control slots", func(t *testing.T) {
		entered, release := make(chan struct{}, 8), make(chan struct{})
		held := httptest.NewServer(transport.ManagementHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered <- struct{}{}
			<-release
			w.WriteHeader(http.StatusNoContent)
		})))
		defer held.Close()
		released := false
		defer func() {
			if !released {
				close(release)
			}
		}()
		results := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func() {
				req, _ := http.NewRequest("GET", held.URL, nil)
				req.Header.Set("Authorization", "Bearer "+c.Peers[0].Credential)
				resp, err := held.Client().Do(req)
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode != http.StatusNoContent {
						err = fmt.Errorf("held control status %d", resp.StatusCode)
					}
				}
				results <- err
			}()
		}
		for i := 0; i < 8; i++ {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("shared control fixture failed to fill eight slots")
			}
		}
		req, _ := http.NewRequest("GET", server.URL+"/private/native/v1/runtime", nil)
		req.Header.Set("Authorization", "Bearer "+c.Peers[0].Credential)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusServiceUnavailable || bytes.Contains(data, []byte("heapAllocBytes")) {
			t.Fatalf("runtime did not share bounded control admission: status=%d err=%v", resp.StatusCode, err)
		}
		// Release and join all fixture requests before testing slot reuse.
		close(release)
		released = true
		for i := 0; i < 8; i++ {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shared control fixture did not finish")
			}
		}
		resp, err = server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("runtime control slot not reusable: %d", resp.StatusCode)
		}
	})
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

func nativeRuntimeUnknownFixture() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("fixture entropy unavailable")
	}
	return hex.EncodeToString(b)
}

// Controlled mount repository only. F3 PG acceptance remains a separate gate;
// this fixture observes the real router, constructors and token HTTP boundary.
type oauthMountJournal struct {
	service.GatewayNativeOAuthConnectRepository
	row     service.GatewayNativeOAuthConnectIntent
	entries int
	finds   int
}

func (s *oauthMountJournal) PrepareConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) (service.GatewayNativeOAuthConnectIntent, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, in.Scope) {
		return in, ErrDenied
	}
	if s.row.Operation == "" {
		s.row = in
	}
	if !service.SameGatewayNativeOAuthConnectIntent(in, s.row) {
		return in, ErrDenied
	}
	return s.row, nil
}
func (s *oauthMountJournal) ReadConnectIntent(ctx context.Context, scope service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthConnectIntent, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || s.row.Scope != scope || s.row.Operation != op {
		return service.GatewayNativeOAuthConnectIntent{}, ErrDenied
	}
	return s.row, nil
}
func (s *oauthMountJournal) FindConnectState(_ context.Context, hash string) (service.GatewayNativeOAuthConnectIntent, error) {
	s.finds++
	if s.row.StateHash != hash {
		return service.GatewayNativeOAuthConnectIntent{}, ErrDenied
	}
	return s.row, nil
}
func (s *oauthMountJournal) EnterConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) (bool, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s.row.Scope) || in.Operation != s.row.Operation {
		return false, ErrDenied
	}
	if s.row.State != "prepared" {
		return false, nil
	}
	s.entries++
	s.row.State = "entered"
	return true, nil
}
func (s *oauthMountJournal) FinishConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent, state string, out service.GatewayNativeOAuthOutcome) (service.GatewayNativeOAuthConnectIntent, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, s.row.Scope) || in.Operation != s.row.Operation {
		return in, ErrDenied
	}
	s.row.State = "unknown"
	s.row.RecoveryDenied = state == "quarantined"
	s.row.Envelope = ""
	return s.row, nil
}

type oauthMountRows struct {
	service.GatewayNativeOAuthRefreshRepository
	refreshResolution service.GatewayNativeOAuthRefreshResolution
	service.AccountRepository
	service.GatewayNativeOAuthRepository
}

func (*oauthMountRows) LockGatewayNativeAccount(context.Context, int64) (*service.Account, func(), error) {
	return nil, nil, ErrDenied
}
func (*oauthMountRows) ReplayGatewayNativeOAuth(context.Context, service.GatewayNativeCredentialScope, string, string) (service.GatewayNativeOAuthOutcome, bool, error) {
	return service.GatewayNativeOAuthOutcome{}, false, nil
}
func (*oauthMountRows) ReadGatewayNativeOAuthDispatch(_ context.Context, s service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthOutcome, error) {
	return service.GatewayNativeOAuthOutcome{Operation: op, Generation: s.Generation, State: "prepared"}, nil
}
func (*oauthMountRows) LockGatewayNativeOAuthDispatch(context.Context, service.GatewayNativeCredentialScope, string, int64) (*service.Account, service.GatewayNativeOAuthPhysical, func(), error) {
	return nil, service.GatewayNativeOAuthPhysical{}, nil, ErrDenied
}
func (*oauthMountRows) QualifyGatewayNativeOAuthDispatch(context.Context, service.GatewayNativeOAuthPhysical, int64) error {
	return ErrDenied
}

func (*oauthMountRows) CleanupGatewayNativeOAuth(ctx context.Context, in service.GatewayNativeOAuthCleanupRequest, authorize service.GatewayNativeOAuthCleanupAuthorizer) (service.GatewayNativeOAuthCleanupResult, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, in.Scope) {
		return service.GatewayNativeOAuthCleanupResult{}, ErrDenied
	}
	grant, err := authorize(ctx, in)
	if err != nil {
		return service.GatewayNativeOAuthCleanupResult{}, err
	}
	return service.GatewayNativeOAuthCleanupResult{Operation: in.Operation, Account: in.Scope.Account, Closure: "pending", Native: grant.Native}, nil
}

type oauthMountAdmin struct{ service.AdminService }

// Controlled rows behind the real candidate create/read handlers and admin
// service. This test does not claim SQL custody or provider qualification.
type additiveHTTPRows struct {
	service.AdminAccountRepository
	mu   sync.Mutex
	rows map[int64]*service.Account
}

var _ service.GatewayNativeAccountLocker = (*additiveHTTPRows)(nil)

func (s *additiveHTTPRows) LockGatewayNativeAccount(_ context.Context, id int64) (*service.Account, func(), error) {
	s.mu.Lock()
	a := s.rows[id]
	if a == nil {
		s.mu.Unlock()
		return nil, nil, ErrDenied
	}
	return a, s.mu.Unlock, nil
}

func (s *additiveHTTPRows) Create(ctx context.Context, a *service.Account) error {
	consumer, err := service.GatewayNativeConsumer(ctx)
	if err != nil || consumer != "fixture-consumer" {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a.ID = int64(len(s.rows) + 1)
	a.CreatedAt = time.Date(2026, 10, 6, 0, 0, 0, 123456000, time.UTC)
	s.rows[a.ID] = a
	return nil
}

func (s *additiveHTTPRows) FindByExtraField(_ context.Context, key string, value any) ([]service.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []service.Account
	for _, a := range s.rows {
		if a.Extra[key] == value {
			found = append(found, *a)
		}
	}
	return found, nil
}

// Delegate to the real HTTP socket, then let its background read observe an
// expired deadline before net/http can abort that read during handler return.
// This makes accidental connection-context cancellation observable without
// manufacturing cancellation or changing the transport's lifetime observer.
type compositionHTTPWriter struct {
	http.ResponseWriter
	ctx context.Context
}

func (w *compositionHTTPWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *compositionHTTPWriter) SetReadDeadline(deadline time.Time) error {
	err := http.NewResponseController(w.ResponseWriter).SetReadDeadline(deadline)
	if err == nil && !deadline.IsZero() && !deadline.After(time.Now()) {
		select {
		case <-w.ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return err
}

// One real HTTP composition: three distinct protected tuples, the MiMo ACK,
// exact admission limits/caps and candidate create/read with optional OAuth.
// The authority returns non-dispatch readback; no provider/login/PG call occurs.
func TestAdditiveThreeProfilesHTTPComposition(t *testing.T) {
	c := fixtureOAuthConfig()
	c.OAuth.Profile = ProfileConfig{Model: service.GatewayCodexOAuthModel, BaseURL: service.GatewayCodexOAuthBaseURL,
		QualificationRef: "codex-composition-fixture", RequestBytes: 8192, OutputBytes: 6144, Tokens: 150, ProviderTokenUpperBound: 300}
	c.OpenRouter = &ProfileConfig{Model: service.GatewayOpenRouterModel, BaseURL: service.GatewayOpenRouterBaseURL,
		QualificationRef: "openrouter-composition-fixture", RequestBytes: 2048, OutputBytes: 3072, Tokens: 40, ProviderTokenUpperBound: 80}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if decodeStrict(raw, &decoded) != nil {
		t.Fatal("three-profile protected config rejected")
	}
	c = decoded
	custody, err := c.validate()
	if err != nil || c.qualifiedProfile() != fixtureConfig().Profile.qualified() {
		t.Fatal("OAuth replaced the original MiMo qualification/limits", err)
	}
	profiles := []gatewaytransport.QualifiedProfile{c.qualifiedProfile(), *c.openRouterProfile(), *c.codexProfile()}
	const origin = "fixture-origin"
	const engineIncarnation = "11111111-1111-4111-8111-111111111111"
	var enrollments, admits, providerEntries atomic.Int32
	var expected atomic.Pointer[gatewaytransport.Request]
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+c.Authority.Credential || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unauthenticated composition callback")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(r.Body, 65537))
		if readErr != nil || len(data) > 65536 {
			t.Error("unbounded composition callback")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/private/native/v1/enrollment":
			var got enrollmentBody
			if decodeStrict(data, &got) != nil || got != (enrollmentBody{origin, engineIncarnation, profiles[0].QualificationRef}) {
				t.Error("enrollment lost original MiMo receipt")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			enrollments.Add(1)
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/private/native/v1/admit":
			var got gatewaytransport.Request
			var fields map[string]json.RawMessage
			var native gatewaytransport.NativeBinding
			var consumer string
			want := expected.Load()
			if json.Unmarshal(data, &fields) != nil || len(fields) != 6 || json.Unmarshal(data, &got) != nil ||
				json.Unmarshal(fields["consumerId"], &consumer) != nil || json.Unmarshal(fields["native"], &native) != nil || want == nil ||
				consumer != "fixture-consumer" || got.Admission != want.Admission || got.RequestRef != want.RequestRef || got.Worker != want.Worker ||
				!service.SameGatewayNativeDescriptor(got.Descriptor, want.Descriptor) || native.Generation != want.Descriptor.Generation ||
				native.OriginRef != origin || native.EngineIncarnation != engineIncarnation || !incarnation.MatchString(native.RequestNonce) {
				t.Error("callback selected a different admission/profile tuple")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			admits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"consumerId": consumer, "admission": got.Admission,
				"status": map[string]any{"requestRef": got.RequestRef, "effect": "not_dispatched"}})
		default:
			t.Error("unexpected authority route", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer node.Close()
	a, err := newAuthority(AuthorityConfig{node.URL, c.Authority.Credential}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.client.CloseIdleConnections()
	provider := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		providerEntries.Add(1)
		return nil, ErrDenied
	}}
	oauthRows := &oauthMountRows{}
	verifier := service.NewGatewayNativeOAuthVerifier(provider)
	key := []byte(strings.Repeat("I", 32))
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, oauthRows, key)
	if err != nil {
		t.Fatal(err)
	}
	connect, err := service.NewGatewayNativeOAuthConnect(key, provider, &oauthMountJournal{}, enrollment, oauthRows)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(oauthRows, custody, verifier, provider)
	if err != nil {
		t.Fatal(err)
	}
	rows := &additiveHTTPRows{rows: map[int64]*service.Account{}}
	u, err := service.NewGatewayNativeLifetimeUpstream(repository.NewHTTPUpstream(&config.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	gateway := service.NewOpenAIGatewayService(rows, nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, u, nil, nil, nil, nil, nil, nil, nil, nil)
	adminSvc := service.NewAdminService(nil, nil, nil, rows, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	auth := authorize(c.Peers)
	cfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, OAuth: dispatch, Authorize: auth,
		Enrollment: gatewaytransport.Enrollment{OriginRef: origin, EngineIncarnation: engineIncarnation, QualificationRef: c.Profile.QualificationRef},
		Profile:    c.qualifiedProfile(), OpenRouter: c.openRouterProfile(), Codex: c.codexProfile(), MaxEntries: 4,
		CallbackTimeout: time.Second, IOTimeout: time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 16384, CallbackBytes: 65536}
	a.compose(&cfg)
	missingCodex := cfg
	missingCodex.Codex = nil
	if _, err := gatewaytransport.New(context.Background(), missingCodex); err == nil || enrollments.Load() != 0 {
		t.Fatal("OAuth inferred its missing qualification/limits or enrolled before validation")
	}
	transport, err := gatewaytransport.New(context.Background(), cfg)
	if err != nil || enrollments.Load() != 1 {
		t.Fatal("additive startup/enrollment failed", err)
	}
	defer func() { _ = transport.Stop(context.Background()) }()
	mode := &privateOAuth{connect: connect, dispatch: dispatch, owners: a}
	handler := privateHandler(c.Profile, adminSvc, gateway, custody, transport, auth, mode)
	var observeNoEntry atomic.Bool
	type contextObservation struct{ before, after bool }
	observations := make(chan contextObservation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !observeNoEntry.Load() {
			handler.ServeHTTP(w, r)
			return
		}
		before := r.Context().Err() == nil
		handler.ServeHTTP(&compositionHTTPWriter{ResponseWriter: w, ctx: r.Context()}, r)
		observations <- contextObservation{before, r.Context().Err() == nil}
	}))
	defer server.Close()
	// Mutation after construction cannot change either optional snapshot.
	*cfg.OpenRouter = gatewaytransport.QualifiedProfile{}
	*cfg.Codex = gatewaytransport.QualifiedProfile{}
	var firstNoEntryConn net.Conn
	var liveContexts, sameConnections int
	request := func(server *httptest.Server, method, path, role string, body any) (int, []byte) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, server.URL+"/private/native/v1/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for _, peer := range c.Peers {
			if peer.Role == role {
				req.Header.Set("Authorization", "Bearer "+peer.Credential)
			}
		}
		observed := observeNoEntry.Load()
		var connection net.Conn
		var reused bool
		if observed {
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) { connection, reused = info.Conn, info.Reused },
			}))
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
		if err != nil || len(data) > 65536 {
			t.Fatal("composition response read failed", err)
		}
		if observed {
			observation := <-observations
			if observation.before && observation.after {
				liveContexts++
			}
			if firstNoEntryConn == nil {
				firstNoEntryConn = connection
			} else if connection == firstNoEntryConn && reused {
				sameConnections++
			}
		}
		return resp.StatusCode, data
	}
	create := func(server *httptest.Server, p gatewaytransport.QualifiedProfile, generation string) service.GatewayNativeRoute {
		t.Helper()
		code, data := request(server, http.MethodPost, "candidates", "management", map[string]any{
			"profile": p.Profile, "generation": generation, "name": "composition fixture", "api_key": nativeRuntimeUnknownFixture(),
			"owner_ref": "fixture-owner", "account_ref": p.Profile})
		var candidate admin.GatewayNativeCandidate
		if code != http.StatusOK || json.Unmarshal(data, &candidate) != nil || candidate.Descriptor.Profile != p.Profile ||
			candidate.Descriptor.BaseURL != p.BaseURL || candidate.Descriptor.Model != p.Model || candidate.Descriptor.Generation != generation ||
			candidate.State != "inactive" || !candidate.GroupFree || candidate.Schedulable || candidate.ProbesEnabled {
			t.Fatalf("candidate selected wrong tuple: profile=%s status=%d", p.Profile, code)
		}
		code, data = request(server, http.MethodGet, "candidates/"+generation, "management", nil)
		var read admin.GatewayNativeCandidate
		if code != http.StatusOK || json.Unmarshal(data, &read) != nil || !service.SameGatewayNativeDescriptor(read.Descriptor, candidate.Descriptor) {
			t.Fatal("candidate read lost original tuple", code)
		}
		return candidate.Descriptor
	}
	for i, p := range profiles {
		generation := fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1)
		descriptor := service.GatewayNativeRoute{AccountID: 3, Generation: generation,
			CreatedAt: time.Date(2026, 10, 6, 0, 0, 0, 123456000, time.UTC), Profile: p.Profile, BaseURL: p.BaseURL, Model: p.Model}
		if i < 2 {
			descriptor = create(server, p, generation)
		}
		input := gatewaytransport.Request{RequestRef: fmt.Sprintf("composition-request-%d", i), Worker: "44444444-4444-4444-8444-444444444444",
			Admission: gatewaytransport.Admission{ExecutionRef: fmt.Sprintf("composition-execution-%d", i), IssuerEpoch: "fixture-issuer",
				InvocationRef: "fixture-invocation", AttemptRef: "fixture-attempt", AccountRef: p.Profile, AuthorizationEpoch: 3,
				SubjectRef: "fixture-subject", PolicyRevision: 4, BindingRevision: 5, ProfileID: p.Profile,
				Limits:    gatewaytransport.Limits{Requests: 2, Concurrency: 1, RequestBytes: p.RequestBytes, OutputBytes: p.OutputBytes, Tokens: p.Tokens},
				ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}, Descriptor: descriptor,
			Payload: json.RawMessage(fmt.Sprintf(`{"model":%q,"input":%q,"store":false,"stream":true,"service_tier":"default","max_output_tokens":%d}`,
				p.Model, strings.Repeat("x", int(p.RequestBytes)-256), p.ProviderTokenUpperBound))}
		for _, mutate := range []func(*gatewaytransport.Request){
			func(r *gatewaytransport.Request) { r.Admission.Limits.RequestBytes++ },
			func(r *gatewaytransport.Request) { r.Admission.Limits.OutputBytes++ },
			func(r *gatewaytransport.Request) { r.Admission.Limits.Tokens++ },
			func(r *gatewaytransport.Request) { r.Descriptor.BaseURL = "https://caller.invalid" },
			func(r *gatewaytransport.Request) { r.Descriptor.Model = "caller-model" },
			func(r *gatewaytransport.Request) { r.Admission.ProfileID = "caller-profile" },
			func(r *gatewaytransport.Request) { r.Admission.ProfileID = profiles[(i+1)%len(profiles)].Profile },
			func(r *gatewaytransport.Request) {
				r.Payload = json.RawMessage(fmt.Sprintf(`{"model":%q,"store":false,"stream":true,"service_tier":"default","max_output_tokens":%d}`, p.Model, p.ProviderTokenUpperBound+1))
			},
		} {
			bad := input
			mutate(&bad)
			code, _ := request(server, http.MethodPost, "transports", "execution", bad)
			if code != http.StatusBadRequest || admits.Load() != int32(i) {
				t.Fatal("cross-tuple or excessive bound reached admission callback", p.Profile, code)
			}
		}
		expected.Store(&input)
		observeNoEntry.Store(true)
		code, data := request(server, http.MethodPost, "transports", "execution", input)
		observeNoEntry.Store(false)
		var receipt gatewaytransport.Receipt
		decodeErr := json.Unmarshal(data, &receipt)
		requestRefMatches := receipt.RequestRef == input.RequestRef
		phase := "invalid"
		switch receipt.Phase {
		case "reserved", "admitted", "entered", "closed":
			phase = receipt.Phase
		}
		admissionCount := admits.Load()
		t.Logf("profileIndex=%d status=%d responseBytes=%d decoded=%t decodeErrorType=%T requestRefMatches=%t phase=%s entered=%t admissionCount=%d",
			i, code, len(data), decodeErr == nil, decodeErr, requestRefMatches, phase, receipt.Lifetime.Entered, admissionCount)
		if code != http.StatusAccepted {
			t.Fatalf("own profile admission HTTP status: got=%d want=%d", code, http.StatusAccepted)
		}
		if decodeErr != nil {
			t.Fatalf("own profile receipt decode: decoded=false errorType=%T responseBytes=%d", decodeErr, len(data))
		}
		if !requestRefMatches {
			t.Fatal("own profile receipt requestRefMatches=false")
		}
		if receipt.Phase != "closed" {
			t.Fatalf("own profile receipt phase: got=%s want=closed", phase)
		}
		if receipt.Lifetime.Entered {
			t.Fatal("own profile receipt entered=true")
		}
		if admissionCount != int32(i+1) {
			t.Fatalf("own profile admission count: got=%d want=%d", admissionCount, i+1)
		}
		if receipt.Status == nil || receipt.Status.RequestRef != input.RequestRef || receipt.Status.Effect != "not_dispatched" {
			t.Fatal("own profile missing authenticated not_dispatched readback")
		}
		if !receipt.Sealed || !receipt.Lifetime.ContextDone || !receipt.Lifetime.Sealed ||
			!receipt.Lifetime.ForwardingReturned || !receipt.Lifetime.BodyKnown || !receipt.Lifetime.BodyClosed || receipt.Lifetime.CloseFailed {
			t.Fatal("own profile no-entry receipt lost positive closure")
		}
	}
	if liveContexts != len(profiles) || sameConnections != len(profiles)-1 {
		t.Fatalf("no-entry keepalive: liveContexts=%d sameConnections=%d", liveContexts, sameConnections)
	}
	// OAuth without OpenRouter must retain MiMo candidate creation and readback.
	c.OpenRouter = nil
	if _, err := c.validate(); err != nil {
		t.Fatal("OAuth without OpenRouter config denied", err)
	}
	cfg.OpenRouter, cfg.Codex = nil, c.codexProfile()
	withoutRouter, err := gatewaytransport.New(context.Background(), cfg)
	if err != nil {
		t.Fatal("OAuth without OpenRouter startup denied", err)
	}
	defer func() { _ = withoutRouter.Stop(context.Background()) }()
	second := httptest.NewServer(privateHandler(c.Profile, adminSvc, gateway, custody, withoutRouter, auth, mode))
	defer second.Close()
	create(second, profiles[0], "55555555-5555-4555-8555-555555555555")
	if code, _ := request(second, http.MethodGet, "candidates/33333333-3333-4333-8333-000000000002", "management", nil); code != http.StatusConflict {
		t.Fatal("unconfigured OpenRouter candidate remained readable", code)
	}
	if enrollments.Load() != 2 || admits.Load() != 3 || providerEntries.Load() != 0 {
		t.Fatal("composition retried authority or entered provider")
	}
}

type oauthMountOwner struct{ live bool }

func (s *oauthMountOwner) AuthorizeNativeOAuthOwner(_ context.Context, consumer, operation, account, generation string) (string, error) {
	if !s.live || consumer != "fixture-consumer" {
		return "", ErrDenied
	}
	return "fixture-live-owner", nil
}

type oauthSelectorJournal struct {
	service.GatewayNativeOAuthConnectRepository
	mu   sync.Mutex
	rows map[string]*oauthMountJournal
}

func (s *oauthSelectorJournal) PrepareConnect(ctx context.Context, in service.GatewayNativeOAuthConnectIntent) (service.GatewayNativeOAuthConnectIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[in.Operation] == nil {
		s.rows[in.Operation] = &oauthMountJournal{}
	}
	return s.rows[in.Operation].PrepareConnect(ctx, in)
}

func (s *oauthSelectorJournal) ReadConnectIntent(ctx context.Context, scope service.GatewayNativeCredentialScope, op string) (service.GatewayNativeOAuthConnectIntent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[op] == nil {
		return service.GatewayNativeOAuthConnectIntent{}, ErrDenied
	}
	return s.rows[op].ReadConnectIntent(ctx, scope, op)
}

// Real native POST -> authenticated HTTP owner callback -> real pending handlers.
// Controlled committed relations are not a SQL/current-management-grant receipt.
func TestOAuthOwnerSelectorsHTTPBeforePhysicalCreation(t *testing.T) {
	c := fixtureOAuthConfig()
	custody, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	first := nativeOAuthOwnerTuple{"operation-a", "owner-a", "account-a", "33333333-3333-4333-8333-333333333333"}
	second := nativeOAuthOwnerTuple{"operation-b", "owner-b", "account-b", "44444444-4444-4444-8444-444444444444"}
	var lookups, tokenEntries, cleanupLookups atomic.Int32
	var grantLive atomic.Bool
	grantLive.Store(true)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/private/native/v1/enrollment" {
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}

		if r.URL.Path == "/private/native/v1/oauth-cleanup-authority" {
			cleanupLookups.Add(1)
			var selectors struct {
				ConsumerID   string `json:"consumerId"`
				OperationID  string `json:"operationId"`
				AccountRef   string `json:"accountRef"`
				Generation   string `json:"generation"`
				CleanupRef   string `json:"cleanupRef"`
				CleanupToken string `json:"cleanupToken"`
				Action       string `json:"action"`
			}
			if r.Header.Get("Authorization") != "Bearer "+c.Authority.Credential || json.NewDecoder(r.Body).Decode(&selectors) != nil || selectors.ConsumerID != "fixture-consumer" || selectors.OperationID != first.Operation || selectors.AccountRef != first.AccountRef || selectors.Generation != first.Generation || selectors.CleanupRef != "cleanup-ref" || selectors.CleanupToken != "current-token" || selectors.Action != "read" {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ownerRef": first.OwnerRef, "leaseExpiresAt": time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano), "native": service.GatewayNativeRoute{AccountID: 42, Generation: first.Generation, CreatedAt: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), Profile: service.GatewayCodexOAuthResponsesProfile, BaseURL: service.GatewayCodexOAuthBaseURL, Model: service.GatewayCodexOAuthModel}})
			return
		}
		lookups.Add(1)
		var selectors oauthOwnerBody
		if r.Method != http.MethodPost || r.URL.Path != "/private/native/v1/oauth-owner-authority" ||
			r.Header.Get("Authorization") != "Bearer "+c.Authority.Credential || json.NewDecoder(r.Body).Decode(&selectors) != nil ||
			selectors.ConsumerID != "fixture-consumer" || !grantLive.Load() {
			w.WriteHeader(403)
			return
		}
		for _, saved := range []nativeOAuthOwnerTuple{first, second} {
			if selectors.OperationID == saved.Operation && selectors.AccountRef == saved.AccountRef && selectors.Generation == saved.Generation {
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ownerRef": saved.OwnerRef})
				return
			}
		}
		w.WriteHeader(403)
	}))
	defer node.Close()
	a, err := newAuthority(AuthorityConfig{node.URL, c.Authority.Credential}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.client.CloseIdleConnections()
	provider := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		tokenEntries.Add(1)
		return nil, ErrDenied
	}}
	rows := &oauthMountRows{}
	verifier := service.NewGatewayNativeOAuthVerifier(provider)
	key := []byte(strings.Repeat("I", 32))
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, rows, key)
	if err != nil {
		t.Fatal(err)
	}
	journal := &oauthSelectorJournal{rows: map[string]*oauthMountJournal{}}
	connect, err := service.NewGatewayNativeOAuthConnect(key, provider, journal, enrollment, rows)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(rows, custody, verifier, provider)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := service.NewGatewayNativeLifetimeUpstream(repository.NewHTTPUpstream(&config.Config{}))
	gateway := service.NewOpenAIGatewayService(rows, nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, u, nil, nil, nil, nil, nil, nil, nil, nil)
	auth := authorize(c.Peers)
	cfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, OAuth: dispatch, Authorize: auth,
		Enrollment: gatewaytransport.Enrollment{OriginRef: "fixture-origin", EngineIncarnation: "11111111-1111-4111-8111-111111111111", QualificationRef: c.Profile.QualificationRef},
		Profile:    c.qualifiedProfile(), Codex: c.codexProfile(), MaxEntries: 4, CallbackTimeout: time.Second, IOTimeout: time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 8192, CallbackBytes: 65536}
	a.compose(&cfg)
	transport, err := gatewaytransport.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.Stop(context.Background()) }()
	server := httptest.NewServer(privateHandler(c.Profile, &oauthMountAdmin{}, gateway, custody, transport, auth, &privateOAuth{connect: connect, dispatch: dispatch, owners: a, cleanup: a.AuthorizeNativeOAuthCleanup}))
	defer server.Close()
	post := func(path string, body any, authenticated bool) (int, []byte) {
		raw, _ := json.Marshal(body)
		if original, ok := body.(json.RawMessage); ok {
			raw = original
		}
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/private/native/v1/oauth/connect"+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+c.Peers[0].Credential)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	if code, _ := post("", first, false); code != 403 || lookups.Load() != 0 {
		t.Fatal("owner callback ran before consumer authentication")
	}
	for _, tuple := range []nativeOAuthOwnerTuple{first, second} {
		for _, path := range []string{"", "/read", "/descriptor"} {
			code, raw := post(path, tuple, true)
			if code != 200 || path == "/descriptor" && (!bytes.Contains(raw, []byte(`"qualification":"pending"`)) || bytes.Contains(raw, []byte(`"native"`))) {
				t.Fatal("exact selector or restored body lost pending relation", tuple.Operation, path, code)
			}
		}
	}
	for _, mutate := range []func(*nativeOAuthOwnerTuple){
		func(t *nativeOAuthOwnerTuple) { t.Operation = second.Operation },
		func(t *nativeOAuthOwnerTuple) { t.AccountRef = second.AccountRef },
		func(t *nativeOAuthOwnerTuple) { t.Generation = second.Generation },
		func(t *nativeOAuthOwnerTuple) { t.OwnerRef = second.OwnerRef },
	} {
		bad := first
		mutate(&bad)
		if code, _ := post("/read", bad, true); code != 403 {
			t.Fatal("foreign selector/body owner gained authority", code)
		}
	}
	before := lookups.Load()
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"operation":"operation-a","Operation":"operation-b","owner_ref":"owner-a","account_ref":"account-a","generation":"` + first.Generation + `"}`),
		json.RawMessage(`{"operation":"operation-a","owner_ref":"owner-a","account_ref":"account-a","generation":"` + first.Generation + `","endpoint":"caller"}`),
		json.RawMessage(strings.Repeat(" ", 4097) + `{}`),
	} {
		if code, _ := post("", raw, true); code != 400 {
			t.Fatal("noncanonical/oversize body reached owner lookup", code)
		}
	}
	if lookups.Load() != before {
		t.Fatal("malformed body reached callback")
	}
	grantLive.Store(false)
	if code, _ := post("/descriptor", second, true); code != 403 || tokenEntries.Load() != 0 {
		t.Fatal("retired grant or selector denial entered token exchange")
	}
	// Failure: cleanup was never mounted on the sanitized router, management
	// bearer reached it, or revoked connect grants prevented exact leased cleanup.
	cleanupBody := map[string]string{"operation": first.Operation, "owner_ref": first.OwnerRef, "account_ref": first.AccountRef, "generation": first.Generation, "action": "read", "cleanup_ref": "cleanup-ref", "cleanup_token": "current-token"}
	for _, tc := range []struct {
		credential string
		want       int
	}{{"fixture-management-credential", 403}, {"fixture-execution-credential", 403}, {"fixture-cleanup-credential", 200}} {
		raw, _ := json.Marshal(cleanupBody)
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/private/native/v1/oauth/connect/cleanup", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+tc.credential)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatal("cleanup mount purpose role", response.StatusCode, tc.want)
		}
		if tc.want == 200 && (!bytes.Contains(data, []byte(`"closure":"pending"`)) || !bytes.Contains(data, []byte(`"account_id":42`))) {
			t.Fatal("cleanup reply lost finite result or exact native timestamp/ID", string(data))
		}
	}
	if cleanupLookups.Load() != 2 || tokenEntries.Load() != 0 {
		t.Fatal("cleanup did not use its own live purpose callback, or entered provider", cleanupLookups.Load(), tokenEntries.Load())
	}

}

// Regression: an opt-in route was absent behind the MiMo-only router, callback
// query was blanket-denied, or body owner_ref could authorize another owner.
func TestProtectedOAuthMountCanonicalCallbackAndLiveOwner(t *testing.T) {
	c := fixtureOAuthConfig()
	custody, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	var tokenEntries atomic.Int32
	tokens := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenEntries.Add(1)
		if r.Host != "auth.openai.com" || r.URL.Path != "/oauth/token" || r.Method != "POST" {
			t.Error("wrong fixed code exchange")
		}
		if r.ParseForm() != nil || r.PostForm.Get("redirect_uri") != service.GatewayOAuthConnectRedirect {
			t.Error("changed callback URI")
		}
		w.WriteHeader(400)
		_, _ = io.WriteString(w, "controlled vendor secret must not reflect")
	}))
	defer tokens.Close()
	tokenTransport, ok := tokens.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test HTTP transport type")
	}
	provider := tokenTransport.Clone()
	provider.TLSClientConfig.ServerName = "example.com"
	provider.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "auth.openai.com:443" {
			return nil, ErrDenied
		}
		return (&net.Dialer{}).DialContext(ctx, network, tokens.Listener.Addr().String())
	}
	defer provider.CloseIdleConnections()
	rows := &oauthMountRows{}
	verifier := service.NewGatewayNativeOAuthVerifier(provider)
	intentKey := []byte(strings.Repeat("I", 32))
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, rows, intentKey)
	if err != nil {
		t.Fatal(err)
	}
	journal := &oauthMountJournal{}
	connect, err := service.NewGatewayNativeOAuthConnect(intentKey, provider, journal, enrollment, rows)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(rows, custody, verifier, provider)
	if err != nil {
		t.Fatal(err)
	}
	owners := &oauthMountOwner{live: true}
	upstream, _ := service.NewGatewayNativeLifetimeUpstream(repository.NewHTTPUpstream(&config.Config{}))
	gateway := service.NewOpenAIGatewayService(rows, nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer authority.Close()
	a, _ := newAuthority(AuthorityConfig{authority.URL, c.Authority.Credential}, nil)
	auth := authorize(c.Peers)
	cfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, OAuth: dispatch, Authorize: auth, Enrollment: gatewaytransport.Enrollment{OriginRef: "fixture-origin", EngineIncarnation: "11111111-1111-4111-8111-111111111111", QualificationRef: c.Profile.QualificationRef}, Profile: c.qualifiedProfile(), Codex: c.codexProfile(), MaxEntries: 4, CallbackTimeout: time.Second, IOTimeout: time.Second, CleanupTimeout: time.Second, EnvelopeBytes: 8192, CallbackBytes: 65536}
	a.compose(&cfg)
	transport, err := gatewaytransport.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	scope := service.GatewayNativeCredentialScope{Consumer: "fixture-consumer", Owner: "fixture-live-owner", Account: "fixture-account", Generation: "33333333-3333-4333-8333-333333333333", Purpose: service.GatewayOAuthBundlePurpose}
	opaque := func() string {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	legacy := service.GatewayNativeOAuthBundle{AccessToken: opaque(), RefreshToken: opaque(), IDToken: opaque(), SensitiveMetadata: json.RawMessage(`{"expires_in":3600}`)}
	legacyEnvelope, err := custody.SealOAuthBundle(scope, legacy)
	if err != nil {
		t.Fatal(err)
	}
	rows.refreshResolution = service.GatewayNativeOAuthRefreshResolution{AccountID: 1, CreatedAt: time.Now().Truncate(time.Microsecond), Version: 1, Envelope: legacyEnvelope}
	refresh, err := service.NewGatewayNativeOAuthRefresh(rows, custody, verifier, provider)
	if err != nil {
		t.Fatal(err)
	}
	mode := &privateOAuth{connect: connect, dispatch: dispatch, owners: owners, refresh: refresh}
	server := httptest.NewServer(privateHandler(c.Profile, &oauthMountAdmin{}, gateway, custody, transport, auth, mode))
	defer server.Close()
	defer func() { _ = transport.Stop(context.Background()) }()
	input := `{"operation":"original-mount-operation","owner_ref":"fixture-live-owner","account_ref":"fixture-account","generation":"33333333-3333-4333-8333-333333333333"}`
	post := func(path, body, role string) (int, []byte) {
		req, _ := http.NewRequest("POST", server.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, p := range c.Peers {
			if p.Role == role {
				req.Header.Set("Authorization", "Bearer "+p.Credential)
			}
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, raw
	}
	refreshPath := "/private/native/v1/oauth/refresh"
	for _, role := range []string{"execution", "cleanup", "missing"} {
		status, _ := post(refreshPath, input, role)
		if status != 403 {
			t.Fatal("non-management maintenance", role, status)
		}
	}
	for _, body := range []string{
		strings.Replace(input, `"operation":`, `"Operation":`, 1),
		strings.TrimSuffix(input, "}") + `,"version":1}`,
		strings.TrimSuffix(input, "}") + `,"operation":"duplicate"}`,
		strings.Replace(input, `"owner_ref":"fixture-live-owner",`, "", 1),
	} {
		status, _ := post(refreshPath, body, "management")
		if status != 400 {
			t.Fatal("refresh accepted expanded/ambiguous selectors", status)
		}
	}
	refreshStatus, refreshRaw := post(refreshPath, input, "management")
	if refreshStatus != 200 {
		t.Fatal("opt-in maintenance route absent", refreshStatus)
	}
	var safe map[string]json.RawMessage
	if json.Unmarshal(refreshRaw, &safe) != nil || len(safe) != 3 || string(safe["state"]) != `"idle"` ||
		string(safe["operation"]) != `"original-mount-operation"` || string(safe["account_ref"]) != `"fixture-account"` {
		t.Fatal("refresh exposed nonfinite reply")
	}
	if tokenEntries.Load() != 0 {
		t.Fatal("unqualified legacy timing entered provider")
	}
	owners.live = false
	refreshStatus, _ = post(refreshPath, input, "management")
	if refreshStatus != 403 {
		t.Fatal("revoked live refresh owner retained authority", refreshStatus)
	}
	owners.live = true
	path := "/private/native/v1/oauth/connect"
	for _, role := range []string{"execution", "cleanup", "missing"} {
		status, _ := post(path, input, role)
		if status != 403 {
			t.Fatal("non-management connected", role, status)
		}
	}
	status, _ := post(path, strings.Replace(input, "fixture-live-owner", "caller-owner", 1), "management")
	if status != 403 {
		t.Fatal("caller owner became authority", status)
	}
	owners.live = false
	status, _ = post(path, input, "management")
	if status != 403 {
		t.Fatal("retired owner mapping connected")
	}
	owners.live = true
	status, raw := post(path, input, "management")
	if status != 200 {
		t.Fatal("opt-in connect absent", status, string(raw))
	}
	var begun service.GatewayNativeOAuthConnectResult
	if json.Unmarshal(raw, &begun) != nil || begun.Operation != "original-mount-operation" {
		t.Fatal("operation changed")
	}
	authorizeURL, err := url.Parse(begun.AuthorizeURL)
	if err != nil || authorizeURL.Query().Get("redirect_uri") != "http://localhost:1455/auth/callback" {
		t.Fatal("fixed localhost callback changed")
	}
	query := url.Values{"code": {"controlled-code-marker"}, "state": {authorizeURL.Query().Get("state")}}.Encode()
	// No bearer; caller owner mapping is now retired. Capability reconstructs
	// original persisted consumer/owner, and it never chooses a new operation.
	owners.live = false
	for range 2 {
		response, err := server.Client().Get(server.URL + "/auth/callback?" + query)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		_ = response.Body.Close() // Secondary cleanup must preserve the response assertions.
		if response.StatusCode != 200 || response.Header.Get("Referrer-Policy") != "no-referrer" || bytes.Contains(data, []byte("controlled-code-marker")) || bytes.Contains(data, []byte("original-mount-operation")) || bytes.Contains(data, []byte("vendor secret")) {
			t.Fatal("callback capability/reflection failed")
		}
	}
	if tokenEntries.Load() != 1 || journal.entries != 1 || journal.row.Operation != "original-mount-operation" || journal.row.State != "unknown" {
		t.Fatal("callback rearmed or changed original operation")
	}
	owners.live = true
	status, raw = post(path+"/read", input, "management")
	if status != 200 || !bytes.Contains(raw, []byte(`"operation":"original-mount-operation"`)) || !bytes.Contains(raw, []byte(`"state":"unknown"`)) {
		t.Fatal("original readback lost")
	}
	for _, bad := range []string{
		"/auth/callback?" + query + "&state=duplicate",
		"/auth/callback?code=controlled-code-marker&%73tate=" + authorizeURL.Query().Get("state"),
		"/auth/%63allback?" + query,
		"/auth/callback?" + strings.Repeat("x", 8193),
		"/private/native/v1/oauth/connect/read?" + query,
	} {
		response, err := server.Client().Get(server.URL + bad)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		_ = response.Body.Close() // Secondary cleanup must preserve the response assertions.
		if response.StatusCode != 400 || bytes.Contains(data, []byte("controlled-code-marker")) {
			t.Fatal("callback alias or query reflection accepted", response.StatusCode)
		}
	}
	mode.owners = nil
	status, _ = post(path, input, "management")
	if status != 403 {
		t.Fatal("missing actual owner seam did not fail closed")
	}
	legacyServer := httptest.NewServer(privateHandler(c.Profile, &oauthMountAdmin{}, gateway, custody, transport, auth))
	defer legacyServer.Close()
	response, err := legacyServer.Client().Get(legacyServer.URL + "/auth/callback?" + query)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close() // Secondary cleanup must preserve the response assertion.
	if response.StatusCode != 400 {
		t.Fatal("legacy callback exception opened")
	}
}

func (s *oauthMountOwner) AuthorizeNativeOAuthRefreshOwner(ctx context.Context, consumer, operation, account, generation string) (string, error) {
	return s.AuthorizeNativeOAuthOwner(ctx, consumer, operation, account, generation)
}

func (s *oauthMountRows) ResolveGatewayNativeOAuthRefresh(ctx context.Context, scope service.GatewayNativeCredentialScope, operation string) (service.GatewayNativeOAuthRefreshResolution, error) {
	if !service.GatewayNativeOAuthScopeAuthorized(ctx, scope) || operation != "original-mount-operation" {
		return service.GatewayNativeOAuthRefreshResolution{}, ErrDenied
	}
	return s.refreshResolution, nil
}

// Counter transitions may invalidate live retention evidence without losing raw heap observation.
func TestNativeNaturalGCConsistency(t *testing.T) {
	before := runtime.MemStats{NumGC: 7, LastGC: 42, NumForcedGC: 1}
	cases := []struct {
		name                     string
		after                    runtime.MemStats
		total, automatic, forced uint64
		want                     bool
	}{
		{"stable", before, 7, 6, 1, true},
		{"cycle completed", runtime.MemStats{NumGC: 8, LastGC: 43, NumForcedGC: 1}, 7, 6, 1, false},
		{"timestamp changed", runtime.MemStats{NumGC: 7, LastGC: 43, NumForcedGC: 1}, 7, 6, 1, false},
		{"forced changed", runtime.MemStats{NumGC: 7, LastGC: 42, NumForcedGC: 2}, 7, 6, 1, false},
		{"metric cycle differs", before, 8, 7, 1, false},
		{"cycle sum differs", before, 7, 7, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeNaturalGCConsistent(before, tc.after, tc.total, tc.automatic, tc.forced); got != tc.want {
				t.Fatalf("live consistency=%v want%v", got, tc.want)
			}
		})
	}
}
