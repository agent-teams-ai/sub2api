//go:build linux

package gatewaybootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/sys/unix"
)

// Options are explicit fixture transport/trust injection at outer composition.
// Production main passes the zero value. Neither field is decoded from FD 6.
type Options struct {
	Upstream            service.HTTPUpstream
	AuthorityTransport  *http.Transport
	OAuthOwnerAuthority NativeOAuthOwnerAuthority
}

func verifyInherited(fd int, kind uint32, access int) error {
	var s syscall.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	fdFlags, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if syscall.Fstat(fd, &s) != nil || err != nil || fdErr != nil || s.Mode&syscall.S_IFMT != kind || flags&unix.O_ACCMODE != access || flags&unix.O_PATH != 0 || fdFlags&unix.FD_CLOEXEC != 0 {
		return ErrDenied
	}
	if s.Uid != 0 || s.Mode&07777 != 0600 || (kind == syscall.S_IFREG && s.Nlink != 1) {
		return ErrDenied
	}
	return nil
}
func inherited(fd int, kind uint32, access int) (*os.File, error) {
	if verifyInherited(fd, kind, access) != nil {
		return nil, ErrDenied
	}
	// Inherited pipes arrive in blocking mode. Register the read side with
	// Go netpoll before wrapping it so cancellation can interrupt a missing gate.
	if kind == syscall.S_IFIFO && access == unix.O_RDONLY {
		if unix.SetNonblock(fd, true) != nil {
			return nil, ErrDenied
		}
	}
	return os.NewFile(uintptr(fd), "private-native-inherited"), nil
}
func readConfig(f *os.File) (Config, error) {
	defer func() { _ = f.Close() }()
	s, err := f.Stat()
	if err != nil || s.Size() < 1 || s.Size() > configBytes {
		return Config{}, ErrDenied
	}
	// ReadAt ignores the shared description offset; caller Seek/Close/path
	// replacement cannot change which captured inode supplies configuration.
	data, err := io.ReadAll(io.NewSectionReader(f, 0, configBytes+1))
	var c Config
	if err != nil || decodeStrict(data, &c) != nil {
		return Config{}, ErrDenied
	}
	return c, nil
}
func waitGate(ctx context.Context, gate *os.File) error {
	defer func() { _ = gate.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = gate.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(gate, 2))
	if err != nil || string(data) != "G" || ctx.Err() != nil {
		return ErrDenied
	}
	return nil
}

// Run obeys the original protected-launcher identity/FD contract. FD 3 is never
// closed or unlocked here, including failed bootstrap; actual process exit owns
// that release. No random incarnation, lock reopen or background descendants.
func Run(ctx context.Context, options Options) error {
	if ctx == nil || os.Geteuid() == 0 || os.Getegid() == 0 {
		return ErrDenied
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return ErrDenied
	}
	origin, inc := os.Getenv("GATEWAY_LAUNCHER_ORIGIN_REF"), os.Getenv("GATEWAY_LAUNCHER_ENGINE_INCARNATION")
	if os.Getenv("GATEWAY_LAUNCHER_LOCK_FD") != "3" || os.Getenv("GATEWAY_LAUNCHER_READY_FD") != "4" || os.Getenv("GATEWAY_LAUNCHER_GATE_FD") != "5" ||
		!identifier.MatchString(origin) || !incarnation.MatchString(inc) {
		return ErrDenied
	}
	// FD 3 has no os.File wrapper/finalizer: only actual process exit closes it.
	if verifyInherited(3, syscall.S_IFREG, unix.O_RDONLY) != nil {
		return ErrDenied
	}
	ready, err := inherited(4, syscall.S_IFIFO, unix.O_WRONLY)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = ready.Close() }()
	gate, err := inherited(5, syscall.S_IFIFO, unix.O_RDONLY)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = gate.Close() }()
	file, err := inherited(6, syscall.S_IFREG, unix.O_RDONLY)
	if err != nil {
		return ErrDenied
	}
	c, err := readConfig(file)
	if err != nil {
		return ErrDenied
	}
	custody, err := c.validate()
	if err != nil || waitGate(ctx, gate) != nil {
		return ErrDenied
	}
	// All network work is below the durable gate. Never migrate native SQL.
	db, err := sql.Open("postgres", c.PostgresDSN)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	pingCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	err = db.PingContext(pingCtx)
	stop()
	if err != nil {
		return ErrDenied
	}
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	repo := repository.NewAccountRepository(client, db, nil)
	// These are the proven private HTTP integration constructor arguments:
	// group-free admin, no cache/scheduler/probe/refresh/ordinary limiter.
	svcCfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}},
		Gateway: config.GatewayConfig{OpenAIResponseHeaderTimeout: 5}}
	upstream := options.Upstream
	if upstream == nil {
		upstream = repository.NewHTTPUpstream(svcCfg)
	}
	lifetimeUpstream, err := service.NewGatewayNativeLifetimeUpstream(upstream)
	if err != nil {
		return ErrDenied
	}
	gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, svcCfg, nil, nil, nil, nil, nil, lifetimeUpstream, nil, nil, nil, nil, nil, nil, nil, nil)
	adminRepo, ok := repo.(service.AdminAccountRepository)
	if !ok {
		return ErrDenied
	}
	adminSvc := service.NewAdminService(nil, nil, nil, adminRepo, nil, nil, nil, nil, nil, nil, nil, nil, nil, client, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	a, err := newAuthority(c.Authority, options.AuthorityTransport)
	if err != nil {
		return ErrDenied
	}
	defer a.client.CloseIdleConnections()
	auth := authorize(c.Peers)
	tcfg := gatewaytransport.Config{Gateway: gateway, Custody: custody, Authorize: auth,
		Enrollment: gatewaytransport.Enrollment{OriginRef: origin, EngineIncarnation: inc, QualificationRef: c.Profile.QualificationRef},
		Profile:    c.qualifiedProfile(), OpenRouter: c.openRouterProfile(), Codex: c.codexProfile(), MaxEntries: int(c.MaxEntries), CallbackTimeout: 5 * time.Second,
		IOTimeout: 30 * time.Second, ProviderReadIdle: 30 * time.Second, CleanupTimeout: 5 * time.Second, EnvelopeBytes: 5 << 20, CallbackBytes: 262144}
	var oauth *privateOAuth
	if c.OAuth != nil {
		owners := options.OAuthOwnerAuthority
		if owners == nil {
			owners = a
		}
		oauth, err = composePrivateOAuth(repo, db, custody, c.OAuth, owners)
		if err != nil {
			return ErrDenied
		}
		tcfg.OAuth = oauth.dispatch
	}
	a.compose(&tcfg)
	transport, err := gatewaytransport.New(ctx, tcfg)
	if err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	handler := privateHandler(c.Profile, adminSvc, gateway, custody, transport, auth, oauth)
	listener, err := net.Listen("tcp", c.ListenAddress)
	if err != nil {
		return ErrDenied
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16384,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx }}
	served := make(chan error, 1)
	go func() { served <- server.Serve(&boundedListener{Listener: listener, slots: make(chan struct{}, 128)}) }()
	if ctx.Err() != nil {
		_ = server.Close()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transport.Stop(stopCtx)
		return ErrDenied
	}
	if n, err := ready.Write([]byte("R")); err != nil || n != 1 {
		_ = server.Close()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transport.Stop(stopCtx)
		return ErrDenied
	}
	_ = ready.Close()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-served:
	}
	// Closing sockets cancels handler contexts. Stop seals every local lifetime;
	// its timeout never certifies closure/SQL release. FD 3 lives until exit.
	_ = server.Close()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopErr := transport.Stop(stopCtx)
	if serveErr != nil || stopErr != nil {
		return ErrDenied
	}
	return nil
}

func privateHandler(profile ProfileConfig, adminSvc service.AdminService, gateway *service.OpenAIGatewayService, custody *service.GatewayNativeCredentialCustody,
	transport *gatewaytransport.Handler, auth func(*http.Request) (gatewaytransport.Peer, error), oauthMode ...*privateOAuth) http.Handler {
	var oauth *privateOAuth
	if len(oauthMode) == 1 {
		oauth = oauthMode[0]
	}
	router := gin.New()
	authorizeCandidate := func(c *gin.Context) {
		peer, err := auth(c.Request)
		if err != nil || peer.Role != "management" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), peer.ConsumerID)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
	secondary, hasOpenRouter := transport.OpenRouterProfile()
	var second []admin.GatewayNativeProfile
	if hasOpenRouter {
		second = []admin.GatewayNativeProfile{{ID: secondary.Profile, BaseURL: secondary.BaseURL, Model: secondary.Model}}
	}
	admin.RegisterGatewayNativeRoutes(router.Group(""), adminSvc, gateway,
		admin.GatewayNativeProfile{ID: service.GatewayMiMoResponsesProfile, BaseURL: profile.BaseURL, Model: profile.Model}, authorizeCandidate,
		func(*gin.Context, service.GatewayNativeRoute) error { return ErrDenied }, func(*gin.Context, bool, error) {}, custody, second...)
	if oauth != nil {
		authorizeOAuth := func(c *gin.Context) {
			peer, err := auth(c.Request)
			if err != nil || peer.Role != "management" || oauth.owners == nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			bounded, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()
			data, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
			var tuple nativeOAuthOwnerTuple
			if err != nil || len(data) > 4096 || decodeStrict(data, &tuple) != nil || !tuple.valid() {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(data))
			owner, err := oauth.owners.AuthorizeNativeOAuthOwner(bounded, peer.ConsumerID, tuple.Operation, tuple.AccountRef, tuple.Generation)
			if err != nil || bounded.Err() != nil || owner != tuple.OwnerRef {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			ctx, err := service.WithGatewayNativeConsumer(c.Request.Context(), peer.ConsumerID)
			if err == nil {
				ctx, err = service.WithGatewayNativeOAuthOwner(ctx, owner)
			}
			if err != nil {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Request = c.Request.WithContext(ctx)
			c.Next()
		}
		if admin.RegisterGatewayNativeOAuthConnectRoutes(router.Group(""), oauth.connect, authorizeOAuth) != nil || admin.RegisterGatewayNativeOAuthDescriptorRoute(router.Group(""), oauth.dispatch, authorizeOAuth) != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
			})
		}
	}
	// Telemetry uses the same management credential, typed consumer context and
	// shared control budget as candidates. No execution/cleanup authority enters.
	router.GET("/private/native/v1/runtime", authorizeCandidate, nativeRuntime)
	management := transport.ManagementHandler(router)
	callback := transport.NativeOAuthCallbackHandler(router)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The sole query-bearing exception is the exact canonical GET callback.
		// F3 parses/scrubs the capability; this outer boundary also denies aliases,
		// duplicates, noncanonical encodings and body smuggling before bypassing auth.
		if oauth != nil && r.URL.Path == "/auth/callback" {
			query := r.URL.RawQuery
			values, err := url.ParseQuery(query)
			valid := r.Method == http.MethodGet && r.URL.RawPath == "" && !r.URL.ForceQuery && len(query) <= 8192 && len(r.RequestURI) <= 8210 &&
				r.RequestURI == "/auth/callback?"+query && err == nil && values.Encode() == query && len(values) == 2 && len(values["state"]) == 1 && len(values["code"]) == 1 &&
				r.ContentLength == 0 && len(r.TransferEncoding) == 0 && r.Header.Get("Content-Encoding") == ""
			if !valid {
				r.URL.RawQuery = ""
				r.RequestURI = "/auth/callback"
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				r.URL.RawQuery = ""
				r.RequestURI = "/auth/callback"
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			callback.ServeHTTP(w, r.WithContext(bounded))
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(r.RequestURI) > 2048 ||
			r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "private native bootstrap denied", 400)
			return
		}
		switch {
		case r.URL.Path == "/private/native/v1/runtime":
			management.ServeHTTP(w, r)
		case oauth != nil && (r.URL.Path == "/private/native/v1/oauth/connect" || r.URL.Path == "/private/native/v1/oauth/connect/read" || r.URL.Path == "/private/native/v1/oauth/connect/descriptor"):
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "private native bootstrap denied", 400)
				return
			}
			controller := http.NewResponseController(w)
			if controller.SetReadDeadline(time.Now().Add(5*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				http.Error(w, "private native bootstrap denied", http.StatusServiceUnavailable)
				return
			}
			bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			management.ServeHTTP(w, r.WithContext(bounded))
		case r.URL.Path == "/private/native/v1/candidates" || strings.HasPrefix(r.URL.Path, "/private/native/v1/candidates/"):
			management.ServeHTTP(w, r)
		case r.URL.Path == "/private/native/v1/transports" || strings.HasPrefix(r.URL.Path, "/private/native/v1/transports/"):
			transport.ServeHTTP(w, r)
		default:
			// The internally registered /responses direct-review path is unreachable.
			http.Error(w, "private native bootstrap denied", http.StatusNotFound)
		}
	})
}

// nativeRuntimeSnapshot is the fixed GET /private/native/v1/runtime JSON contract
// for the C sampler. Every field is an unsigned integer, except the positive
// integer numGoroutine. There are no optional fields or caller-selected metrics.
//
// Exact keys and sources:
//
//	heapAllocBytes: runtime.MemStats.HeapAlloc, bytes of allocated heap objects.
//	heapInuseBytes: runtime.MemStats.HeapInuse, bytes in in-use heap spans.
//	sysBytes: runtime.MemStats.Sys, bytes obtained from the OS by the Go runtime.
//	numGC: runtime.MemStats.NumGC, completed GC cycles.
//	numGoroutine: runtime.NumGoroutine(), current Go goroutine count.
//
// This describes only the current native Go process. Sys is not RSS, cgroup
// memory, C memory or readiness. The memory snapshot and goroutine count are
// separate observations; callers must not infer an atomic cross-field instant.
type nativeRuntimeSnapshot struct {
	HeapAllocBytes uint64 `json:"heapAllocBytes"`
	HeapInuseBytes uint64 `json:"heapInuseBytes"`
	SysBytes       uint64 `json:"sysBytes"`
	NumGC          uint32 `json:"numGC"`
	NumGoroutine   int    `json:"numGoroutine"`
}

// nativeRuntime reads aggregate counters on demand. It does not force GC,
// retain samples, start polling, or inspect processes/files/configuration.
// Authorization and admission happen before this handler in privateHandler.
func nativeRuntime(c *gin.Context) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	snapshot := nativeRuntimeSnapshot{
		HeapAllocBytes: memory.HeapAlloc,
		HeapInuseBytes: memory.HeapInuse,
		SysBytes:       memory.Sys,
		NumGC:          memory.NumGC,
		NumGoroutine:   runtime.NumGoroutine(),
	}
	// An authenticated sample must never become a cached management response.
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, snapshot)
}

type boundedListener struct {
	net.Listener
	slots chan struct{}
}
type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}
func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// The fixed authenticated callback resolves the original committed TS relation.
// Selectors carry no owner authority, including before physical creation.
type NativeOAuthOwnerAuthority interface {
	AuthorizeNativeOAuthOwner(ctx context.Context, consumer, operation, account, generation string) (string, error)
}
type nativeOAuthOwnerTuple struct {
	Operation  string `json:"operation"`
	OwnerRef   string `json:"owner_ref"`
	AccountRef string `json:"account_ref"`
	Generation string `json:"generation"`
}

func (t nativeOAuthOwnerTuple) valid() bool {
	return service.GatewayNativeCredentialRefValid(t.Operation) && service.GatewayNativeCredentialRefValid(t.OwnerRef) &&
		service.GatewayNativeCredentialRefValid(t.AccountRef) && incarnation.MatchString(t.Generation)
}

type privateOAuth struct {
	connect  *service.GatewayNativeOAuthConnect
	dispatch *service.GatewayNativeOAuthDispatch
	owners   NativeOAuthOwnerAuthority
}

func composePrivateOAuth(repo service.AccountRepository, db *sql.DB, custody *service.GatewayNativeCredentialCustody, cfg *OAuthConfig, owners NativeOAuthOwnerAuthority) (*privateOAuth, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(cfg.IntentKey)
	if err != nil || len(key) != 32 {
		return nil, ErrDenied
	}
	f1, ok := repo.(service.GatewayNativeOAuthRepository)
	if !ok {
		return nil, ErrDenied
	}
	f4, ok := repo.(service.GatewayNativeOAuthDispatchRepository)
	if !ok {
		return nil, ErrDenied
	}
	providerTransport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, MaxConnsPerHost: 2, DisableKeepAlives: true}
	verifier := service.NewGatewayNativeOAuthVerifier(providerTransport)
	enrollment, err := service.NewGatewayNativeOAuthEnrollment(verifier, custody, f1, key)
	if err != nil {
		return nil, ErrDenied
	}
	journal, err := repository.NewGatewayNativeOAuthConnectRepository(db)
	if err != nil {
		return nil, ErrDenied
	}
	connect, err := service.NewGatewayNativeOAuthConnect(key, providerTransport, journal, enrollment, f1)
	if err != nil {
		return nil, ErrDenied
	}
	dispatch, err := service.NewGatewayNativeOAuthDispatch(f4, custody, verifier, providerTransport)
	if err != nil {
		return nil, ErrDenied
	}
	return &privateOAuth{connect: connect, dispatch: dispatch, owners: owners}, nil
}
