//go:build linux

package gatewaybootstrap

import (
	"context"
	"database/sql"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/gatewaytransport"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	_ "github.com/lib/pq"
	"golang.org/x/sys/unix"
)

// Options are explicit fixture transport/trust injection at outer composition.
// Production main passes the zero value. These fields are never decoded from FD 6.
type Options struct {
	Upstream                  service.HTTPUpstream
	OpenRouterModelsTransport http.RoundTripper
	AuthorityTransport        *http.Transport
	OAuthOwnerAuthority       NativeOAuthOwnerAuthority
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
	svcCfg := privateGatewayServiceConfig()
	upstream := options.Upstream
	if upstream == nil {
		upstream = repository.NewHTTPUpstream(svcCfg)
	}
	lifetimeUpstream, err := service.NewGatewayNativeLifetimeUpstream(upstream)
	if err != nil {
		return ErrDenied
	}
	gateway := service.NewOpenAIGatewayService(repo, nil, nil, nil, nil, nil, nil, svcCfg, nil, nil, nil, nil, nil, lifetimeUpstream, nil, nil, nil, nil, nil, nil, nil, nil)
	if c.OpenRouter != nil && gateway.SetGatewayOpenRouterModels(service.NewGatewayOpenRouterModels(options.OpenRouterModelsTransport)) != nil {
		return ErrDenied
	}
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
		Profile:    c.qualifiedProfile(), CodingPlans: c.codingPlanProfiles(), Grok: c.grokProfile(), OpenRouter: c.openRouterProfile(), Codex: c.codexProfile(), MaxEntries: int(c.MaxEntries), CallbackTimeout: 5 * time.Second,
		IOTimeout: 30 * time.Second, ProviderReadIdle: service.GatewayNativeProviderReadIdle, CleanupTimeout: 5 * time.Second, EnvelopeBytes: 5 << 20, CallbackBytes: 262144}
	var oauth *privateOAuth
	if c.OAuth != nil || c.Claude != nil || c.Grok != nil || len(c.CodingPlans) > 0 || c.OpenRouter != nil {
		owners := options.OAuthOwnerAuthority
		if owners == nil {
			owners = a
		}
		if c.OAuth != nil {
			oauth, err = composePrivateOAuth(repo, db, custody, c.OAuth, owners)
		} else {
			oauth = &privateOAuth{owners: owners}
		}
		if err != nil {
			return ErrDenied
		}
		if c.Claude != nil {
			if err = composePrivateClaude(oauth, repo, db, custody, owners); err != nil {
				return ErrDenied
			}
		}
		if c.Grok != nil {
			if err = composePrivateGrok(oauth, db, custody, c.Grok, owners); err != nil {
				return ErrDenied
			}
		}
		if len(c.CodingPlans) > 0 || c.Grok != nil {
			if err = composePrivateLimitsV2(oauth, db, owners); err != nil {
				return ErrDenied
			}
		}
		if oauth.limitsV2 != nil {
			tcfg.ProviderLimits = repository.NewGatewayAccountLimitsRepositoryV2(db)
		}
		tcfg.GrokOAuth = oauth.grok
		tcfg.OAuth = oauth.dispatch
		tcfg.ClaudeOAuth = oauth.claude
		tcfg.Claude = c.claudeProfile()
	}
	if oauth != nil {
		if composePrivateModels(oauth, oauth.owners, gateway) != nil {
			return ErrDenied
		}
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
	served := make(chan error, 2)
	var publicServer *http.Server
	closeServers := func() {
		_ = server.Close()
		if publicServer != nil {
			_ = publicServer.Close()
		}
	}
	defer closeServers()
	if c.PublicListenAddress != "" {
		publicListener, listenErr := net.Listen("tcp", c.PublicListenAddress)
		if listenErr != nil {
			return ErrDenied
		}
		defer func() { _ = publicListener.Close() }()
		publicServer = newPublicHTTPServer(ctx, transport.PublicHandler(int(c.PublicMaxActive)))
		go func() {
			served <- publicServer.Serve(&boundedListener{Listener: publicListener, slots: make(chan struct{}, publicSocketBudget(c.PublicMaxActive))})
		}()
	}
	go func() { served <- server.Serve(&boundedListener{Listener: listener, slots: make(chan struct{}, 128)}) }()
	if ctx.Err() != nil {
		closeServers()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transport.Stop(stopCtx)
		return ErrDenied
	}
	if n, err := ready.Write([]byte("R")); err != nil || n != 1 {
		closeServers()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = transport.Stop(stopCtx)
		return ErrDenied
	}
	_ = ready.Close()
	if len(c.CodingPlans) > 0 || c.Grok != nil {
		quotaCtx, stopQuota := context.WithCancel(ctx)
		quotaDone := make(chan struct{})
		go func() { defer close(quotaDone); runPrivateProviderQuota(quotaCtx, db, c, gateway, custody, oauth) }()
		defer func() { stopQuota(); <-quotaDone }()
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-served:
	}
	// Closing sockets cancels handler contexts. Stop seals every local lifetime;
	// its timeout never certifies closure/SQL release. FD 3 lives until exit.
	closeServers()
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopErr := transport.Stop(stopCtx)
	if serveErr != nil || stopErr != nil {
		return ErrDenied
	}
	return nil
}
