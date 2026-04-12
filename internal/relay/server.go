package relay

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme/autocert"
)

//go:embed dist/index.html dist/assets/* dist/logo.svg dist/logo-white.svg
var embeddedDashboard embed.FS

type relayServer struct {
	logger         *slog.Logger
	opts           *relayOptions
	metrics        *relayMetrics
	agentDirectory map[string]*agentRecord
	acl            []*regexp.Regexp

	ctx    context.Context
	cancel context.CancelFunc

	agents sync.Map // map[string]*relayAgentSession

	upgrader    websocket.Upgrader
	acmeManager *autocert.Manager
	statusTmpl  *template.Template
	proxySrv    *http.Server
	secureSrv   *http.Server
	plainSrv    *http.Server
	acmeSrv     *http.Server
	secureLn    net.Listener
	socksLn     net.Listener
	stats       relayCounters
	resources   *resourceTracker
	control     controlplane.Store

	staticFS       fs.FS
	updatesDir     string
	executablePath string
	updateManager  *updateManager
	dnsOverrides   *dnsOverrideStore
	routeHistory   *routeHistory
	diagnosticRuns *diagnosticHistory
	breakers       *circuitBreakerRegistry
	streamSeq      atomic.Uint64
}

type agentRecord struct {
	Login          string
	Password       string
	Identification string
	Location       string
	ACL            []*regexp.Regexp
	ACLPatterns    []string
}

func newRelayServer(logger *slog.Logger, opts *relayOptions) (*relayServer, error) {
	if strings.TrimSpace(opts.agentConfig) == "" {
		return nil, errors.New("--agent-config is required")
	}
	agentDirectory, err := loadAgentConfig(opts.agentConfig)
	if err != nil {
		return nil, err
	}
	if len(agentDirectory) == 0 {
		return nil, errors.New("agent configuration file must define at least one agent")
	}
	if (opts.dashboardUser == "") != (opts.dashboardPass == "") {
		return nil, errors.New("--dashboard-user and --dashboard-pass must be set together")
	}

	acl, err := compileACLs(opts.aclPatterns)
	if err != nil {
		return nil, err
	}

	if opts.maxFrame <= 0 {
		return nil, errors.New("--max-frame must be positive")
	}
	if opts.maxInFlight < 0 {
		return nil, errors.New("--max-inflight cannot be negative")
	}
	if opts.streamQueueDepth <= 0 {
		return nil, errors.New("--stream-queue-depth must be positive")
	}

	if len(opts.acmeHosts) == 0 && strings.TrimSpace(opts.plainListen) == "" {
		return nil, errors.New("at least one --acme-host is required for Let's Encrypt (or use --plain-listen to run behind a reverse proxy)")
	}

	metrics := newRelayMetrics()
	resources := newResourceTracker()

	if opts.acmeCache != "" {
		if err := os.MkdirAll(opts.acmeCache, 0o750); err != nil {
			return nil, fmt.Errorf("create acme cache: %w", err)
		}
	}
	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	updatesDir := opts.updatesDir
	if updatesDir == "" {
		updatesDir = filepath.Dir(executablePath)
	}
	if info, err := os.Stat(updatesDir); err != nil {
		return nil, fmt.Errorf("updates dir: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("updates dir %q is not a directory", updatesDir)
	}
	dnsOverridesFile := strings.TrimSpace(opts.dnsOverridesFile)
	if dnsOverridesFile == "" {
		dnsOverridesFile = filepath.Join(filepath.Dir(opts.agentConfig), "dns-overrides.yaml")
	}
	dnsOverrides, err := newDNSOverrideStore(dnsOverridesFile)
	if err != nil {
		return nil, fmt.Errorf("prepare dns override store: %w", err)
	}
	controlPlaneDB := strings.TrimSpace(opts.controlPlaneDB)
	if controlPlaneDB == "" {
		controlPlaneDB = filepath.Join(filepath.Dir(opts.agentConfig), "controlplane.db")
	}
	var controlStore controlplane.Store
	switch strings.ToLower(controlPlaneDB) {
	case "memory", ":memory:", "mem", "off":
		controlStore = controlplane.NewMemoryStore()
	default:
		controlStore, err = controlplane.NewSQLiteStore(controlPlaneDB)
		if err != nil {
			return nil, fmt.Errorf("prepare control-plane store: %w", err)
		}
	}
	if err := bootstrapLegacyControlPlane(context.Background(), controlStore, agentDirectory); err != nil {
		return nil, fmt.Errorf("bootstrap control plane: %w", err)
	}
	updateManager, err := newUpdateManager(logger.With("component", "updates"), updatesDir)
	if err != nil {
		return nil, fmt.Errorf("prepare update manager: %w", err)
	}

	acmeManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(opts.acmeHosts...),
		Email:      opts.acmeEmail,
	}
	if opts.acmeCache != "" {
		acmeManager.Cache = autocert.DirCache(opts.acmeCache)
	}

	distFS, err := fs.Sub(embeddedDashboard, "dist")
	if err != nil {
		return nil, fmt.Errorf("prepare dashboard assets: %w", err)
	}

	switch mode := strings.ToLower(strings.TrimSpace(opts.streamIDMode)); mode {
	case "", "uuid", "cuid", "counter", "uint64":
	default:
		return nil, fmt.Errorf("unsupported stream id mode %q (use uuid, cuid, counter or uint64)", opts.streamIDMode)
	}

	indexHTMLBytes, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("load dashboard index: %w", err)
	}

	const bootstrapScript = `<script id="status-bootstrap">window.STATUS_BOOTSTRAP = {{ .Bootstrap }};</script>`
	indexTemplateSource := string(indexHTMLBytes)
	if strings.Contains(indexTemplateSource, "</head>") {
		indexTemplateSource = strings.Replace(indexTemplateSource, "</head>", bootstrapScript+"</head>", 1)
	} else {
		indexTemplateSource = bootstrapScript + indexTemplateSource
	}

	tmpl, err := template.New("status").Parse(indexTemplateSource)
	if err != nil {
		return nil, fmt.Errorf("parse status template: %w", err)
	}

	return &relayServer{
		logger:         logger.With("role", "relay"),
		opts:           opts,
		metrics:        metrics,
		agentDirectory: agentDirectory,
		acl:            acl,
		resources:      resources,
		control:        controlStore,
		acmeManager:    acmeManager,
		statusTmpl:     tmpl,
		staticFS:       distFS,
		updatesDir:     updatesDir,
		executablePath: executablePath,
		dnsOverrides:   dnsOverrides,
		routeHistory:   newRouteHistory(defaultRouteHistoryLimit),
		diagnosticRuns: newDiagnosticHistory(defaultDiagnosticHistoryLimit),
		breakers:       newCircuitBreakerRegistry(opts.breakerFailures, opts.breakerCooldown),
		updateManager:  updateManager,
		upgrader: websocket.Upgrader{
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: false,
			ReadBufferSize:    opts.maxFrame,
			WriteBufferSize:   opts.maxFrame,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}, nil
}

func (s *relayServer) nextStreamID() uint64 {
	return s.streamSeq.Add(1)
}

func (s *relayServer) run(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()
	if closer, ok := s.control.(interface{ Close() error }); ok {
		defer func() {
			_ = closer.Close()
		}()
	}

	if s.resources != nil {
		s.resources.start(s.ctx)
	}

	errCh := make(chan error, 1)
	sendErr := func(err error) {
		if err == nil {
			return
		}
		select {
		case errCh <- err:
		default:
		}
	}

	if s.opts.acmeHTTPAddr != "" && len(s.opts.acmeHosts) > 0 {
		s.acmeSrv = &http.Server{
			Addr:              s.opts.acmeHTTPAddr,
			Handler:           s.acmeManager.HTTPHandler(nil),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			s.logger.Info("acme http listening", "addr", s.opts.acmeHTTPAddr)
			if err := s.acmeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				sendErr(fmt.Errorf("acme http: %w", err))
			}
		}()
	}

	proxyMux := http.NewServeMux()
	proxyMux.Handle("/tunnel", http.HandlerFunc(s.handleTunnel))
	proxyMux.HandleFunc("/", s.handleProxy)
	s.proxySrv = &http.Server{
		Addr:              s.opts.proxyListen,
		Handler:           proxyMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		s.logger.Info("proxy listening", "addr", s.opts.proxyListen)
		if err := s.proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sendErr(fmt.Errorf("proxy http: %w", err))
		}
	}()

	secureMux := http.NewServeMux()
	secureMux.Handle("/metrics", promhttp.Handler())
	secureMux.Handle("/tunnel", http.HandlerFunc(s.handleTunnel))
	secureMux.Handle("/autoconfig/", http.HandlerFunc(s.handleAutoConfig))
	secureMux.Handle("/status.json", s.dashboardAuth(http.HandlerFunc(s.handleStatusJSON)))
	secureMux.Handle("/api/agents/", s.dashboardAuth(http.HandlerFunc(s.handleAgentDeploymentAPI)))
	secureMux.Handle("/api/diagnostics", s.dashboardAuth(http.HandlerFunc(s.handleDiagnosticsAPI)))
	secureMux.Handle("/api/control-plane/agent-groups", s.dashboardAuth(http.HandlerFunc(s.handleAgentGroupsAPI)))
	secureMux.Handle("/api/control-plane/agent-groups/", s.dashboardAuth(http.HandlerFunc(s.handleAgentGroupsAPI)))
	secureMux.Handle("/api/control-plane/agent-memberships", s.dashboardAuth(http.HandlerFunc(s.handleAgentMembershipsAPI)))
	secureMux.Handle("/api/control-plane/agent-memberships/", s.dashboardAuth(http.HandlerFunc(s.handleAgentMembershipsAPI)))
	secureMux.Handle("/api/control-plane/destination-profiles", s.dashboardAuth(http.HandlerFunc(s.handleDestinationProfilesAPI)))
	secureMux.Handle("/api/control-plane/destination-profiles/", s.dashboardAuth(http.HandlerFunc(s.handleDestinationProfilesAPI)))
	secureMux.Handle("/api/control-plane/access-grants", s.dashboardAuth(http.HandlerFunc(s.handleAccessGrantsAPI)))
	secureMux.Handle("/api/control-plane/access-grants/", s.dashboardAuth(http.HandlerFunc(s.handleAccessGrantsAPI)))
	secureMux.Handle("/api/control-plane/users", s.dashboardAuth(http.HandlerFunc(s.handleUsersAPI)))
	secureMux.Handle("/api/control-plane/users/", s.dashboardAuth(http.HandlerFunc(s.handleUsersAPI)))
	secureMux.Handle("/api/dns-overrides", s.dashboardAuth(http.HandlerFunc(s.handleDNSOverridesAPI)))
	secureMux.Handle("/api/dns-overrides/", s.dashboardAuth(http.HandlerFunc(s.handleDNSOverridesAPI)))
	secureMux.Handle("/downloads/", s.dashboardAuth(http.HandlerFunc(s.handleDashboardDownloads)))
	secureMux.Handle("/updates/", http.HandlerFunc(s.handleUpdates))
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		protectedFiles := s.dashboardAuth(fileServer)
		secureMux.Handle("/assets/", protectedFiles)
		secureMux.Handle("/logo.svg", protectedFiles)
		secureMux.Handle("/logo-white.svg", protectedFiles)
	}
	secureMux.Handle("/", s.dashboardAuth(http.HandlerFunc(s.handleStatus)))

	s.secureSrv = &http.Server{
		Addr:              s.opts.secureListen,
		Handler:           secureMux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         s.acmeManager.TLSConfig(),
	}

	if strings.TrimSpace(s.opts.plainListen) != "" {
		s.plainSrv = &http.Server{
			Addr:              s.opts.plainListen,
			Handler:           secureMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			s.logger.Info("plain listening (reverse-proxy mode)", "addr", s.opts.plainListen)
			if err := s.plainSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				sendErr(fmt.Errorf("plain serve: %w", err))
			}
		}()
	}

	if len(s.opts.acmeHosts) > 0 {
		go func() {
			ln, err := net.Listen("tcp", s.opts.secureListen)
			if err != nil {
				sendErr(fmt.Errorf("secure listen: %w", err))
				return
			}
			s.secureLn = ln
			s.logger.Info("secure listening", "addr", s.opts.secureListen, "hosts", strings.Join(s.opts.acmeHosts, ","))
			tlsListener := tls.NewListener(ln, s.secureSrv.TLSConfig)
			if err := s.secureSrv.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				sendErr(fmt.Errorf("secure serve: %w", err))
			}
		}()
	}

	if s.opts.socksListen != "" {
		go func() {
			if err := s.serveSocks(); err != nil {
				sendErr(err)
			}
		}()
	}

	var err error
	select {
	case err = <-errCh:
	case <-s.ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.proxySrv != nil {
		if errShutdown := s.proxySrv.Shutdown(shutdownCtx); errShutdown != nil {
			s.logger.Warn("proxy shutdown", "error", errShutdown)
		}
	}
	if s.secureSrv != nil {
		if errShutdown := s.secureSrv.Shutdown(shutdownCtx); errShutdown != nil {
			s.logger.Warn("secure shutdown", "error", errShutdown)
		}
	}
	if s.plainSrv != nil {
		if errShutdown := s.plainSrv.Shutdown(shutdownCtx); errShutdown != nil {
			s.logger.Warn("plain shutdown", "error", errShutdown)
		}
	}
	if s.acmeSrv != nil {
		if errShutdown := s.acmeSrv.Shutdown(shutdownCtx); errShutdown != nil {
			s.logger.Warn("acme http shutdown", "error", errShutdown)
		}
	}
	if s.secureLn != nil {
		_ = s.secureLn.Close()
	}
	if s.socksLn != nil {
		_ = s.socksLn.Close()
	}

	s.agents.Range(func(key, value any) bool {
		if session, ok := value.(*relayAgentSession); ok {
			session.close()
		}
		return true
	})

	return err
}

func (s *relayServer) lookupAgent(id string) (*relayAgentSession, bool) {
	value, ok := s.agents.Load(id)
	if !ok {
		return nil, false
	}
	session, ok := value.(*relayAgentSession)
	return session, ok
}

func (s *relayServer) registerAgent(session *relayAgentSession) {
	old, loaded := s.agents.LoadAndDelete(session.id)
	if loaded {
		if prev, ok := old.(*relayAgentSession); ok {
			prev.close()
		}
	}
	s.agents.Store(session.id, session)
	s.metrics.agentsConnected.Inc()
}

func (s *relayServer) unregisterAgent(id string) {
	if _, ok := s.agents.LoadAndDelete(id); ok {
		s.metrics.agentsConnected.Dec()
	}
}

func (s *relayServer) dialTimeout() time.Duration {
	if s.opts.dialTimeoutMs <= 0 {
		return 0
	}
	return time.Duration(s.opts.dialTimeoutMs) * time.Millisecond
}

func (s *relayServer) validateAgent(agentID, token string) bool {
	_, ok := s.authenticateAgent(agentID, token)
	return ok
}

func (s *relayServer) authenticateAgent(agentID, token string) (*agentRecord, bool) {
	record, ok := s.agentDirectory[agentID]
	if !ok {
		return nil, false
	}
	if !secureStringEquals(record.Password, token) {
		return nil, false
	}
	return record, true
}

func (s *relayServer) dashboardAuth(next http.Handler) http.Handler {
	if s.opts == nil || (s.opts.dashboardUser == "" && s.opts.dashboardPass == "") {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !secureStringEquals(s.opts.dashboardUser, user) || !secureStringEquals(s.opts.dashboardPass, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="intratun-dashboard", charset="UTF-8"`)
			http.Error(w, "dashboard auth required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secureStringEquals(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func (s *relayServer) authorizeTarget(agentID, hostport string) error {
	var patterns []*regexp.Regexp
	if record, ok := s.agentDirectory[agentID]; ok && len(record.ACL) > 0 {
		patterns = record.ACL
	} else {
		patterns = s.acl
	}
	if len(patterns) == 0 {
		return nil
	}
	for _, re := range patterns {
		if re.MatchString(hostport) {
			return nil
		}
	}
	return fmt.Errorf("target %s blocked by ACL", hostport)
}
