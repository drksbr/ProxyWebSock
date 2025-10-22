package relay

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/lucsky/cuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
)

//go:embed dist/index.html dist/assets/* dist/logo.svg dist/logo-white.svg
var embeddedDashboard embed.FS

const (
	heartbeatExpectedInterval = 10 * time.Second
	heartbeatDegradedAfter    = 3 * heartbeatExpectedInterval
)

type relayOptions struct {
	proxyListen   string
	secureListen  string
	socksListen   string
	agentConfig   string
	aclPatterns   []string
	maxFrame      int
	wsIdle        time.Duration
	dialTimeoutMs int
	acmeHosts     []string
	acmeEmail     string
	acmeCache     string
	acmeHTTPAddr  string
	streamIDMode  string
}

type relayCounters struct {
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	dialErrors   atomic.Int64
	authFailures atomic.Int64
}

func NewCommand(globals *runtime.Options) *cobra.Command {
	opts := &relayOptions{
		proxyListen:   ":8080",
		secureListen:  ":8443",
		socksListen:   "",
		maxFrame:      32 * 1024,
		wsIdle:        45 * time.Second,
		dialTimeoutMs: 10000,
		acmeHTTPAddr:  "",
		streamIDMode:  "uuid",
	}

	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Public relay accepting agents and proxying HTTP CONNECT",
		RunE: func(cmd *cobra.Command, args []string) error {
			if globals.Logger() == nil {
				if err := globals.SetupLogger(); err != nil {
					return err
				}
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			server, err := newRelayServer(globals.Logger().With("component", "relay"), opts)
			if err != nil {
				return err
			}
			return server.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.proxyListen, "proxy-listen", opts.proxyListen, "listen address for HTTP CONNECT proxy (plain HTTP)")
	cmd.Flags().StringVar(&opts.secureListen, "secure-listen", opts.secureListen, "listen address for TLS endpoints (/tunnel, /, /metrics)")
	cmd.Flags().StringVar(&opts.socksListen, "socks-listen", opts.socksListen, "optional listen address for SOCKS5 proxy (plain TCP)")
	cmd.Flags().StringVar(&opts.agentConfig, "agent-config", "", "path to YAML file containing agent definitions")
	cmd.Flags().StringSliceVar(&opts.aclPatterns, "acl-allow", nil, "regex ACLs for allowed host:port destinations (repeatable)")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().DurationVar(&opts.wsIdle, "ws-idle", opts.wsIdle, "maximum idle time on agent websocket before disconnect")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for agent dial acknowledgment (0 disables)")
	cmd.Flags().StringSliceVar(&opts.acmeHosts, "acme-host", nil, "hostnames for Let's Encrypt certificates (repeatable)")
	cmd.Flags().StringVar(&opts.acmeEmail, "acme-email", "", "contact email for Let's Encrypt registration")
	cmd.Flags().StringVar(&opts.acmeCache, "acme-cache", "", "directory for ACME certificate cache")
	cmd.Flags().StringVar(&opts.acmeHTTPAddr, "acme-http", opts.acmeHTTPAddr, "optional listen address for ACME HTTP-01 challenges (e.g. :80)")
	cmd.Flags().StringVar(&opts.streamIDMode, "stream-id-mode", opts.streamIDMode, "stream identifier generator (uuid or cuid)")

	return cmd
}

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
	acmeSrv     *http.Server
	secureLn    net.Listener
	socksLn     net.Listener
	stats       relayCounters
	resources   *resourceTracker

	staticFS fs.FS
	idGen    func() string
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

	acl, err := compileACLs(opts.aclPatterns)
	if err != nil {
		return nil, err
	}

	if opts.maxFrame <= 0 {
		return nil, errors.New("--max-frame must be positive")
	}

	if len(opts.acmeHosts) == 0 {
		return nil, errors.New("at least one --acme-host is required for Let's Encrypt")
	}

	metrics := newRelayMetrics()
	resources := newResourceTracker()

	if opts.acmeCache != "" {
		if err := os.MkdirAll(opts.acmeCache, 0o750); err != nil {
			return nil, fmt.Errorf("create acme cache: %w", err)
		}
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

	var idGen func() string
	switch mode := strings.ToLower(strings.TrimSpace(opts.streamIDMode)); mode {
	case "", "uuid":
		idGen = uuid.NewString
	case "cuid":
		idGen = cuid.New
	default:
		return nil, fmt.Errorf("unsupported stream id mode %q (use uuid or cuid)", opts.streamIDMode)
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
		acmeManager:    acmeManager,
		statusTmpl:     tmpl,
		staticFS:       distFS,
		idGen:          idGen,
		upgrader: websocket.Upgrader{
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: false,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}, nil
}

func (s *relayServer) nextStreamID() string {
	if s.idGen != nil {
		return s.idGen()
	}
	return uuid.NewString()
}

func (s *relayServer) run(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

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

	// ACME challenge HTTP listener
	if s.opts.acmeHTTPAddr != "" {
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

	// Plain HTTP CONNECT proxy server
	proxyMux := http.NewServeMux()
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

	// TLS-secured server for WebSocket tunnel, metrics, and dashboard
	secureMux := http.NewServeMux()
	secureMux.Handle("/metrics", promhttp.Handler())
	secureMux.Handle("/tunnel", http.HandlerFunc(s.handleTunnel))
	secureMux.Handle("/autoconfig/", http.HandlerFunc(s.handleAutoConfig))
	secureMux.Handle("/status.json", http.HandlerFunc(s.handleStatusJSON))
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		secureMux.Handle("/assets/", fileServer)
		secureMux.Handle("/logo.svg", fileServer)
		secureMux.Handle("/logo-white.svg", fileServer)
	}
	secureMux.Handle("/", http.HandlerFunc(s.handleStatus))

	s.secureSrv = &http.Server{
		Addr:              s.opts.secureListen,
		Handler:           secureMux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         s.acmeManager.TLSConfig(),
	}

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

	// Optional SOCKS5 server
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

func (s *relayServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Warn("upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	session := newRelayAgentSession(s, conn, r.RemoteAddr)
	go session.run()
}

func (s *relayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	payload := s.collectStatus(r)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		s.logger.Warn("status marshal failed", "error", err)
		http.Error(w, "status error", http.StatusInternalServerError)
		return
	}
	view := statusView{
		Bootstrap: template.JS(jsonBytes),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.statusTmpl.Execute(w, view); err != nil {
		s.logger.Warn("status render failed", "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *relayServer) handleStatusJSON(w http.ResponseWriter, r *http.Request) {
	payload := s.collectStatus(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("status json failed", "error", err)
	}
}

func (s *relayServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	agentID, token, err := parseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="intratun"`)
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}
	if !s.validateAgent(agentID, token) {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.authorizeTarget(agentID, r.Host); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	session, ok := s.lookupAgent(agentID)
	if !ok {
		http.Error(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	defer func() {
		if err != nil {
			clientConn.Close()
		}
	}()

	host, port, err := splitHostPort(r.Host)
	if err != nil {
		writeProxyError(buf, fmt.Sprintf("invalid host: %v", err))
		return
	}

	streamID := s.nextStreamID()
	stream := newRelayStream(streamID, session, streamProtoHTTP, clientConn, buf, host, port)
	if err := session.registerStream(stream); err != nil {
		writeProxyError(buf, fmt.Sprintf("stream register failed: %v", err))
		return
	}

	if err := session.send(&protocol.Frame{
		Type:     protocol.FrameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		writeProxyError(buf, fmt.Sprintf("dial send failed: %v", err))
		stream.closeSilent(err)
		return
	}

	if err := stream.waitReady(s.dialTimeout()); err != nil {
		s.metrics.dialErrors.Inc()
		s.stats.dialErrors.Add(1)
		_ = session.send(&protocol.Frame{
			Type:     protocol.FrameTypeClose,
			StreamID: streamID,
			Error:    err.Error(),
		})
		writeProxyError(buf, fmt.Sprintf("dial failed: %v", err))
		stream.closeSilent(err)
		return
	}

	if err := stream.accept(); err != nil {
		stream.closeFromRelay(err)
		return
	}

	go stream.pipeClientOutbound()
}

func (s *relayServer) serveSocks() error {
	ln, err := net.Listen("tcp", s.opts.socksListen)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	s.socksLn = ln
	s.logger.Info("socks listening", "addr", s.opts.socksListen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("socks accept: %w", err)
		}
		go s.handleSocksConn(conn)
	}
}

func (s *relayServer) handleSocksConn(conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	remote := conn.RemoteAddr().String()
	logger := s.logger.With("remote", remote, "protocol", "socks5")
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		logger.Warn("set deadline failed", "error", err)
		return
	}

	versionBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, versionBuf); err != nil {
		logger.Debug("read greeting failed", "error", err)
		return
	}
	if versionBuf[0] != 0x05 {
		_, _ = conn.Write([]byte{0x05, 0xff})
		logger.Warn("unsupported socks version", "version", versionBuf[0])
		return
	}
	methodCount := int(versionBuf[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		logger.Debug("read methods failed", "error", err)
		return
	}
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = conn.Write([]byte{0x05, 0xff})
		logger.Warn("client missing username/password auth")
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		logger.Debug("write method selection failed", "error", err)
		return
	}

	agentID, token, err := readSocksCredentials(conn)
	if err != nil {
		logger.Debug("read credentials failed", "error", err)
		return
	}
	if !s.validateAgent(agentID, token) {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		_, _ = conn.Write([]byte{0x01, 0x01})
		logger.Warn("invalid credentials", "agent", agentID)
		return
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		logger.Debug("write auth success failed", "error", err)
		return
	}

	host, port, err := readSocksRequest(conn)
	if err != nil {
		logger.Debug("read request failed", "error", err)
		_ = writeSocksReply(conn, 0x01)
		return
	}
	targetHostPort := net.JoinHostPort(host, strconv.Itoa(port))
	if err := s.authorizeTarget(agentID, targetHostPort); err != nil {
		logger.Warn("acl denied", "target", targetHostPort)
		_ = writeSocksReply(conn, 0x02)
		return
	}

	session, ok := s.lookupAgent(agentID)
	if !ok {
		logger.Warn("agent missing", "agent", agentID)
		_ = writeSocksReply(conn, 0x05)
		return
	}

	streamID := s.nextStreamID()
	stream := newRelayStream(streamID, session, streamProtoSOCKS5, conn, nil, host, port)
	if err := session.registerStream(stream); err != nil {
		logger.Warn("register stream failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		return
	}

	if err := session.send(&protocol.Frame{
		Type:     protocol.FrameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		logger.Warn("send dial failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		stream.closeSilent(err)
		return
	}

	if err := stream.waitReady(s.dialTimeout()); err != nil {
		s.metrics.dialErrors.Inc()
		s.stats.dialErrors.Add(1)
		_ = session.send(&protocol.Frame{
			Type:     protocol.FrameTypeClose,
			StreamID: streamID,
			Error:    err.Error(),
		})
		logger.Warn("dial timeout", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x05)
		stream.closeSilent(err)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Debug("clear deadline failed", "error", err)
	}

	if err := stream.accept(); err != nil {
		logger.Warn("accept send failed", "stream", streamID, "error", err)
		stream.closeFromRelay(err)
		return
	}

	conn = nil // ownership transferred to stream
	go stream.pipeClientOutbound()
}

func (s *relayServer) collectStatus(r *http.Request) statusPayload {
	agentsByID := make(map[string]statusAgent, len(s.agentDirectory))
	for id, record := range s.agentDirectory {
		agent := statusAgent{
			ID:             id,
			Identification: record.Identification,
			Location:       record.Location,
			Status:         "disconnected",
		}
		if len(record.ACLPatterns) > 0 {
			agent.ACL = append(agent.ACL, record.ACLPatterns...)
		}
		if r != nil {
			agent.AutoConfig = s.autoConfigURL(r, id)
		}
		agentsByID[id] = agent
	}

	s.agents.Range(func(_, value any) bool {
		if session, ok := value.(*relayAgentSession); ok {
			snapshot := session.snapshot()
			base, exists := agentsByID[snapshot.ID]
			if exists && len(snapshot.ACL) == 0 {
				snapshot.ACL = base.ACL
			}
			if snapshot.AutoConfig == "" && r != nil {
				snapshot.AutoConfig = s.autoConfigURL(r, snapshot.ID)
			}
			agentsByID[snapshot.ID] = snapshot
		}
		return true
	})

	agents := make([]statusAgent, 0, len(agentsByID))
	totalStreams := 0
	connectedCount := 0
	for id, agent := range agentsByID {
		if agent.ID == "" {
			agent.ID = id
		}
		if agent.AutoConfig == "" && r != nil {
			agent.AutoConfig = s.autoConfigURL(r, agent.ID)
		}
		if agent.Status == "" {
			agent.Status = "connected"
		}
		if agent.Status != "disconnected" {
			connectedCount++
			totalStreams += len(agent.Streams)
		}
		agents = append(agents, agent)
	}

	sort.Slice(agents, func(i, j int) bool {
		return agents[i].ID < agents[j].ID
	})

	resources := resourceSnapshot{}
	if s.resources != nil {
		const historyLimit = 7 * 24 * 60
		resources = s.resources.snapshot(historyLimit)
	}

	return statusPayload{
		GeneratedAt: time.Now(),
		ProxyAddr:   s.opts.proxyListen,
		SecureAddr:  s.opts.secureListen,
		SocksAddr:   s.opts.socksListen,
		ACMEHosts:   append([]string(nil), s.opts.acmeHosts...),
		Agents:      agents,
		Metrics: statusMetrics{
			AgentsConnected: connectedCount,
			ActiveStreams:   totalStreams,
			BytesUp:         s.stats.bytesUp.Load(),
			BytesDown:       s.stats.bytesDown.Load(),
			DialErrors:      s.stats.dialErrors.Load(),
			AuthFailures:    s.stats.authFailures.Load(),
		},
		Resources: resources,
	}
}

func readSocksCredentials(conn net.Conn) (string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != 0x01 {
		return "", "", fmt.Errorf("unsupported auth version %d", header[0])
	}
	ulen := int(header[1])
	if ulen == 0 {
		return "", "", errors.New("username required")
	}
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", "", err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return "", "", err
	}
	plen := int(header[0])
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", "", err
	}
	return string(username), string(password), nil
}

func readSocksRequest(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid request version %d", header[0])
	}
	if header[1] != 0x01 {
		return "", 0, fmt.Errorf("unsupported command %d", header[1])
	}
	atyp := header[3]
	var host string
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	case 0x03:
		if _, err := io.ReadFull(conn, header[:1]); err != nil {
			return "", 0, err
		}
		length := int(header[0])
		if length == 0 {
			return "", 0, errors.New("empty domain name")
		}
		addr := make([]byte, length)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = string(addr)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	return host, port, nil
}

func writeSocksReply(conn net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

type statusPayload struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	ProxyAddr   string           `json:"proxyAddr"`
	SecureAddr  string           `json:"secureAddr"`
	SocksAddr   string           `json:"socksAddr"`
	ACMEHosts   []string         `json:"acmeHosts"`
	Agents      []statusAgent    `json:"agents"`
	Metrics     statusMetrics    `json:"metrics"`
	Resources   resourceSnapshot `json:"resources"`
}

type statusView struct {
	Bootstrap template.JS
}

type statusMetrics struct {
	AgentsConnected int   `json:"agentsConnected"`
	ActiveStreams   int   `json:"activeStreams"`
	BytesUp         int64 `json:"bytesUp"`
	BytesDown       int64 `json:"bytesDown"`
	DialErrors      int64 `json:"dialErrors"`
	AuthFailures    int64 `json:"authFailures"`
}

type statusAgent struct {
	ID                string         `json:"id"`
	Identification    string         `json:"identification"`
	Location          string         `json:"location"`
	Status            string         `json:"status"`
	Remote            string         `json:"remote,omitempty"`
	ConnectedAt       time.Time      `json:"connectedAt,omitempty"`
	LastHeartbeatAt   time.Time      `json:"lastHeartbeatAt,omitempty"`
	LatencyMillis     float64        `json:"latencyMillis,omitempty"`
	JitterMillis      float64        `json:"jitterMillis,omitempty"`
	HeartbeatSeq      uint64         `json:"heartbeatSeq,omitempty"`
	HeartbeatFailures int            `json:"heartbeatFailures,omitempty"`
	ErrorCount        int64          `json:"errorCount,omitempty"`
	LastError         string         `json:"lastError,omitempty"`
	LastErrorAt       time.Time      `json:"lastErrorAt,omitempty"`
	ACL               []string       `json:"acl,omitempty"`
	Streams           []statusStream `json:"streams"`
	AutoConfig        string         `json:"autoConfig,omitempty"`
}

type statusStream struct {
	StreamID  string    `json:"streamId"`
	Target    string    `json:"target"`
	Protocol  string    `json:"protocol"`
	CreatedAt time.Time `json:"createdAt"`
	BytesUp   int64     `json:"bytesUp"`
	BytesDown int64     `json:"bytesDown"`
}

func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		if idx := strings.LastIndex(hostport, "]"); idx != -1 {
			return hostport[:idx+1]
		}
	}
	if strings.Contains(hostport, ":") {
		host, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return host
		}
	}
	return hostport
}

func portFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

func millisToDuration(ms float64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

func durationToMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

func safeLatencyFromSent(sentAt int64, now time.Time) time.Duration {
	if sentAt == 0 {
		return 0
	}
	sent := time.Unix(0, sentAt)
	latency := now.Sub(sent)
	if latency < 0 {
		return 0
	}
	return latency
}

func generatePAC(agentID, token, socksHost, socksPort, proxyHost, proxyPort string) string {
	socksEntry := fmt.Sprintf("SOCKS5 %s:%s@%s:%s", agentID, token, socksHost, socksPort)
	proxyEntry := fmt.Sprintf("PROXY %s:%s", proxyHost, proxyPort)
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host)) {
    return "DIRECT";
  }
  return "%s; %s; DIRECT";
}
`, socksEntry, proxyEntry)
}

func (s *relayServer) autoConfigURL(r *http.Request, agentID string) string {
	record, ok := s.agentDirectory[agentID]
	if !ok {
		return ""
	}
	if s.opts.socksListen == "" {
		return ""
	}
	scheme := "https"
	if r != nil && r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s/autoconfig/%s.pac?token=%s", scheme, host, url.PathEscape(agentID), url.QueryEscape(record.Password))
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
	if len(record.Password) != len(token) {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(record.Password), []byte(token)) != 1 {
		return nil, false
	}
	return record, true
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

type relayAgentSession struct {
	server *relayServer
	conn   *websocket.Conn

	id             string
	identification string
	location       string
	acl            []*regexp.Regexp
	aclPatterns    []string
	remote         string
	connectedAt    time.Time

	writeMu   sync.Mutex
	streams   map[string]*relayStream
	streamsMu sync.RWMutex

	shutdown chan struct{}
	closed   bool
	closeMu  sync.Mutex

	heartbeatMu          sync.Mutex
	lastHeartbeat        time.Time
	latency              time.Duration
	jitter               time.Duration
	heartbeatSeq         uint64
	heartbeatFailures    int
	lastHeartbeatError   string
	lastHeartbeatErrorAt time.Time

	errorMu     sync.Mutex
	errorCount  int64
	lastError   string
	lastErrorAt time.Time
}

var errSessionClosed = errors.New("agent session closed")

func newRelayAgentSession(server *relayServer, conn *websocket.Conn, remote string) *relayAgentSession {
	return &relayAgentSession{
		server:   server,
		conn:     conn,
		remote:   remote,
		streams:  make(map[string]*relayStream),
		shutdown: make(chan struct{}),
	}
}

func (s *relayAgentSession) run() {
	defer s.close()

	if err := s.performRegister(); err != nil {
		s.server.logger.Warn("register failed", "error", err, "remote", s.remote)
		return
	}

	s.connectedAt = time.Now()
	s.server.registerAgent(s)
	s.server.logger.Info("agent connected", "agent", s.id, "remote", s.remote)

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		s.readLoop()
	}()

	pingInterval := s.server.opts.wsIdle / 2
	if pingInterval <= 0 {
		pingInterval = 15 * time.Second
	}
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-s.shutdown:
			return
		case <-readDone:
			return
		case <-pingTicker.C:
			if err := s.sendControl(websocket.PingMessage); err != nil {
				s.server.logger.Debug("ping failed", "agent", s.id, "error", err)
				return
			}
		}
	}
}

func (s *relayAgentSession) performRegister() error {
	if err := s.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	var f protocol.Frame
	if err := s.conn.ReadJSON(&f); err != nil {
		return fmt.Errorf("read register: %w", err)
	}
	if f.Type != protocol.FrameTypeRegister {
		return errors.New("first frame must be register")
	}
	if f.AgentID == "" {
		return errors.New("register missing agentId")
	}
	record, ok := s.server.authenticateAgent(f.AgentID, f.Token)
	if !ok {
		return errors.New("invalid credentials")
	}
	s.id = record.Login
	s.identification = record.Identification
	s.location = record.Location
	s.acl = record.ACL
	if len(record.ACLPatterns) > 0 {
		s.aclPatterns = append([]string(nil), record.ACLPatterns...)
	}
	if s.server.opts.wsIdle > 0 {
		if err := s.conn.SetReadDeadline(time.Now().Add(s.server.opts.wsIdle)); err != nil {
			return err
		}
	} else {
		if err := s.conn.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
	}
	s.conn.SetPongHandler(func(string) error {
		if s.server.opts.wsIdle <= 0 {
			return nil
		}
		return s.conn.SetReadDeadline(time.Now().Add(s.server.opts.wsIdle))
	})
	return nil
}

func (s *relayAgentSession) readLoop() {
	defer s.conn.Close()
	for {
		messageType, r, err := s.conn.NextReader()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, net.ErrClosed) {
				s.server.logger.Info("agent disconnected", "agent", s.id)
			} else {
				s.server.logger.Warn("agent read failed", "agent", s.id, "error", err)
			}
			return
		}

		switch messageType {
		case websocket.BinaryMessage:
			data, err := io.ReadAll(r)
			if err != nil {
				s.server.logger.Warn("binary read failed", "agent", s.id, "error", err)
				return
			}
			streamID, payload, err := protocol.DecodeBinaryFrame(data)
			if err != nil {
				s.server.logger.Warn("binary decode failed", "agent", s.id, "error", err)
				continue
			}
			s.handleBinaryWrite(streamID, payload)
		case websocket.TextMessage:
			var f protocol.Frame
			if err := json.NewDecoder(r).Decode(&f); err != nil {
				s.server.logger.Warn("frame decode failed", "agent", s.id, "error", err)
				return
			}
			switch f.Type {
			case protocol.FrameTypeDial:
				s.handleDialAck(f)
			case protocol.FrameTypeWrite:
				s.handleWrite(f)
			case protocol.FrameTypeClose:
				s.handleClose(f)
			case protocol.FrameTypeError:
				s.handleError(f)
			case protocol.FrameTypeHeartbeat:
				s.handleHeartbeat(f)
			default:
				s.server.logger.Warn("unknown frame type", "agent", s.id, "type", f.Type)
			}
		default:
			// ignore other message types
		}
	}
}

func (s *relayAgentSession) handleDialAck(f protocol.Frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Warn("dial ack for unknown stream", "agent", s.id, "stream", f.StreamID)
		return
	}
	if f.Error != "" {
		stream.closeFromAgent(errors.New(f.Error))
		return
	}
	stream.markReady(nil)
}

func (s *relayAgentSession) handleWrite(f protocol.Frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Debug("write for unknown stream", "agent", s.id, "stream", f.StreamID)
		return
	}
	payload, err := protocol.DecodePayload(f.Payload)
	if err != nil {
		s.server.logger.Warn("payload decode failed", "agent", s.id, "stream", f.StreamID, "error", err)
		return
	}
	s.handleBinaryWrite(f.StreamID, payload)
}

func (s *relayAgentSession) handleBinaryWrite(streamID string, payload []byte) {
	stream := s.lookupStream(streamID)
	if stream == nil {
		s.server.logger.Debug("write for unknown stream", "agent", s.id, "stream", streamID)
		return
	}
	stream.markReady(nil)
	if len(payload) == 0 {
		return
	}
	if err := stream.writeToClient(payload); err != nil {
		s.server.logger.Debug("client write failed", "agent", s.id, "stream", streamID, "error", err)
		return
	}
	s.server.metrics.bytesDownstream.Add(float64(len(payload)))
}

func (s *relayAgentSession) handleClose(f protocol.Frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		return
	}
	stream.closeFromAgent(nil)
}

func (s *relayAgentSession) handleError(f protocol.Frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Warn("error frame for unknown stream", "agent", s.id, "stream", f.StreamID, "error", f.Error)
		if f.Error != "" {
			s.recordAgentError(f.Error)
		}
		return
	}
	if f.Error != "" {
		s.recordAgentError(f.Error)
	}
	stream.closeFromAgent(errors.New(f.Error))
}

func (s *relayAgentSession) handleHeartbeat(f protocol.Frame) {
	payload := f.Heartbeat
	if payload == nil {
		s.server.logger.Warn("heartbeat frame missing payload", "agent", s.id)
		return
	}

	now := time.Now()
	switch payload.Mode {
	case protocol.HeartbeatModePing, "":
		s.updateHeartbeatFromAgent(payload, now)
		reply := &protocol.Frame{
			Type: protocol.FrameTypeHeartbeat,
			Heartbeat: &protocol.HeartbeatPayload{
				Sequence: payload.Sequence,
				SentAt:   payload.SentAt,
				AckAt:    now.UnixNano(),
				Mode:     protocol.HeartbeatModePong,
			},
		}
		if err := s.send(reply); err != nil {
			s.server.logger.Debug("heartbeat pong failed", "agent", s.id, "error", err)
			s.markHeartbeatFailure()
		}
	case protocol.HeartbeatModePong:
		s.updateHeartbeatAck(payload, now)
	default:
		s.server.logger.Warn("heartbeat frame with unknown mode", "agent", s.id, "mode", payload.Mode)
	}
}

func (s *relayAgentSession) lookupStream(id string) *relayStream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.streams[id]
}

func (s *relayAgentSession) registerStream(stream *relayStream) error {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if s.id == "" {
		return errors.New("agent not registered")
	}
	if _, exists := s.streams[stream.id]; exists {
		return fmt.Errorf("stream %s already exists", stream.id)
	}
	s.streams[stream.id] = stream
	s.server.metrics.activeStreams.Inc()
	return nil
}

func (s *relayAgentSession) removeStream(streamID string) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if _, ok := s.streams[streamID]; ok {
		delete(s.streams, streamID)
		s.server.metrics.activeStreams.Dec()
	}
}

func (s *relayAgentSession) send(f *protocol.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	err := s.conn.WriteJSON(f)
	if err == nil {
		err = s.conn.SetWriteDeadline(time.Time{})
	}
	return err
}

func (s *relayAgentSession) sendBinary(streamID string, payload []byte) error {
	data, err := protocol.EncodeBinaryFrame(streamID, payload)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	err = s.conn.WriteMessage(websocket.BinaryMessage, data)
	if err == nil {
		err = s.conn.SetWriteDeadline(time.Time{})
	}
	return err
}

func (s *relayAgentSession) sendControl(messageType int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteControl(messageType, nil, time.Now().Add(5*time.Second))
}

func (s *relayAgentSession) close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	close(s.shutdown)
	s.closeMu.Unlock()

	s.conn.Close()
	if s.id != "" {
		s.server.unregisterAgent(s.id)
	}
	var streams []*relayStream
	s.streamsMu.Lock()
	if len(s.streams) > 0 {
		streams = make([]*relayStream, 0, len(s.streams))
		for id, stream := range s.streams {
			streams = append(streams, stream)
			delete(s.streams, id)
			s.server.metrics.activeStreams.Dec()
		}
	}
	s.streamsMu.Unlock()
	for _, stream := range streams {
		stream.closeSilent(errSessionClosed)
	}
}

func (s *relayAgentSession) updateHeartbeatFromAgent(payload *protocol.HeartbeatPayload, now time.Time) {
	s.heartbeatMu.Lock()
	s.lastHeartbeat = now
	s.heartbeatSeq = payload.Sequence
	if payload.Stats != nil {
		if payload.Stats.RTTMillis > 0 {
			s.latency = millisToDuration(payload.Stats.RTTMillis)
		} else if payload.SentAt != 0 {
			s.latency = safeLatencyFromSent(payload.SentAt, now)
		}
		if payload.Stats.JitterMillis > 0 {
			s.jitter = millisToDuration(payload.Stats.JitterMillis)
		}
		if payload.Stats.ConsecutiveFailures > 0 {
			s.heartbeatFailures = payload.Stats.ConsecutiveFailures
		} else {
			s.heartbeatFailures = 0
		}
		if payload.Stats.LastError != "" {
			s.lastHeartbeatError = payload.Stats.LastError
			if payload.Stats.LastErrorAt != 0 {
				s.lastHeartbeatErrorAt = time.Unix(0, payload.Stats.LastErrorAt)
			} else {
				s.lastHeartbeatErrorAt = now
			}
		}
	} else {
		if payload.SentAt != 0 {
			s.latency = safeLatencyFromSent(payload.SentAt, now)
		}
		s.heartbeatFailures = 0
	}
	s.heartbeatMu.Unlock()
}

func (s *relayAgentSession) updateHeartbeatAck(payload *protocol.HeartbeatPayload, now time.Time) {
	if payload == nil {
		return
	}
	s.heartbeatMu.Lock()
	s.lastHeartbeat = now
	s.heartbeatSeq = payload.Sequence
	if payload.AckAt != 0 && payload.SentAt != 0 {
		s.latency = safeLatencyFromSent(payload.SentAt, time.Unix(0, payload.AckAt))
	}
	s.heartbeatMu.Unlock()
}

func (s *relayAgentSession) markHeartbeatFailure() {
	s.heartbeatMu.Lock()
	s.heartbeatFailures++
	s.heartbeatMu.Unlock()
}

func (s *relayAgentSession) recordAgentError(message string) {
	if message == "" {
		return
	}
	now := time.Now()
	s.errorMu.Lock()
	s.errorCount++
	s.lastError = message
	s.lastErrorAt = now
	s.errorMu.Unlock()

	s.heartbeatMu.Lock()
	s.lastHeartbeatError = message
	s.lastHeartbeatErrorAt = now
	s.heartbeatMu.Unlock()
}

func (s *relayAgentSession) snapshot() statusAgent {
	now := time.Now()
	agent := statusAgent{
		ID:             s.id,
		Identification: s.identification,
		Location:       s.location,
		Remote:         s.remote,
		ConnectedAt:    s.connectedAt,
		Status:         "connected",
	}
	s.heartbeatMu.Lock()
	lastHeartbeat := s.lastHeartbeat
	latency := s.latency
	jitter := s.jitter
	seq := s.heartbeatSeq
	failures := s.heartbeatFailures
	hbLastError := s.lastHeartbeatError
	hbLastErrorAt := s.lastHeartbeatErrorAt
	s.heartbeatMu.Unlock()

	if lastHeartbeat.IsZero() {
		lastHeartbeat = s.connectedAt
	}
	if !lastHeartbeat.IsZero() && now.Sub(lastHeartbeat) > heartbeatDegradedAfter {
		agent.Status = "degraded"
	}
	if failures > 0 {
		agent.Status = "degraded"
	}

	agent.LastHeartbeatAt = lastHeartbeat
	agent.LatencyMillis = durationToMillis(latency)
	agent.JitterMillis = durationToMillis(jitter)
	agent.HeartbeatSeq = seq
	agent.HeartbeatFailures = failures

	s.errorMu.Lock()
	agent.ErrorCount = s.errorCount
	lastError := s.lastError
	lastErrorAt := s.lastErrorAt
	s.errorMu.Unlock()

	if hbLastErrorAt.After(lastErrorAt) {
		lastErrorAt = hbLastErrorAt
		lastError = hbLastError
	}
	if lastError != "" {
		agent.LastError = lastError
		agent.LastErrorAt = lastErrorAt
	}

	if len(s.aclPatterns) > 0 {
		agent.ACL = append(agent.ACL, s.aclPatterns...)
	}
	s.streamsMu.RLock()
	if len(s.streams) > 0 {
		agent.Streams = make([]statusStream, 0, len(s.streams))
		for _, stream := range s.streams {
			agent.Streams = append(agent.Streams, stream.stats())
		}
		sort.Slice(agent.Streams, func(i, j int) bool {
			return agent.Streams[i].CreatedAt.Before(agent.Streams[j].CreatedAt)
		})
	}
	s.streamsMu.RUnlock()
	return agent
}

type streamProtocol int

const (
	streamProtoHTTP streamProtocol = iota
	streamProtoSOCKS5
)

func (p streamProtocol) String() string {
	switch p {
	case streamProtoHTTP:
		return "http-connect"
	case streamProtoSOCKS5:
		return "socks5"
	default:
		return "unknown"
	}
}

type relayStream struct {
	id         string
	agent      *relayAgentSession
	client     net.Conn
	bufrw      *bufio.ReadWriter
	protocol   streamProtocol
	targetHost string
	targetPort int
	createdAt  time.Time
	once       sync.Once
	closing    chan struct{}
	readyCh    chan error
	readyOnce  sync.Once
	handshake  chan struct{}
	bytesUp    atomic.Int64
	bytesDown  atomic.Int64
}

func newRelayStream(id string, agent *relayAgentSession, proto streamProtocol, client net.Conn, bufrw *bufio.ReadWriter, host string, port int) *relayStream {
	return &relayStream{
		id:         id,
		agent:      agent,
		client:     client,
		bufrw:      bufrw,
		protocol:   proto,
		targetHost: host,
		targetPort: port,
		createdAt:  time.Now(),
		closing:    make(chan struct{}),
		readyCh:    make(chan error, 1),
		handshake:  make(chan struct{}),
	}
}

func (s *relayStream) accept() error {
	switch s.protocol {
	case streamProtoHTTP:
		if s.bufrw != nil {
			if _, err := s.bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return err
			}
			if err := s.bufrw.Flush(); err != nil {
				return err
			}
		} else {
			if _, err := s.client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return err
			}
		}
	case streamProtoSOCKS5:
		reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if _, err := s.client.Write(reply); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown stream protocol")
	}
	select {
	case <-s.handshake:
	default:
		close(s.handshake)
	}
	return nil
}

func (s *relayStream) waitReady(timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-s.readyCh:
		return err
	case <-timer.C:
		return fmt.Errorf("agent did not confirm dial within %s", timeout)
	case <-s.closing:
		return errors.New("stream closed")
	}
}

func (s *relayStream) markReady(err error) {
	s.readyOnce.Do(func() {
		select {
		case s.readyCh <- err:
		default:
		}
	})
}

func (s *relayStream) pipeClientOutbound() {
	buffer := make([]byte, s.agent.server.opts.maxFrame)
	for {
		n, err := s.client.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			if err := s.agent.sendBinary(s.id, chunk); err != nil {
				s.agent.server.logger.Debug("send to agent failed", "agent", s.agent.id, "stream", s.id, "error", err)
				s.closeFromRelay(err)
				return
			}
			s.agent.server.metrics.bytesUpstream.Add(float64(n))
			s.agent.server.stats.bytesUp.Add(int64(n))
			s.bytesUp.Add(int64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.closeFromRelay(nil)
			} else {
				s.closeFromRelay(err)
			}
			return
		}
	}
}

func (s *relayStream) writeToClient(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	select {
	case <-s.handshake:
	case <-s.closing:
		return errors.New("stream closed")
	}
	total := 0
	for total < len(data) {
		n, err := s.client.Write(data[total:])
		if err != nil {
			s.closeFromRelay(err)
			return err
		}
		total += n
	}
	s.bytesDown.Add(int64(total))
	s.agent.server.stats.bytesDown.Add(int64(total))
	return nil
}

func (s *relayStream) closeFromRelay(err error) {
	s.shutdown(true, err)
}

func (s *relayStream) closeFromAgent(err error) {
	s.shutdown(false, err)
}

func (s *relayStream) closeSilent(err error) {
	s.shutdown(false, err)
}

func (s *relayStream) shutdown(notifyAgent bool, err error) {
	s.once.Do(func() {
		s.markReady(err)
		close(s.closing)
		s.agent.removeStream(s.id)
		_ = s.client.Close()
		if notifyAgent {
			frameType := protocol.FrameTypeClose
			frameErr := ""
			if err != nil && err.Error() != "" {
				frameType = protocol.FrameTypeError
				frameErr = err.Error()
			}
			_ = s.agent.send(&protocol.Frame{
				Type:     frameType,
				StreamID: s.id,
				Error:    frameErr,
			})
		}
	})
}

func (s *relayStream) target() string {
	return net.JoinHostPort(s.targetHost, strconv.Itoa(s.targetPort))
}

func (s *relayStream) stats() statusStream {
	return statusStream{
		StreamID:  s.id,
		Target:    s.target(),
		Protocol:  s.protocol.String(),
		CreatedAt: s.createdAt,
		BytesUp:   s.bytesUp.Load(),
		BytesDown: s.bytesDown.Load(),
	}
}

func compileACLs(patterns []string) ([]*regexp.Regexp, error) {
	acls := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile ACL %q: %w", pattern, err)
		}
		acls = append(acls, re)
	}
	return acls, nil
}

func parseProxyAuthorization(header string) (string, string, error) {
	if header == "" {
		return "", "", errors.New("missing proxy authorization")
	}
	const prefix = "Basic "
	if !strings.HasPrefix(strings.ToLower(header), strings.ToLower(prefix)) {
		return "", "", errors.New("unsupported proxy auth scheme")
	}
	encoded := strings.TrimSpace(header[len(prefix):])
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("decode proxy authorization: %w", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid proxy authorization payload")
	}
	return parts[0], parts[1], nil
}

func splitHostPort(host string) (string, int, error) {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

func writeProxyError(buf *bufio.ReadWriter, msg string) {
	_, _ = buf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
	_, _ = buf.WriteString(msg)
	_ = buf.Flush()
}
func (s *relayServer) handleAutoConfig(w http.ResponseWriter, r *http.Request) {
	if s.opts.socksListen == "" {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/autoconfig/")
	if path == "" || !strings.HasSuffix(path, ".pac") {
		http.NotFound(w, r)
		return
	}
	agentID := strings.TrimSuffix(path, ".pac")
	record, ok := s.agentDirectory[agentID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if subtle.ConstantTimeCompare([]byte(record.Password), []byte(token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	host := hostOnly(r.Host)
	if host == "" {
		http.Error(w, "invalid host", http.StatusInternalServerError)
		return
	}

	socksPort := portFromAddr(s.opts.socksListen)
	if socksPort == "" {
		http.Error(w, "socks port unavailable", http.StatusInternalServerError)
		return
	}
	proxyPort := portFromAddr(s.opts.proxyListen)
	if proxyPort == "" {
		proxyPort = "8080"
	}

	pac := generatePAC(agentID, record.Password, host, socksPort, host, proxyPort)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pac)
}
