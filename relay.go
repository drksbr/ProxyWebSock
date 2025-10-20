package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

type relayOptions struct {
	proxyListen   string
	secureListen  string
	socksListen   string
	agentEntries  []string
	aclPatterns   []string
	maxFrame      int
	wsIdle        time.Duration
	dialTimeoutMs int
	acmeHosts     []string
	acmeEmail     string
	acmeCache     string
	acmeHTTPAddr  string
}

type relayCounters struct {
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	dialErrors   atomic.Int64
	authFailures atomic.Int64
}

func newRelayCommand(globals *globalOptions) *cobra.Command {
	opts := &relayOptions{
		proxyListen:   ":8080",
		secureListen:  ":8443",
		socksListen:   "",
		maxFrame:      32 * 1024,
		wsIdle:        45 * time.Second,
		dialTimeoutMs: 10000,
		acmeHTTPAddr:  "",
	}

	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Public relay accepting agents and proxying HTTP CONNECT",
		RunE: func(cmd *cobra.Command, args []string) error {
			if globals.logger == nil {
				if err := globals.setupLogger(); err != nil {
					return err
				}
			}
			ctx := withSignalContext(context.Background())
			server, err := newRelayServer(globals.logger.With("component", "relay"), opts)
			if err != nil {
				return err
			}
			return server.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.proxyListen, "proxy-listen", opts.proxyListen, "listen address for HTTP CONNECT proxy (plain HTTP)")
	cmd.Flags().StringVar(&opts.secureListen, "secure-listen", opts.secureListen, "listen address for TLS endpoints (/tunnel, /, /metrics)")
	cmd.Flags().StringVar(&opts.socksListen, "socks-listen", opts.socksListen, "optional listen address for SOCKS5 proxy (plain TCP)")
	cmd.Flags().StringSliceVar(&opts.agentEntries, "agents", nil, "allowed agent credentials in the form agentId:token (repeatable)")
	cmd.Flags().StringSliceVar(&opts.aclPatterns, "acl-allow", nil, "regex ACLs for allowed host:port destinations (repeatable)")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().DurationVar(&opts.wsIdle, "ws-idle", opts.wsIdle, "maximum idle time on agent websocket before disconnect")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for agent dial acknowledgment (0 disables)")
	cmd.Flags().StringSliceVar(&opts.acmeHosts, "acme-host", nil, "hostnames for Let's Encrypt certificates (repeatable)")
	cmd.Flags().StringVar(&opts.acmeEmail, "acme-email", "", "contact email for Let's Encrypt registration")
	cmd.Flags().StringVar(&opts.acmeCache, "acme-cache", "", "directory for ACME certificate cache")
	cmd.Flags().StringVar(&opts.acmeHTTPAddr, "acme-http", opts.acmeHTTPAddr, "optional listen address for ACME HTTP-01 challenges (e.g. :80)")

	return cmd
}

type relayServer struct {
	logger      *slog.Logger
	opts        *relayOptions
	metrics     *relayMetrics
	agentTokens map[string]string
	acl         []*regexp.Regexp

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
}

func newRelayServer(logger *slog.Logger, opts *relayOptions) (*relayServer, error) {
	agentTokens, err := parseAgentEntries(opts.agentEntries)
	if err != nil {
		return nil, err
	}
	if len(agentTokens) == 0 {
		return nil, errors.New("at least one --agents entry is required")
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

	tmpl, err := template.New("status").Funcs(statusTemplateFuncMap).Parse(statusTemplateHTML)
	if err != nil {
		return nil, fmt.Errorf("parse status template: %w", err)
	}

	return &relayServer{
		logger:      logger.With("role", "relay"),
		opts:        opts,
		metrics:     metrics,
		agentTokens: agentTokens,
		acl:         acl,
		acmeManager: acmeManager,
		statusTmpl:  tmpl,
		upgrader: websocket.Upgrader{
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: false,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}, nil
}

func (s *relayServer) run(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

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
	view := s.snapshotStatus()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.statusTmpl.Execute(w, view); err != nil {
		s.logger.Warn("status render failed", "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
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

	if err := s.authorizeTarget(r.Host); err != nil {
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

	streamID := uuid.NewString()
	stream := newRelayStream(streamID, session, streamProtoHTTP, clientConn, buf, host, port)
	if err := session.registerStream(stream); err != nil {
		writeProxyError(buf, fmt.Sprintf("stream register failed: %v", err))
		return
	}

	if err := session.send(&frame{
		Type:     frameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		writeProxyError(buf, fmt.Sprintf("dial send failed: %v", err))
		stream.close()
		return
	}

	if err := stream.waitReady(s.dialTimeout()); err != nil {
		s.metrics.dialErrors.Inc()
		s.stats.dialErrors.Add(1)
		_ = session.send(&frame{
			Type:     frameTypeClose,
			StreamID: streamID,
			Error:    err.Error(),
		})
		writeProxyError(buf, fmt.Sprintf("dial failed: %v", err))
		stream.close()
		return
	}

	if err := stream.accept(); err != nil {
		stream.close()
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
	if err := s.authorizeTarget(targetHostPort); err != nil {
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

	streamID := uuid.NewString()
	stream := newRelayStream(streamID, session, streamProtoSOCKS5, conn, nil, host, port)
	if err := session.registerStream(stream); err != nil {
		logger.Warn("register stream failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		return
	}

	if err := session.send(&frame{
		Type:     frameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		logger.Warn("send dial failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		stream.close()
		return
	}

	if err := stream.waitReady(s.dialTimeout()); err != nil {
		s.metrics.dialErrors.Inc()
		s.stats.dialErrors.Add(1)
		_ = session.send(&frame{
			Type:     frameTypeClose,
			StreamID: streamID,
			Error:    err.Error(),
		})
		logger.Warn("dial timeout", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x05)
		stream.close()
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Debug("clear deadline failed", "error", err)
	}

	if err := stream.accept(); err != nil {
		logger.Warn("accept send failed", "stream", streamID, "error", err)
		stream.close()
		return
	}

	conn = nil // ownership transferred to stream
	go stream.pipeClientOutbound()
}

func (s *relayServer) snapshotStatus() statusView {
	agents := make([]statusAgent, 0)
	s.agents.Range(func(_, value any) bool {
		if session, ok := value.(*relayAgentSession); ok {
			agents = append(agents, session.snapshot())
		}
		return true
	})
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].ID < agents[j].ID
	})
	totalStreams := 0
	for _, agent := range agents {
		totalStreams += len(agent.Streams)
	}

	view := statusView{
		GeneratedAt: time.Now(),
		ProxyAddr:   s.opts.proxyListen,
		SecureAddr:  s.opts.secureListen,
		SocksAddr:   s.opts.socksListen,
		ACMEHosts:   append([]string(nil), s.opts.acmeHosts...),
		Agents:      agents,
		Metrics: statusMetrics{
			AgentsConnected: len(agents),
			ActiveStreams:   totalStreams,
			BytesUp:         s.stats.bytesUp.Load(),
			BytesDown:       s.stats.bytesDown.Load(),
			DialErrors:      s.stats.dialErrors.Load(),
			AuthFailures:    s.stats.authFailures.Load(),
		},
	}
	return view
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

type statusView struct {
	GeneratedAt time.Time
	ProxyAddr   string
	SecureAddr  string
	SocksAddr   string
	ACMEHosts   []string
	Agents      []statusAgent
	Metrics     statusMetrics
}

type statusMetrics struct {
	AgentsConnected int
	ActiveStreams   int
	BytesUp         int64
	BytesDown       int64
	DialErrors      int64
	AuthFailures    int64
}

type statusAgent struct {
	ID          string
	Remote      string
	ConnectedAt time.Time
	Streams     []statusStream
}

type statusStream struct {
	StreamID  string
	Target    string
	Protocol  string
	CreatedAt time.Time
	BytesUp   int64
	BytesDown int64
}

var statusTemplateFuncMap = template.FuncMap{
	"since":      humanSince,
	"formatTime": humanTime,
	"humanBytes": humanBytes,
}

func humanSince(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	d := time.Since(t)
	if d < 0 {
		d = -d
	}
	return d.Truncate(time.Second).String()
}

func humanTime(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	return t.Local().Format(time.RFC3339)
}

func humanBytes(v any) string {
	var value float64
	switch n := v.(type) {
	case float64:
		value = n
	case float32:
		value = float64(n)
	case int64:
		value = float64(n)
	case int32:
		value = float64(n)
	case int:
		value = float64(n)
	default:
		return "-"
	}
	if value < 1024 {
		return fmt.Sprintf("%.0f B", value)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	div, exp := 1024.0, 0
	for value >= div && exp < len(units) {
		value /= 1024
		exp++
		if exp == len(units) {
			break
		}
	}
	return fmt.Sprintf("%.2f %s", value, units[exp-1])
}

const statusTemplateHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Intratun Relay Status</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100">
  <div class="max-w-6xl mx-auto px-4 py-8 space-y-10">
    <header class="space-y-4">
      <h1 class="text-3xl font-semibold tracking-tight">Intratun Relay</h1>
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Proxy (HTTP CONNECT)</div>
          <div class="text-lg font-mono mt-1">{{.ProxyAddr}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Secure (WSS / Metrics)</div>
          <div class="text-lg font-mono mt-1">{{.SecureAddr}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">SOCKS5</div>
          <div class="text-lg font-mono mt-1">{{if .SocksAddr}}{{.SocksAddr}}{{else}}disabled{{end}}</div>
        </div>
      </div>
      <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div class="text-sm text-slate-400 mb-2">ACME Hosts</div>
        <div class="font-mono text-sm">{{range .ACMEHosts}}{{.}} {{end}}</div>
      </div>
    </header>

    <section>
      <h2 class="text-xl font-semibold mb-4">Resumo</h2>
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Agentes Conectados</div>
          <div class="text-3xl font-semibold mt-1">{{.Metrics.AgentsConnected}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Streams Ativas</div>
          <div class="text-3xl font-semibold mt-1">{{.Metrics.ActiveStreams}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Bytes (cliente → intranet)</div>
          <div class="text-lg font-mono mt-1">{{humanBytes .Metrics.BytesUp}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Bytes (intranet → cliente)</div>
          <div class="text-lg font-mono mt-1">{{humanBytes .Metrics.BytesDown}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Falhas de Dial</div>
          <div class="text-lg font-mono mt-1">{{.Metrics.DialErrors}}</div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="text-sm text-slate-400">Falhas de Autenticação</div>
          <div class="text-lg font-mono mt-1">{{.Metrics.AuthFailures}}</div>
        </div>
      </div>
    </section>

    <section>
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-xl font-semibold">Agentes</h2>
        <div class="text-sm text-slate-400">Atualizado {{formatTime .GeneratedAt}}</div>
      </div>
      {{if .Agents}}
      <div class="space-y-6">
        {{range .Agents}}
        <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <div class="text-lg font-semibold">{{.ID}}</div>
              <div class="text-sm text-slate-400">Remoto {{.Remote}} · Conectado há {{since .ConnectedAt}}</div>
            </div>
            <div class="text-sm text-slate-400">{{len .Streams}} streams ativas</div>
          </div>
          {{if .Streams}}
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-slate-800 text-sm">
              <thead class="text-slate-400">
                <tr>
                  <th class="px-3 py-2 text-left">Stream</th>
                  <th class="px-3 py-2 text-left">Destino</th>
                  <th class="px-3 py-2 text-left">Protocolo</th>
                  <th class="px-3 py-2 text-left">Criada</th>
                  <th class="px-3 py-2 text-left">⬆ Bytes</th>
                  <th class="px-3 py-2 text-left">⬇ Bytes</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800">
                {{range .Streams}}
                <tr>
                  <td class="px-3 py-2 font-mono text-xs">{{.StreamID}}</td>
                  <td class="px-3 py-2 font-mono text-xs">{{.Target}}</td>
                  <td class="px-3 py-2 uppercase">{{.Protocol}}</td>
                  <td class="px-3 py-2 text-slate-300">{{since .CreatedAt}}</td>
                  <td class="px-3 py-2 text-slate-300">{{humanBytes .BytesUp}}</td>
                  <td class="px-3 py-2 text-slate-300">{{humanBytes .BytesDown}}</td>
                </tr>
                {{end}}
              </tbody>
            </table>
          </div>
          {{else}}
          <div class="text-sm text-slate-400">Nenhum fluxo ativo</div>
          {{end}}
        </div>
        {{end}}
      </div>
      {{else}}
      <div class="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-slate-400">
        Nenhum agente conectado.
      </div>
      {{end}}
    </section>
  </div>
</body>
</html>`

func (s *relayServer) validateAgent(agentID, token string) bool {
	expected, ok := s.agentTokens[agentID]
	if !ok {
		return false
	}
	if len(expected) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func (s *relayServer) authorizeTarget(hostport string) error {
	if len(s.acl) == 0 {
		return nil
	}
	for _, re := range s.acl {
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

	id          string
	remote      string
	connectedAt time.Time

	writeMu   sync.Mutex
	streams   map[string]*relayStream
	streamsMu sync.RWMutex

	shutdown chan struct{}
	closed   bool
	closeMu  sync.Mutex
}

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

	var f frame
	if err := s.conn.ReadJSON(&f); err != nil {
		return fmt.Errorf("read register: %w", err)
	}
	if f.Type != frameTypeRegister {
		return errors.New("first frame must be register")
	}
	if f.AgentID == "" {
		return errors.New("register missing agentId")
	}
	if !s.server.validateAgent(f.AgentID, f.Token) {
		return errors.New("invalid credentials")
	}
	s.id = f.AgentID
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
		var f frame
		if err := s.conn.ReadJSON(&f); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, net.ErrClosed) {
				s.server.logger.Info("agent disconnected", "agent", s.id)
			} else {
				s.server.logger.Warn("agent read failed", "agent", s.id, "error", err)
			}
			return
		}
		switch f.Type {
		case frameTypeDial:
			s.handleDialAck(f)
		case frameTypeWrite:
			s.handleWrite(f)
		case frameTypeClose:
			s.handleClose(f)
		case frameTypeError:
			s.handleError(f)
		default:
			s.server.logger.Warn("unknown frame type", "agent", s.id, "type", f.Type)
		}
	}
}

func (s *relayAgentSession) handleDialAck(f frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Warn("dial ack for unknown stream", "agent", s.id, "stream", f.StreamID)
		return
	}
	if f.Error != "" {
		stream.closeWithError(errors.New(f.Error))
		return
	}
	stream.markReady(nil)
}

func (s *relayAgentSession) handleWrite(f frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Debug("write for unknown stream", "agent", s.id, "stream", f.StreamID)
		return
	}
	stream.markReady(nil)
	payload, err := decodePayload(f.Payload)
	if err != nil {
		s.server.logger.Warn("payload decode failed", "agent", s.id, "stream", f.StreamID, "error", err)
		return
	}
	if len(payload) == 0 {
		return
	}
	if err := stream.writeToClient(payload); err != nil {
		s.server.logger.Debug("client write failed", "agent", s.id, "stream", f.StreamID, "error", err)
		stream.close()
		return
	}
	s.server.metrics.bytesDownstream.Add(float64(len(payload)))
}

func (s *relayAgentSession) handleClose(f frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		return
	}
	stream.close()
}

func (s *relayAgentSession) handleError(f frame) {
	stream := s.lookupStream(f.StreamID)
	if stream == nil {
		s.server.logger.Warn("error frame for unknown stream", "agent", s.id, "stream", f.StreamID, "error", f.Error)
		return
	}
	stream.closeWithError(errors.New(f.Error))
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

func (s *relayAgentSession) send(f *frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteJSON(f)
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
	s.streamsMu.Lock()
	for id, stream := range s.streams {
		stream.close()
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
}

func (s *relayAgentSession) snapshot() statusAgent {
	agent := statusAgent{
		ID:          s.id,
		Remote:      s.remote,
		ConnectedAt: s.connectedAt,
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
			if err := s.agent.send(&frame{
				Type:     frameTypeWrite,
				StreamID: s.id,
				Payload:  encodePayload(chunk),
			}); err != nil {
				s.agent.server.logger.Debug("send to agent failed", "agent", s.agent.id, "stream", s.id, "error", err)
				break
			}
			s.agent.server.metrics.bytesUpstream.Add(float64(n))
			s.agent.server.stats.bytesUp.Add(int64(n))
			s.bytesUp.Add(int64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = s.agent.send(&frame{
					Type:     frameTypeClose,
					StreamID: s.id,
				})
			} else {
				_ = s.agent.send(&frame{
					Type:     frameTypeError,
					StreamID: s.id,
					Error:    err.Error(),
				})
			}
			break
		}
	}
	s.close()
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
			return err
		}
		total += n
	}
	s.bytesDown.Add(int64(total))
	s.agent.server.stats.bytesDown.Add(int64(total))
	return nil
}

func (s *relayStream) close() {
	s.once.Do(func() {
		s.markReady(errors.New("stream closed"))
		close(s.closing)
		s.agent.removeStream(s.id)
		s.client.Close()
	})
}

func (s *relayStream) closeWithError(err error) {
	s.markReady(err)
	s.agent.server.logger.Debug("closing stream", "agent", s.agent.id, "stream", s.id, "error", err)
	s.close()
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

func parseAgentEntries(entries []string) (map[string]string, error) {
	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid agent entry %q, expected agentId:token", entry)
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
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
