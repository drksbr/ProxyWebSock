package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

type relayOptions struct {
	listenAddr    string
	metricsAddr   string
	agentEntries  []string
	aclPatterns   []string
	maxFrame      int
	wsIdle        time.Duration
	dialTimeoutMs int
}

func newRelayCommand(globals *globalOptions) *cobra.Command {
	opts := &relayOptions{
		listenAddr:    ":8080",
		maxFrame:      32 * 1024,
		wsIdle:        45 * time.Second,
		dialTimeoutMs: 10000,
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

	cmd.Flags().StringVar(&opts.listenAddr, "listen", opts.listenAddr, "listen address for HTTP CONNECT and /tunnel")
	cmd.Flags().StringVar(&opts.metricsAddr, "metrics", "", "optional separate listen address for Prometheus metrics")
	cmd.Flags().StringSliceVar(&opts.agentEntries, "agents", nil, "allowed agent credentials in the form agentId:token (repeatable)")
	cmd.Flags().StringSliceVar(&opts.aclPatterns, "acl-allow", nil, "regex ACLs for allowed host:port destinations (repeatable)")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().DurationVar(&opts.wsIdle, "ws-idle", opts.wsIdle, "maximum idle time on agent websocket before disconnect")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for agent dial acknowledgment (0 disables)")

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

	upgrader websocket.Upgrader
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

	metrics := newRelayMetrics()

	return &relayServer{
		logger:      logger.With("role", "relay"),
		opts:        opts,
		metrics:     metrics,
		agentTokens: agentTokens,
		acl:         acl,
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

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/tunnel", http.HandlerFunc(s.handleTunnel))
	mux.Handle("/", http.HandlerFunc(s.handleProxy))

	httpSrv := &http.Server{
		Addr:              s.opts.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("relay listening", "addr", s.opts.listenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	var metricsSrv *http.Server
	if s.opts.metricsAddr != "" && s.opts.metricsAddr != s.opts.listenAddr {
		metricsSrv = &http.Server{
			Addr:              s.opts.metricsAddr,
			Handler:           promhttp.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			s.logger.Info("metrics listening", "addr", s.opts.metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-s.ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		s.logger.Warn("http shutdown", "error", err)
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("metrics shutdown", "error", err)
		}
	}

	s.agents.Range(func(key, value any) bool {
		if session, ok := value.(*relayAgentSession); ok {
			session.close()
		}
		return true
	})

	return nil
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

func (s *relayServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	agentID, token, err := parseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		s.metrics.authFailures.Inc()
		w.Header().Set("Proxy-Authenticate", `Basic realm="intratun"`)
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}
	if !s.validateAgent(agentID, token) {
		s.metrics.authFailures.Inc()
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
	stream := newRelayStream(streamID, session, clientConn, buf)
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

	id     string
	remote string

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

type relayStream struct {
	id        string
	agent     *relayAgentSession
	client    net.Conn
	bufrw     *bufio.ReadWriter
	once      sync.Once
	closing   chan struct{}
	readyCh   chan error
	readyOnce sync.Once
	handshake chan struct{}
}

func newRelayStream(id string, agent *relayAgentSession, client net.Conn, bufrw *bufio.ReadWriter) *relayStream {
	return &relayStream{
		id:        id,
		agent:     agent,
		client:    client,
		bufrw:     bufrw,
		closing:   make(chan struct{}),
		readyCh:   make(chan error, 1),
		handshake: make(chan struct{}),
	}
}

func (s *relayStream) accept() error {
	if _, err := s.bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	if err := s.bufrw.Flush(); err != nil {
		return err
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
