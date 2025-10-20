package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
	"github.com/drksbr/ProxyWebSock/internal/util"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

type options struct {
	relayURL      string
	agentID       string
	token         string
	dialTimeoutMs int
	readBuffer    int
	writeBuffer   int
	maxFrame      int
	maxInFlight   int
	reconnectMin  time.Duration
	reconnectMax  time.Duration
	relayParsed   *url.URL
	logger        *slog.Logger
}

func NewCommand(globals *runtime.Options) *cobra.Command {
	opts := &options{
		dialTimeoutMs: 5000,
		readBuffer:    64 * 1024,
		writeBuffer:   64 * 1024,
		maxFrame:      32 * 1024,
		maxInFlight:   256 * 1024,
		reconnectMin:  2 * time.Second,
		reconnectMax:  30 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent that originates tunnels from inside the intranet",
		RunE: func(cmd *cobra.Command, args []string) error {
			if globals.Logger() == nil {
				if err := globals.SetupLogger(); err != nil {
					return err
				}
			}
			if err := opts.validate(); err != nil {
				return err
			}
			opts.logger = globals.Logger().With("component", "agent")
			ctx, cancel := util.WithSignalContext(context.Background())
			defer cancel()
			return opts.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.relayURL, "relay", "", "relay websocket endpoint (wss://host/tunnel)")
	cmd.Flags().StringVar(&opts.agentID, "id", "", "agent identifier")
	cmd.Flags().StringVar(&opts.token, "token", "", "agent shared token")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for dialing internal targets")
	cmd.Flags().IntVar(&opts.readBuffer, "read-buf", opts.readBuffer, "TCP read buffer size per stream")
	cmd.Flags().IntVar(&opts.writeBuffer, "write-buf", opts.writeBuffer, "websocket write buffer size")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().IntVar(&opts.maxInFlight, "max-inflight", opts.maxInFlight, "maximum unacknowledged bytes per stream (0 disables)")

	return cmd
}

func (o *options) validate() error {
	if o.relayURL == "" {
		return errors.New("--relay is required")
	}
	parsed, err := url.Parse(o.relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay url: %w", err)
	}
	if parsed.Scheme != "wss" && parsed.Scheme != "ws" {
		return errors.New("relay url must use ws or wss scheme")
	}
	if parsed.Host == "" {
		return errors.New("relay url missing host")
	}
	o.relayParsed = parsed

	if o.agentID == "" || o.token == "" {
		return errors.New("--id and --token are required")
	}
	if o.maxFrame <= 0 {
		return errors.New("--max-frame must be positive")
	}
	if o.readBuffer <= 0 || o.writeBuffer <= 0 {
		return errors.New("buffers must be positive")
	}
	if o.reconnectMin <= 0 {
		o.reconnectMin = 2 * time.Second
	}
	if o.reconnectMax < o.reconnectMin {
		o.reconnectMax = o.reconnectMin
	}
	return nil
}

func (o *options) run(ctx context.Context) error {
	a := &agent{
		opts:   o,
		logger: o.logger,
	}
	return a.run(ctx)
}

type agent struct {
	opts   *options
	logger *slog.Logger
}

func (a *agent) run(ctx context.Context) error {
	backoff := a.opts.reconnectMin
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		start := time.Now()
		err := a.connectOnce(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err != nil {
			a.logger.Warn("connection failed", "error", err)
		} else {
			a.logger.Info("connection terminated, reconnecting")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > time.Minute {
			backoff = a.opts.reconnectMin
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		if backoff < a.opts.reconnectMax {
			backoff *= 2
			if backoff > a.opts.reconnectMax {
				backoff = a.opts.reconnectMax
			}
		}
	}
}

func (a *agent) connectOnce(ctx context.Context) error {
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: false,
		ReadBufferSize:    a.opts.readBuffer,
		WriteBufferSize:   a.opts.writeBuffer,
	}
	if a.opts.relayParsed.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: a.opts.relayParsed.Hostname(),
		}
	}

	header := http.Header{
		"User-Agent": {fmt.Sprintf("intratun-agent/%s", version.Version)},
	}

	conn, resp, err := dialer.DialContext(ctx, a.opts.relayURL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	session := newSession(a, conn)
	return session.run(ctx)
}

type session struct {
	agent *agent
	conn  *websocket.Conn

	streams   map[string]*agentStream
	streamsMu sync.RWMutex

	writeMu sync.Mutex
	logger  *slog.Logger
}

func newSession(agent *agent, conn *websocket.Conn) *session {
	return &session{
		agent:   agent,
		conn:    conn,
		streams: make(map[string]*agentStream),
		logger:  agent.logger.With("session", time.Now().UnixNano()),
	}
}

func (s *session) run(ctx context.Context) error {
	defer s.conn.Close()

	s.conn.SetReadLimit(1 << 20)
	if err := s.register(); err != nil {
		return err
	}

	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readLoop()
	}()

	pingTicker := time.NewTicker(20 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-pingTicker.C:
			if err := s.sendControl(websocket.PingMessage); err != nil {
				return err
			}
		}
	}
}

func (s *session) register() error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := s.conn.WriteJSON(&protocol.Frame{
		Type:    protocol.FrameTypeRegister,
		AgentID: s.agent.opts.agentID,
		Token:   s.agent.opts.token,
	}); err != nil {
		return fmt.Errorf("send register: %w", err)
	}
	if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	readDeadline := 30 * time.Second
	if err := s.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		return err
	}
	s.conn.SetPongHandler(func(string) error {
		return s.conn.SetReadDeadline(time.Now().Add(readDeadline))
	})
	return nil
}

func (s *session) readLoop() error {
	for {
		var f protocol.Frame
		if err := s.conn.ReadJSON(&f); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		switch f.Type {
		case protocol.FrameTypeDial:
			go s.handleDial(f)
		case protocol.FrameTypeWrite:
			s.handleWrite(f)
		case protocol.FrameTypeClose:
			s.handleClose(f)
		case protocol.FrameTypeError:
			s.handleRelayError(f)
		default:
			s.logger.Warn("unknown frame type", "type", f.Type)
		}
	}
}

func (s *session) handleDial(f protocol.Frame) {
	if f.StreamID == "" {
		s.logger.Warn("dial missing streamId")
		return
	}
	address := net.JoinHostPort(f.Host, fmt.Sprintf("%d", f.Port))

	timeout := time.Duration(s.agent.opts.dialTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		s.logger.Warn("dial failed", "stream", f.StreamID, "target", address, "error", err)
		_ = s.sendFrame(&protocol.Frame{
			Type:     protocol.FrameTypeError,
			StreamID: f.StreamID,
			Error:    err.Error(),
		})
		return
	}

	stream := newAgentStream(f.StreamID, conn, s.agent.opts.maxInFlight)
	if err := s.storeStream(stream); err != nil {
		s.logger.Warn("stream register failed", "stream", f.StreamID, "error", err)
		conn.Close()
		_ = s.sendFrame(&protocol.Frame{
			Type:     protocol.FrameTypeError,
			StreamID: f.StreamID,
			Error:    err.Error(),
		})
		return
	}

	if err := s.sendFrame(&protocol.Frame{
		Type:     protocol.FrameTypeDial,
		StreamID: f.StreamID,
	}); err != nil {
		s.logger.Warn("send dial ack failed", "stream", f.StreamID, "error", err)
		stream.close()
		return
	}

	go s.pipeOutbound(stream)
}

func (s *session) handleWrite(f protocol.Frame) {
	stream := s.getStream(f.StreamID)
	if stream == nil {
		s.logger.Warn("write for unknown stream", "stream", f.StreamID)
		return
	}
	payload, err := protocol.DecodePayload(f.Payload)
	if err != nil {
		s.logger.Warn("payload decode failed", "stream", f.StreamID, "error", err)
		return
	}
	if len(payload) == 0 {
		return
	}

	total := 0
	for total < len(payload) {
		n, err := stream.conn.Write(payload[total:])
		if err != nil {
			s.logger.Warn("stream write failed", "stream", f.StreamID, "error", err)
			stream.close()
			_ = s.sendFrame(&protocol.Frame{
				Type:     protocol.FrameTypeError,
				StreamID: f.StreamID,
				Error:    err.Error(),
			})
			return
		}
		total += n
	}
}

func (s *session) handleClose(f protocol.Frame) {
	stream := s.removeStream(f.StreamID)
	if stream == nil {
		return
	}
	stream.close()
	if f.Error != "" {
		s.logger.Info("stream closed by relay", "stream", f.StreamID, "error", f.Error)
	}
}

func (s *session) handleRelayError(f protocol.Frame) {
	stream := s.removeStream(f.StreamID)
	if stream != nil {
		stream.close()
	}
	if f.Error != "" {
		s.logger.Warn("relay reported error", "stream", f.StreamID, "error", f.Error)
	}
}

func (s *session) sendFrame(f *protocol.Frame) error {
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

func (s *session) sendControl(messageType int) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteControl(messageType, nil, time.Now().Add(10*time.Second))
}

func (s *session) storeStream(stream *agentStream) error {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if _, exists := s.streams[stream.id]; exists {
		return fmt.Errorf("stream %s already exists", stream.id)
	}
	s.streams[stream.id] = stream
	return nil
}

func (s *session) getStream(id string) *agentStream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.streams[id]
}

func (s *session) removeStream(id string) *agentStream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	stream, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	return stream
}

func (s *session) pipeOutbound(stream *agentStream) {
	defer func() {
		s.removeStream(stream.id)
		stream.close()
		_ = s.sendFrame(&protocol.Frame{
			Type:     protocol.FrameTypeClose,
			StreamID: stream.id,
		})
	}()

	bufferSize := s.agent.opts.maxFrame
	if bufferSize > s.agent.opts.readBuffer {
		bufferSize = s.agent.opts.readBuffer
	}
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}

	buf := make([]byte, bufferSize)
	for {
		n, err := stream.conn.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			stream.acquire(n)
			errSend := s.sendFrame(&protocol.Frame{
				Type:     protocol.FrameTypeWrite,
				StreamID: stream.id,
				Payload:  protocol.EncodePayload(chunk),
			})
			stream.release(n)
			if errSend != nil {
				s.logger.Warn("send payload failed", "stream", stream.id, "error", errSend)
				return
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			s.logger.Warn("stream read failed", "stream", stream.id, "error", err)
			_ = s.sendFrame(&protocol.Frame{
				Type:     protocol.FrameTypeError,
				StreamID: stream.id,
				Error:    err.Error(),
			})
			return
		}
	}
}

type agentStream struct {
	id        string
	conn      net.Conn
	limiter   *byteLimiter
	closed    chan struct{}
	closeOnce sync.Once
}

func newAgentStream(id string, conn net.Conn, maxInFlight int) *agentStream {
	return &agentStream{
		id:      id,
		conn:    conn,
		limiter: newByteLimiter(maxInFlight),
		closed:  make(chan struct{}),
	}
}

func (s *agentStream) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.conn.Close()
		if s.limiter != nil {
			s.limiter.Close()
		}
	})
}

func (s *agentStream) acquire(n int) {
	if s.limiter != nil {
		s.limiter.Acquire(n)
	}
}

func (s *agentStream) release(n int) {
	if s.limiter != nil {
		s.limiter.Release(n)
	}
}

type byteLimiter struct {
	max  int
	mu   sync.Mutex
	cond *sync.Cond
	used int
}

func newByteLimiter(max int) *byteLimiter {
	if max <= 0 {
		return nil
	}
	l := &byteLimiter{max: max}
	l.cond = sync.NewCond(&l.mu)
	return l
}

func (b *byteLimiter) Acquire(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used+n > b.max {
		b.cond.Wait()
	}
	b.used += n
}

func (b *byteLimiter) Release(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *byteLimiter) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used = 0
	b.mu.Unlock()
	b.cond.Broadcast()
}
