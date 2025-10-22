package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

const (
	heartbeatInterval = 10 * time.Second
	heartbeatTimeout  = 25 * time.Second
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
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
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

	heartbeat *heartbeatState
}

func newSession(agent *agent, conn *websocket.Conn) *session {
	return &session{
		agent:     agent,
		conn:      conn,
		streams:   make(map[string]*agentStream),
		logger:    agent.logger.With("session", time.Now().UnixNano()),
		heartbeat: newHeartbeatState(),
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

	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go s.heartbeatLoop(hbCtx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
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
	readDeadline := heartbeatTimeout
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
		messageType, r, err := s.conn.NextReader()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := s.conn.SetReadDeadline(time.Now().Add(heartbeatTimeout)); err != nil {
			return err
		}

		switch messageType {
		case websocket.BinaryMessage:
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			streamID, payload, err := protocol.DecodeBinaryFrame(data)
			if err != nil {
				s.logger.Warn("binary decode failed", "error", err)
				continue
			}
			s.handleBinaryWrite(streamID, payload)
		case websocket.TextMessage:
			var f protocol.Frame
			if err := json.NewDecoder(r).Decode(&f); err != nil {
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
			case protocol.FrameTypeHeartbeat:
				s.handleHeartbeat(f)
			default:
				s.logger.Warn("unknown frame type", "type", f.Type)
			}
		default:
			// ignore other message types
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
		s.heartbeat.recordError(err.Error())
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
		s.heartbeat.recordError(err.Error())
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
	s.handleBinaryWrite(f.StreamID, payload)
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
		s.heartbeat.recordError(f.Error)
	}
}

func (s *session) handleHeartbeat(f protocol.Frame) {
	payload := f.Heartbeat
	if payload == nil {
		s.logger.Warn("heartbeat frame missing payload")
		return
	}

	switch payload.Mode {
	case protocol.HeartbeatModePong:
		ackTime := time.Now()
		if payload.AckAt != 0 {
			ackTime = time.Unix(0, payload.AckAt)
		}
		s.heartbeat.handleAck(payload.Sequence, ackTime)
		_ = s.conn.SetReadDeadline(time.Now().Add(heartbeatTimeout))
	case protocol.HeartbeatModePing:
		reply := &protocol.Frame{
			Type: protocol.FrameTypeHeartbeat,
			Heartbeat: &protocol.HeartbeatPayload{
				Sequence: payload.Sequence,
				SentAt:   payload.SentAt,
				AckAt:    time.Now().UnixNano(),
				Mode:     protocol.HeartbeatModePong,
			},
		}
		if err := s.sendFrame(reply); err != nil {
			s.logger.Debug("heartbeat pong failed", "error", err)
			s.heartbeat.markSendFailure()
			return
		}
	default:
		s.logger.Warn("heartbeat frame with unknown mode", "mode", payload.Mode)
	}
}

func (s *session) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// send first heartbeat immediately to prime the watchdog
	s.sendHeartbeat()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

func (s *session) sendHeartbeat() {
	now := time.Now()
	payload := s.heartbeat.nextPayload(now)
	if payload == nil {
		return
	}
	frame := &protocol.Frame{
		Type:      protocol.FrameTypeHeartbeat,
		Heartbeat: payload,
	}
	if err := s.sendFrame(frame); err != nil {
		s.logger.Debug("heartbeat send failed", "error", err)
		s.heartbeat.markSendFailure()
		return
	}
	s.heartbeat.markSent(payload.Sequence, now)
	s.heartbeat.expirePending(now)
}

type heartbeatState struct {
	seq atomic.Uint64

	mu                  sync.Mutex
	pending             map[uint64]time.Time
	lastRTT             time.Duration
	jitter              time.Duration
	consecutiveFailures int
	lastAck             time.Time
	lastSent            time.Time
	lastError           string
	lastErrorAt         time.Time
}

func newHeartbeatState() *heartbeatState {
	return &heartbeatState{
		pending: make(map[uint64]time.Time),
	}
}

func (h *heartbeatState) nextPayload(now time.Time) *protocol.HeartbeatPayload {
	seq := h.seq.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()

	payload := &protocol.HeartbeatPayload{
		Sequence: seq,
		SentAt:   now.UnixNano(),
		Mode:     protocol.HeartbeatModePing,
	}
	if stats := h.statsSnapshotLocked(); stats != nil {
		payload.Stats = stats
	}
	return payload
}

func (h *heartbeatState) markSent(seq uint64, sentAt time.Time) {
	h.mu.Lock()
	h.pending[seq] = sentAt
	h.lastSent = sentAt
	h.mu.Unlock()
}

func (h *heartbeatState) markSendFailure() {
	h.mu.Lock()
	h.consecutiveFailures++
	h.mu.Unlock()
}

func (h *heartbeatState) handleAck(seq uint64, ackTime time.Time) {
	h.mu.Lock()
	sentAt, ok := h.pending[seq]
	if ok {
		delete(h.pending, seq)
	}
	if !ok {
		h.mu.Unlock()
		return
	}
	rtt := ackTime.Sub(sentAt)
	if rtt < 0 {
		rtt = time.Since(sentAt)
	}
	if rtt < 0 {
		rtt = 0
	}

	if h.lastRTT == 0 {
		h.lastRTT = rtt
	} else {
		delta := rtt - h.lastRTT
		if delta < 0 {
			delta = -delta
		}
		h.jitter = (3*h.jitter + delta) / 4
		h.lastRTT = (3*h.lastRTT + rtt) / 4
	}

	h.consecutiveFailures = 0
	h.lastAck = ackTime
	h.mu.Unlock()
}

func (h *heartbeatState) expirePending(now time.Time) {
	h.mu.Lock()
	for seq, sentAt := range h.pending {
		if now.Sub(sentAt) > heartbeatTimeout {
			delete(h.pending, seq)
			h.consecutiveFailures++
		}
	}
	h.mu.Unlock()
}

func (h *heartbeatState) recordError(message string) {
	if message == "" {
		return
	}
	h.mu.Lock()
	h.lastError = message
	h.lastErrorAt = time.Now()
	h.mu.Unlock()
}

func (h *heartbeatState) statsSnapshotLocked() *protocol.HeartbeatStats {
	if h.lastRTT == 0 && h.jitter == 0 && h.consecutiveFailures == 0 && h.lastError == "" {
		return nil
	}
	stats := &protocol.HeartbeatStats{
		RTTMillis:           durationToMillis(h.lastRTT),
		JitterMillis:        durationToMillis(h.jitter),
		ConsecutiveFailures: h.consecutiveFailures,
	}
	if h.lastError != "" {
		stats.LastError = h.lastError
		if !h.lastErrorAt.IsZero() {
			stats.LastErrorAt = h.lastErrorAt.UnixNano()
		}
	}
	return stats
}

func durationToMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

func (s *session) handleBinaryWrite(streamID string, payload []byte) {
	stream := s.getStream(streamID)
	if stream == nil {
		s.logger.Warn("write for unknown stream", "stream", streamID)
		return
	}
	if len(payload) == 0 {
		return
	}

	total := 0
	for total < len(payload) {
		n, err := stream.conn.Write(payload[total:])
		if err != nil {
			s.logger.Warn("stream write failed", "stream", streamID, "error", err)
			s.heartbeat.recordError(err.Error())
			stream.close()
			_ = s.sendFrame(&protocol.Frame{
				Type:     protocol.FrameTypeError,
				StreamID: streamID,
				Error:    err.Error(),
			})
			return
		}
		total += n
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

func (s *session) sendBinary(streamID string, payload []byte) error {
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
			errSend := s.sendBinary(stream.id, chunk)
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
			s.heartbeat.recordError(err.Error())
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
