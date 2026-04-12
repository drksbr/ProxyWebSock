package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	logctx "github.com/drksbr/ProxyWebSock/internal/logger"
	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

const (
	heartbeatExpectedInterval = 10 * time.Second
	heartbeatDegradedAfter    = 3 * heartbeatExpectedInterval
)

type outboundMessage struct {
	packet          []byte
	binaryStreamID  uint64
	binaryPayload   []byte
	control         *controlMessage
	onWriteComplete func(success bool)
}

type controlMessage struct {
	messageType int
	data        []byte
	deadline    time.Duration
}

type relayAgentSession struct {
	server *relayServer
	conn   *websocket.Conn
	logger *slog.Logger

	id             string
	identification string
	location       string
	goos           string
	goarch         string
	currentVersion string
	acl            []*regexp.Regexp
	aclPatterns    []string
	remote         string
	connectedAt    time.Time

	streams   map[uint64]*relayStream
	streamsMu sync.RWMutex

	diagnosticsMu sync.Mutex
	diagnostics   map[uint64]chan protocol.DiagnosticResponse

	shutdown chan struct{}
	closed   bool
	closeMu  sync.Mutex
	traceID  string

	controlQueue  chan outboundMessage
	dataQueue     chan outboundMessage
	writerDone    chan struct{}
	writerStarted bool
	writerClose   sync.Once

	heartbeatMu           sync.Mutex
	lastHeartbeat         time.Time
	latency               time.Duration
	jitter                time.Duration
	heartbeatSeq          uint64
	heartbeatFailures     int
	lastHeartbeatError    string
	lastHeartbeatErrorAt  time.Time
	heartbeatSendDelay    time.Duration
	heartbeatPending      int
	agentControlQueue     int
	agentDataQueue        int
	agentCPU              float64
	agentRSS              uint64
	agentGoroutines       int
	agentResourcesSampled bool

	errorMu     sync.Mutex
	errorCount  int64
	lastError   string
	lastErrorAt time.Time
}

var (
	errSessionClosed = errors.New("agent session closed")
	errWriterClosed  = errors.New("writer closed")
)

func newRelayAgentSession(server *relayServer, conn *websocket.Conn, remote string) *relayAgentSession {
	traceID := logctx.NewTraceID()
	sessionLogger := server.logger.With("trace_id", traceID, "remote", remote)
	return &relayAgentSession{
		server:       server,
		conn:         conn,
		logger:       sessionLogger,
		remote:       remote,
		streams:      make(map[uint64]*relayStream),
		diagnostics:  make(map[uint64]chan protocol.DiagnosticResponse),
		shutdown:     make(chan struct{}),
		controlQueue: make(chan outboundMessage, 128),
		dataQueue:    make(chan outboundMessage, 256),
		writerDone:   make(chan struct{}),
		traceID:      traceID,
	}
}

func (s *relayAgentSession) startWriter() {
	if s.writerStarted {
		return
	}
	s.writerStarted = true
	go s.writerLoop()
}

func (s *relayAgentSession) stopWriter() {
	s.writerClose.Do(func() {
		if s.controlQueue != nil {
			close(s.controlQueue)
		}
		if s.dataQueue != nil {
			close(s.dataQueue)
		}
	})
	if s.writerStarted {
		<-s.writerDone
		s.writerStarted = false
	}
}

func (s *relayAgentSession) writerLoop() {
	defer close(s.writerDone)
	controlCh := s.controlQueue
	dataCh := s.dataQueue
	for controlCh != nil || dataCh != nil {
		var (
			msg outboundMessage
			ok  bool
		)
		if controlCh != nil {
			select {
			case msg, ok = <-controlCh:
				if !ok {
					controlCh = nil
					continue
				}
				if err := s.writeMessage(&msg); err != nil {
					if msg.onWriteComplete != nil {
						msg.onWriteComplete(false)
					}
					s.logger.Warn("writer failed", "error", err)
					return
				}
				if msg.onWriteComplete != nil {
					msg.onWriteComplete(true)
				}
				continue
			default:
			}
		}
		if controlCh != nil && dataCh != nil {
			select {
			case msg, ok = <-controlCh:
				if !ok {
					controlCh = nil
					continue
				}
			case msg, ok = <-dataCh:
				if !ok {
					dataCh = nil
					continue
				}
			}
		} else if controlCh != nil {
			msg, ok = <-controlCh
			if !ok {
				controlCh = nil
				continue
			}
		} else {
			msg, ok = <-dataCh
			if !ok {
				dataCh = nil
				continue
			}
		}
		if err := s.writeMessage(&msg); err != nil {
			if msg.onWriteComplete != nil {
				msg.onWriteComplete(false)
			}
			s.logger.Warn("writer failed", "error", err)
			return
		}
		if msg.onWriteComplete != nil {
			msg.onWriteComplete(true)
		}
	}
}

func (s *relayAgentSession) writeMessage(msg *outboundMessage) error {
	if msg == nil {
		return nil
	}
	if msg.control != nil {
		ctrl := msg.control
		deadline := ctrl.deadline
		if deadline <= 0 {
			deadline = 5 * time.Second
		}
		return s.conn.WriteControl(ctrl.messageType, ctrl.data, time.Now().Add(deadline))
	}
	if len(msg.packet) > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		if err := s.conn.WriteMessage(websocket.BinaryMessage, msg.packet); err != nil {
			return err
		}
		if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
			s.logger.Debug("reset write deadline failed", "error", err)
		}
		return nil
	}
	if len(msg.binaryPayload) > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		writer, err := s.conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			return err
		}
		writeErr := protocol.WriteDataPacket(writer, msg.binaryStreamID, msg.binaryPayload)
		closeErr := writer.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			return writeErr
		}
		if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
			s.logger.Debug("reset write deadline failed", "error", err)
		}
		return nil
	}
	return nil
}

func (s *relayAgentSession) enqueueControl(msg outboundMessage) error {
	return s.enqueueMessage(s.controlQueue, msg)
}

func (s *relayAgentSession) enqueueData(msg outboundMessage) error {
	return s.enqueueMessage(s.dataQueue, msg)
}

func (s *relayAgentSession) enqueueMessage(ch chan outboundMessage, msg outboundMessage) (err error) {
	if ch == nil {
		return errWriterClosed
	}
	defer func() {
		if r := recover(); r != nil {
			err = errWriterClosed
		}
	}()
	ch <- msg
	return nil
}

func (s *relayAgentSession) run() {
	defer s.close()
	defer s.stopWriter()

	if err := s.performRegister(); err != nil {
		s.logger.Warn("register failed", "error", err)
		return
	}

	s.connectedAt = time.Now()
	s.server.registerAgent(s)
	s.startWriter()
	s.logger.Info("agent connected")

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
				s.logger.Debug("ping failed", "error", err)
				return
			}
		}
	}
}

func (s *relayAgentSession) performRegister() error {
	readLimit := int64(s.server.opts.maxFrame + 64*1024)
	if readLimit < 1<<20 {
		readLimit = 1 << 20
	}
	s.conn.SetReadLimit(readLimit)
	if err := s.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	messageType, r, err := s.conn.NextReader()
	if err != nil {
		return fmt.Errorf("read register: %w", err)
	}
	if messageType != websocket.BinaryMessage {
		return errors.New("register packet must be binary")
	}
	header, body, release, err := protocol.ReadPacketPooled(r, s.server.opts.maxFrame+64*1024)
	if err != nil {
		return fmt.Errorf("read register: %w", err)
	}
	defer release()

	req, err := protocol.DecodeRegisterPacket(header, body)
	if err != nil {
		return fmt.Errorf("decode register: %w", err)
	}
	if req.AgentID == "" {
		return errors.New("register missing agent id")
	}
	record, ok := s.server.authenticateAgent(req.AgentID, req.Token)
	if !ok {
		return errors.New("invalid credentials")
	}
	s.id = record.Login
	s.identification = record.Identification
	s.location = record.Location
	s.goos = strings.TrimSpace(req.GOOS)
	s.goarch = strings.TrimSpace(req.GOARCH)
	s.currentVersion = strings.TrimSpace(req.Version)
	s.acl = record.ACL
	if len(record.ACLPatterns) > 0 {
		s.aclPatterns = append([]string(nil), record.ACLPatterns...)
	}
	if s.server.updateManager != nil {
		s.server.updateManager.observeRuntime(s.id, s.currentVersion, s.goos, s.goarch)
	}
	attrs := []any{slog.String("agent", s.id)}
	if s.identification != "" {
		attrs = append(attrs, slog.String("agent_identification", s.identification))
	}
	if s.location != "" {
		attrs = append(attrs, slog.String("agent_location", s.location))
	}
	s.logger = s.logger.With(attrs...)
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
				s.logger.Info("agent disconnected")
			} else {
				s.logger.Warn("agent read failed", "error", err)
			}
			return
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		header, body, release, err := protocol.ReadPacketPooled(r, s.server.opts.maxFrame+64*1024)
		if err != nil {
			s.logger.Warn("packet read failed", "error", err)
			return
		}
		switch header.Type {
		case protocol.PacketTypeDialResponse:
			resp, err := protocol.DecodeDialResponsePacket(header, body)
			release()
			if err != nil {
				s.logger.Warn("dial response decode failed", "error", err)
				return
			}
			s.handleDialAck(resp)
		case protocol.PacketTypeDiagnosticResponse:
			resp, err := protocol.DecodeDiagnosticResponsePacket(header, body)
			release()
			if err != nil {
				s.logger.Warn("diagnostic response decode failed", "error", err)
				return
			}
			s.handleDiagnosticResponse(resp)
		case protocol.PacketTypeData:
			streamID := header.StreamID
			s.handleBinaryWrite(streamID, body, release)
		case protocol.PacketTypeWindowUpdate:
			update, err := protocol.DecodeWindowUpdatePacket(header, body)
			release()
			if err != nil {
				s.logger.Warn("window decode failed", "error", err)
				return
			}
			s.handleWindow(update)
		case protocol.PacketTypeClose:
			closePacket, err := protocol.DecodeClosePacket(header, body)
			release()
			if err != nil {
				s.logger.Warn("close decode failed", "error", err)
				return
			}
			s.handleClose(closePacket)
		case protocol.PacketTypeHeartbeat:
			payload, err := protocol.DecodeHeartbeatPacket(header, body)
			release()
			if err != nil {
				s.logger.Warn("heartbeat decode failed", "error", err)
				return
			}
			s.handleHeartbeat(payload)
		default:
			release()
			s.logger.Warn("unknown packet type", "type", header.Type)
		}
	}
}

func (s *relayAgentSession) handleDialAck(resp protocol.DialResponse) {
	stream := s.lookupStream(resp.StreamID)
	if stream == nil {
		s.logger.Warn("dial ack for unknown stream", "stream", resp.StreamID)
		return
	}
	if resp.DialAddress != "" || resp.ResolutionSource != "" {
		stream.setResolvedTarget(resp.DialAddress, resp.ResolutionSource)
	}
	if resp.Error != "" {
		stream.closeFromAgent(errors.New(resp.Error))
		return
	}
	stream.markReady(nil)
}

func (s *relayAgentSession) handleDiagnosticResponse(resp protocol.DiagnosticResponse) {
	ch := s.popDiagnosticWaiter(resp.RequestID)
	if ch == nil {
		s.logger.Debug("diagnostic response without waiter", "request", resp.RequestID)
		return
	}
	select {
	case ch <- resp:
	default:
	}
}

func (s *relayAgentSession) handleBinaryWrite(streamID uint64, payload []byte, release func()) {
	stream := s.lookupStream(streamID)
	if stream == nil {
		if release != nil {
			release()
		}
		s.logger.Debug("write for unknown stream", "stream", streamID)
		return
	}
	s.handleBinaryWriteWithStream(stream, payload, release)
}

func (s *relayAgentSession) handleBinaryWriteWithStream(stream *relayStream, payload []byte, release func()) {
	stream.markReady(nil)
	if len(payload) == 0 {
		if release != nil {
			release()
		}
		return
	}
	if err := stream.writeToClientBuffer(payload, len(payload), release); err != nil {
		if errors.Is(err, errClientStreamClosed) {
			return
		}
		if errors.Is(err, errClientBacklog) {
			s.logger.Debug("client backlog exceeded", "stream", stream.id)
		} else {
			s.logger.Debug("enqueue to client failed", "stream", stream.id, "error", err)
		}
		stream.closeFromRelay(err)
	}
}

func (s *relayAgentSession) handleWindow(update protocol.WindowUpdate) {
	if update.Delta == 0 {
		return
	}
	stream := s.lookupStream(update.StreamID)
	if stream == nil {
		s.logger.Debug("window update for unknown stream", "stream", update.StreamID)
		return
	}
	stream.release(int(update.Delta))
}

func (s *relayAgentSession) handleClose(closePacket protocol.ClosePacket) {
	stream := s.lookupStream(closePacket.StreamID)
	if stream == nil {
		return
	}
	if closePacket.Message != "" {
		s.recordAgentError(closePacket.Message)
	}
	if closePacket.Code == protocol.CloseCodeOK {
		stream.closeFromAgent(nil)
		return
	}
	stream.closeFromAgent(errors.New(closePacket.Message))
}

func (s *relayAgentSession) handleHeartbeat(payload *protocol.HeartbeatPayload) {
	if payload == nil {
		s.logger.Warn("heartbeat packet missing payload")
		return
	}

	now := time.Now()
	switch payload.Mode {
	case protocol.HeartbeatModePing, 0:
		s.updateHeartbeatFromAgent(payload, now)
		reply, err := protocol.EncodeHeartbeatPacket(&protocol.HeartbeatPayload{
			Sequence: payload.Sequence,
			SentAt:   payload.SentAt,
			Mode:     protocol.HeartbeatModePong,
		})
		if err != nil {
			s.logger.Debug("heartbeat pong encode failed", "error", err)
			s.markHeartbeatFailure()
			return
		}
		if err := s.sendPacket(reply); err != nil {
			s.logger.Debug("heartbeat pong failed", "error", err)
			s.markHeartbeatFailure()
		}
	case protocol.HeartbeatModePong:
		s.updateHeartbeatAck(payload, now)
	default:
		s.logger.Warn("heartbeat packet with unknown mode", "mode", payload.Mode)
	}
}

func (s *relayAgentSession) lookupStream(id uint64) *relayStream {
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
		return fmt.Errorf("stream %d already exists", stream.id)
	}
	s.streams[stream.id] = stream
	s.server.metrics.activeStreams.Inc()
	return nil
}

func (s *relayAgentSession) removeStream(streamID uint64) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if _, ok := s.streams[streamID]; ok {
		delete(s.streams, streamID)
		s.server.metrics.activeStreams.Dec()
	}
}

func (s *relayAgentSession) sendPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	return s.enqueueControl(outboundMessage{packet: packet})
}

func (s *relayAgentSession) sendDial(req protocol.DialRequest) error {
	packet, err := protocol.EncodeDialRequestPacket(req)
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *relayAgentSession) sendClose(closePacket protocol.ClosePacket) error {
	packet, err := protocol.EncodeClosePacket(closePacket)
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *relayAgentSession) sendWindowUpdate(streamID uint64, delta int) error {
	if delta <= 0 {
		return nil
	}
	packet, err := protocol.EncodeWindowUpdatePacket(protocol.WindowUpdate{
		StreamID: streamID,
		Delta:    uint32(delta),
	})
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *relayAgentSession) sendBinary(streamID uint64, payload []byte, release func()) error {
	msg := outboundMessage{
		binaryStreamID: streamID,
		binaryPayload:  payload,
		onWriteComplete: func(bool) {
			if release != nil {
				release()
			}
		},
	}
	if err := s.enqueueData(msg); err != nil {
		if release != nil {
			release()
		}
		return err
	}
	return nil
}

func (s *relayAgentSession) sendUpdateCommand() error {
	packet, err := protocol.EncodeUpdatePacket()
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *relayAgentSession) sendControl(messageType int) error {
	return s.enqueueControl(outboundMessage{
		control: &controlMessage{
			messageType: messageType,
			deadline:    5 * time.Second,
		},
	})
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
	s.stopWriter()
	if s.id != "" {
		s.server.unregisterAgent(s.id)
	}
	s.diagnosticsMu.Lock()
	if len(s.diagnostics) > 0 {
		for requestID := range s.diagnostics {
			delete(s.diagnostics, requestID)
		}
	}
	s.diagnosticsMu.Unlock()
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
		if payload.Stats.SendDelayMillis > 0 {
			s.heartbeatSendDelay = millisToDuration(payload.Stats.SendDelayMillis)
		} else {
			s.heartbeatSendDelay = 0
		}
		s.heartbeatPending = payload.Stats.Pending
		s.agentControlQueue = payload.Stats.ControlQueueDepth
		s.agentDataQueue = payload.Stats.DataQueueDepth
		s.agentCPU = payload.Stats.CPUPercent
		s.agentRSS = payload.Stats.RSSBytes
		s.agentGoroutines = payload.Stats.Goroutines
		if payload.Stats.CPUPercent != 0 || payload.Stats.RSSBytes != 0 || payload.Stats.Goroutines != 0 {
			s.agentResourcesSampled = true
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
		s.heartbeatSendDelay = 0
		s.heartbeatPending = 0
		s.agentControlQueue = 0
		s.agentDataQueue = 0
		s.agentCPU = 0
		s.agentRSS = 0
		s.agentGoroutines = 0
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
	if payload.SentAt != 0 {
		s.latency = safeLatencyFromSent(payload.SentAt, now)
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
		GOOS:           s.goos,
		GOARCH:         s.goarch,
		CurrentVersion: s.currentVersion,
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
	sendDelay := s.heartbeatSendDelay
	pending := s.heartbeatPending
	agentControlQueue := s.agentControlQueue
	agentDataQueue := s.agentDataQueue
	cpu := s.agentCPU
	rss := s.agentRSS
	goroutines := s.agentGoroutines
	sampled := s.agentResourcesSampled
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
	if sendDelay > 0 {
		agent.HeartbeatSendDelayMillis = durationToMillis(sendDelay)
	}
	if pending > 0 {
		agent.HeartbeatPending = pending
	}
	if sampled {
		cpuCopy := cpu
		rssCopy := rss
		goroutinesCopy := goroutines
		agent.AgentCPUPercent = &cpuCopy
		agent.AgentRSSBytes = &rssCopy
		agent.AgentGoroutines = &goroutinesCopy
	}

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
	if depth := len(s.controlQueue); depth > 0 {
		agent.RelayControlQueueDepth = depth
	}
	if depth := len(s.dataQueue); depth > 0 {
		agent.RelayDataQueueDepth = depth
	}
	if agentControlQueue > 0 {
		agent.AgentControlQueueDepth = agentControlQueue
	}
	if agentDataQueue > 0 {
		agent.AgentDataQueueDepth = agentDataQueue
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
