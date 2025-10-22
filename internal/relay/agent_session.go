package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

const (
	heartbeatExpectedInterval = 10 * time.Second
	heartbeatDegradedAfter    = 3 * heartbeatExpectedInterval
)

type outboundMessage struct {
	frame   *protocol.Frame
	binary  []byte
	control *controlMessage
	onWrite func(success bool)
}

type controlMessage struct {
	messageType int
	data        []byte
	deadline    time.Duration
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

	streams   map[string]*relayStream
	streamsMu sync.RWMutex

	shutdown chan struct{}
	closed   bool
	closeMu  sync.Mutex

	controlQueue  chan outboundMessage
	dataQueue     chan outboundMessage
	writerDone    chan struct{}
	writerStarted bool
	writerClose   sync.Once

	heartbeatMu          sync.Mutex
	lastHeartbeat        time.Time
	latency              time.Duration
	jitter               time.Duration
	heartbeatSeq         uint64
	heartbeatFailures    int
	lastHeartbeatError   string
	lastHeartbeatErrorAt time.Time
	heartbeatSendDelay   time.Duration
	heartbeatPending     int
	agentControlQueue    int
	agentDataQueue       int
	agentCPU             float64
	agentRSS             uint64
	agentGoroutines      int

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
	return &relayAgentSession{
		server:       server,
		conn:         conn,
		remote:       remote,
		streams:      make(map[string]*relayStream),
		shutdown:     make(chan struct{}),
		controlQueue: make(chan outboundMessage, 128),
		dataQueue:    make(chan outboundMessage, 256),
		writerDone:   make(chan struct{}),
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
					if msg.onWrite != nil {
						msg.onWrite(false)
					}
					s.server.logger.Warn("writer failed", "agent", s.id, "error", err)
					return
				}
				if msg.onWrite != nil {
					msg.onWrite(true)
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
			if msg.onWrite != nil {
				msg.onWrite(false)
			}
			s.server.logger.Warn("writer failed", "agent", s.id, "error", err)
			return
		}
		if msg.onWrite != nil {
			msg.onWrite(true)
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
	if msg.frame != nil {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		writeErr := s.conn.WriteJSON(msg.frame)
		if writeErr != nil {
			return writeErr
		}
		if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
			s.server.logger.Debug("reset write deadline failed", "agent", s.id, "error", err)
		}
		return nil
	}
	if len(msg.binary) > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		writeErr := s.conn.WriteMessage(websocket.BinaryMessage, msg.binary)
		if writeErr != nil {
			return writeErr
		}
		if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
			s.server.logger.Debug("reset write deadline failed", "agent", s.id, "error", err)
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
		s.server.logger.Warn("register failed", "error", err, "remote", s.remote)
		return
	}

	s.connectedAt = time.Now()
	s.server.registerAgent(s)
	s.startWriter()
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
		if errors.Is(err, errClientStreamClosed) {
			return
		}
		if errors.Is(err, errClientBacklog) {
			s.server.logger.Debug("client backlog exceeded", "agent", s.id, "stream", streamID)
		} else {
			s.server.logger.Debug("enqueue to client failed", "agent", s.id, "stream", streamID, "error", err)
		}
		stream.closeFromRelay(err)
		return
	}
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
	if f == nil {
		return nil
	}
	return s.enqueueControl(outboundMessage{frame: f})
}

func (s *relayAgentSession) sendBinary(streamID string, payload []byte) error {
	data, err := protocol.EncodeBinaryFrame(streamID, payload)
	if err != nil {
		return err
	}
	return s.enqueueData(outboundMessage{binary: data})
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
	if cpu > 0 {
		agent.AgentCPUPercent = cpu
	}
	if rss > 0 {
		agent.AgentRSSBytes = rss
	}
	if goroutines > 0 {
		agent.AgentGoroutines = goroutines
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
