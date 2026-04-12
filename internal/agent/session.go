package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/drksbr/ProxyWebSock/internal/logger"
	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"github.com/drksbr/ProxyWebSock/internal/util"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

var errWriterClosed = errors.New("writer closed")

type outboundMessage struct {
	packet          []byte
	heartbeat       *protocol.HeartbeatPayload
	binaryStreamID  uint64
	binaryPayload   []byte
	onWriteComplete func(success bool)
}

const resourceSampleInterval = 10 * time.Second

type session struct {
	agent *agent
	conn  *websocket.Conn

	streams   map[uint64]*agentStream
	streamsMu sync.RWMutex
	logger    *slog.Logger
	traceID   string

	heartbeat     *heartbeatState
	controlQueue  chan outboundMessage
	dataQueue     chan outboundMessage
	writerDone    chan struct{}
	writerStarted bool
	writerClose   sync.Once
	proc          *process.Process
}

func newSession(agent *agent, conn *websocket.Conn) *session {
	proc, _ := process.NewProcess(int32(os.Getpid()))
	traceID := logger.NewTraceID()
	return &session{
		agent:        agent,
		conn:         conn,
		streams:      make(map[uint64]*agentStream),
		logger:       agent.logger.With("session", time.Now().UnixNano(), "trace_id", traceID),
		traceID:      traceID,
		heartbeat:    newHeartbeatState(),
		controlQueue: make(chan outboundMessage, 128),
		dataQueue:    make(chan outboundMessage, 256),
		writerDone:   make(chan struct{}),
		proc:         proc,
	}
}

func (s *session) startWriter() {
	if s.writerStarted {
		return
	}
	s.writerStarted = true
	go s.writerLoop()
}

func (s *session) stopWriter() {
	s.writerClose.Do(func() {
		close(s.controlQueue)
		close(s.dataQueue)
	})
	if s.writerStarted {
		<-s.writerDone
		s.writerStarted = false
	}
}

func (s *session) writerLoop() {
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

func (s *session) writeMessage(msg *outboundMessage) error {
	if msg == nil {
		return nil
	}
	if msg.heartbeat != nil {
		payload := msg.heartbeat
		var sendTime time.Time
		if payload.Mode == protocol.HeartbeatModePing && payload.SentAt == 0 {
			sendTime = time.Now()
			payload.SentAt = sendTime.UnixNano()
		}
		packet, err := protocol.EncodeHeartbeatPacket(payload)
		if err != nil {
			return err
		}
		if err := s.writePacket(packet); err != nil {
			if payload.Mode == protocol.HeartbeatModePing {
				s.heartbeat.markSendFailure()
			}
			return err
		}
		if payload.Mode == protocol.HeartbeatModePing {
			if sendTime.IsZero() {
				sendTime = time.Unix(0, payload.SentAt)
			}
			s.heartbeat.markSent(payload.Sequence, sendTime)
			s.heartbeat.expirePending(sendTime)
		}
		return nil
	}
	if len(msg.packet) > 0 {
		return s.writePacket(msg.packet)
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

func (s *session) writePacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	if err := s.conn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		return err
	}
	if err := s.conn.SetWriteDeadline(time.Time{}); err != nil {
		s.logger.Debug("reset write deadline failed", "error", err)
	}
	return nil
}

func (s *session) enqueueControl(msg outboundMessage) error {
	return s.enqueueMessage(s.controlQueue, msg)
}

func (s *session) enqueueData(msg outboundMessage) error {
	return s.enqueueMessage(s.dataQueue, msg)
}

func (s *session) enqueueMessage(ch chan outboundMessage, msg outboundMessage) (err error) {
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

func (s *session) run(ctx context.Context) error {
	ctx = logger.ContextWithTrace(ctx, s.traceID)
	defer s.conn.Close()

	readLimit := int64(s.agent.opts.maxFrame + 64*1024)
	if readLimit < 1<<20 {
		readLimit = 1 << 20
	}
	s.conn.SetReadLimit(readLimit)
	if err := s.register(); err != nil {
		return err
	}

	s.startWriter()
	defer s.stopWriter()

	readErr := make(chan error, 1)
	go func() {
		readErr <- s.readLoop()
	}()

	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go s.heartbeatLoop(hbCtx)
	go s.resourceLoop(hbCtx)

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
	packet, err := protocol.EncodeRegisterPacket(protocol.RegisterRequest{
		AgentID: s.agent.opts.agentID,
		Token:   s.agent.opts.token,
		Version: version.Version,
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
	})
	if err != nil {
		return fmt.Errorf("encode register: %w", err)
	}
	if err := s.writePacket(packet); err != nil {
		return fmt.Errorf("send register: %w", err)
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
		if messageType != websocket.BinaryMessage {
			continue
		}
		header, body, release, err := protocol.ReadPacketPooled(r, s.agent.opts.maxFrame+64*1024)
		if err != nil {
			return err
		}
		switch header.Type {
		case protocol.PacketTypeDialRequest:
			req, err := protocol.DecodeDialRequestPacket(header, body)
			release()
			if err != nil {
				return err
			}
			go s.handleDial(req)
		case protocol.PacketTypeDiagnosticRequest:
			req, err := protocol.DecodeDiagnosticRequestPacket(header, body)
			release()
			if err != nil {
				return err
			}
			go s.handleDiagnostic(req)
		case protocol.PacketTypeData:
			streamID := header.StreamID
			s.handleBinaryWrite(streamID, body, release)
		case protocol.PacketTypeWindowUpdate:
			update, err := protocol.DecodeWindowUpdatePacket(header, body)
			release()
			if err != nil {
				return err
			}
			s.handleWindow(update)
		case protocol.PacketTypeClose:
			closePacket, err := protocol.DecodeClosePacket(header, body)
			release()
			if err != nil {
				return err
			}
			s.handleClose(closePacket)
		case protocol.PacketTypeHeartbeat:
			payload, err := protocol.DecodeHeartbeatPacket(header, body)
			release()
			if err != nil {
				return err
			}
			s.handleHeartbeat(payload)
		case protocol.PacketTypeUpdate:
			release()
			go s.agent.checkForUpdate(context.Background())
		default:
			release()
			s.logger.Warn("unknown packet type", "type", header.Type)
		}
	}
}

func (s *session) handleDiagnostic(req protocol.DiagnosticRequest) {
	resp := s.agent.runDiagnostic(req)
	if err := s.sendDiagnosticResponse(resp); err != nil {
		s.logger.Warn("send diagnostic response failed", "request", req.RequestID, "error", err)
	}
}

func (s *session) handleDial(req protocol.DialRequest) {
	if req.StreamID == 0 {
		s.logger.Warn("dial missing stream id")
		return
	}

	timeout := time.Duration(s.agent.opts.dialTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, dialAddress, resolutionSource, err := s.agent.dialTarget(ctx, req.Host, req.Port, req.OverrideAddress)
	if err != nil {
		s.logger.Warn("dial failed", "stream", req.StreamID, "target", net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port)), "error", err)
		s.heartbeat.recordError(err.Error())
		_ = s.sendDialResponse(protocol.DialResponse{
			StreamID: req.StreamID,
			Error:    err.Error(),
		})
		return
	}
	util.TuneTCPConn(conn, s.agent.opts.readBuffer, s.agent.opts.writeBuffer)

	stream := newAgentStream(req.StreamID, conn, s.agent.opts.maxInFlight, s.agent.opts.queueDepth, s.logger, func(delta int) error {
		return s.sendWindowUpdate(req.StreamID, delta)
	})
	if err := s.storeStream(stream); err != nil {
		conn.Close()
		s.heartbeat.recordError(err.Error())
		_ = s.sendDialResponse(protocol.DialResponse{
			StreamID: req.StreamID,
			Error:    err.Error(),
		})
		return
	}

	if err := s.sendDialResponse(protocol.DialResponse{
		StreamID:         req.StreamID,
		DialAddress:      dialAddress,
		ResolutionSource: resolutionSource,
	}); err != nil {
		s.logger.Warn("send dial response failed", "stream", req.StreamID, "error", err)
		stream.close()
		s.removeStream(req.StreamID)
		return
	}

	go s.pipeOutbound(stream)
}

func (s *session) handleClose(closePacket protocol.ClosePacket) {
	stream := s.removeStream(closePacket.StreamID)
	if stream == nil {
		return
	}
	stream.close()
	if closePacket.Message != "" {
		s.logger.Info("stream closed by relay", "stream", closePacket.StreamID, "code", closePacket.Code, "error", closePacket.Message)
	}
}

func (s *session) handleWindow(update protocol.WindowUpdate) {
	if update.Delta == 0 {
		return
	}
	stream := s.getStream(update.StreamID)
	if stream == nil {
		s.logger.Debug("window update for unknown stream", "stream", update.StreamID)
		return
	}
	stream.release(int(update.Delta))
}

func (s *session) handleHeartbeat(payload *protocol.HeartbeatPayload) {
	if payload == nil {
		s.logger.Warn("heartbeat packet missing payload")
		return
	}

	switch payload.Mode {
	case protocol.HeartbeatModePong:
		ackTime := time.Now()
		s.heartbeat.handleAck(payload.Sequence, ackTime)
		_ = s.conn.SetReadDeadline(time.Now().Add(heartbeatTimeout))
	case protocol.HeartbeatModePing:
		if err := s.sendHeartbeatPacket(&protocol.HeartbeatPayload{
			Sequence: payload.Sequence,
			SentAt:   payload.SentAt,
			Mode:     protocol.HeartbeatModePong,
		}); err != nil {
			s.logger.Debug("heartbeat pong failed", "error", err)
			s.heartbeat.markSendFailure()
		}
	default:
		s.logger.Warn("heartbeat packet with unknown mode", "mode", payload.Mode)
	}
}

func (s *session) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

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

func (s *session) resourceLoop(ctx context.Context) {
	if s.proc == nil {
		return
	}
	ticker := time.NewTicker(resourceSampleInterval)
	defer ticker.Stop()
	s.collectResources(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.collectResources(ctx)
		}
	}
}

func (s *session) collectResources(ctx context.Context) {
	if s.proc == nil {
		return
	}
	cpuPercent, err := s.proc.PercentWithContext(ctx, 0)
	if err != nil {
		cpuPercent = 0
	}
	mem, err := s.proc.MemoryInfoWithContext(ctx)
	var rss uint64
	if err == nil && mem != nil {
		rss = mem.RSS
	}
	goroutines := runtime.NumGoroutine()
	s.heartbeat.updateResources(cpuPercent, rss, goroutines)
}

func (s *session) sendHeartbeat() {
	now := time.Now()
	payload := s.heartbeat.nextPayload(now)
	s.heartbeat.expirePending(now)
	if payload == nil {
		return
	}
	controlDepth := 0
	if s.controlQueue != nil {
		controlDepth = len(s.controlQueue)
	}
	dataDepth := 0
	if s.dataQueue != nil {
		dataDepth = len(s.dataQueue)
	}
	if controlDepth > 0 || dataDepth > 0 {
		if payload.Stats == nil {
			payload.Stats = &protocol.HeartbeatStats{}
		}
		if controlDepth > 0 {
			payload.Stats.ControlQueueDepth = controlDepth
		}
		if dataDepth > 0 {
			payload.Stats.DataQueueDepth = dataDepth
		}
	}
	if err := s.sendHeartbeatPacket(payload); err != nil {
		s.logger.Debug("heartbeat send failed", "error", err)
		s.heartbeat.markSendFailure()
	}
}

func (s *session) handleBinaryWrite(streamID uint64, payload []byte, release func()) {
	stream := s.getStream(streamID)
	if stream == nil {
		if release != nil {
			release()
		}
		s.logger.Warn("write for unknown stream", "stream", streamID)
		return
	}
	s.handleBinaryWriteWithStream(stream, payload, release)
}

func (s *session) handleBinaryWriteWithStream(stream *agentStream, payload []byte, release func()) {
	if len(payload) == 0 {
		if release != nil {
			release()
		}
		return
	}

	if err := stream.enqueueInboundBuffer(payload, len(payload), release); err != nil && !errors.Is(err, errStreamClosed) {
		s.logger.Warn("stream enqueue failed", "stream", stream.id, "error", err)
		s.heartbeat.recordError(err.Error())
		stream.close()
		_ = s.sendClose(protocol.ClosePacket{
			StreamID: stream.id,
			Code:     protocol.CloseCodeBackpressure,
			Message:  err.Error(),
		})
	}
}

func (s *session) sendPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	return s.enqueueControl(outboundMessage{packet: packet})
}

func (s *session) sendHeartbeatPacket(payload *protocol.HeartbeatPayload) error {
	if payload == nil {
		return nil
	}
	return s.enqueueControl(outboundMessage{heartbeat: payload})
}

func (s *session) sendDialResponse(resp protocol.DialResponse) error {
	packet, err := protocol.EncodeDialResponsePacket(resp)
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *session) sendDiagnosticResponse(resp protocol.DiagnosticResponse) error {
	packet, err := protocol.EncodeDiagnosticResponsePacket(resp)
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *session) sendWindowUpdate(streamID uint64, delta int) error {
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

func (s *session) sendClose(closePacket protocol.ClosePacket) error {
	packet, err := protocol.EncodeClosePacket(closePacket)
	if err != nil {
		return err
	}
	return s.sendPacket(packet)
}

func (s *session) sendBinary(streamID uint64, payload []byte, release func()) error {
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

func (s *session) storeStream(stream *agentStream) error {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if _, exists := s.streams[stream.id]; exists {
		return fmt.Errorf("stream %d already exists", stream.id)
	}
	s.streams[stream.id] = stream
	return nil
}

func (s *session) getStream(id uint64) *agentStream {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	return s.streams[id]
}

func (s *session) removeStream(id uint64) *agentStream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	stream, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	return stream
}

func (s *session) pipeOutbound(stream *agentStream) {
	closeCode := protocol.CloseCodeOK
	closeMessage := ""
	defer func() {
		s.removeStream(stream.id)
		stream.close()
		_ = s.sendClose(protocol.ClosePacket{
			StreamID: stream.id,
			Code:     closeCode,
			Message:  closeMessage,
		})
	}()

	bufferSize := s.agent.opts.maxFrame
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}

	buf := borrowAgentBuffer(bufferSize)
	defer func() {
		if buf != nil {
			releaseAgentBuffer(buf)
		}
	}()

	for {
		n, err := stream.conn.Read(buf[:bufferSize])
		if n > 0 {
			if !stream.acquire(n) {
				closeCode = protocol.CloseCodeBackpressure
				closeMessage = "stream window closed"
				return
			}
			sendBuf := buf[:n]
			buf = nil
			if errSend := s.sendBinary(stream.id, sendBuf, func() {
				releaseAgentBuffer(sendBuf)
			}); errSend != nil {
				stream.release(n)
				closeCode = protocol.CloseCodeShutdown
				closeMessage = errSend.Error()
				s.logger.Warn("send payload failed", "stream", stream.id, "error", errSend)
				return
			}
			buf = borrowAgentBuffer(bufferSize)
		}

		if err != nil {
			if errors.Is(err, io.EOF) || util.IsExpectedNetClose(err) || stream.isClosed() {
				return
			}
			closeCode = protocol.CloseCodeRemoteError
			closeMessage = err.Error()
			s.logger.Warn("stream read failed", "stream", stream.id, "error", err)
			s.heartbeat.recordError(err.Error())
			return
		}
	}
}
