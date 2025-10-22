package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

var errWriterClosed = errors.New("writer closed")

type outboundMessage struct {
	frame  *protocol.Frame
	binary []byte
}

type session struct {
	agent *agent
	conn  *websocket.Conn

	streams   map[string]*agentStream
	streamsMu sync.RWMutex
	logger    *slog.Logger

	heartbeat     *heartbeatState
	controlQueue  chan outboundMessage
	dataQueue     chan outboundMessage
	writerDone    chan struct{}
	writerStarted bool
	writerClose   sync.Once
}

func newSession(agent *agent, conn *websocket.Conn) *session {
	return &session{
		agent:        agent,
		conn:         conn,
		streams:      make(map[string]*agentStream),
		logger:       agent.logger.With("session", time.Now().UnixNano()),
		heartbeat:    newHeartbeatState(),
		controlQueue: make(chan outboundMessage, 128),
		dataQueue:    make(chan outboundMessage, 256),
		writerDone:   make(chan struct{}),
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
				if err := s.writeMessage(msg); err != nil {
					s.logger.Warn("writer failed", "error", err)
					return
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
		if err := s.writeMessage(msg); err != nil {
			s.logger.Warn("writer failed", "error", err)
			return
		}
	}
}

func (s *session) writeMessage(msg outboundMessage) error {
	if msg.frame != nil {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		err := s.conn.WriteJSON(msg.frame)
		if err == nil {
			err = s.conn.SetWriteDeadline(time.Time{})
		}
		return err
	}
	if len(msg.binary) > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
			return err
		}
		err := s.conn.WriteMessage(websocket.BinaryMessage, msg.binary)
		if err == nil {
			err = s.conn.SetWriteDeadline(time.Time{})
		}
		return err
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
	defer s.conn.Close()

	s.conn.SetReadLimit(1 << 20)
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
		s.heartbeat.handleAck(payload.Sequence, ackTime)
		_ = s.conn.SetReadDeadline(time.Now().Add(heartbeatTimeout))
	case protocol.HeartbeatModePing:
		reply := &protocol.Frame{
			Type: protocol.FrameTypeHeartbeat,
			Heartbeat: &protocol.HeartbeatPayload{
				Sequence: payload.Sequence,
				SentAt:   payload.SentAt,
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
	if f == nil {
		return nil
	}
	return s.enqueueControl(outboundMessage{frame: f})
}

func (s *session) sendBinary(streamID string, payload []byte) error {
	data, err := protocol.EncodeBinaryFrame(streamID, payload)
	if err != nil {
		return err
	}
	return s.enqueueData(outboundMessage{binary: data})
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
