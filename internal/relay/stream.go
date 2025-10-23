package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
	"github.com/drksbr/ProxyWebSock/internal/util/bytelimiter"
)

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

var (
	errClientStreamClosed = errors.New("stream closed")
	errClientBacklog      = errors.New("client backlog exceeded")
)

type relayWriteRequest struct {
	data []byte
	size int
}

const maxRelayPooledBuffer = 512 * 1024

var relayQueueBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 32*1024)
	},
}

func borrowRelayBuffer(size int) []byte {
	buf := relayQueueBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func releaseRelayBuffer(buf []byte) {
	if buf == nil {
		return
	}
	if cap(buf) <= maxRelayPooledBuffer {
		relayQueueBufferPool.Put(buf[:0])
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

	writeQueue         chan relayWriteRequest
	writerOnce         sync.Once
	writerDone         chan struct{}
	backlogLimit       *bytelimiter.ByteLimiter
	pendingClientBytes atomic.Int64
	logger             *slog.Logger
	queueClosed        atomic.Bool
}

func newRelayStream(id string, agent *relayAgentSession, proto streamProtocol, client net.Conn, bufrw *bufio.ReadWriter, host string, port int, queueDepth int) *relayStream {
	streamLogger := agent.server.logger.With("agent", agent.id, "stream", id)
	rs := &relayStream{
		id:           id,
		agent:        agent,
		client:       client,
		bufrw:        bufrw,
		protocol:     proto,
		targetHost:   host,
		targetPort:   port,
		createdAt:    time.Now(),
		closing:      make(chan struct{}),
		readyCh:      make(chan error, 1),
		handshake:    make(chan struct{}),
		writeQueue:   make(chan relayWriteRequest, queueDepth),
		writerDone:   make(chan struct{}),
		backlogLimit: bytelimiter.New(agent.server.opts.maxInFlight),
		logger:       streamLogger,
	}
	rs.startWriter()
	return rs
}

func (s *relayStream) startWriter() {
	s.writerOnce.Do(func() {
		go s.writerLoop()
	})
}

func (s *relayStream) writerLoop() {
	defer close(s.writerDone)
	for {
		select {
		case req, ok := <-s.writeQueue:
			if !ok {
				return
			}
			if req.size == 0 {
				releaseRelayBuffer(req.data)
				continue
			}
			total := 0
			var writeErr error
			for total < len(req.data) {
				n, err := s.client.Write(req.data[total:])
				if err != nil {
					writeErr = err
					break
				}
				total += n
			}
			if total > 0 {
				s.bytesDown.Add(int64(total))
				s.agent.server.metrics.bytesDownstream.Add(float64(total))
				s.agent.server.stats.bytesDown.Add(int64(total))
			}
			if s.backlogLimit != nil {
				s.backlogLimit.Release(req.size)
			}
			releaseRelayBuffer(req.data)
			newPending := s.pendingClientBytes.Add(-int64(req.size))
			if newPending < 0 {
				s.pendingClientBytes.Store(0)
			}
			if writeErr != nil {
				if s.logger != nil {
					s.logger.Debug("client write failed", "error", writeErr)
				}
				s.closeFromRelay(writeErr)
			}
		case <-s.closing:
			return
		}
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

func (s *relayStream) isClosing() bool {
	select {
	case <-s.closing:
		return true
	default:
		return false
	}
}

func (s *relayStream) writeToClient(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if s.isClosing() {
		return errClientStreamClosed
	}
	if s.queueClosed.Load() {
		return errClientStreamClosed
	}
	select {
	case <-s.handshake:
	case <-s.closing:
		return errClientStreamClosed
	}
	size := len(data)
	if s.backlogLimit != nil && !s.backlogLimit.TryAcquire(size) {
		return errClientBacklog
	}
	buf := borrowRelayBuffer(size)
	copy(buf, data)
	req := relayWriteRequest{
		data: buf,
		size: size,
	}
	select {
	case s.writeQueue <- req:
		s.pendingClientBytes.Add(int64(size))
		return nil
	case <-s.closing:
		if s.backlogLimit != nil {
			s.backlogLimit.Release(size)
		}
		releaseRelayBuffer(buf)
		return errClientStreamClosed
	}
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
		s.queueClosed.Store(true)
		if s.writeQueue != nil {
			close(s.writeQueue)
		}
		// Wait for writerLoop to finish processing all pending data
		if s.writerDone != nil {
			<-s.writerDone
		}
		if s.backlogLimit != nil {
			s.backlogLimit.Close()
		}
		s.pendingClientBytes.Store(0)
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
	pendingBytes := s.pendingClientBytes.Load()
	pendingChunks := 0
	if s.writeQueue != nil {
		pendingChunks = len(s.writeQueue)
	}
	backlogLimit := 0
	if s.backlogLimit != nil {
		backlogLimit = s.backlogLimit.Capacity()
	}
	return statusStream{
		StreamID:            s.id,
		Target:              s.target(),
		Protocol:            s.protocol.String(),
		CreatedAt:           s.createdAt,
		BytesUp:             s.bytesUp.Load(),
		BytesDown:           s.bytesDown.Load(),
		PendingClientBytes:  pendingBytes,
		PendingClientChunks: pendingChunks,
		ClientBacklogLimit:  backlogLimit,
	}
}
