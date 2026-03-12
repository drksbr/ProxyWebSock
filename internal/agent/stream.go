package agent

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/logger"
	"github.com/drksbr/ProxyWebSock/internal/util/bytelimiter"
)

var errStreamClosed = errors.New("stream closed")
var errStreamBacklog = errors.New("stream backlog exceeded")

const backlogAcquireWait = 500 * time.Millisecond

type streamWriteRequest struct {
	data    []byte
	size    int
	release func()
}

type agentStream struct {
	id           string
	conn         net.Conn
	sendWindow   *bytelimiter.ByteLimiter
	inboundLimit *bytelimiter.ByteLimiter
	writeQueue   chan streamWriteRequest
	writerOnce   sync.Once
	logger       *slog.Logger
	spanID       string
	closed       chan struct{}
	closeOnce    sync.Once
	queueClosed  atomic.Bool
	windowUpdate func(int) error
	windowBatch  int
}

const maxAgentPooledBuffer = 512 * 1024

var agentQueueBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 32*1024)
	},
}

func borrowAgentBuffer(size int) []byte {
	buf := agentQueueBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func releaseAgentBuffer(buf []byte) {
	if buf == nil {
		return
	}
	if cap(buf) <= maxAgentPooledBuffer {
		agentQueueBufferPool.Put(buf[:0])
	}
}

func newAgentStream(id string, conn net.Conn, maxInFlight, queueDepth int, baseLogger *slog.Logger, windowUpdate func(int) error) *agentStream {
	spanID := logger.NewSpanID()
	streamLogger := baseLogger
	if streamLogger != nil {
		streamLogger = streamLogger.With("stream", id, "span_id", spanID)
	}
	as := &agentStream{
		id:           id,
		conn:         conn,
		sendWindow:   bytelimiter.New(maxInFlight),
		inboundLimit: bytelimiter.New(maxInFlight),
		writeQueue:   make(chan streamWriteRequest, queueDepth),
		logger:       streamLogger,
		spanID:       spanID,
		closed:       make(chan struct{}),
		windowUpdate: windowUpdate,
		windowBatch:  windowBatchSize(maxInFlight),
	}
	as.startWriter()
	return as
}

func (s *agentStream) startWriter() {
	s.writerOnce.Do(func() {
		go s.writerLoop()
	})
}

func (s *agentStream) enqueueInbound(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	buf := borrowAgentBuffer(len(data))
	copy(buf, data)
	return s.enqueueInboundBuffer(buf, len(data), func() {
		releaseAgentBuffer(buf)
	})
}

func (s *agentStream) enqueueInboundBuffer(data []byte, size int, release func()) error {
	if len(data) == 0 {
		if release != nil {
			release()
		}
		return nil
	}
	if s.isClosed() {
		if release != nil {
			release()
		}
		return errStreamClosed
	}
	if s.queueClosed.Load() {
		if release != nil {
			release()
		}
		return errStreamClosed
	}
	if !waitForCapacity(s.inboundLimit, size, s.closed, backlogAcquireWait) {
		if release != nil {
			release()
		}
		if s.logger != nil {
			s.logger.Warn("inbound backlog exceeded, closing stream")
		}
		s.close()
		return errStreamBacklog
	}
	req := streamWriteRequest{
		data:    data,
		size:    size,
		release: release,
	}
	select {
	case s.writeQueue <- req:
		return nil
	case <-s.closed:
		if s.inboundLimit != nil {
			s.inboundLimit.Release(size)
		}
		if release != nil {
			release()
		}
		return errStreamClosed
	}
}

func (s *agentStream) writerLoop() {
	pendingWindow := 0
	flushWindow := func(force bool) {
		if pendingWindow <= 0 || s.windowUpdate == nil {
			return
		}
		if !force && pendingWindow < s.windowBatch {
			return
		}
		if err := s.windowUpdate(pendingWindow); err != nil && s.logger != nil {
			s.logger.Debug("window update failed", "error", err)
		}
		pendingWindow = 0
	}
	draining := false
	for req := range s.writeQueue {
		if req.size == 0 {
			if req.release != nil {
				req.release()
			}
			continue
		}
		if draining || len(req.data) == 0 {
			if s.inboundLimit != nil && req.size > 0 {
				s.inboundLimit.Release(req.size)
			}
			if req.release != nil {
				req.release()
			}
			continue
		}
		total := 0
		var writeErr error
		for total < len(req.data) {
			n, err := s.conn.Write(req.data[total:])
			if err != nil {
				if s.logger != nil {
					s.logger.Warn("stream write failed", "error", err)
				}
				writeErr = err
				draining = true
				s.close()
				break
			}
			total += n
		}
		if s.inboundLimit != nil && req.size > 0 {
			s.inboundLimit.Release(req.size)
		}
		pendingWindow += total
		flushWindow(len(s.writeQueue) == 0)
		if req.release != nil {
			req.release()
		}
		if writeErr != nil {
			continue
		}
	}
	flushWindow(true)
}

func (s *agentStream) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.queueClosed.Store(true)
		close(s.writeQueue)
		s.conn.Close()
		if s.sendWindow != nil {
			s.sendWindow.Close()
		}
		if s.inboundLimit != nil {
			s.inboundLimit.Close()
		}
	})
}

func (s *agentStream) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *agentStream) acquire(n int) bool {
	return waitForCapacity(s.sendWindow, n, s.closed, -1)
}

func (s *agentStream) release(n int) {
	if s.sendWindow != nil {
		s.sendWindow.Release(n)
	}
}

func waitForCapacity(limit *bytelimiter.ByteLimiter, n int, closed <-chan struct{}, maxWait time.Duration) bool {
	return limit.WaitAcquire(n, closed, maxWait)
}

func windowBatchSize(maxInFlight int) int {
	switch {
	case maxInFlight <= 0:
		return 64 * 1024
	case maxInFlight <= 64*1024:
		return maxInFlight
	case maxInFlight < 1024*1024:
		return maxInFlight / 2
	case maxInFlight < 8*1024*1024:
		return 256 * 1024
	default:
		return 512 * 1024
	}
}
