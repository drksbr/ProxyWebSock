package agent

import (
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/drksbr/ProxyWebSock/internal/util/bytelimiter"
)

var errStreamClosed = errors.New("stream closed")

type streamWriteRequest struct {
	data []byte
	size int
}

type agentStream struct {
	id            string
	conn          net.Conn
	outboundLimit *bytelimiter.ByteLimiter
	inboundLimit  *bytelimiter.ByteLimiter
	writeQueue    chan streamWriteRequest
	writerOnce    sync.Once
	logger        *slog.Logger
	closed        chan struct{}
	closeOnce     sync.Once
}

func newAgentStream(id string, conn net.Conn, maxInFlight int, logger *slog.Logger) *agentStream {
	streamLogger := logger
	if streamLogger != nil {
		streamLogger = streamLogger.With("stream", id)
	}
	as := &agentStream{
		id:            id,
		conn:          conn,
		outboundLimit: bytelimiter.New(maxInFlight),
		inboundLimit:  bytelimiter.New(maxInFlight),
		writeQueue:    make(chan streamWriteRequest, 64),
		logger:        streamLogger,
		closed:        make(chan struct{}),
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
	if s.isClosed() {
		return errStreamClosed
	}
	size := len(data)
	if s.inboundLimit != nil && !s.inboundLimit.TryAcquire(size) {
		if s.logger != nil {
			s.logger.Warn("inbound backlog exceeded, closing stream")
		}
		s.close()
		return errStreamClosed
	}
	select {
	case s.writeQueue <- streamWriteRequest{data: data, size: size}:
		return nil
	case <-s.closed:
		if s.inboundLimit != nil {
			s.inboundLimit.Release(size)
		}
		return errStreamClosed
	default:
		if s.inboundLimit != nil {
			s.inboundLimit.Release(size)
		}
		if s.logger != nil {
			s.logger.Warn("inbound write queue overflow, closing stream")
		}
		s.close()
		return errStreamClosed
	}
}

func (s *agentStream) writerLoop() {
	for {
		select {
		case req, ok := <-s.writeQueue:
			if !ok {
				return
			}
			if len(req.data) == 0 {
				if s.inboundLimit != nil && req.size > 0 {
					s.inboundLimit.Release(req.size)
				}
				continue
			}
			total := 0
			for total < len(req.data) {
				n, err := s.conn.Write(req.data[total:])
				if err != nil {
					if s.logger != nil {
						s.logger.Warn("stream write failed", "error", err)
					}
					s.close()
					break
				}
				total += n
			}
			if s.inboundLimit != nil && req.size > 0 {
				s.inboundLimit.Release(req.size)
			}
		case <-s.closed:
			return
		}
	}
}

func (s *agentStream) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		close(s.writeQueue)
		s.conn.Close()
		if s.outboundLimit != nil {
			s.outboundLimit.Close()
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

func (s *agentStream) acquire(n int) {
	if s.outboundLimit != nil {
		s.outboundLimit.Acquire(n)
	}
}

func (s *agentStream) release(n int) {
	if s.outboundLimit != nil {
		s.outboundLimit.Release(n)
	}
}
