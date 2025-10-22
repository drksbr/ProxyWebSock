package relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
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
}

func newRelayStream(id string, agent *relayAgentSession, proto streamProtocol, client net.Conn, bufrw *bufio.ReadWriter, host string, port int) *relayStream {
	return &relayStream{
		id:         id,
		agent:      agent,
		client:     client,
		bufrw:      bufrw,
		protocol:   proto,
		targetHost: host,
		targetPort: port,
		createdAt:  time.Now(),
		closing:    make(chan struct{}),
		readyCh:    make(chan error, 1),
		handshake:  make(chan struct{}),
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
			s.closeFromRelay(err)
			return err
		}
		total += n
	}
	s.bytesDown.Add(int64(total))
	s.agent.server.stats.bytesDown.Add(int64(total))
	return nil
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
	return statusStream{
		StreamID:  s.id,
		Target:    s.target(),
		Protocol:  s.protocol.String(),
		CreatedAt: s.createdAt,
		BytesUp:   s.bytesUp.Load(),
		BytesDown: s.bytesDown.Load(),
	}
}
