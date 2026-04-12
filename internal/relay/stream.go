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

	logctx "github.com/drksbr/ProxyWebSock/internal/logger"
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

const backlogAcquireWait = 500 * time.Millisecond

type relayWriteRequest struct {
	data    []byte
	size    int
	release func()
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
	id               uint64
	agent            *relayAgentSession
	client           net.Conn
	bufrw            *bufio.ReadWriter
	protocol         streamProtocol
	targetHost       string
	targetPort       int
	metaMu           sync.RWMutex
	resolvedTarget   string
	resolutionSource string
	principalType    string
	principalName    string
	groupID          string
	groupName        string
	profileID        string
	profileName      string
	routeReasonCode  string
	routeReason      string
	createdAt        time.Time
	once             sync.Once
	closing          chan struct{}
	readyCh          chan error
	readyOnce        sync.Once
	handshake        chan struct{}
	bytesUp          atomic.Int64
	bytesDown        atomic.Int64
	spanID           string

	writeQueue         chan relayWriteRequest
	writerOnce         sync.Once
	sendWindow         *bytelimiter.ByteLimiter
	backlogLimit       *bytelimiter.ByteLimiter
	pendingClientBytes atomic.Int64
	logger             *slog.Logger
	queueClosed        atomic.Bool
	windowUpdate       func(int) error
	windowBatch        int
}

func newRelayStream(id uint64, agent *relayAgentSession, proto streamProtocol, client net.Conn, bufrw *bufio.ReadWriter, host string, port int, queueDepth int, windowUpdate func(int) error) *relayStream {
	spanID := logctx.NewSpanID()
	streamLogger := agent.logger
	if streamLogger == nil {
		streamLogger = agent.server.logger
	}
	if streamLogger != nil {
		streamLogger = streamLogger.With("stream", id, "span_id", spanID)
	}
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
		sendWindow:   bytelimiter.New(agent.server.opts.maxInFlight),
		backlogLimit: bytelimiter.New(agent.server.opts.maxInFlight),
		logger:       streamLogger,
		spanID:       spanID,
		windowUpdate: windowUpdate,
		windowBatch:  windowBatchSize(agent.server.opts.maxInFlight),
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
			if s.backlogLimit != nil {
				s.backlogLimit.Release(req.size)
			}
			if req.release != nil {
				req.release()
			}
			newPending := s.pendingClientBytes.Add(-int64(req.size))
			if newPending < 0 {
				s.pendingClientBytes.Store(0)
			}
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
		pendingWindow += total
		flushWindow(len(s.writeQueue) == 0)
		if req.release != nil {
			req.release()
		}
		newPending := s.pendingClientBytes.Add(-int64(req.size))
		if newPending < 0 {
			s.pendingClientBytes.Store(0)
		}
		if writeErr != nil {
			if s.logger != nil {
				s.logger.Debug("client write failed", "error", writeErr)
			}
			draining = true
			s.closeFromRelay(writeErr)
		}
	}
	flushWindow(true)
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
	buffer := borrowRelayBuffer(s.agent.server.opts.maxFrame)
	defer func() {
		if buffer != nil {
			releaseRelayBuffer(buffer)
		}
	}()
	for {
		n, err := s.client.Read(buffer[:s.agent.server.opts.maxFrame])
		if n > 0 {
			if !s.acquire(n) {
				return
			}
			sendBuf := buffer[:n]
			buffer = nil
			if err := s.agent.sendBinary(s.id, sendBuf, func() {
				releaseRelayBuffer(sendBuf)
			}); err != nil {
				s.release(n)
				s.agent.server.logger.Debug("send to agent failed", "agent", s.agent.id, "stream", s.id, "error", err)
				s.closeFromRelay(err)
				return
			}
			buffer = borrowRelayBuffer(s.agent.server.opts.maxFrame)
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
	buf := borrowRelayBuffer(len(data))
	copy(buf, data)
	return s.writeToClientBuffer(buf, len(data), func() {
		releaseRelayBuffer(buf)
	})
}

func (s *relayStream) writeToClientBuffer(data []byte, size int, release func()) error {
	if len(data) == 0 {
		if release != nil {
			release()
		}
		return nil
	}
	if s.isClosing() {
		if release != nil {
			release()
		}
		return errClientStreamClosed
	}
	if s.queueClosed.Load() {
		if release != nil {
			release()
		}
		return errClientStreamClosed
	}
	select {
	case <-s.handshake:
	case <-s.closing:
		if release != nil {
			release()
		}
		return errClientStreamClosed
	}
	if !waitForRelayCapacity(s.backlogLimit, size, s.closing, backlogAcquireWait) {
		if release != nil {
			release()
		}
		return errClientBacklog
	}
	req := relayWriteRequest{
		data:    data,
		size:    size,
		release: release,
	}
	select {
	case s.writeQueue <- req:
		s.pendingClientBytes.Add(int64(size))
		return nil
	case <-s.closing:
		if s.backlogLimit != nil {
			s.backlogLimit.Release(size)
		}
		if release != nil {
			release()
		}
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
		if s.backlogLimit != nil {
			s.backlogLimit.Close()
		}
		if s.sendWindow != nil {
			s.sendWindow.Close()
		}
		s.pendingClientBytes.Store(0)
		s.agent.removeStream(s.id)
		_ = s.client.Close()
		if notifyAgent {
			frameErr := ""
			if err != nil && err.Error() != "" {
				frameErr = err.Error()
			}
			code := protocol.CloseCodeOK
			if err != nil {
				code = protocol.CloseCodeRemoteError
			}
			_ = s.agent.sendClose(protocol.ClosePacket{
				StreamID: s.id,
				Code:     code,
				Message:  frameErr,
			})
		}
	})
}

func (s *relayStream) target() string {
	return net.JoinHostPort(s.targetHost, strconv.Itoa(s.targetPort))
}

func (s *relayStream) setResolvedTarget(target, source string) {
	s.metaMu.Lock()
	s.resolvedTarget = target
	s.resolutionSource = source
	s.metaMu.Unlock()
}

func (s *relayStream) setRouting(decision routeDecision) {
	s.metaMu.Lock()
	s.principalType = decision.PrincipalType
	s.principalName = decision.PrincipalName
	s.groupID = decision.GroupID
	s.groupName = decision.GroupName
	s.profileID = decision.ProfileID
	s.profileName = decision.ProfileName
	s.routeReasonCode = decision.ReasonCode
	s.routeReason = decision.Reason
	s.metaMu.Unlock()
}

type relayStreamQuotaMeta struct {
	PrincipalType string
	PrincipalName string
	GroupID       string
	GroupName     string
}

func (s *relayStream) quotaMeta() relayStreamQuotaMeta {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return relayStreamQuotaMeta{
		PrincipalType: s.principalType,
		PrincipalName: s.principalName,
		GroupID:       s.groupID,
		GroupName:     s.groupName,
	}
}

func (s *relayStream) stats() statusStream {
	s.metaMu.RLock()
	resolvedTarget := s.resolvedTarget
	resolutionSource := s.resolutionSource
	principalType := s.principalType
	principalName := s.principalName
	groupID := s.groupID
	groupName := s.groupName
	profileID := s.profileID
	profileName := s.profileName
	routeReasonCode := s.routeReasonCode
	routeReason := s.routeReason
	s.metaMu.RUnlock()
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
		StreamID:            formatStreamID(s.id),
		Target:              s.target(),
		ResolvedTarget:      resolvedTarget,
		ResolutionSource:    resolutionSource,
		PrincipalType:       principalType,
		PrincipalName:       principalName,
		GroupID:             groupID,
		GroupName:           groupName,
		ProfileID:           profileID,
		ProfileName:         profileName,
		RouteReasonCode:     routeReasonCode,
		RouteReason:         routeReason,
		Protocol:            s.protocol.String(),
		CreatedAt:           s.createdAt,
		BytesUp:             s.bytesUp.Load(),
		BytesDown:           s.bytesDown.Load(),
		PendingClientBytes:  pendingBytes,
		PendingClientChunks: pendingChunks,
		ClientBacklogLimit:  backlogLimit,
	}
}

func (s *relayStream) acquire(n int) bool {
	return waitForRelayCapacity(s.sendWindow, n, s.closing, -1)
}

func (s *relayStream) release(n int) {
	if s.sendWindow != nil {
		s.sendWindow.Release(n)
	}
}

func waitForRelayCapacity(limit *bytelimiter.ByteLimiter, n int, closing <-chan struct{}, maxWait time.Duration) bool {
	return limit.WaitAcquire(n, closing, maxWait)
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
