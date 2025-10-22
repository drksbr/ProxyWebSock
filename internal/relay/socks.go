package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

func (s *relayServer) serveSocks() error {
	ln, err := net.Listen("tcp", s.opts.socksListen)
	if err != nil {
		return fmt.Errorf("socks listen: %w", err)
	}
	s.socksLn = ln
	s.logger.Info("socks listening", "addr", s.opts.socksListen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("socks accept: %w", err)
		}
		go s.handleSocksConn(conn)
	}
}

func (s *relayServer) handleSocksConn(conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	remote := conn.RemoteAddr().String()
	logger := s.logger.With("remote", remote, "protocol", "socks5")
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		logger.Warn("set deadline failed", "error", err)
		return
	}

	versionBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, versionBuf); err != nil {
		logger.Debug("read greeting failed", "error", err)
		return
	}
	if versionBuf[0] != 0x05 {
		_, _ = conn.Write([]byte{0x05, 0xff})
		logger.Warn("unsupported socks version", "version", versionBuf[0])
		return
	}
	methodCount := int(versionBuf[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		logger.Debug("read methods failed", "error", err)
		return
	}
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = conn.Write([]byte{0x05, 0xff})
		logger.Warn("client missing username/password auth")
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		logger.Debug("write method selection failed", "error", err)
		return
	}

	agentID, token, err := readSocksCredentials(conn)
	if err != nil {
		logger.Debug("read credentials failed", "error", err)
		return
	}
	if !s.validateAgent(agentID, token) {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		_, _ = conn.Write([]byte{0x01, 0x01})
		logger.Warn("invalid credentials", "agent", agentID)
		return
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		logger.Debug("write auth success failed", "error", err)
		return
	}

	host, port, err := readSocksRequest(conn)
	if err != nil {
		logger.Debug("read request failed", "error", err)
		_ = writeSocksReply(conn, 0x01)
		return
	}
	targetHostPort := net.JoinHostPort(host, strconv.Itoa(port))
	if err := s.authorizeTarget(agentID, targetHostPort); err != nil {
		logger.Warn("acl denied", "target", targetHostPort)
		_ = writeSocksReply(conn, 0x02)
		return
	}

	session, ok := s.lookupAgent(agentID)
	if !ok {
		logger.Warn("agent missing", "agent", agentID)
		_ = writeSocksReply(conn, 0x05)
		return
	}

	streamID := s.nextStreamID()
	stream := newRelayStream(streamID, session, streamProtoSOCKS5, conn, nil, host, port)
	if err := session.registerStream(stream); err != nil {
		logger.Warn("register stream failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		return
	}

	if err := session.send(&protocol.Frame{
		Type:     protocol.FrameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		logger.Warn("send dial failed", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x01)
		stream.closeSilent(err)
		return
	}

	if err := stream.waitReady(s.dialTimeout()); err != nil {
		s.metrics.dialErrors.Inc()
		s.stats.dialErrors.Add(1)
		_ = session.send(&protocol.Frame{
			Type:     protocol.FrameTypeClose,
			StreamID: streamID,
			Error:    err.Error(),
		})
		logger.Warn("dial timeout", "stream", streamID, "error", err)
		_ = writeSocksReply(conn, 0x05)
		stream.closeSilent(err)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Debug("clear deadline failed", "error", err)
	}

	if err := stream.accept(); err != nil {
		logger.Warn("accept send failed", "stream", streamID, "error", err)
		stream.closeFromRelay(err)
		return
	}

	conn = nil
	go stream.pipeClientOutbound()
}

func readSocksCredentials(conn net.Conn) (string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != 0x01 {
		return "", "", fmt.Errorf("unsupported auth version %d", header[0])
	}
	ulen := int(header[1])
	if ulen == 0 {
		return "", "", errors.New("username required")
	}
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", "", err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return "", "", err
	}
	plen := int(header[0])
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", "", err
	}
	return string(username), string(password), nil
}

func readSocksRequest(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid request version %d", header[0])
	}
	if header[1] != 0x01 {
		return "", 0, fmt.Errorf("unsupported command %d", header[1])
	}
	atyp := header[3]
	var host string
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	case 0x03:
		if _, err := io.ReadFull(conn, header[:1]); err != nil {
			return "", 0, err
		}
		length := int(header[0])
		if length == 0 {
			return "", 0, errors.New("empty domain name")
		}
		addr := make([]byte, length)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = string(addr)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		host = net.IP(addr).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	return host, port, nil
}

func writeSocksReply(conn net.Conn, rep byte) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}
