package relay

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

func (s *relayServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Warn("upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	session := newRelayAgentSession(s, conn, r.RemoteAddr)
	go session.run()
}

func (s *relayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	payload := s.collectStatus(r)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		s.logger.Warn("status marshal failed", "error", err)
		http.Error(w, "status error", http.StatusInternalServerError)
		return
	}
	view := statusView{
		Bootstrap: template.JS(jsonBytes),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.statusTmpl.Execute(w, view); err != nil {
		s.logger.Warn("status render failed", "error", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func (s *relayServer) handleStatusJSON(w http.ResponseWriter, r *http.Request) {
	payload := s.collectStatus(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("status json failed", "error", err)
	}
}

func (s *relayServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	agentID, token, err := parseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="intratun"`)
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}
	if !s.validateAgent(agentID, token) {
		s.metrics.authFailures.Inc()
		s.stats.authFailures.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.authorizeTarget(agentID, r.Host); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	session, ok := s.lookupAgent(agentID)
	if !ok {
		http.Error(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	defer func() {
		if err != nil {
			clientConn.Close()
		}
	}()

	host, port, err := splitHostPort(r.Host)
	if err != nil {
		writeProxyError(buf, fmt.Sprintf("invalid host: %v", err))
		return
	}

	streamID := s.nextStreamID()
	stream := newRelayStream(streamID, session, streamProtoHTTP, clientConn, buf, host, port)
	if err := session.registerStream(stream); err != nil {
		writeProxyError(buf, fmt.Sprintf("stream register failed: %v", err))
		return
	}

	if err := session.send(&protocol.Frame{
		Type:     protocol.FrameTypeDial,
		StreamID: streamID,
		Host:     host,
		Port:     port,
	}); err != nil {
		writeProxyError(buf, fmt.Sprintf("dial send failed: %v", err))
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
		writeProxyError(buf, fmt.Sprintf("dial failed: %v", err))
		stream.closeSilent(err)
		return
	}

	if err := stream.accept(); err != nil {
		stream.closeFromRelay(err)
		return
	}

	go stream.pipeClientOutbound()
}
