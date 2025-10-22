package relay

import (
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
)

func (s *relayServer) handleAutoConfig(w http.ResponseWriter, r *http.Request) {
	if s.opts.socksListen == "" {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/autoconfig/")
	if path == "" || !strings.HasSuffix(path, ".pac") {
		http.NotFound(w, r)
		return
	}
	agentID := strings.TrimSuffix(path, ".pac")
	record, ok := s.agentDirectory[agentID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if subtle.ConstantTimeCompare([]byte(record.Password), []byte(token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	host := hostOnly(r.Host)
	if host == "" {
		http.Error(w, "invalid host", http.StatusInternalServerError)
		return
	}

	socksPort := portFromAddr(s.opts.socksListen)
	if socksPort == "" {
		http.Error(w, "socks port unavailable", http.StatusInternalServerError)
		return
	}
	proxyPort := portFromAddr(s.opts.proxyListen)
	if proxyPort == "" {
		proxyPort = "8080"
	}

	pac := generatePAC(agentID, record.Password, host, socksPort, host, proxyPort)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pac)
}
