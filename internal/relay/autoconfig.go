package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
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
	if strings.HasPrefix(path, "users/") {
		s.handleUserAutoConfig(w, r, strings.TrimPrefix(path, "users/"))
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

func (s *relayServer) handleUserAutoConfig(w http.ResponseWriter, r *http.Request, userPath string) {
	userID := strings.TrimSuffix(userPath, ".pac")
	if userID == "" || userID == userPath {
		http.NotFound(w, r)
		return
	}
	secret := s.userAutoConfigSecret()
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	if !verifyUserAutoConfigToken(secret, userID, r.URL.Query().Get("token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}
	user, found, err := s.control.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	if !found || user.Status != controlplane.UserStatusActive {
		http.NotFound(w, r)
		return
	}
	profiles, catchAll, err := s.userPACPolicy(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "autoconfig policy failed", http.StatusInternalServerError)
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

	pac := generateUserPAC(profiles, catchAll, host, socksPort, host, proxyPort)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, pac)
}

func (s *relayServer) userAutoConfigSecret() string {
	if s == nil || s.opts == nil {
		return ""
	}
	if secret := strings.TrimSpace(s.opts.autoconfigSecret); secret != "" {
		return secret
	}
	if secret := strings.TrimSpace(s.opts.dashboardPass); secret != "" {
		return secret
	}
	return ""
}

func mintUserAutoConfigToken(secret, userID string) string {
	if secret == "" || userID == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("user-pac:v1:"))
	_, _ = mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyUserAutoConfigToken(secret, userID, token string) bool {
	expected := mintUserAutoConfigToken(secret, userID)
	if expected == "" || token == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(token))
}

func (s *relayServer) userPACPolicy(ctx context.Context, userID string) ([]controlplane.DestinationProfile, bool, error) {
	grants, err := s.control.ListAccessGrantsByUser(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	profilesByID := make(map[string]controlplane.DestinationProfile)
	catchAll := false
	for _, grant := range grants {
		if strings.TrimSpace(grant.DestinationProfileID) == "" {
			catchAll = true
			continue
		}
		profile, found, err := s.control.GetDestinationProfile(ctx, grant.DestinationProfileID)
		if err != nil {
			return nil, false, err
		}
		if !found {
			continue
		}
		profilesByID[profile.ID] = profile
	}
	profiles := make([]controlplane.DestinationProfile, 0, len(profilesByID))
	for _, profile := range profilesByID {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].Host == profiles[j].Host {
			return profiles[i].Port < profiles[j].Port
		}
		return profiles[i].Host < profiles[j].Host
	})
	return profiles, catchAll, nil
}

func generateUserPAC(profiles []controlplane.DestinationProfile, catchAll bool, socksHost, socksPort, proxyHost, proxyPort string) string {
	socksEntry := "SOCKS5 " + socksHost + ":" + socksPort
	proxyEntry := "PROXY " + proxyHost + ":" + proxyPort
	proxyChain := socksEntry + "; " + proxyEntry + "; DIRECT"
	var builder strings.Builder
	builder.WriteString("function FindProxyForURL(url, host) {\n")
	builder.WriteString("  var proxy = " + `"` + proxyChain + `"` + ";\n")
	if catchAll {
		builder.WriteString("  if (isPlainHostName(host)) {\n")
		builder.WriteString("    return \"DIRECT\";\n")
		builder.WriteString("  }\n")
		builder.WriteString("  return proxy;\n")
		builder.WriteString("}\n")
		return builder.String()
	}
	if len(profiles) == 0 {
		builder.WriteString("  return \"DIRECT\";\n")
		builder.WriteString("}\n")
		return builder.String()
	}
	for _, profile := range profiles {
		host := jsString(profile.Host)
		builder.WriteString("  if (host === \"" + host + "\" || host === \"" + host + ".\") {\n")
		builder.WriteString("    return proxy;\n")
		builder.WriteString("  }\n")
	}
	builder.WriteString("  return \"DIRECT\";\n")
	builder.WriteString("}\n")
	return builder.String()
}

func jsString(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return replacer.Replace(value)
}
