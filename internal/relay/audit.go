package relay

import (
	"context"
	"net/http"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

const defaultAuditEventLimit = 100

func (s *relayServer) appendAuditEvent(ctx context.Context, event controlplane.AuditEvent) {
	if s == nil || s.control == nil {
		return
	}
	if _, err := s.control.AppendAuditEvent(ctx, event); err != nil {
		s.logger.Warn("append audit event failed", "category", event.Category, "action", event.Action, "resource_type", event.ResourceType, "resource_id", event.ResourceID, "error", err)
	}
}

func (s *relayServer) recordDashboardAudit(r *http.Request, event controlplane.AuditEvent) {
	if s == nil || s.control == nil {
		return
	}
	if event.ActorType == "" && event.ActorName == "" && event.ActorID == "" {
		event.ActorType, event.ActorID, event.ActorName = dashboardActor(r)
	}
	if event.RemoteAddr == "" {
		event.RemoteAddr = requestRemoteAddr(r)
	}
	s.appendAuditEvent(r.Context(), event)
}

func dashboardActor(r *http.Request) (string, string, string) {
	if r == nil {
		return "dashboard", "", "dashboard"
	}
	user, _, ok := r.BasicAuth()
	user = strings.TrimSpace(user)
	if ok && user != "" {
		return "dashboard_user", user, user
	}
	return "dashboard", "", "dashboard"
}

func requestRemoteAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func auditMetadata(kv ...string) map[string]string {
	if len(kv) == 0 {
		return nil
	}
	fields := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key := strings.TrimSpace(kv[i])
		if key == "" {
			continue
		}
		fields[key] = strings.TrimSpace(kv[i+1])
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}
