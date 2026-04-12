package relay

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

type dnsOverrideRequest struct {
	Host    string `json:"host"`
	Address string `json:"address"`
}

func (s *relayServer) handleDNSOverridesAPI(w http.ResponseWriter, r *http.Request) {
	if s.dnsOverrides == nil {
		http.Error(w, "dns override store unavailable", http.StatusServiceUnavailable)
		return
	}

	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/dns-overrides"))
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(struct {
				Overrides []dnsOverrideEntry `json:"overrides"`
			}{
				Overrides: s.dnsOverrides.List(),
			})
		case http.MethodPost:
			var req dnsOverrideRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			entry, err := s.dnsOverrides.Set(req.Host, req.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "dns_override",
				Action:       "created",
				ResourceType: "dns_override",
				ResourceID:   entry.Host,
				ResourceName: entry.Host,
				Message:      "dns override created",
				Metadata: auditMetadata(
					"host", entry.Host,
					"address", entry.Address,
				),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(entry)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		hostPath := strings.TrimPrefix(cleanPath, "/")
		host, err := url.PathUnescape(hostPath)
		if err != nil {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req dnsOverrideRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			entry, err := s.dnsOverrides.Set(host, req.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "dns_override",
				Action:       "updated",
				ResourceType: "dns_override",
				ResourceID:   entry.Host,
				ResourceName: entry.Host,
				Message:      "dns override updated",
				Metadata: auditMetadata(
					"host", entry.Host,
					"address", entry.Address,
				),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(entry)
		case http.MethodDelete:
			if err := s.dnsOverrides.Delete(host); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "dns_override",
				Action:       "deleted",
				ResourceType: "dns_override",
				ResourceID:   host,
				ResourceName: host,
				Message:      "dns override deleted",
				Metadata: auditMetadata(
					"host", host,
				),
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
