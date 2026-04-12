package relay

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

type agentDeploymentRequest struct {
	Version    string `json:"version"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	ForceCheck bool   `json:"forceCheck"`
}

type agentDeploymentResponse struct {
	AgentID         string   `json:"agentId"`
	CurrentVersion  string   `json:"currentVersion,omitempty"`
	DesiredVersion  string   `json:"desiredVersion,omitempty"`
	PinnedVersion   string   `json:"pinnedVersion,omitempty"`
	Track           string   `json:"track,omitempty"`
	GOOS            string   `json:"goos,omitempty"`
	GOARCH          string   `json:"goarch,omitempty"`
	ForceDispatched bool     `json:"forceDispatched,omitempty"`
	Available       []string `json:"availableVersions,omitempty"`
}

func (s *relayServer) handleAgentDeploymentAPI(w http.ResponseWriter, r *http.Request) {
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/agents/"))
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "deployment" {
		http.NotFound(w, r)
		return
	}
	agentID := parts[0]
	if _, ok := s.agentDirectory[agentID]; !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req agentDeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	versionText := strings.TrimSpace(req.Version)
	if strings.EqualFold(versionText, "latest") {
		versionText = ""
	}
	if s.updateManager == nil {
		http.Error(w, "update manager unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.updateManager.setPinnedTarget(agentID, req.GOOS, req.GOARCH, versionText); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			http.Error(w, "requested version not found for agent platform", http.StatusNotFound)
		default:
			s.logger.Warn("deployment update failed", "agent", agentID, "version", versionText, "error", err)
			http.Error(w, "deployment update error", http.StatusInternalServerError)
		}
		return
	}

	dispatched := false
	if req.ForceCheck {
		if session, ok := s.lookupAgent(agentID); ok {
			if err := session.sendUpdateCommand(); err != nil {
				s.logger.Debug("update trigger dispatch failed", "agent", agentID, "error", err)
			} else {
				dispatched = true
			}
		}
	}

	status := s.updateManager.deploymentStatus(agentID, req.GOOS, req.GOARCH)
	response := agentDeploymentResponse{
		AgentID:         agentID,
		CurrentVersion:  status.CurrentVersion,
		DesiredVersion:  status.DesiredVersion,
		PinnedVersion:   status.PinnedVersion,
		Track:           status.Track,
		GOOS:            status.GOOS,
		GOARCH:          status.GOARCH,
		ForceDispatched: dispatched,
		Available:       s.updateManager.availableVersions(status.GOOS, status.GOARCH),
	}
	action := "updated"
	message := "agent deployment target updated"
	if response.Track == "latest" {
		action = "reset"
		message = "agent deployment target reset to latest"
	}
	if req.ForceCheck {
		message = "agent deployment target updated and forced update check requested"
	}
	s.recordDashboardAudit(r, controlplane.AuditEvent{
		Category:     "deployment",
		Action:       action,
		ResourceType: "agent_deployment",
		ResourceID:   agentID,
		ResourceName: agentID,
		Message:      message,
		Metadata: auditMetadata(
			"agentId", agentID,
			"goos", response.GOOS,
			"goarch", response.GOARCH,
			"desiredVersion", response.DesiredVersion,
			"pinnedVersion", response.PinnedVersion,
			"track", response.Track,
			"forceDispatched", strconv.FormatBool(response.ForceDispatched),
		),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Warn("deployment response encode failed", "agent", agentID, "error", err)
	}
}
