package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
	"github.com/google/uuid"
)

type agentGroupAPIRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	RoutingMode string `json:"routingMode"`
}

type destinationProfileAPIRequest struct {
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	ProtocolHint   string `json:"protocolHint"`
	DefaultGroupID string `json:"defaultGroupId"`
	Notes          string `json:"notes"`
}

func (s *relayServer) handleAgentGroupsAPI(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}

	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/control-plane/agent-groups"))
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			groups, err := s.listStatusAgentGroups(r.Context())
			if err != nil {
				s.logger.Warn("list agent groups failed", "error", err)
				http.Error(w, "agent group listing failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, struct {
				Groups []statusAgentGroup `json:"groups"`
			}{
				Groups: groups,
			})
		case http.MethodPost:
			var req agentGroupAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			group, err := s.upsertAgentGroup(r.Context(), newControlPlaneID("grp"), req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.statusAgentGroup(r.Context(), group)
			if err != nil {
				s.logger.Warn("build agent group payload failed", "group", group.ID, "error", err)
				http.Error(w, "agent group payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "created",
				ResourceType: "agent_group",
				ResourceID:   group.ID,
				ResourceName: group.Name,
				Message:      "agent group created",
				Metadata: auditMetadata(
					"slug", group.Slug,
					"routingMode", group.RoutingMode,
				),
			})
			s.writeJSON(w, http.StatusCreated, payload)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		id, ok := singleResourceID(cleanPath)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			group, found, err := s.control.GetAgentGroup(r.Context(), id)
			if err != nil {
				s.logger.Warn("get agent group failed", "group", id, "error", err)
				http.Error(w, "agent group lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			payload, err := s.statusAgentGroup(r.Context(), group)
			if err != nil {
				s.logger.Warn("build agent group payload failed", "group", id, "error", err)
				http.Error(w, "agent group payload failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodPut:
			group, found, err := s.control.GetAgentGroup(r.Context(), id)
			if err != nil {
				s.logger.Warn("get agent group before update failed", "group", id, "error", err)
				http.Error(w, "agent group lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			if group.ID == legacyAgentGroupID {
				http.Error(w, "legacy compatibility group is managed automatically", http.StatusConflict)
				return
			}
			var req agentGroupAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			group, err = s.upsertAgentGroup(r.Context(), id, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.statusAgentGroup(r.Context(), group)
			if err != nil {
				s.logger.Warn("build agent group payload failed", "group", id, "error", err)
				http.Error(w, "agent group payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "agent_group",
				ResourceID:   group.ID,
				ResourceName: group.Name,
				Message:      "agent group updated",
				Metadata: auditMetadata(
					"slug", group.Slug,
					"routingMode", group.RoutingMode,
				),
			})
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodDelete:
			group, found, err := s.control.GetAgentGroup(r.Context(), id)
			if err != nil {
				s.logger.Warn("get agent group before delete failed", "group", id, "error", err)
				http.Error(w, "agent group lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			if err := s.validateAgentGroupDelete(r.Context(), group); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if err := s.control.DeleteAgentGroup(r.Context(), id); err != nil {
				s.logger.Warn("delete agent group failed", "group", id, "error", err)
				http.Error(w, "agent group delete failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "deleted",
				ResourceType: "agent_group",
				ResourceID:   group.ID,
				ResourceName: group.Name,
				Message:      "agent group deleted",
				Metadata: auditMetadata(
					"slug", group.Slug,
				),
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *relayServer) handleDestinationProfilesAPI(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}

	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/control-plane/destination-profiles"))
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			profiles, err := s.listStatusDestinationProfiles(r.Context())
			if err != nil {
				s.logger.Warn("list destination profiles failed", "error", err)
				http.Error(w, "destination profile listing failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, struct {
				Profiles []statusDestinationProfile `json:"profiles"`
			}{
				Profiles: profiles,
			})
		case http.MethodPost:
			var req destinationProfileAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			profile, err := s.upsertDestinationProfile(r.Context(), newControlPlaneID("dst"), req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.statusDestinationProfile(r.Context(), profile)
			if err != nil {
				s.logger.Warn("build destination profile payload failed", "profile", profile.ID, "error", err)
				http.Error(w, "destination profile payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "created",
				ResourceType: "destination_profile",
				ResourceID:   profile.ID,
				ResourceName: profile.Name,
				Message:      "destination profile created",
				Metadata: auditMetadata(
					"host", profile.Host,
					"port", fmt.Sprintf("%d", profile.Port),
					"defaultGroupId", profile.DefaultGroupID,
				),
			})
			s.writeJSON(w, http.StatusCreated, payload)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		id, ok := singleResourceID(cleanPath)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			profile, found, err := s.control.GetDestinationProfile(r.Context(), id)
			if err != nil {
				s.logger.Warn("get destination profile failed", "profile", id, "error", err)
				http.Error(w, "destination profile lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			payload, err := s.statusDestinationProfile(r.Context(), profile)
			if err != nil {
				s.logger.Warn("build destination profile payload failed", "profile", id, "error", err)
				http.Error(w, "destination profile payload failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodPut:
			if _, found, err := s.control.GetDestinationProfile(r.Context(), id); err != nil {
				s.logger.Warn("get destination profile before update failed", "profile", id, "error", err)
				http.Error(w, "destination profile lookup failed", http.StatusInternalServerError)
				return
			} else if !found {
				http.NotFound(w, r)
				return
			}
			var req destinationProfileAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			profile, err := s.upsertDestinationProfile(r.Context(), id, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.statusDestinationProfile(r.Context(), profile)
			if err != nil {
				s.logger.Warn("build destination profile payload failed", "profile", id, "error", err)
				http.Error(w, "destination profile payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "destination_profile",
				ResourceID:   profile.ID,
				ResourceName: profile.Name,
				Message:      "destination profile updated",
				Metadata: auditMetadata(
					"host", profile.Host,
					"port", fmt.Sprintf("%d", profile.Port),
					"defaultGroupId", profile.DefaultGroupID,
				),
			})
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodDelete:
			profile, found, err := s.control.GetDestinationProfile(r.Context(), id)
			if err != nil {
				s.logger.Warn("get destination profile before delete failed", "profile", id, "error", err)
				http.Error(w, "destination profile lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			if err := s.validateDestinationProfileDelete(r.Context(), profile); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if err := s.control.DeleteDestinationProfile(r.Context(), id); err != nil {
				s.logger.Warn("delete destination profile failed", "profile", id, "error", err)
				http.Error(w, "destination profile delete failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "deleted",
				ResourceType: "destination_profile",
				ResourceID:   profile.ID,
				ResourceName: profile.Name,
				Message:      "destination profile deleted",
				Metadata: auditMetadata(
					"host", profile.Host,
					"port", fmt.Sprintf("%d", profile.Port),
				),
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *relayServer) upsertAgentGroup(ctx context.Context, id string, req agentGroupAPIRequest) (controlplane.AgentGroup, error) {
	group, err := s.control.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:          id,
		Name:        strings.TrimSpace(req.Name),
		Slug:        strings.TrimSpace(req.Slug),
		Description: strings.TrimSpace(req.Description),
		RoutingMode: strings.TrimSpace(req.RoutingMode),
	})
	if err != nil {
		return controlplane.AgentGroup{}, err
	}
	return group, nil
}

func (s *relayServer) upsertDestinationProfile(ctx context.Context, id string, req destinationProfileAPIRequest) (controlplane.DestinationProfile, error) {
	defaultGroupID := strings.TrimSpace(req.DefaultGroupID)
	if defaultGroupID == "" {
		return controlplane.DestinationProfile{}, fmt.Errorf("default group is required")
	}
	if _, found, err := s.control.GetAgentGroup(ctx, defaultGroupID); err != nil {
		return controlplane.DestinationProfile{}, fmt.Errorf("default group lookup failed: %w", err)
	} else if !found {
		return controlplane.DestinationProfile{}, fmt.Errorf("default group does not exist")
	}

	profile, err := s.control.UpsertDestinationProfile(ctx, controlplane.DestinationProfile{
		ID:             id,
		Name:           strings.TrimSpace(req.Name),
		Slug:           strings.TrimSpace(req.Slug),
		Host:           strings.TrimSpace(req.Host),
		Port:           req.Port,
		ProtocolHint:   strings.TrimSpace(req.ProtocolHint),
		DefaultGroupID: defaultGroupID,
		Notes:          strings.TrimSpace(req.Notes),
	})
	if err != nil {
		return controlplane.DestinationProfile{}, err
	}
	return profile, nil
}

func (s *relayServer) validateAgentGroupDelete(ctx context.Context, group controlplane.AgentGroup) error {
	if group.ID == legacyAgentGroupID {
		return fmt.Errorf("legacy compatibility group cannot be deleted")
	}

	profiles, err := s.control.ListDestinationProfiles(ctx)
	if err != nil {
		return fmt.Errorf("check destination profiles: %w", err)
	}
	for _, profile := range profiles {
		if profile.DefaultGroupID == group.ID {
			return fmt.Errorf("group %q is the default route for destination profile %q", group.Name, profile.Name)
		}
	}

	grants, err := s.control.ListAccessGrants(ctx)
	if err != nil {
		return fmt.Errorf("check access grants: %w", err)
	}
	for _, grant := range grants {
		if grant.GroupID == group.ID {
			return fmt.Errorf("group %q is still referenced by access grants", group.Name)
		}
	}
	return nil
}

func (s *relayServer) validateDestinationProfileDelete(ctx context.Context, profile controlplane.DestinationProfile) error {
	grants, err := s.control.ListAccessGrants(ctx)
	if err != nil {
		return fmt.Errorf("check access grants: %w", err)
	}
	for _, grant := range grants {
		if grant.DestinationProfileID == profile.ID {
			return fmt.Errorf("destination profile %q is still referenced by access grants", profile.Name)
		}
	}
	return nil
}

func (s *relayServer) listStatusAgentGroups(ctx context.Context) ([]statusAgentGroup, error) {
	if s.control == nil {
		return nil, nil
	}
	groups, err := s.control.ListAgentGroups(ctx)
	if err != nil {
		return nil, err
	}
	memberships, err := s.control.ListAgentMemberships(ctx)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]struct {
		total   int
		enabled int
	}, len(groups))
	for _, membership := range memberships {
		count := counts[membership.GroupID]
		count.total++
		if membership.Enabled {
			count.enabled++
		}
		counts[membership.GroupID] = count
	}
	result := make([]statusAgentGroup, 0, len(groups))
	for _, group := range groups {
		count := counts[group.ID]
		result = append(result, statusAgentGroup{
			ID:                 group.ID,
			Name:               group.Name,
			Slug:               group.Slug,
			Description:        group.Description,
			RoutingMode:        group.RoutingMode,
			MemberCount:        count.total,
			EnabledMemberCount: count.enabled,
			CreatedAt:          group.CreatedAt,
			UpdatedAt:          group.UpdatedAt,
			Legacy:             group.ID == legacyAgentGroupID,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Slug < result[j].Slug
	})
	return result, nil
}

func (s *relayServer) statusAgentGroup(ctx context.Context, group controlplane.AgentGroup) (statusAgentGroup, error) {
	groups, err := s.listStatusAgentGroups(ctx)
	if err != nil {
		return statusAgentGroup{}, err
	}
	for _, candidate := range groups {
		if candidate.ID == group.ID {
			return candidate, nil
		}
	}
	return statusAgentGroup{}, fmt.Errorf("agent group %s missing from status snapshot", group.ID)
}

func (s *relayServer) listStatusDestinationProfiles(ctx context.Context) ([]statusDestinationProfile, error) {
	if s.control == nil {
		return nil, nil
	}
	profiles, err := s.control.ListDestinationProfiles(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := s.control.ListAgentGroups(ctx)
	if err != nil {
		return nil, err
	}
	groupNames := make(map[string]string, len(groups))
	for _, group := range groups {
		groupNames[group.ID] = group.Name
	}
	result := make([]statusDestinationProfile, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, statusDestinationProfile{
			ID:               profile.ID,
			Name:             profile.Name,
			Slug:             profile.Slug,
			Host:             profile.Host,
			Port:             profile.Port,
			ProtocolHint:     profile.ProtocolHint,
			DefaultGroupID:   profile.DefaultGroupID,
			DefaultGroupName: groupNames[profile.DefaultGroupID],
			Notes:            profile.Notes,
			CreatedAt:        profile.CreatedAt,
			UpdatedAt:        profile.UpdatedAt,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Slug < result[j].Slug
	})
	return result, nil
}

func (s *relayServer) statusDestinationProfile(ctx context.Context, profile controlplane.DestinationProfile) (statusDestinationProfile, error) {
	profiles, err := s.listStatusDestinationProfiles(ctx)
	if err != nil {
		return statusDestinationProfile{}, err
	}
	for _, candidate := range profiles {
		if candidate.ID == profile.ID {
			return candidate, nil
		}
	}
	return statusDestinationProfile{}, fmt.Errorf("destination profile %s missing from status snapshot", profile.ID)
}

func (s *relayServer) writeControlPlaneError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	message := err.Error()
	status := http.StatusBadRequest
	if strings.Contains(message, "lookup failed") || strings.Contains(message, "check ") {
		status = http.StatusInternalServerError
	}
	http.Error(w, message, status)
}

func (s *relayServer) writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("json encode failed", "status", statusCode, "error", err)
	}
}

func newControlPlaneID(prefix string) string {
	return prefix + "-" + uuid.NewString()
}

func singleResourceID(cleanPath string) (string, bool) {
	id := strings.TrimPrefix(cleanPath, "/")
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}
