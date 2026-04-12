package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

type controlPlaneUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Status    string    `json:"status"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

type controlPlaneMembership struct {
	GroupID             string    `json:"groupId"`
	GroupName           string    `json:"groupName,omitempty"`
	AgentID             string    `json:"agentId"`
	AgentIdentification string    `json:"agentIdentification,omitempty"`
	AgentLocation       string    `json:"agentLocation,omitempty"`
	Priority            int       `json:"priority"`
	Weight              int       `json:"weight"`
	Enabled             bool      `json:"enabled"`
	Connected           bool      `json:"connected"`
	CreatedAt           time.Time `json:"createdAt,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt,omitempty"`
}

type controlPlaneAccessGrant struct {
	ID                     string    `json:"id"`
	UserID                 string    `json:"userId"`
	Username               string    `json:"username,omitempty"`
	GroupID                string    `json:"groupId,omitempty"`
	GroupName              string    `json:"groupName,omitempty"`
	DestinationProfileID   string    `json:"destinationProfileId,omitempty"`
	DestinationProfileName string    `json:"destinationProfileName,omitempty"`
	AccessMode             string    `json:"accessMode,omitempty"`
	CreatedAt              time.Time `json:"createdAt,omitempty"`
	UpdatedAt              time.Time `json:"updatedAt,omitempty"`
}

type userAPIRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Status   string `json:"status"`
	Role     string `json:"role"`
}

type agentMembershipAPIRequest struct {
	GroupID  string `json:"groupId"`
	AgentID  string `json:"agentId"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Enabled  bool   `json:"enabled"`
}

type accessGrantAPIRequest struct {
	UserID               string `json:"userId"`
	GroupID              string `json:"groupId"`
	DestinationProfileID string `json:"destinationProfileId"`
	AccessMode           string `json:"accessMode"`
}

type userAutoConfigResponse struct {
	UserID            string   `json:"userId"`
	Username          string   `json:"username"`
	PACURL            string   `json:"pacUrl"`
	CatchAll          bool     `json:"catchAll"`
	ProfileHosts      []string `json:"profileHosts,omitempty"`
	ProxyListen       string   `json:"proxyListen,omitempty"`
	SOCKSListen       string   `json:"socksListen,omitempty"`
	RequiresProxyAuth bool     `json:"requiresProxyAuth"`
}

func (s *relayServer) handleUsersAPI(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/control-plane/users"))
	if userID, ok := nestedUserAutoConfigPath(cleanPath); ok {
		s.handleUserAutoConfigAPI(w, r, userID)
		return
	}
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			users, err := s.listControlPlaneUsers(r.Context())
			if err != nil {
				s.logger.Warn("list users failed", "error", err)
				http.Error(w, "user listing failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, struct {
				Users []controlPlaneUser `json:"users"`
			}{Users: users})
		case http.MethodPost:
			var req userAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			user, err := s.upsertUser(r.Context(), nil, newControlPlaneID("usr"), req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "created",
				ResourceType: "user",
				ResourceID:   user.ID,
				ResourceName: user.Username,
				Message:      "user created",
				Metadata: auditMetadata(
					"status", string(user.Status),
					"role", string(user.Role),
				),
			})
			s.writeJSON(w, http.StatusCreated, userResponse(user))
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
			user, found, err := s.control.GetUser(r.Context(), id)
			if err != nil {
				s.logger.Warn("get user failed", "user", id, "error", err)
				http.Error(w, "user lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			s.writeJSON(w, http.StatusOK, userResponse(user))
		case http.MethodPut:
			current, found, err := s.control.GetUser(r.Context(), id)
			if err != nil {
				s.logger.Warn("get user before update failed", "user", id, "error", err)
				http.Error(w, "user lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			var req userAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			user, err := s.upsertUser(r.Context(), &current, id, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "user",
				ResourceID:   user.ID,
				ResourceName: user.Username,
				Message:      "user updated",
				Metadata: auditMetadata(
					"status", string(user.Status),
					"role", string(user.Role),
				),
			})
			s.writeJSON(w, http.StatusOK, userResponse(user))
		case http.MethodDelete:
			user, found, err := s.control.GetUser(r.Context(), id)
			if err != nil {
				s.logger.Warn("get user before delete failed", "user", id, "error", err)
				http.Error(w, "user lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			if err := s.validateUserDelete(r.Context(), user); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if err := s.control.DeleteUser(r.Context(), id); err != nil {
				s.logger.Warn("delete user failed", "user", id, "error", err)
				http.Error(w, "user delete failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "deleted",
				ResourceType: "user",
				ResourceID:   user.ID,
				ResourceName: user.Username,
				Message:      "user deleted",
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *relayServer) handleUserAutoConfigAPI(w http.ResponseWriter, r *http.Request, userID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, found, err := s.control.GetUser(r.Context(), userID)
	if err != nil {
		s.logger.Warn("get user autoconfig failed", "user", userID, "error", err)
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	payload, err := s.userAutoConfigResponse(r.Context(), r, user)
	if err != nil {
		s.writeControlPlaneError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, payload)
}

func (s *relayServer) handleAgentMembershipsAPI(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/control-plane/agent-memberships"))
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			memberships, err := s.listControlPlaneMemberships(r.Context())
			if err != nil {
				s.logger.Warn("list memberships failed", "error", err)
				http.Error(w, "membership listing failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, struct {
				Memberships []controlPlaneMembership `json:"memberships"`
			}{Memberships: memberships})
		case http.MethodPost:
			var req agentMembershipAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			membership, err := s.upsertMembership(r.Context(), req.GroupID, req.AgentID, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.membershipResponse(r.Context(), membership)
			if err != nil {
				s.logger.Warn("build membership payload failed", "group", membership.GroupID, "agent", membership.AgentID, "error", err)
				http.Error(w, "membership payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "created",
				ResourceType: "agent_membership",
				ResourceID:   membership.GroupID + ":" + membership.AgentID,
				ResourceName: payload.GroupName + " / " + payload.AgentID,
				Message:      "agent membership created",
				Metadata: auditMetadata(
					"groupId", membership.GroupID,
					"agentId", membership.AgentID,
					"enabled", fmt.Sprintf("%t", membership.Enabled),
					"priority", fmt.Sprintf("%d", membership.Priority),
					"weight", fmt.Sprintf("%d", membership.Weight),
				),
			})
			s.writeJSON(w, http.StatusCreated, payload)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		groupID, agentID, ok := pairResourceIDs(cleanPath)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var req agentMembershipAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			membership, err := s.upsertMembership(r.Context(), groupID, agentID, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.membershipResponse(r.Context(), membership)
			if err != nil {
				s.logger.Warn("build membership payload failed", "group", groupID, "agent", agentID, "error", err)
				http.Error(w, "membership payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "agent_membership",
				ResourceID:   membership.GroupID + ":" + membership.AgentID,
				ResourceName: payload.GroupName + " / " + payload.AgentID,
				Message:      "agent membership updated",
				Metadata: auditMetadata(
					"groupId", membership.GroupID,
					"agentId", membership.AgentID,
					"enabled", fmt.Sprintf("%t", membership.Enabled),
					"priority", fmt.Sprintf("%d", membership.Priority),
					"weight", fmt.Sprintf("%d", membership.Weight),
				),
			})
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodDelete:
			if err := s.control.DeleteAgentMembership(r.Context(), groupID, agentID); err != nil {
				s.logger.Warn("delete membership failed", "group", groupID, "agent", agentID, "error", err)
				http.Error(w, "membership delete failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "deleted",
				ResourceType: "agent_membership",
				ResourceID:   groupID + ":" + agentID,
				ResourceName: groupID + " / " + agentID,
				Message:      "agent membership deleted",
				Metadata: auditMetadata(
					"groupId", groupID,
					"agentId", agentID,
				),
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *relayServer) handleAccessGrantsAPI(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
		return
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/api/control-plane/access-grants"))
	switch {
	case cleanPath == "/":
		switch r.Method {
		case http.MethodGet:
			grants, err := s.listControlPlaneAccessGrants(r.Context())
			if err != nil {
				s.logger.Warn("list access grants failed", "error", err)
				http.Error(w, "grant listing failed", http.StatusInternalServerError)
				return
			}
			s.writeJSON(w, http.StatusOK, struct {
				Grants []controlPlaneAccessGrant `json:"grants"`
			}{Grants: grants})
		case http.MethodPost:
			var req accessGrantAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			grant, err := s.upsertAccessGrant(r.Context(), nil, newControlPlaneID("grt"), req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.accessGrantResponse(r.Context(), grant)
			if err != nil {
				s.logger.Warn("build access grant payload failed", "grant", grant.ID, "error", err)
				http.Error(w, "grant payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "created",
				ResourceType: "access_grant",
				ResourceID:   grant.ID,
				ResourceName: payload.Username,
				Message:      "access grant created",
				Metadata: auditMetadata(
					"userId", grant.UserID,
					"groupId", grant.GroupID,
					"destinationProfileId", grant.DestinationProfileID,
					"accessMode", grant.AccessMode,
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
			grant, found, err := s.control.GetAccessGrant(r.Context(), id)
			if err != nil {
				s.logger.Warn("get access grant failed", "grant", id, "error", err)
				http.Error(w, "grant lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			payload, err := s.accessGrantResponse(r.Context(), grant)
			if err != nil {
				s.logger.Warn("build access grant payload failed", "grant", id, "error", err)
				http.Error(w, "grant payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "access_grant",
				ResourceID:   grant.ID,
				ResourceName: payload.Username,
				Message:      "access grant updated",
				Metadata: auditMetadata(
					"userId", grant.UserID,
					"groupId", grant.GroupID,
					"destinationProfileId", grant.DestinationProfileID,
					"accessMode", grant.AccessMode,
				),
			})
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodPut:
			current, found, err := s.control.GetAccessGrant(r.Context(), id)
			if err != nil {
				s.logger.Warn("get access grant before update failed", "grant", id, "error", err)
				http.Error(w, "grant lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			var req accessGrantAPIRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			grant, err := s.upsertAccessGrant(r.Context(), &current, id, req)
			if err != nil {
				s.writeControlPlaneError(w, err)
				return
			}
			payload, err := s.accessGrantResponse(r.Context(), grant)
			if err != nil {
				s.logger.Warn("build access grant payload failed", "grant", id, "error", err)
				http.Error(w, "grant payload failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "updated",
				ResourceType: "access_grant",
				ResourceID:   grant.ID,
				ResourceName: payload.Username,
				Message:      "access grant updated",
				Metadata: auditMetadata(
					"userId", grant.UserID,
					"groupId", grant.GroupID,
					"destinationProfileId", grant.DestinationProfileID,
					"accessMode", grant.AccessMode,
				),
			})
			s.writeJSON(w, http.StatusOK, payload)
		case http.MethodDelete:
			grant, found, err := s.control.GetAccessGrant(r.Context(), id)
			if err != nil {
				s.logger.Warn("get access grant before delete failed", "grant", id, "error", err)
				http.Error(w, "grant lookup failed", http.StatusInternalServerError)
				return
			}
			if !found {
				http.NotFound(w, r)
				return
			}
			if err := s.control.DeleteAccessGrant(r.Context(), id); err != nil {
				s.logger.Warn("delete access grant failed", "grant", id, "error", err)
				http.Error(w, "grant delete failed", http.StatusInternalServerError)
				return
			}
			s.recordDashboardAudit(r, controlplane.AuditEvent{
				Category:     "control_plane",
				Action:       "deleted",
				ResourceType: "access_grant",
				ResourceID:   grant.ID,
				ResourceName: grant.UserID,
				Message:      "access grant deleted",
				Metadata: auditMetadata(
					"userId", grant.UserID,
					"groupId", grant.GroupID,
					"destinationProfileId", grant.DestinationProfileID,
					"accessMode", grant.AccessMode,
				),
			})
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *relayServer) upsertUser(ctx context.Context, current *controlplane.User, id string, req userAPIRequest) (controlplane.User, error) {
	passwordHash := ""
	if current != nil {
		passwordHash = current.PasswordHash
	}
	password := strings.TrimSpace(req.Password)
	if password != "" {
		hash, err := controlplane.HashPassword(password)
		if err != nil {
			return controlplane.User{}, fmt.Errorf("hash password: %w", err)
		}
		passwordHash = hash
	}
	status, err := parseUserStatus(req.Status, current)
	if err != nil {
		return controlplane.User{}, err
	}
	role, err := parseUserRole(req.Role, current)
	if err != nil {
		return controlplane.User{}, err
	}
	return s.control.UpsertUser(ctx, controlplane.User{
		ID:           id,
		Username:     strings.TrimSpace(req.Username),
		PasswordHash: passwordHash,
		Status:       status,
		Role:         role,
	})
}

func (s *relayServer) validateUserDelete(ctx context.Context, user controlplane.User) error {
	grants, err := s.control.ListAccessGrantsByUser(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("check user grants: %w", err)
	}
	if len(grants) > 0 {
		return fmt.Errorf("user %q still has access grants", user.Username)
	}
	return nil
}

func (s *relayServer) listControlPlaneUsers(ctx context.Context) ([]controlPlaneUser, error) {
	users, err := s.control.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]controlPlaneUser, 0, len(users))
	for _, user := range users {
		result = append(result, userResponse(user))
	}
	return result, nil
}

func userResponse(user controlplane.User) controlPlaneUser {
	return controlPlaneUser{
		ID:        user.ID,
		Username:  user.Username,
		Status:    string(user.Status),
		Role:      string(user.Role),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func (s *relayServer) userAutoConfigResponse(ctx context.Context, r *http.Request, user controlplane.User) (userAutoConfigResponse, error) {
	secret := s.userAutoConfigSecret()
	if secret == "" {
		return userAutoConfigResponse{}, fmt.Errorf("user autoconfig secret is not configured")
	}
	if s.opts == nil || strings.TrimSpace(s.opts.socksListen) == "" {
		return userAutoConfigResponse{}, fmt.Errorf("socks listener is required for user autoconfig")
	}
	if user.Status != controlplane.UserStatusActive {
		return userAutoConfigResponse{}, fmt.Errorf("user %q is disabled", user.Username)
	}
	profiles, catchAll, err := s.userPACPolicy(ctx, user.ID)
	if err != nil {
		return userAutoConfigResponse{}, fmt.Errorf("build user autoconfig policy: %w", err)
	}
	profileHosts := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		profileHosts = append(profileHosts, fmt.Sprintf("%s:%d", profile.Host, profile.Port))
	}
	scheme := "https"
	host := ""
	if r != nil {
		if r.TLS == nil {
			scheme = "http"
		}
		host = r.Host
	}
	if host == "" {
		return userAutoConfigResponse{}, fmt.Errorf("request host unavailable")
	}
	return userAutoConfigResponse{
		UserID:            user.ID,
		Username:          user.Username,
		PACURL:            fmt.Sprintf("%s://%s/autoconfig/users/%s.pac?token=%s", scheme, host, user.ID, mintUserAutoConfigToken(secret, user.ID)),
		CatchAll:          catchAll,
		ProfileHosts:      profileHosts,
		ProxyListen:       s.opts.proxyListen,
		SOCKSListen:       s.opts.socksListen,
		RequiresProxyAuth: true,
	}, nil
}

func (s *relayServer) upsertMembership(ctx context.Context, groupID, agentID string, req agentMembershipAPIRequest) (controlplane.AgentMembership, error) {
	groupID = strings.TrimSpace(groupID)
	agentID = strings.TrimSpace(agentID)
	if groupID == "" {
		groupID = strings.TrimSpace(req.GroupID)
	}
	if agentID == "" {
		agentID = strings.TrimSpace(req.AgentID)
	}
	if _, found, err := s.control.GetAgentGroup(ctx, groupID); err != nil {
		return controlplane.AgentMembership{}, fmt.Errorf("group lookup failed: %w", err)
	} else if !found {
		return controlplane.AgentMembership{}, fmt.Errorf("group does not exist")
	}
	record, ok := s.agentDirectory[agentID]
	if !ok || record == nil {
		return controlplane.AgentMembership{}, fmt.Errorf("agent does not exist in relay config")
	}
	return s.control.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID:  groupID,
		AgentID:  agentID,
		Priority: req.Priority,
		Weight:   req.Weight,
		Enabled:  req.Enabled,
	})
}

func (s *relayServer) listControlPlaneMemberships(ctx context.Context) ([]controlPlaneMembership, error) {
	memberships, err := s.control.ListAgentMemberships(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]controlPlaneMembership, 0, len(memberships))
	for _, membership := range memberships {
		payload, err := s.membershipResponse(ctx, membership)
		if err != nil {
			return nil, err
		}
		result = append(result, payload)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].GroupName == result[j].GroupName {
			return result[i].AgentID < result[j].AgentID
		}
		return result[i].GroupName < result[j].GroupName
	})
	return result, nil
}

func (s *relayServer) membershipResponse(ctx context.Context, membership controlplane.AgentMembership) (controlPlaneMembership, error) {
	groupName := membership.GroupID
	group, found, err := s.control.GetAgentGroup(ctx, membership.GroupID)
	if err != nil {
		return controlPlaneMembership{}, fmt.Errorf("group lookup failed: %w", err)
	}
	if found {
		groupName = group.Name
	}
	agentIdentification := membership.AgentID
	agentLocation := ""
	if record, ok := s.agentDirectory[membership.AgentID]; ok && record != nil {
		if record.Identification != "" {
			agentIdentification = record.Identification
		}
		agentLocation = record.Location
	}
	_, connected := s.lookupAgent(membership.AgentID)
	return controlPlaneMembership{
		GroupID:             membership.GroupID,
		GroupName:           groupName,
		AgentID:             membership.AgentID,
		AgentIdentification: agentIdentification,
		AgentLocation:       agentLocation,
		Priority:            membership.Priority,
		Weight:              membership.Weight,
		Enabled:             membership.Enabled,
		Connected:           connected,
		CreatedAt:           membership.CreatedAt,
		UpdatedAt:           membership.UpdatedAt,
	}, nil
}

func (s *relayServer) upsertAccessGrant(ctx context.Context, current *controlplane.AccessGrant, id string, req accessGrantAPIRequest) (controlplane.AccessGrant, error) {
	userID := strings.TrimSpace(req.UserID)
	groupID := strings.TrimSpace(req.GroupID)
	profileID := strings.TrimSpace(req.DestinationProfileID)
	if current != nil {
		if userID == "" {
			userID = current.UserID
		}
	}
	if _, found, err := s.control.GetUser(ctx, userID); err != nil {
		return controlplane.AccessGrant{}, fmt.Errorf("user lookup failed: %w", err)
	} else if !found {
		return controlplane.AccessGrant{}, fmt.Errorf("user does not exist")
	}
	if groupID != "" {
		if _, found, err := s.control.GetAgentGroup(ctx, groupID); err != nil {
			return controlplane.AccessGrant{}, fmt.Errorf("group lookup failed: %w", err)
		} else if !found {
			return controlplane.AccessGrant{}, fmt.Errorf("group does not exist")
		}
	}
	if profileID != "" {
		if _, found, err := s.control.GetDestinationProfile(ctx, profileID); err != nil {
			return controlplane.AccessGrant{}, fmt.Errorf("destination profile lookup failed: %w", err)
		} else if !found {
			return controlplane.AccessGrant{}, fmt.Errorf("destination profile does not exist")
		}
	}
	accessMode := strings.TrimSpace(req.AccessMode)
	if accessMode == "" && current != nil {
		accessMode = current.AccessMode
	}
	return s.control.UpsertAccessGrant(ctx, controlplane.AccessGrant{
		ID:                   id,
		UserID:               userID,
		GroupID:              groupID,
		DestinationProfileID: profileID,
		AccessMode:           accessMode,
	})
}

func (s *relayServer) listControlPlaneAccessGrants(ctx context.Context) ([]controlPlaneAccessGrant, error) {
	grants, err := s.control.ListAccessGrants(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]controlPlaneAccessGrant, 0, len(grants))
	for _, grant := range grants {
		payload, err := s.accessGrantResponse(ctx, grant)
		if err != nil {
			return nil, err
		}
		result = append(result, payload)
	}
	return result, nil
}

func (s *relayServer) accessGrantResponse(ctx context.Context, grant controlplane.AccessGrant) (controlPlaneAccessGrant, error) {
	username := grant.UserID
	if user, found, err := s.control.GetUser(ctx, grant.UserID); err != nil {
		return controlPlaneAccessGrant{}, fmt.Errorf("user lookup failed: %w", err)
	} else if found {
		username = user.Username
	}
	groupName := ""
	if grant.GroupID != "" {
		if group, found, err := s.control.GetAgentGroup(ctx, grant.GroupID); err != nil {
			return controlPlaneAccessGrant{}, fmt.Errorf("group lookup failed: %w", err)
		} else if found {
			groupName = group.Name
		}
	}
	profileName := ""
	if grant.DestinationProfileID != "" {
		if profile, found, err := s.control.GetDestinationProfile(ctx, grant.DestinationProfileID); err != nil {
			return controlPlaneAccessGrant{}, fmt.Errorf("destination profile lookup failed: %w", err)
		} else if found {
			profileName = profile.Name
		}
	}
	return controlPlaneAccessGrant{
		ID:                     grant.ID,
		UserID:                 grant.UserID,
		Username:               username,
		GroupID:                grant.GroupID,
		GroupName:              groupName,
		DestinationProfileID:   grant.DestinationProfileID,
		DestinationProfileName: profileName,
		AccessMode:             grant.AccessMode,
		CreatedAt:              grant.CreatedAt,
		UpdatedAt:              grant.UpdatedAt,
	}, nil
}

func parseUserStatus(raw string, current *controlplane.User) (controlplane.UserStatus, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" && current != nil {
		return current.Status, nil
	}
	switch controlplane.UserStatus(value) {
	case "", controlplane.UserStatusActive:
		return controlplane.UserStatusActive, nil
	case controlplane.UserStatusDisabled:
		return controlplane.UserStatusDisabled, nil
	default:
		return "", fmt.Errorf("invalid user status")
	}
}

func parseUserRole(raw string, current *controlplane.User) (controlplane.UserRole, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" && current != nil {
		return current.Role, nil
	}
	switch controlplane.UserRole(value) {
	case "", controlplane.UserRoleUser:
		return controlplane.UserRoleUser, nil
	case controlplane.UserRoleAdmin, controlplane.UserRoleOperator:
		return controlplane.UserRole(value), nil
	default:
		return "", fmt.Errorf("invalid user role")
	}
}

func pairResourceIDs(cleanPath string) (string, string, bool) {
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func nestedUserAutoConfigPath(cleanPath string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "autoconfig" {
		return "", false
	}
	return parts[0], true
}
