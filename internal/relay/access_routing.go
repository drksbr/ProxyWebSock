package relay

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

type proxyPrincipalKind string

const (
	proxyPrincipalAgent proxyPrincipalKind = "agent"
	proxyPrincipalUser  proxyPrincipalKind = "user"
)

type proxyPrincipal struct {
	Kind       proxyPrincipalKind
	AgentID    string
	User       controlplane.User
	Username   string
	LegacyAuth bool
}

type routeDecision struct {
	PrincipalType  string
	PrincipalName  string
	GroupID        string
	GroupName      string
	ProfileID      string
	ProfileName    string
	ReasonCode     string
	Reason         string
	AgentID        string
	AgentName      string
	SelectedStatus string
	CandidateCount int
}

type routeError struct {
	httpStatus     int
	socksReply     byte
	reasonCode     string
	message        string
	groupID        string
	groupName      string
	profileID      string
	profileName    string
	candidateCount int
}

func (e *routeError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

type userRouteCandidate struct {
	GroupID     string
	GroupName   string
	ProfileID   string
	ProfileName string
	ReasonCode  string
	Reason      string
	Priority    int
}

type groupSelection struct {
	Session        *relayAgentSession
	GroupID        string
	GroupName      string
	ProfileID      string
	ProfileName    string
	ReasonCode     string
	Reason         string
	Membership     controlplane.AgentMembership
	Snapshot       statusAgent
	CandidateCount int
}

func (s *relayServer) authenticateProxyPrincipal(ctx context.Context, username, secret string) (proxyPrincipal, error) {
	if username == "" || secret == "" {
		return proxyPrincipal{}, fmt.Errorf("credentials required")
	}
	if _, ok := s.authenticateAgent(username, secret); ok {
		return proxyPrincipal{
			Kind:       proxyPrincipalAgent,
			AgentID:    username,
			Username:   username,
			LegacyAuth: true,
		}, nil
	}
	if s.control == nil {
		return proxyPrincipal{}, fmt.Errorf("invalid credentials")
	}
	user, found, err := s.control.GetUserByUsername(ctx, username)
	if err != nil {
		return proxyPrincipal{}, fmt.Errorf("lookup user: %w", err)
	}
	if !found {
		return proxyPrincipal{}, fmt.Errorf("invalid credentials")
	}
	if !controlplane.VerifyPassword(user.PasswordHash, secret) {
		return proxyPrincipal{}, fmt.Errorf("invalid credentials")
	}
	if user.Status != controlplane.UserStatusActive {
		return proxyPrincipal{}, fmt.Errorf("user %q is disabled", user.Username)
	}
	return proxyPrincipal{
		Kind:     proxyPrincipalUser,
		User:     user,
		Username: user.Username,
	}, nil
}

func (s *relayServer) resolveRouteForPrincipal(ctx context.Context, principal proxyPrincipal, host string, port int) (*relayAgentSession, routeDecision, error) {
	targetHostPort := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	switch principal.Kind {
	case proxyPrincipalAgent:
		if err := s.authorizeTarget(principal.AgentID, targetHostPort); err != nil {
			return nil, routeDecision{}, &routeError{
				httpStatus: http.StatusForbidden,
				socksReply: 0x02,
				reasonCode: "legacy_acl_blocked",
				message:    err.Error(),
			}
		}
		session, ok := s.lookupAgent(principal.AgentID)
		if !ok {
			return nil, routeDecision{}, &routeError{
				httpStatus: http.StatusServiceUnavailable,
				socksReply: 0x05,
				reasonCode: "legacy_agent_disconnected",
				message:    "agent not connected",
			}
		}
		record, _ := s.agentDirectory[principal.AgentID]
		agentName := principal.AgentID
		if record != nil && strings.TrimSpace(record.Identification) != "" {
			agentName = record.Identification
		}
		return session, routeDecision{
			PrincipalType:  string(proxyPrincipalAgent),
			PrincipalName:  principal.AgentID,
			ReasonCode:     "legacy_agent_direct",
			Reason:         "legacy agent-auth direct route",
			AgentID:        principal.AgentID,
			AgentName:      agentName,
			SelectedStatus: session.snapshot().Status,
			CandidateCount: 1,
		}, nil
	case proxyPrincipalUser:
		return s.resolveUserRoute(ctx, principal.User, host, port)
	default:
		return nil, routeDecision{}, &routeError{
			httpStatus: http.StatusForbidden,
			socksReply: 0x01,
			reasonCode: "unsupported_principal",
			message:    "unsupported principal",
		}
	}
}

func (s *relayServer) resolveUserRoute(ctx context.Context, user controlplane.User, host string, port int) (*relayAgentSession, routeDecision, error) {
	grants, err := s.control.ListAccessGrantsByUser(ctx, user.ID)
	if err != nil {
		return nil, routeDecision{}, fmt.Errorf("list access grants: %w", err)
	}
	if len(grants) == 0 {
		return nil, routeDecision{}, &routeError{
			httpStatus: http.StatusForbidden,
			socksReply: 0x02,
			reasonCode: "user_no_grants",
			message:    fmt.Sprintf("user %q has no access grants", user.Username),
		}
	}

	candidates := make([]userRouteCandidate, 0, len(grants))
	for _, grant := range grants {
		candidate, ok, err := s.userRouteCandidateFromGrant(ctx, grant, host, port)
		if err != nil {
			return nil, routeDecision{}, err
		}
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, routeDecision{}, &routeError{
			httpStatus: http.StatusForbidden,
			socksReply: 0x02,
			reasonCode: "target_not_granted",
			message:    fmt.Sprintf("target %s:%d is not allowed for user %q", host, port, user.Username),
		}
	}

	selections := make([]groupSelection, 0, len(candidates))
	var lastRouteErr *routeError
	for _, candidate := range candidates {
		selection, err := s.selectAgentForGroup(ctx, candidate, host, port)
		if err != nil {
			if re, ok := err.(*routeError); ok {
				lastRouteErr = re
				continue
			}
			return nil, routeDecision{}, err
		}
		selections = append(selections, selection)
	}
	if len(selections) == 0 {
		if lastRouteErr != nil {
			return nil, routeDecision{}, lastRouteErr
		}
		return nil, routeDecision{}, &routeError{
			httpStatus: http.StatusServiceUnavailable,
			socksReply: 0x05,
			reasonCode: "no_group_candidates",
			message:    "no relay agent available for granted groups",
		}
	}

	sort.Slice(selections, func(i, j int) bool {
		return betterGroupSelection(selections[i], selections[j])
	})
	best := selections[0]
	return best.Session, routeDecision{
		PrincipalType:  string(proxyPrincipalUser),
		PrincipalName:  user.Username,
		GroupID:        best.GroupID,
		GroupName:      best.GroupName,
		ProfileID:      best.ProfileID,
		ProfileName:    best.ProfileName,
		ReasonCode:     best.ReasonCode,
		Reason:         best.Reason,
		AgentID:        best.Membership.AgentID,
		AgentName:      best.agentName(),
		SelectedStatus: best.Snapshot.Status,
		CandidateCount: best.CandidateCount,
	}, nil
}

func (s *relayServer) userRouteCandidateFromGrant(ctx context.Context, grant controlplane.AccessGrant, host string, port int) (userRouteCandidate, bool, error) {
	groupID := strings.TrimSpace(grant.GroupID)
	groupName := ""
	profileID := strings.TrimSpace(grant.DestinationProfileID)
	profileName := ""
	priority := 1

	if profileID != "" {
		profile, found, err := s.control.GetDestinationProfile(ctx, profileID)
		if err != nil {
			return userRouteCandidate{}, false, fmt.Errorf("lookup destination profile: %w", err)
		}
		if !found {
			return userRouteCandidate{}, false, nil
		}
		if !profileMatchesTarget(profile, host, port) {
			return userRouteCandidate{}, false, nil
		}
		profileName = profile.Name
		if groupID == "" {
			groupID = profile.DefaultGroupID
		}
		priority = 0
	}

	if groupID == "" {
		return userRouteCandidate{}, false, nil
	}
	group, found, err := s.control.GetAgentGroup(ctx, groupID)
	if err != nil {
		return userRouteCandidate{}, false, fmt.Errorf("lookup agent group: %w", err)
	}
	if !found {
		return userRouteCandidate{}, false, nil
	}
	groupName = group.Name

	reason := fmt.Sprintf("user grant via group %q", groupName)
	reasonCode := "user_group_grant"
	if profileName != "" {
		reason = fmt.Sprintf("destination profile %q routed through group %q", profileName, groupName)
		reasonCode = "user_profile_grant"
	}

	return userRouteCandidate{
		GroupID:     groupID,
		GroupName:   groupName,
		ProfileID:   profileID,
		ProfileName: profileName,
		ReasonCode:  reasonCode,
		Reason:      reason,
		Priority:    priority,
	}, true, nil
}

func (s *relayServer) selectAgentForGroup(ctx context.Context, candidate userRouteCandidate, host string, port int) (groupSelection, error) {
	return s.selectAgentForGroupWithOptions(ctx, candidate, host, port, false)
}

func (s *relayServer) selectAgentForGroupWithOptions(ctx context.Context, candidate userRouteCandidate, host string, port int, ignoreBreaker bool) (groupSelection, error) {
	targetHostPort := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if !ignoreBreaker {
		if snapshot, allowed := s.allowRouteTarget(candidate.GroupID, candidate.GroupName, targetHostPort); !allowed {
			reasonCode := "destination_circuit_open"
			if snapshot.State == string(circuitBreakerHalfOpen) {
				reasonCode = "destination_circuit_half_open"
			}
			message := fmt.Sprintf("destination circuit breaker %s for group %q and target %s", snapshot.State, candidate.GroupName, targetHostPort)
			if !snapshot.OpenUntil.IsZero() {
				message = fmt.Sprintf("%s until %s", message, snapshot.OpenUntil.Format(time.RFC3339))
			}
			return groupSelection{}, &routeError{
				httpStatus:     http.StatusServiceUnavailable,
				socksReply:     0x05,
				reasonCode:     reasonCode,
				message:        message,
				groupID:        candidate.GroupID,
				groupName:      candidate.GroupName,
				profileID:      candidate.ProfileID,
				profileName:    candidate.ProfileName,
				candidateCount: 0,
			}
		}
	}
	memberships, err := s.control.ListAgentMemberships(ctx)
	if err != nil {
		return groupSelection{}, fmt.Errorf("list agent memberships: %w", err)
	}
	filtered := make([]controlplane.AgentMembership, 0)
	for _, membership := range memberships {
		if membership.GroupID == candidate.GroupID && membership.Enabled {
			filtered = append(filtered, membership)
		}
	}
	if len(filtered) == 0 {
		return groupSelection{}, &routeError{
			httpStatus:     http.StatusServiceUnavailable,
			socksReply:     0x05,
			reasonCode:     "group_no_enabled_memberships",
			message:        fmt.Sprintf("group %q has no enabled agent memberships", candidate.GroupName),
			groupID:        candidate.GroupID,
			groupName:      candidate.GroupName,
			profileID:      candidate.ProfileID,
			profileName:    candidate.ProfileName,
			candidateCount: 0,
		}
	}

	selections := make([]groupSelection, 0, len(filtered))
	aclAllowed := 0
	quotaUsage := s.collectQuotaUsage()
	quotaFiltered := 0
	for _, membership := range filtered {
		if err := s.authorizeTarget(membership.AgentID, targetHostPort); err != nil {
			continue
		}
		aclAllowed++
		if s.filterAgentByQuota(membership.AgentID, quotaUsage) {
			quotaFiltered++
			continue
		}
		session, ok := s.lookupAgent(membership.AgentID)
		if !ok {
			continue
		}
		selections = append(selections, groupSelection{
			Session:     session,
			GroupID:     candidate.GroupID,
			GroupName:   candidate.GroupName,
			ProfileID:   candidate.ProfileID,
			ProfileName: candidate.ProfileName,
			ReasonCode:  candidate.ReasonCode,
			Reason:      candidate.Reason,
			Membership:  membership,
			Snapshot:    session.snapshot(),
		})
	}

	if aclAllowed == 0 {
		return groupSelection{}, &routeError{
			httpStatus:     http.StatusForbidden,
			socksReply:     0x02,
			reasonCode:     "group_acl_blocked",
			message:        fmt.Sprintf("target %s blocked by ACL for group %q", targetHostPort, candidate.GroupName),
			groupID:        candidate.GroupID,
			groupName:      candidate.GroupName,
			profileID:      candidate.ProfileID,
			profileName:    candidate.ProfileName,
			candidateCount: len(filtered),
		}
	}
	if len(selections) == 0 {
		if quotaFiltered > 0 {
			return groupSelection{}, &routeError{
				httpStatus:     http.StatusTooManyRequests,
				socksReply:     0x01,
				reasonCode:     "agent_stream_quota_exceeded",
				message:        fmt.Sprintf("all connected agents for group %q reached the concurrent stream quota (%d)", candidate.GroupName, s.opts.agentStreamQuota),
				groupID:        candidate.GroupID,
				groupName:      candidate.GroupName,
				profileID:      candidate.ProfileID,
				profileName:    candidate.ProfileName,
				candidateCount: aclAllowed,
			}
		}
		return groupSelection{}, &routeError{
			httpStatus:     http.StatusServiceUnavailable,
			socksReply:     0x05,
			reasonCode:     "group_agents_disconnected",
			message:        fmt.Sprintf("no connected agents available for group %q", candidate.GroupName),
			groupID:        candidate.GroupID,
			groupName:      candidate.GroupName,
			profileID:      candidate.ProfileID,
			profileName:    candidate.ProfileName,
			candidateCount: aclAllowed,
		}
	}

	sort.Slice(selections, func(i, j int) bool {
		return betterGroupSelection(selections[i], selections[j])
	})
	best := selections[0]
	best.CandidateCount = len(selections)
	return best, nil
}

func betterGroupSelection(a, b groupSelection) bool {
	if rank := profilePriority(a) - profilePriority(b); rank != 0 {
		return rank < 0
	}
	if rank := agentStatusRank(a.Snapshot.Status) - agentStatusRank(b.Snapshot.Status); rank != 0 {
		return rank < 0
	}
	if a.Membership.Priority != b.Membership.Priority {
		return a.Membership.Priority < b.Membership.Priority
	}
	if len(a.Snapshot.Streams) != len(b.Snapshot.Streams) {
		return len(a.Snapshot.Streams) < len(b.Snapshot.Streams)
	}
	if queueLoad(a.Snapshot) != queueLoad(b.Snapshot) {
		return queueLoad(a.Snapshot) < queueLoad(b.Snapshot)
	}
	if a.Snapshot.HeartbeatFailures != b.Snapshot.HeartbeatFailures {
		return a.Snapshot.HeartbeatFailures < b.Snapshot.HeartbeatFailures
	}
	if normalizeLatency(a.Snapshot.LatencyMillis) != normalizeLatency(b.Snapshot.LatencyMillis) {
		return normalizeLatency(a.Snapshot.LatencyMillis) < normalizeLatency(b.Snapshot.LatencyMillis)
	}
	if a.Membership.Weight != b.Membership.Weight {
		return a.Membership.Weight > b.Membership.Weight
	}
	return a.Membership.AgentID < b.Membership.AgentID
}

func profilePriority(selection groupSelection) int {
	if selection.ProfileID != "" {
		return 0
	}
	return 1
}

func agentStatusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "connected":
		return 0
	case "degraded":
		return 1
	default:
		return 2
	}
}

func queueLoad(agent statusAgent) int {
	return agent.RelayControlQueueDepth + agent.RelayDataQueueDepth + agent.AgentControlQueueDepth + agent.AgentDataQueueDepth
}

func normalizeLatency(value float64) float64 {
	if value <= 0 {
		return 1e9
	}
	return value
}

func profileMatchesTarget(profile controlplane.DestinationProfile, host string, port int) bool {
	return strings.EqualFold(strings.TrimSpace(profile.Host), strings.TrimSpace(host)) && profile.Port == port
}

func routeHTTPStatus(err error) int {
	if re, ok := err.(*routeError); ok && re.httpStatus > 0 {
		return re.httpStatus
	}
	return http.StatusInternalServerError
}

func routeSOCKSReply(err error) byte {
	if re, ok := err.(*routeError); ok && re.socksReply != 0 {
		return re.socksReply
	}
	return 0x01
}

func (s groupSelection) agentName() string {
	if s.Session != nil && strings.TrimSpace(s.Session.identification) != "" {
		return s.Session.identification
	}
	return s.Membership.AgentID
}
