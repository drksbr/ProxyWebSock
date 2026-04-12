package controlplane

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func prepareUser(user User) (User, error) {
	if strings.TrimSpace(user.ID) == "" {
		return User{}, fmt.Errorf("user id is required")
	}
	user.Username = strings.TrimSpace(user.Username)
	if user.Username == "" {
		return User{}, fmt.Errorf("username is required")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return User{}, fmt.Errorf("password hash is required")
	}
	if user.Status == "" {
		user.Status = UserStatusActive
	}
	if user.Role == "" {
		user.Role = UserRoleUser
	}
	return user, nil
}

func prepareAgentGroup(group AgentGroup) (AgentGroup, error) {
	if strings.TrimSpace(group.ID) == "" {
		return AgentGroup{}, fmt.Errorf("agent group id is required")
	}
	group.Name = strings.TrimSpace(group.Name)
	group.Slug = strings.TrimSpace(group.Slug)
	if group.Name == "" {
		return AgentGroup{}, fmt.Errorf("agent group name is required")
	}
	if group.Slug == "" {
		return AgentGroup{}, fmt.Errorf("agent group slug is required")
	}
	if group.RoutingMode == "" {
		group.RoutingMode = "health-first"
	}
	return group, nil
}

func prepareAgentMembership(membership AgentMembership) (AgentMembership, error) {
	membership.AgentID = strings.TrimSpace(membership.AgentID)
	membership.GroupID = strings.TrimSpace(membership.GroupID)
	if membership.AgentID == "" {
		return AgentMembership{}, fmt.Errorf("agent id is required")
	}
	if membership.GroupID == "" {
		return AgentMembership{}, fmt.Errorf("group id is required")
	}
	if membership.Weight == 0 {
		membership.Weight = 1
	}
	return membership, nil
}

func prepareDestinationProfile(profile DestinationProfile) (DestinationProfile, error) {
	if strings.TrimSpace(profile.ID) == "" {
		return DestinationProfile{}, fmt.Errorf("destination profile id is required")
	}
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Slug = strings.TrimSpace(profile.Slug)
	profile.Host = strings.TrimSpace(profile.Host)
	if profile.Name == "" {
		return DestinationProfile{}, fmt.Errorf("destination profile name is required")
	}
	if profile.Slug == "" {
		return DestinationProfile{}, fmt.Errorf("destination profile slug is required")
	}
	if profile.Host == "" {
		return DestinationProfile{}, fmt.Errorf("destination profile host is required")
	}
	if profile.Port <= 0 || profile.Port > 65535 {
		return DestinationProfile{}, fmt.Errorf("destination profile port is invalid")
	}
	return profile, nil
}

func prepareAccessGrant(grant AccessGrant) (AccessGrant, error) {
	if strings.TrimSpace(grant.ID) == "" {
		return AccessGrant{}, fmt.Errorf("access grant id is required")
	}
	grant.UserID = strings.TrimSpace(grant.UserID)
	grant.GroupID = strings.TrimSpace(grant.GroupID)
	grant.DestinationProfileID = strings.TrimSpace(grant.DestinationProfileID)
	if grant.UserID == "" {
		return AccessGrant{}, fmt.Errorf("access grant user id is required")
	}
	if grant.GroupID == "" && grant.DestinationProfileID == "" {
		return AccessGrant{}, fmt.Errorf("access grant requires group id or destination profile id")
	}
	if grant.AccessMode == "" {
		grant.AccessMode = "direct"
	}
	return grant, nil
}

func prepareAuditEvent(event AuditEvent) (AuditEvent, error) {
	event.ID = strings.TrimSpace(event.ID)
	if event.ID == "" {
		event.ID = "evt-" + uuid.NewString()
	}
	event.Category = strings.TrimSpace(event.Category)
	event.Action = strings.TrimSpace(event.Action)
	event.ActorType = strings.TrimSpace(event.ActorType)
	event.ActorID = strings.TrimSpace(event.ActorID)
	event.ActorName = strings.TrimSpace(event.ActorName)
	event.ResourceType = strings.TrimSpace(event.ResourceType)
	event.ResourceID = strings.TrimSpace(event.ResourceID)
	event.ResourceName = strings.TrimSpace(event.ResourceName)
	event.Outcome = strings.TrimSpace(event.Outcome)
	event.Message = strings.TrimSpace(event.Message)
	event.RemoteAddr = strings.TrimSpace(event.RemoteAddr)
	if event.Category == "" {
		return AuditEvent{}, fmt.Errorf("audit event category is required")
	}
	if event.Action == "" {
		return AuditEvent{}, fmt.Errorf("audit event action is required")
	}
	if event.Outcome == "" {
		event.Outcome = "success"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}
	return event, nil
}

func membershipKey(groupID, agentID string) string {
	return strings.TrimSpace(groupID) + ":" + strings.TrimSpace(agentID)
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
